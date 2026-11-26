#!/usr/bin/env python3
"""Generate per-run secrets, keys, certificates and the lab inventory.

Runs inside the lab tools image. Everything is written below the runtime
directory, which is mounted read-only into the lab services afterwards.
All values are synthetic and regenerated on every run.
"""

import argparse
import base64
import datetime
import hashlib
import json
import os
import secrets
import subprocess
import uuid
from pathlib import Path

import bcrypt

DOMAIN = "lab.test"

SSH_HOSTS = ("ssh-modern", "ssh-bastion", "ssh-inner", "ts-target")
TLS_SERVERS = {
    "ldap1": ["ldap1.lab.test", "ldap1", "toxiproxy.lab.test", "localhost", "127.0.0.1"],
    "ldap2": ["ldap2.lab.test", "ldap2", "localhost", "127.0.0.1"],
    "dex": ["dex.lab.test", "dex", "localhost", "127.0.0.1"],
    "github-stub": ["github.lab.test", "api.github.lab.test", "github-stub", "localhost", "127.0.0.1"],
}

# ssh-keygen arguments for every client key format the SSH targets accept.
CLIENT_KEYS = {
    "ed25519": ["-t", "ed25519"],
    "ed25519-encrypted": ["-t", "ed25519"],
    "ecdsa-p256": ["-t", "ecdsa", "-b", "256"],
    "ecdsa-p384": ["-t", "ecdsa", "-b", "384"],
    "ecdsa-p521": ["-t", "ecdsa", "-b", "521"],
    "ecdsa-p256-pem": ["-t", "ecdsa", "-b", "256", "-m", "PEM"],
    "rsa-3072": ["-t", "rsa", "-b", "3072"],
    "rsa-3072-pem": ["-t", "rsa", "-b", "3072", "-m", "PEM"],
    "rsa-3072-pkcs8": ["-t", "rsa", "-b", "3072", "-m", "PKCS8"],
    "rsa-3072-pem-encrypted": ["-t", "rsa", "-b", "3072", "-m", "PEM"],
}


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"{args[0]} failed: {result.stderr.strip()}")


def password():
    # URL-safe, no shell or config metacharacters, 128 bits of entropy.
    return "Lab-" + secrets.token_urlsafe(16)


class Runtime:
    def __init__(self, root):
        self.root = Path(root)
        self.secret_index = {}

    def path(self, relative):
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        return target

    def write(self, relative, content, mode=0o600):
        target = self.path(relative)
        data = content.encode() if isinstance(content, str) else content
        target.write_bytes(data)
        os.chmod(target, mode)
        return relative

    def secret(self, name, value=None):
        """Store one secret value in its own file and return the relative path."""
        value = value if value is not None else password()
        relative = f"secrets/{name}"
        self.write(relative, value + "\n", 0o644)
        self.secret_index[name] = value
        return relative


def ssha(value):
    salt = secrets.token_bytes(8)
    digest = hashlib.sha1(value.encode() + salt).digest()
    return "{SSHA}" + base64.b64encode(digest + salt).decode()


def make_ca(rt):
    key = rt.path("ca/ca.key")
    crt = rt.path("ca/ca.crt")
    run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-nodes", "-keyout", str(key), "-out", str(crt), "-days", "30",
        "-subj", "/CN=WebSSH Test Lab CA " + datetime.date.today().isoformat(),
        "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    os.chmod(key, 0o600)
    os.chmod(crt, 0o644)


def make_server_cert(rt, name, names):
    key = rt.path(f"tls/{name}.key")
    csr = rt.path(f"tls/{name}.csr")
    crt = rt.path(f"tls/{name}.crt")
    san = ",".join(("IP:" if n[0].isdigit() else "DNS:") + n for n in names)
    run("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-nodes", "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={names[0]}")
    ext = rt.path(f"tls/{name}.ext")
    ext.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth\n"
        f"subjectAltName={san}\n"
    )
    run("openssl", "x509", "-req", "-in", str(csr), "-CA", str(rt.path("ca/ca.crt")),
        "-CAkey", str(rt.path("ca/ca.key")), "-CAcreateserial", "-out", str(crt),
        "-days", "30", "-extfile", str(ext))
    csr.unlink()
    ext.unlink()
    # Services run as unprivileged users inside their containers; the
    # runtime root stays 0700 on the host.
    os.chmod(key, 0o644)
    os.chmod(crt, 0o644)


def fingerprint(pub_path):
    out = subprocess.run(["ssh-keygen", "-lf", str(pub_path), "-E", "sha256"],
                         check=True, capture_output=True, text=True).stdout.split()
    return out[1]


def make_host_keys(rt, host):
    result = {}
    for kind in ("ed25519", "ecdsa", "rsa"):
        key = rt.path(f"ssh/hostkeys/{host}/ssh_host_{kind}_key")
        args = ["ssh-keygen", "-q", "-t", kind, "-N", "", "-C", f"{host}.{DOMAIN}", "-f", str(key)]
        if kind == "rsa":
            args[4:4] = ["-b", "3072"]
        run(*args)
        os.chmod(key, 0o600)
        result[kind] = fingerprint(str(key) + ".pub")
    return result


def make_client_keys(rt):
    keys = {}
    authorized = []
    for name, args in CLIENT_KEYS.items():
        key = rt.path(f"ssh/client/{name}")
        passphrase = ""
        entry = {"private_key_file": f"ssh/client/{name}", "public_key_file": f"ssh/client/{name}.pub"}
        if name.endswith("encrypted"):
            passphrase = password()
            entry["passphrase_file"] = rt.secret(f"ssh-key-{name}-passphrase", passphrase)
        run("ssh-keygen", "-q", *args, "-N", passphrase, "-C", f"lab-{name}", "-f", str(key))
        os.chmod(key, 0o600)
        authorized.append(Path(str(key) + ".pub").read_text().strip())
        entry["format"] = "PEM" if "-pem" in name else ("PKCS8" if "pkcs8" in name else "OpenSSH")
        entry["fingerprint"] = fingerprint(str(key) + ".pub")
        keys[name] = entry
    rt.write("ssh/authorized_keys", "\n".join(authorized) + "\n", 0o644)
    return keys


def totp_secret(rt, user):
    raw = secrets.token_bytes(20)
    b32 = base64.b32encode(raw).decode()
    # google-authenticator file format: secret line followed by options.
    rt.write(f"ssh/{user}.google_authenticator",
             f'{b32}\n" RATE_LIMIT 10 30\n" WINDOW_SIZE 3\n" TOTP_AUTH\n', 0o644)
    return rt.secret(f"ssh-{user}-totp-base32", b32)


def render_ldap(rt, users):
    admin = rt.secret("ldap-admin")
    bind = rt.secret("ldap-bind-webssh")
    rt.write("ldap/rootpw-ldap1", ssha(rt.secret_index["ldap-admin"]) + "\n", 0o644)
    rt.write("ldap/rootpw-ldap2", ssha(rt.secret_index["ldap-admin"]) + "\n", 0o644)

    def person(uid, given, ou):
        entry_uuid = str(uuid.uuid4())
        return (
            f"dn: uid={uid},ou={ou},dc=lab,dc=test\n"
            "objectClass: inetOrgPerson\n"
            f"uid: {uid}\ncn: {given} Lab\nsn: Lab\ngivenName: {given}\n"
            f"mail: {uid}@{DOMAIN}\n"
            f"userPassword: {ssha(rt.secret_index[f'ldap-{uid}'])}\n"
            f"entryUUID: {entry_uuid}\n\n"
        )

    for uid in users["ldap1"] + users["ldap2"]:
        rt.secret(f"ldap-{uid}")

    base = (
        "dn: dc=lab,dc=test\nobjectClass: dcObject\nobjectClass: organization\n"
        "o: WebSSH Lab\ndc: lab\n\n"
    )
    ldap1 = base
    for ou in ("people", "services", "groups"):
        ldap1 += f"dn: ou={ou},dc=lab,dc=test\nobjectClass: organizationalUnit\nou: {ou}\n\n"
    ldap1 += "".join(person(uid, uid.capitalize(), "people") for uid in users["ldap1"])
    ldap1 += (
        "dn: cn=webssh,ou=services,dc=lab,dc=test\n"
        "objectClass: applicationProcess\nobjectClass: simpleSecurityObject\n"
        f"cn: webssh\nuserPassword: {ssha(rt.secret_index['ldap-bind-webssh'])}\n\n"
        "dn: cn=webssh-users,ou=groups,dc=lab,dc=test\nobjectClass: groupOfNames\n"
        "cn: webssh-users\nmember: uid=alice,ou=people,dc=lab,dc=test\n\n"
        "dn: ou=partners,dc=lab,dc=test\nobjectClass: referral\nobjectClass: extensibleObject\n"
        "ou: partners\nref: ldap://ldap2.lab.test:389/ou=partners,dc=lab,dc=test\n\n"
    )
    ldap2 = base + "dn: ou=partners,dc=lab,dc=test\nobjectClass: organizationalUnit\nou: partners\n\n"
    ldap2 += "".join(person(uid, uid.capitalize(), "partners") for uid in users["ldap2"])
    rt.write("ldap/ldap1.ldif", ldap1, 0o644)
    rt.write("ldap/ldap2.ldif", ldap2, 0o644)
    return admin, bind


def render_dex(rt, ports):
    client_secret = rt.secret("dex-client-secret")
    users = []
    for name in ("alice", "bob"):
        pw = rt.secret(f"dex-{name}")
        users.append({
            "email": f"{name}@{DOMAIN}",
            "hash": bcrypt.hashpw(rt.secret_index[f"dex-{name}"].encode(), bcrypt.gensalt(10)).decode(),
            "username": name,
            "userID": str(uuid.uuid4()),
            "_password_file": pw,
        })
    issuer = f"https://localhost:{ports['dex']}/dex"
    config = {
        "issuer": issuer,
        "storage": {"type": "memory"},
        "web": {"https": f"0.0.0.0:{ports['dex']}", "tlsCert": "/lab/tls/dex.crt",
                "tlsKey": "/lab/tls/dex.key"},
        "oauth2": {"skipApprovalScreen": True, "passwordConnector": "local",
                   "grantTypes": ["authorization_code", "refresh_token", "password"]},
        "enablePasswordDB": True,
        "staticPasswords": [{k: v for k, v in u.items() if not k.startswith("_")} for u in users],
        "staticClients": [{
            "id": "webssh-lab",
            "name": "WebSSH Lab",
            "secret": rt.secret_index["dex-client-secret"],
            "redirectURIs": [
                "https://localhost:5000/oidc/callback",
                "https://127.0.0.1:5000/oidc/callback",
            ],
        }],
    }
    # JSON is valid YAML; dex reads it unchanged.
    rt.write("dex/config.yaml", json.dumps(config, indent=2) + "\n", 0o644)
    return issuer, client_secret, users


def render_github(rt):
    client_secret = rt.secret("github-client-secret")
    users = {
        "octo-alice": {"id": 1001, "name": "Alice Octo", "orgs": {"lab-org": "active"}},
        "octo-bob": {"id": 1002, "name": None, "orgs": {"lab-org": "pending"}},
        "octo-carol": {"id": 1003, "name": "Carol Octo", "orgs": {}},
    }
    config = {
        "client_id": "webssh-lab-github",
        "client_secret": rt.secret_index["github-client-secret"],
        "default_login": "octo-alice",
        # Membership checks for this organization answer 502 to exercise
        # the "could not be verified" path.
        "unavailable_orgs": ["flaky-org"],
        "users": users,
    }
    rt.write("github/config.json", json.dumps(config, indent=2) + "\n", 0o644)
    return client_secret, users


def windows_ssh_keys(storage):
    """Client and host key for the guest's OpenSSH server. Like the passwords
    they persist with the VM storage, because the guest receives them once at
    installation."""
    keys = Path(storage) / "lab-ssh"
    keys.mkdir(parents=True, exist_ok=True)
    os.chmod(keys, 0o700)
    for name, comment in (("labadmin_ed25519", "labadmin@lab"), ("ssh_host_ed25519_key", "windows.lab.test")):
        if not (keys / name).exists():
            run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(keys / name))
    return keys


def fingerprint(pub_path):
    result = subprocess.run(["ssh-keygen", "-l", "-E", "sha256", "-f", str(pub_path)],
                            capture_output=True, text=True, check=True)
    return result.stdout.split()[1]


def render_windows(rt, storage):
    """Windows credentials persist with the installed VM, not per run."""
    persisted = Path(storage) / "lab-credentials.json"
    if persisted.exists():
        creds = json.loads(persisted.read_text())
    else:
        creds = {"admin": password(), "smbuser": password()}
        persisted.parent.mkdir(parents=True, exist_ok=True)
        persisted.write_text(json.dumps(creds))
        os.chmod(persisted, 0o600)
    rt.write("windows/windows.env",
             f"USERNAME=labadmin\nPASSWORD={creds['admin']}\n", 0o600)
    template = Path("/opt/lab/windows/install.bat.in").read_text()
    rt.write("windows/oem/install.bat",
             template.replace("@SMBUSER_PASSWORD@", creds["smbuser"]).replace("\n", "\r\n"),
             0o644)
    keys = windows_ssh_keys(storage)
    ssh_template = Path("/opt/lab/windows/enable-ssh.ps1.in").read_text()
    script = (ssh_template
              .replace("@HOST_KEY@", (keys / "ssh_host_ed25519_key").read_text().strip())
              .replace("@HOST_KEY_PUB@", (keys / "ssh_host_ed25519_key.pub").read_text().strip())
              .replace("@ADMIN_PUBKEY@", (keys / "labadmin_ed25519.pub").read_text().strip()))
    # The OEM folder is copied into the guest; it already holds lab passwords.
    rt.write("windows/oem/enable-ssh.ps1", script.replace("\n", "\r\n"), 0o644)
    rt.write("windows/ssh/labadmin_ed25519", (keys / "labadmin_ed25519").read_bytes(), 0o600)
    return {"labadmin": rt.secret("windows-labadmin", creds["admin"]),
            "smbuser": rt.secret("windows-smbuser", creds["smbuser"]),
            "ssh_key": "windows/ssh/labadmin_ed25519",
            "ssh_host_fp": fingerprint(keys / "ssh_host_ed25519_key.pub")}


def windows_inventory(bind, ports, windows_secrets):
    return {"profile": "windows", "host": bind, "web_port": ports["win_web"],
            "rdp_port": ports["win_rdp"], "smb_port": ports["win_smb"],
            "share": "LabShare",
            "users": [{"username": "labadmin", "password_file": windows_secrets["labadmin"]},
                      {"username": "smbuser", "password_file": windows_secrets["smbuser"]}],
            "ssh": {"port": ports["win_ssh"], "internal_port": 22, "user": "labadmin",
                    "auth": ["publickey"], "key_file": windows_secrets["ssh_key"],
                    "host_key_fingerprints": {"ed25519": windows_secrets["ssh_host_fp"]},
                    "default_shell": "powershell"},
            "note": "credentials and SSH keys persist with the VM storage, not per run"}


def render_windows_only(rt, storage, bind, ports):
    """Re-render only the Windows files and its inventory entry, keeping every
    other per-run secret of a running lab."""
    inventory_path = rt.root / "lab.json"
    inventory = json.loads(inventory_path.read_text())
    inventory["services"]["windows"] = windows_inventory(bind, ports, render_windows(rt, storage))
    # Other clients read lab.json while the lab runs: replace it atomically.
    rt.write("lab.json.tmp", json.dumps(inventory, indent=2) + "\n", 0o600)
    os.replace(rt.root / "lab.json.tmp", inventory_path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--host-runtime", required=True)
    parser.add_argument("--windows-storage", required=True)
    parser.add_argument("--only-windows", action="store_true",
                        help="re-render only the Windows files of a running lab")
    args = parser.parse_args()

    env = os.environ
    bind = env["LAB_BIND"]
    ports = {k[len("LAB_PORT_"):].lower(): int(v) for k, v in env.items() if k.startswith("LAB_PORT_")}
    rt = Runtime(args.out)
    if args.only_windows:
        render_windows_only(rt, args.windows_storage, bind, ports)
        return

    make_ca(rt)
    for name, names in TLS_SERVERS.items():
        make_server_cert(rt, name, names)
    host_fps = {host: make_host_keys(rt, host) for host in SSH_HOSTS}
    client_keys = make_client_keys(rt)

    ssh_users = {
        "pwuser": {"auth": ["password"], "password_file": rt.secret("ssh-pwuser")},
        "keyuser": {"auth": ["publickey"], "keys": sorted(client_keys)},
        "kiuser": {"auth": ["keyboard-interactive"], "password_file": rt.secret("ssh-kiuser"),
                   "totp_base32_file": totp_secret(rt, "kiuser"),
                   "prompts": ["Password: ", "Verification code: "]},
        "mfauser": {"auth": ["publickey", "keyboard-interactive"],
                    "keys": sorted(client_keys),
                    "password_file": rt.secret("ssh-mfauser"),
                    "totp_base32_file": totp_secret(rt, "mfauser"),
                    "note": "partial success: publickey first, then password and TOTP"},
    }
    legacy_password = rt.secret("ssh-legacyuser")
    samba_users = {"smbuser": rt.secret("samba-smbuser"), "smbreader": rt.secret("samba-smbreader")}
    socks_password = rt.secret("socks-labproxy")
    ldap_users = {"ldap1": ["alice", "bob"], "ldap2": ["carol"]}
    render_ldap(rt, ldap_users)
    issuer, _, dex_users = render_dex(rt, ports)
    _, gh_users = render_github(rt)
    windows_secrets = render_windows(rt, args.windows_storage)

    def svc(port_key, internal_host, internal_port, **extra):
        return {"host": bind, "port": ports[port_key], "internal_host": internal_host,
                "internal_port": internal_port, **extra}

    ssh_common = {"users": ssh_users}
    inventory = {
        "format": 1,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "runtime_dir": args.host_runtime,
        "note": "Paths are relative to runtime_dir. All secrets are synthetic and regenerated per run.",
        "ca_file": "ca/ca.crt",
        "services": {
            "samba": svc("samba", "samba.lab.test", 445, protocol="smb", dialect="SMB3_11",
                         signing="mandatory",
                         shares={"Secure": {"encryption": "required", "writable": True},
                                 "Plain": {"encryption": "off", "writable": True},
                                 "ReadOnly": {"encryption": "if_required", "writable": False}},
                         users=[{"username": u, "password_file": p, "domain": "LAB"}
                                for u, p in samba_users.items()],
                         access={"smbuser": ["Secure", "Plain", "ReadOnly"],
                                 "smbreader": ["ReadOnly"]}),
            "ssh-modern": svc("ssh_modern", "ssh-modern.lab.test", 22, protocol="ssh",
                              host_key_fingerprints=host_fps["ssh-modern"], **ssh_common),
            "ssh-bastion": svc("ssh_bastion", "ssh-bastion.lab.test", 22, protocol="ssh",
                               host_key_fingerprints=host_fps["ssh-bastion"], **ssh_common),
            "ssh-inner": {"host": None, "port": None, "internal_host": "ssh-inner.lab.test",
                          "internal_port": 22, "protocol": "ssh",
                          "reachable_via": "ssh-bastion (ProxyJump) or socks-open/socks-auth",
                          "host_key_fingerprints": host_fps["ssh-inner"], **ssh_common},
            "ssh-legacy": svc("ssh_legacy", "ssh-legacy.lab.test", 22, protocol="ssh",
                              host_key_fingerprints_file="ssh/legacy/fingerprints.json",
                              offers={"host_key": ["ssh-rsa", "ssh-dss"],
                                      "kex": ["diffie-hellman-group14-sha1",
                                              "diffie-hellman-group-exchange-sha1",
                                              "diffie-hellman-group1-sha1"],
                                      "cipher": ["aes128-ctr", "aes128-cbc", "3des-cbc"],
                                      "mac": ["hmac-sha1"]},
                              users={"legacyuser": {"auth": ["password", "publickey"],
                                                    "password_file": legacy_password,
                                                    "keys": {
                                                        "rsa-2048-pem": "ssh/legacy/client/rsa-2048-pem",
                                                        "dsa-1024": "ssh/legacy/client/dsa-1024"}}}),
            "socks-open": svc("socks_open", "socks-open.lab.test", 1080, protocol="socks5", auth="none",
                              reaches=["ssh-modern", "ssh-inner", "ssh-legacy", "github-stub", "dex"]),
            "socks-auth": svc("socks_auth", "socks-auth.lab.test", 1080, protocol="socks5",
                              auth="username/password",
                              users=[{"username": "labproxy", "password_file": socks_password}],
                              reaches=["ssh-modern", "ssh-inner", "ssh-legacy", "github-stub", "dex"]),
            "ldap1": svc("ldap1", "ldap1.lab.test", 389, protocol="ldap", starttls="required for binds",
                         ldaps_port=ports["ldap1_tls"], base_dn="dc=lab,dc=test",
                         user_base_dn="ou=people,dc=lab,dc=test",
                         user_filter="(&(objectClass=inetOrgPerson)(uid={username}))",
                         unique_id_attribute="entryUUID",
                         admin={"dn": "cn=admin,dc=lab,dc=test", "password_file": "secrets/ldap-admin"},
                         bind={"dn": "cn=webssh,ou=services,dc=lab,dc=test",
                               "password_file": "secrets/ldap-bind-webssh"},
                         referral={"dn": "ou=partners,dc=lab,dc=test",
                                   "target": "ldap://ldap2.lab.test:389/ou=partners,dc=lab,dc=test"},
                         users=[{"username": u, "dn": f"uid={u},ou=people,dc=lab,dc=test",
                                 "password_file": f"secrets/ldap-{u}"} for u in ldap_users["ldap1"]]),
            "ldap2": svc("ldap2", "ldap2.lab.test", 389, protocol="ldap", starttls="required for binds",
                         base_dn="ou=partners,dc=lab,dc=test",
                         users=[{"username": u, "dn": f"uid={u},ou=partners,dc=lab,dc=test",
                                 "password_file": f"secrets/ldap-{u}"} for u in ldap_users["ldap2"]]),
            "ldap-slow": svc("ldap_slow", "toxiproxy.lab.test", 3891, protocol="ldap",
                             upstream="ldap1", behaviour="every response delayed by 3000 ms"),
            "ldap-blackhole": svc("ldap_blackhole", "toxiproxy.lab.test", 3892, protocol="ldap",
                                  upstream="ldap1", behaviour="TCP accepted, no data ever returned"),
            "dex": svc("dex", "dex.lab.test", ports["dex"], protocol="oidc", issuer=issuer,
                       discovery=f"{issuer}/.well-known/openid-configuration",
                       client={"id": "webssh-lab", "secret_file": "secrets/dex-client-secret",
                               "redirect_uris": ["https://localhost:5000/oidc/callback",
                                                 "https://127.0.0.1:5000/oidc/callback"]},
                       users=[{"username": u["username"], "email": u["email"], "subject_user_id": u["userID"],
                               "password_file": u["_password_file"]} for u in dex_users],
                       note="issuer is host-facing (localhost); containers reach the same port as "
                            "dex.lab.test, where the issuer string differs from the URL"),
            "mock-oauth2": svc("mock_oauth2", "mock-oauth2.lab.test", 8080, protocol="oauth2",
                               issuer=f"http://{bind}:{ports['mock_oauth2']}/default",
                               discovery=f"http://{bind}:{ports['mock_oauth2']}/default/.well-known/openid-configuration",
                               note="accepts any client_id/client_secret; tokens signed with a per-start key"),
            "github-stub": svc("github_stub", "github.lab.test", 8443, protocol="https",
                               base_url=f"https://localhost:{ports['github_stub']}",
                               endpoints=["GET /login/oauth/authorize", "POST /login/oauth/access_token",
                                          "GET /user", "GET /user/memberships/orgs/{org}"],
                               client={"id": "webssh-lab-github", "secret_file": "secrets/github-client-secret"},
                               users={login: {"id": u["id"], "orgs": u["orgs"]} for login, u in gh_users.items()},
                               unavailable_orgs=["flaky-org"]),
            "tailscale": {"host": None, "port": None, "protocol": "ssh",
                          "node_container": "lab-ts-node", "interface": "tailscale0",
                          "target": {"ip": "100.100.100.10", "port": 22, "remote_user": "tsuser",
                                     "auth": "none",
                                     "host_key_fingerprints": host_fps["ts-target"]},
                          "route_table": 52,
                          "usage": "run clients with --network container:lab-ts-node"},
            "windows": windows_inventory(bind, ports, windows_secrets),
        },
    }
    rt.write("lab.json", json.dumps(inventory, indent=2) + "\n", 0o600)


if __name__ == "__main__":
    main()
