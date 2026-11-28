# Local test lab

Counterparts for the kill-risk checks of the Go migration (K1-K9): SMB,
OpenSSH (current and legacy), SOCKS5, LDAP, OIDC, GitHub OAuth, a Tailscale
SSH stand-in and an optional Windows Server VM. Everything runs locally in
rootless Docker. No external accounts are used.

This is test infrastructure only. Never expose or deploy any of it.

## Usage

```bash
tests/lab/up.sh              # build, generate secrets, start, wait for health
tests/lab/smoke.sh           # one real client per counterpart
tests/lab/down.sh            # stop, remove containers, volumes and secrets
tests/lab/up.sh --windows    # additionally start the Windows Server VM
tests/lab/down.sh --purge-windows   # also delete the VM disk and ISO cache
```

Requirements: Docker with Compose (rootless works), `/dev/kvm` for Windows.
`smoke.sh` also needs `ssh`, `smbclient`, `curl`, `openssl` and `jq` on the
host; LDAP and paramiko checks run in the lab tools image.

To run Compose commands by hand, pass the same files as the scripts:

```bash
LAB_RUNTIME_HOST=$PWD/tests/lab/runtime \
LAB_WINDOWS_STORAGE=~/.cache/webssh-lab/windows \
docker compose -f tests/lab/compose.yml --env-file tests/lab/lab.env ps
```

## Secrets and inventory

`up.sh` regenerates every secret on each start (lab CA, server certificates,
SSH host and client keys, passwords, TOTP seeds, OAuth client secrets) into
`tests/lab/runtime/` (mode 0700, ignored by git). Services mount it read-only.
Only the Windows credentials and SSH keys persist with the VM storage
(`lab-credentials.json`, `lab-ssh/`), because the VM is installed once.

`runtime/lab.json` is the machine-readable inventory for tests: host, port,
in-network hostname, users and the path of each secret file (relative to
`runtime_dir`), host-key fingerprints, CA file. Each secret is one file under
`runtime/secrets/`, first line is the value.

Ports are defined in `lab.env` and bind to `127.0.0.1` only.

## Counterparts

| Service | Host port | Notes |
|---|---|---|
| samba | 14445 | Samba (Alpine), SMB 3.1.1 only, signing mandatory, NTLMv2. `Secure` forces encryption, `Plain` disables it, `ReadOnly`. Users `smbuser`, `smbreader` |
| ssh-modern | 12201 | Current OpenSSH (Alpine) with PAM. `pwuser` password, `keyuser` keys (ed25519, ECDSA P-256/384/521, RSA in OpenSSH/PEM/PKCS#8, two encrypted), `kiuser` keyboard-interactive (password + TOTP), `mfauser` publickey then keyboard-interactive |
| ssh-bastion | 12202 | Same accounts; only path to `ssh-inner` besides SOCKS |
| ssh-inner | - | Internal network only, reachable via bastion or SOCKS |
| ssh-legacy | 12203 | OpenSSH 9.2 (Debian 12) offering only `ssh-rsa`/`ssh-dss` host keys, SHA-1 KEX, CBC ciphers, `hmac-sha1`. `legacyuser` with password, RSA PEM and DSA keys (DSA material generated with the legacy image, current ssh-keygen cannot) |
| socks-open / socks-auth | 11080 / 11081 | Dante SOCKS5, no auth / username `labproxy`. Reach SSH targets including `ssh-inner` and the HTTP stubs; loopback destinations blocked |
| ldap1 | 13389, 13636 | OpenLDAP, StartTLS and LDAPS with the lab CA, simple binds require TLS. Referral `ou=partners` to ldap2 |
| ldap2 | 13390 | Referral target with `uid=carol` |
| ldap-slow | 13391 | Toxiproxy to ldap1, every downstream chunk delayed by 3 s |
| ldap-blackhole | 13392 | Toxiproxy to ldap1, accepts TCP, never answers |
| dex | 15556 | OIDC, issuer `https://localhost:15556/dex`, static users alice/bob, client `webssh-lab`, password grant enabled for tests |
| mock-oauth2 | 18080 | navikt mock-oauth2-server, issuer `http://127.0.0.1:18080/default` |
| github-stub | 18443 | Stub of the GitHub endpoints that `internal/auth/github` calls (authorize with PKCE S256, token, `/user`, `/user/memberships/orgs/{org}`); `flaky-org` answers 502 |
| ts-node / ts-target | - | Tailscale stand-in, see below |
| windows (profile) | 18006 web, 13489 RDP, 14446 SMB, 12204 SSH | dockur/windows, Windows Server 2025 evaluation, share `LabShare`, user `smbuser`; OpenSSH for `labadmin` with key `runtime/windows/ssh/labadmin_ed25519` only, default shell PowerShell |

In-network hostnames are `<service>.lab.test` on the `webssh-lab_front`
network; the inventory lists them as `internal_host`.

## Tailscale SSH stand-in

`lab-ts-node` is a network namespace with an interface named `tailscale0`
(100.100.100.2/24). Its setup moves the tailnet route out of the main table
into table 52 behind rule 5270, as tailscaled does, so only a kernel FIB
lookup (RTM_GETROUTE) sees it. `ts-target` (100.100.100.10) runs sshd where
the `none` method succeeds for `tsuser`, like tailssh after it authorized
the node. Run a client in that namespace with
`docker run --network container:lab-ts-node ...`.

Limits of the stand-in:

- `tailscale0` is a veth on an internal Docker bridge, not a WireGuard TUN;
  no tailscaled, no MagicDNS, no `*.ts.net` names, no 4via6 routes.
- The target accepts anyone on that network. There is no node identity, ACL
  or `check` mode; Tailscale's authorization decision is not exercised.
- A real tailnet test needs a Tailscale account and stays a residual risk.

## Limits

- Dex and the GitHub stub use `localhost` URLs from the host's point of view.
  Containers reach them as `dex.lab.test` / `github.lab.test` on the same
  ports, where the OIDC issuer string does not match the URL.
- WebSSH hardcodes the GitHub URLs; tests point requests at the stub
  (e.g. a rewriting HTTP session) until the base URL is injectable.
- Samba offers NTLM only; there is no Kerberos/AD domain.
- The Windows VM needs KVM, about 8 GB download and roughly 35 minutes for
  the first install (download included); later starts take under a minute.
  Storage defaults to `~/.cache/webssh-lab/windows` (`LAB_WINDOWS_STORAGE`,
  about 11 GB after install). Under rootless Docker dockur falls back to
  user-mode networking (passt), so only listed ports reach the guest
  (`USER_PORTS`), and its own host-folder Samba is disabled to free 445.
  `C:\OEM\install.bat` runs at the first logon and creates `smbuser` and
  `LabShare`, then `enable-ssh.ps1` enables the built-in OpenSSH server
  (public key only, `AllowUsers labadmin`, fixed host key from the
  generator, listed in `lab.json`).
- A VM installed before the SSH step gets it with
  `tests/lab/windows/enable-ssh-existing.sh`: it re-renders only the Windows
  files, copies the script into the guest with a one-shot Startup entry and
  recreates only `lab-windows`. Other services and their secrets stay as
  they are.
