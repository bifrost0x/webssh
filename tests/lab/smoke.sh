#!/usr/bin/env bash
# Smoke test for a running lab: one real client per counterpart.
# Host side needs ssh, smbclient, curl, openssl and jq; everything else runs
# in the lab tools image. Exits non-zero if any check fails.
set -uo pipefail

lab_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rt="$lab_dir/runtime"
[ -f "$rt/lab.json" ] || { echo "lab is not up (missing $rt/lab.json)" >&2; exit 1; }
# shellcheck disable=SC1091
source "$lab_dir/lab.env"

failures=0
check() {
    local name="$1"; shift
    local out
    if out="$("$@" 2>&1)"; then
        printf 'PASS  %s\n' "$name"
    else
        printf 'FAIL  %s\n%s\n' "$name" "$(printf '%s\n' "$out" | tail -n 3 | sed 's/^/      /')"
        failures=$((failures + 1))
    fi
}
expect_fail() { ! "$@"; }
secret() { head -n1 "$rt/secrets/$1"; }

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
known_hosts="$work/known_hosts"
for host in ssh-modern ssh-bastion; do
    port="$(jq -r ".services[\"$host\"].port" "$rt/lab.json")"
    for key in "$rt/ssh/hostkeys/$host"/*.pub; do
        printf '[%s]:%s %s\n' "$LAB_BIND" "$port" "$(cut -d' ' -f1,2 "$key")"
    done
done > "$known_hosts"
for key in "$rt/ssh/hostkeys/ssh-inner"/*.pub; do
    printf 'ssh-inner.lab.test %s\n' "$(cut -d' ' -f1,2 "$key")"
done >> "$known_hosts"
for key in "$rt/ssh/legacy/hostkeys"/*.pub; do
    printf '[%s]:%s %s\n' "$LAB_BIND" "$LAB_PORT_SSH_LEGACY" "$(cut -d' ' -f1,2 "$key")"
done >> "$known_hosts"
ssh_opts=(-o UserKnownHostsFile="$known_hosts" -o StrictHostKeyChecking=yes -o BatchMode=yes
          -o IdentitiesOnly=yes -o ConnectTimeout=10)
key="$rt/ssh/client/ed25519"

echo "== SMB"
smb() { smbclient "//$LAB_BIND/$1" -p "$LAB_PORT_SAMBA" -U "$2%$(secret "samba-$2")" -m SMB3 -c "${3:-ls}" >/dev/null; }
check "smb Secure share as smbuser" smb Secure smbuser
check "smb Plain share write as smbuser" smb Plain smbuser "put $lab_dir/lab.env smoke.txt; del smoke.txt"
check "smb ReadOnly as smbreader" smb ReadOnly smbreader
check "smb Secure denied for smbreader" expect_fail smb Secure smbreader
check "smb SMB2 dialect refused" expect_fail smbclient "//$LAB_BIND/Plain" -p "$LAB_PORT_SAMBA" \
    -U "smbuser%$(secret samba-smbuser)" -m SMB2_10 -c ls
check "smb encryption only on Secure" sh -c "
    for s in Secure Plain; do ( (echo ls; sleep 4) | smbclient //$LAB_BIND/\$s -p $LAB_PORT_SAMBA \
        -U 'smbuser%$(secret samba-smbuser)' >/dev/null 2>&1 & ) ; done; sleep 2
    st=\$(docker exec webssh-lab-samba-1 smbstatus -S 2>/dev/null)
    echo \"\$st\" | grep -E '^Secure .*AES-128-GCM' && echo \"\$st\" | grep -E '^Plain .* - +AES-128-GMAC'"

echo "== OpenSSH current"
check "ssh publickey (ed25519)" ssh "${ssh_opts[@]}" -p "$LAB_PORT_SSH_MODERN" -i "$key" "keyuser@$LAB_BIND" true
check "ssh publickey (rsa PEM)" ssh "${ssh_opts[@]}" -p "$LAB_PORT_SSH_MODERN" -i "$rt/ssh/client/rsa-3072-pem" "keyuser@$LAB_BIND" true
check "ssh ProxyJump bastion -> inner" ssh "${ssh_opts[@]}" -i "$key" \
    -o "ProxyCommand=ssh ${ssh_opts[*]} -i $key -W %h:%p -p $LAB_PORT_SSH_BASTION keyuser@$LAB_BIND" \
    keyuser@ssh-inner.lab.test true
check "ssh via SOCKS5 (no auth) -> inner" ssh "${ssh_opts[@]}" -i "$key" \
    -o "ProxyCommand=nc -X 5 -x $LAB_BIND:$LAB_PORT_SOCKS_OPEN %h %p" keyuser@ssh-inner.lab.test true

echo "== OpenSSH legacy"
legacy=(-p "$LAB_PORT_SSH_LEGACY" -i "$rt/ssh/legacy/client/rsa-2048-pem")
check "legacy refused by default client" expect_fail ssh "${ssh_opts[@]}" "${legacy[@]}" "legacyuser@$LAB_BIND" true
check "legacy with +ssh-rsa and SHA-1 KEX" ssh "${ssh_opts[@]}" "${legacy[@]}" -oHostKeyAlgorithms=+ssh-rsa \
    -oKexAlgorithms=+diffie-hellman-group14-sha1 -oPubkeyAcceptedAlgorithms=ssh-rsa "legacyuser@$LAB_BIND" true

echo "== SOCKS5"
check "curl via SOCKS5 with credentials" curl -fsS --max-time 10 --cacert "$rt/ca/ca.crt" \
    -x "socks5h://labproxy:$(secret socks-labproxy)@$LAB_BIND:$LAB_PORT_SOCKS_AUTH" https://github.lab.test:8443/healthz
check "SOCKS5 wrong password refused" expect_fail curl -fsS --max-time 10 \
    -x "socks5h://labproxy:wrong@$LAB_BIND:$LAB_PORT_SOCKS_AUTH" https://github.lab.test:8443/healthz

echo "== OIDC / OAuth"
check "dex discovery" sh -c "curl -fsS --cacert '$rt/ca/ca.crt' https://localhost:$LAB_PORT_DEX/dex/.well-known/openid-configuration | jq -e '.issuer == \"https://localhost:$LAB_PORT_DEX/dex\"'"
check "dex password grant" sh -c "curl -fsS --cacert '$rt/ca/ca.crt' -u 'webssh-lab:$(secret dex-client-secret)' \
    -d grant_type=password -d scope=openid -d username=alice@lab.test --data-urlencode 'password=$(secret dex-alice)' \
    https://localhost:$LAB_PORT_DEX/dex/token | jq -e .id_token"
check "mock-oauth2 token" sh -c "curl -fsS -d grant_type=client_credentials -d client_id=lab -d client_secret=lab \
    http://$LAB_BIND:$LAB_PORT_MOCK_OAUTH2/default/token | jq -e .access_token"
check "github stub reachable over TLS" curl -fsS --cacert "$rt/ca/ca.crt" "https://localhost:$LAB_PORT_GITHUB_STUB/healthz"

echo "== In-network checks (tools image)"
inner() {
    docker run --rm -i --network "${2:-webssh-lab_front}" -v "$rt:/lab:ro" \
        -e LDAPTLS_CACERT=/lab/ca/ca.crt webssh-lab/tools:local sh -c "$1"
}
check "ldap StartTLS bind + search (-ZZ)" inner 'ldapsearch -LLL -ZZ -H ldap://ldap1.lab.test \
    -D cn=webssh,ou=services,dc=lab,dc=test -w "$(head -n1 /lab/secrets/ldap-bind-webssh)" \
    -b ou=people,dc=lab,dc=test "(uid=alice)" dn | grep -q uid=alice'
check "ldap simple bind without TLS refused" inner '! ldapwhoami -x -H ldap://ldap1.lab.test \
    -D uid=alice,ou=people,dc=lab,dc=test -w "$(head -n1 /lab/secrets/ldap-alice)"'
check "ldap referral to ldap2" inner 'ldapsearch -ZZ -H ldap://ldap1.lab.test \
    -D cn=webssh,ou=services,dc=lab,dc=test -w "$(head -n1 /lab/secrets/ldap-bind-webssh)" \
    -b dc=lab,dc=test "(uid=carol)" | grep -q "^ref: ldap://ldap2.lab.test"'
check "ldap blackhole times out" inner '! LDAPTIMEOUT=3 timeout 8 ldapsearch -x -H ldap://toxiproxy.lab.test:3892 -b "" -s base'
check "ssh password + keyboard-interactive TOTP (paramiko)" inner 'python3 - <<"PY"
import base64, hashlib, hmac, struct, time, paramiko
sec = lambda n: open("/lab/secrets/" + n).read().strip()
def totp(b32):
    h = hmac.new(base64.b32decode(b32), struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    o = h[-1] & 15
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 10 ** 6)
t = paramiko.Transport(("ssh-modern.lab.test", 22)); t.start_client(timeout=10)
t.auth_password("pwuser", sec("ssh-pwuser")); assert t.is_authenticated(); t.close()
t = paramiko.Transport(("ssh-modern.lab.test", 22)); t.start_client(timeout=10)
t.auth_interactive("kiuser", lambda a, b, p: [sec("ssh-kiuser") if "assword" in q else totp(sec("ssh-kiuser-totp-base32")) for q, _ in p])
assert t.is_authenticated(); t.close()
PY'
check "tailscale0 route via table 52" inner 'ip route get 100.100.100.10 | grep -q "dev tailscale0 table 52"' container:lab-ts-node
check "tailscale stand-in accepts none auth" inner 'ssh -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes -o PreferredAuthentications=none tsuser@100.100.100.10 true' container:lab-ts-node

if [ "$(docker inspect -f '{{.State.Running}}' lab-windows 2>/dev/null)" = true ]; then
    echo "== Windows (profile windows)"
    check "windows LabShare as smbuser" smbclient "//$LAB_BIND/LabShare" -p "$LAB_PORT_WIN_SMB" \
        -U "smbuser%$(secret windows-smbuser)" -m SMB3 -c "get hello.txt /dev/null"
fi

echo
if [ "$failures" -eq 0 ]; then
    echo "all checks passed"
else
    echo "$failures check(s) failed"
    exit 1
fi
