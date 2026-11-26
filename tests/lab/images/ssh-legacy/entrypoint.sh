#!/bin/sh
# keygen: create DSA/RSA material that current ssh-keygen can no longer make.
# serve (default): run sshd with the material from the read-only runtime.
set -eu
if [ "${1:-serve}" = keygen ]; then
    out=/lab-runtime/ssh/legacy
    mkdir -p "$out/hostkeys" "$out/client"
    ssh-keygen -q -t rsa -b 2048 -N '' -C ssh-legacy.lab.test -f "$out/hostkeys/ssh_host_rsa_key"
    ssh-keygen -q -t dsa -N '' -C ssh-legacy.lab.test -f "$out/hostkeys/ssh_host_dsa_key"
    ssh-keygen -q -t rsa -b 2048 -m PEM -N '' -C lab-legacy-rsa -f "$out/client/rsa-2048-pem"
    ssh-keygen -q -t dsa -N '' -C lab-legacy-dsa -f "$out/client/dsa-1024"
    chmod 0600 "$out/client/rsa-2048-pem" "$out/client/dsa-1024"
    cat "$out/client/rsa-2048-pem.pub" "$out/client/dsa-1024.pub" > "$out/authorized_keys"
    python3 - "$out" <<'PY'
import json, subprocess, sys
out = sys.argv[1]
fps = {}
for kind in ("rsa", "dsa"):
    line = subprocess.run(["ssh-keygen", "-lf", f"{out}/hostkeys/ssh_host_{kind}_key.pub", "-E", "sha256"],
                          check=True, capture_output=True, text=True).stdout.split()
    fps[kind] = line[1]
json.dump(fps, open(f"{out}/fingerprints.json", "w"), indent=2)
PY
    exit 0
fi

LAB_SSH_LEGACYUSER="$(head -n1 /lab/secrets/ssh-legacyuser)"
install -d -m 0755 /etc/ssh/keys /etc/ssh/authorized_keys
install -m 0600 /lab/ssh/legacy/hostkeys/ssh_host_rsa_key /lab/ssh/legacy/hostkeys/ssh_host_dsa_key /etc/ssh/keys/
install -m 0644 /lab/ssh/legacy/authorized_keys /etc/ssh/authorized_keys/legacyuser
id -u legacyuser >/dev/null 2>&1 || useradd --create-home --shell /bin/sh legacyuser
printf 'legacyuser:%s\n' "$LAB_SSH_LEGACYUSER" | chpasswd
/usr/sbin/sshd -t
exec /usr/sbin/sshd -D -e
