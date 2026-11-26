#!/usr/bin/env bash
# Adds the OpenSSH server to a Windows VM that was installed before the OEM
# script enabled it. New installations get it from install.bat and do not
# need this script.
#
# It re-renders only the Windows files (no other lab secret changes), copies
# enable-ssh.ps1 into the guest over the admin share together with a one-shot
# Startup entry, recreates only the lab-windows container (new USER_PORTS and
# SSH port binding) and waits until sshd presents the expected host key.
# labadmin logs on automatically with UAC disabled, so the Startup entry runs
# elevated once and deletes itself.
set -euo pipefail

lab_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
runtime="$lab_dir/runtime"
export LAB_RUNTIME_HOST="$runtime"
export LAB_WINDOWS_STORAGE="${LAB_WINDOWS_STORAGE:-${XDG_CACHE_HOME:-$HOME/.cache}/webssh-lab/windows}"
compose() {
    docker compose --project-directory "$lab_dir" -f "$lab_dir/compose.yml" \
        --env-file "$lab_dir/lab.env" "$@"
}
set -a; . "$lab_dir/lab.env"; set +a

[ "$(docker inspect -f '{{.State.Running}}' lab-windows 2>/dev/null)" = true ] \
    || { echo "lab-windows is not running" >&2; exit 1; }

compose --profile init build lab-init
compose run --rm lab-init python3 /opt/lab/generate.py --out=/lab-runtime \
    --host-runtime="$runtime" --windows-storage=/windows-storage --only-windows

auth=$(mktemp); trap 'rm -f -- "$auth"' EXIT
chmod 600 "$auth"
printf 'username = labadmin\npassword = %s\ndomain = .\n' "$(head -n1 "$runtime/secrets/windows-labadmin")" > "$auth"
wrapper=$(mktemp); trap 'rm -f -- "$auth" "$wrapper"' EXIT
printf '@echo off\r\npowershell -NoProfile -ExecutionPolicy Bypass -File "C:\\ProgramData\\lab-ssh\\enable-ssh.ps1"\r\nif not errorlevel 1 (del /q "C:\\ProgramData\\lab-ssh\\enable-ssh.ps1" & rmdir "C:\\ProgramData\\lab-ssh" & del "%%~f0")\r\n' > "$wrapper"
smbclient "//$LAB_BIND/C\$" -p "$LAB_PORT_WIN_SMB" -A "$auth" -m SMB3 -c \
    "mkdir ProgramData\\lab-ssh; put \"$runtime/windows/oem/enable-ssh.ps1\" ProgramData\\lab-ssh\\enable-ssh.ps1; put \"$wrapper\" \"ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\lab-enable-ssh.cmd\"" \
    2>&1 | grep -v "smb.conf" || true

compose --profile windows up -d --no-deps --force-recreate windows

want=$(jq -r '.services.windows.ssh.host_key_fingerprints.ed25519' "$runtime/lab.json")
for _ in $(seq 120); do
    if got=$(ssh-keyscan -T 3 -t ed25519 -p "$LAB_PORT_WIN_SSH" "$LAB_BIND" 2>/dev/null | ssh-keygen -l -E sha256 -f - 2>/dev/null | awk '{print $2}') \
        && [ -n "$got" ]; then
        [ "$got" = "$want" ] && { echo "windows sshd is up with host key $got"; exit 0; }
        echo "unexpected host key $got (want $want)" >&2; exit 1
    fi
    sleep 5
done
echo "windows sshd did not come up within 10 minutes" >&2
exit 1
