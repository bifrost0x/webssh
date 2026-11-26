#!/usr/bin/env bash
# Start the test lab with freshly generated secrets.
#   tests/lab/up.sh            core services
#   tests/lab/up.sh --windows  core services plus the Windows Server VM
# The inventory for tests is written to tests/lab/runtime/lab.json.
set -euo pipefail

lab_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
runtime="$lab_dir/runtime"
export LAB_RUNTIME_HOST="$runtime"
export LAB_WINDOWS_STORAGE="${LAB_WINDOWS_STORAGE:-${XDG_CACHE_HOME:-$HOME/.cache}/webssh-lab/windows}"

with_windows=false
for arg in "$@"; do
    case "$arg" in
        --windows) with_windows=true ;;
        *) echo "usage: $0 [--windows]" >&2; exit 2 ;;
    esac
done

compose() {
    docker compose --project-directory "$lab_dir" -f "$lab_dir/compose.yml" \
        --env-file "$lab_dir/lab.env" "$@"
}

if [ -n "$(compose ps -q 2>/dev/null)" ]; then
    echo "lab is already running; run $lab_dir/down.sh first" >&2
    exit 1
fi

# Fresh secrets on every start.
if [ -d "$runtime" ]; then
    "$lab_dir/down.sh" >/dev/null
fi
install -d -m 0700 "$runtime" "$LAB_WINDOWS_STORAGE"
# dockur/windows recommends no copy-on-write for the VM disk on btrfs.
if [ "$(stat -f -c %T "$LAB_WINDOWS_STORAGE")" = btrfs ]; then
    chattr +C "$LAB_WINDOWS_STORAGE" 2>/dev/null || true
fi

compose --profile init build
compose run --rm lab-init
compose run --rm lab-init-legacy

mapfile -t services < <(compose config --services \
    | grep -v -e '^lab-init' -e '^windows$' -e '^toxiproxy-config$')
compose up -d --wait --wait-timeout 180 "${services[@]}"
# One-shot toxic configuration; exits when done.
compose up --exit-code-from toxiproxy-config toxiproxy-config >/dev/null

if $with_windows; then
    # The first start downloads and installs Windows; do not wait for it.
    compose --profile windows up -d windows
    echo "windows: first install takes long; follow with: docker logs -f lab-windows"
fi
echo "lab is up; inventory: $runtime/lab.json"
