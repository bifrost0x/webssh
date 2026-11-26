#!/usr/bin/env bash
# Stop the test lab and delete its per-run secrets. The Windows VM storage
# (LAB_WINDOWS_STORAGE) is kept; pass --purge-windows to delete it as well.
set -euo pipefail

lab_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
runtime="$lab_dir/runtime"
export LAB_RUNTIME_HOST="$runtime"
export LAB_WINDOWS_STORAGE="${LAB_WINDOWS_STORAGE:-${XDG_CACHE_HOME:-$HOME/.cache}/webssh-lab/windows}"

purge_windows=false
for arg in "$@"; do
    case "$arg" in
        --purge-windows) purge_windows=true ;;
        *) echo "usage: $0 [--purge-windows]" >&2; exit 2 ;;
    esac
done

docker compose --project-directory "$lab_dir" -f "$lab_dir/compose.yml" \
    --env-file "$lab_dir/lab.env" --profile init --profile windows \
    down --volumes --remove-orphans --timeout 130

if [ -d "$runtime" ] && [ "$(basename "$runtime")" = runtime ] \
        && [ "$(basename "$(dirname "$runtime")")" = lab ]; then
    rm -rf -- "$runtime"
fi

if $purge_windows; then
    case "$LAB_WINDOWS_STORAGE" in
        */webssh-lab/windows) rm -rf -- "$LAB_WINDOWS_STORAGE" ;;
        *) echo "refusing to delete unexpected path: $LAB_WINDOWS_STORAGE" >&2; exit 1 ;;
    esac
fi
echo "lab is down"
