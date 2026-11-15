#!/bin/bash
set -euo pipefail

# Resolve one canonical persistent root for application state and the
# encryption root. Relative paths are intentionally rejected because backup,
# restore, and secret rotation all treat DATA_DIR as an absolute trust boundary.
DATA_DIR="${DATA_DIR:-/app/data}"
case "$DATA_DIR" in
    /*) ;;
    *)
        echo "ERROR: DATA_DIR must be an absolute path." >&2
        exit 1
        ;;
esac
DATA_DIR="$(python -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$DATA_DIR")"
export DATA_DIR

# Data directories. A mount owned by another identity fails here; say how to
# fix it instead of leaving only the raw mkdir/chmod error.
if ! mkdir -p "$DATA_DIR/logs" "$DATA_DIR/keys" \
    || ! chmod 700 "$DATA_DIR" "$DATA_DIR/logs" "$DATA_DIR/keys"; then
    runtime_id="$(id -u):$(id -g)"
    echo "ERROR: $DATA_DIR is not writable by the container user $runtime_id." >&2
    echo "Give the mounted host directory to that user, for example: chown -R $runtime_id <host directory>" >&2
    exit 1
fi

# Gunicorn keeps its control socket under XDG_RUNTIME_DIR or ~/.gunicorn. An
# arbitrary numeric user (for example --user 99:100) has no writable home, so
# use a private temporary directory when one can be created.
if [ -z "${XDG_RUNTIME_DIR:-}" ] && [ ! -w "${HOME:-/}" ]; then
    if runtime_dir="$(mktemp -d "${TMPDIR:-/tmp}/webssh-runtime.XXXXXXXX" 2>/dev/null)"; then
        export XDG_RUNTIME_DIR="$runtime_dir"
    fi
fi

# SECRET_KEY resolution order:
#   1) SECRET_KEY environment variable (explicit; wins, e.g. external secrets)
#   2) persisted file under DATA_DIR (survives restarts when DATA_DIR is a volume)
#   3) auto-generated and persisted (zero-config first run)
# Known placeholders (e.g. the compose template) are treated as "not set".
SECRET_KEY_FILE="$DATA_DIR/secret_key"
LEGACY_SECRET_KEY_FILE="/app/data/secret_key"

_sk="${SECRET_KEY:-}"
case "$(printf '%s' "$_sk" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')" in
    ""|"<your-secret-key>"|"changeme"|"secret"|"your-secret-key")
        _sk=""
        ;;
esac

if [ -z "$_sk" ]; then
    if [ "$SECRET_KEY_FILE" != "$LEGACY_SECRET_KEY_FILE" ] && [ -f "$LEGACY_SECRET_KEY_FILE" ]; then
        if [ ! -f "$SECRET_KEY_FILE" ]; then
            echo "ERROR: a legacy secret exists at $LEGACY_SECRET_KEY_FILE but DATA_DIR is $DATA_DIR." >&2
            echo "Copy that file to $SECRET_KEY_FILE with mode 600 before starting WebSSH." >&2
            exit 1
        fi
        if ! cmp -s "$LEGACY_SECRET_KEY_FILE" "$SECRET_KEY_FILE"; then
            echo "ERROR: conflicting secret_key files exist under /app/data and DATA_DIR." >&2
            exit 1
        fi
    fi
    if [ -f "$SECRET_KEY_FILE" ]; then
        _sk="$(cat "$SECRET_KEY_FILE")"
        echo "Loaded persisted SECRET_KEY from $SECRET_KEY_FILE"
    else
        _sk="$(python -c 'import secrets; print(secrets.token_hex(32))')"
        if (umask 077; printf '%s\n' "$_sk" > "$SECRET_KEY_FILE"); then
            echo "Generated a new SECRET_KEY and persisted it to $SECRET_KEY_FILE"
            echo "   Keep $DATA_DIR on a volume so it survives container re-creation."
        else
            echo "ERROR: could not write $SECRET_KEY_FILE -- mount a writable volume on $DATA_DIR." >&2
            exit 1
        fi
    fi
    export SECRET_KEY="$_sk"
fi

exec "$@"
