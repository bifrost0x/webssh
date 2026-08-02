#!/bin/bash
set -euo pipefail

# Data directories
mkdir -p /app/data/logs /app/data/keys
chmod 700 /app/data/logs /app/data/keys

# SECRET_KEY resolution order:
#   1) SECRET_KEY environment variable (explicit; wins, e.g. external secrets)
#   2) persisted file under the data dir (survives restarts if /app/data is a volume)
#   3) auto-generated and persisted (zero-config first run)
# Known placeholders (e.g. the compose template) are treated as "not set".
SECRET_KEY_FILE="/app/data/secret_key"
_sk="${SECRET_KEY:-}"
case "$(printf '%s' "$_sk" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')" in
    ""|"<your-secret-key>"|"changeme"|"secret"|"your-secret-key")
        _sk=""
        ;;
esac

if [ -z "$_sk" ]; then
    if [ -f "$SECRET_KEY_FILE" ]; then
        _sk="$(cat "$SECRET_KEY_FILE")"
        echo "Loaded persisted SECRET_KEY from $SECRET_KEY_FILE"
    else
        _sk="$(python -c 'import secrets; print(secrets.token_hex(32))')"
        if (umask 077; printf '%s\n' "$_sk" > "$SECRET_KEY_FILE"); then
            echo "Generated a new SECRET_KEY and persisted it to $SECRET_KEY_FILE"
            echo "   Keep /app/data on a volume so it survives container re-creation."
        else
            echo "ERROR: could not write $SECRET_KEY_FILE -- mount a writable volume on /app/data." >&2
            exit 1
        fi
    fi
    export SECRET_KEY="$_sk"
fi

exec "$@"
