#!/bin/bash
set -e
mkdir -p /app/data/logs /app/data/keys
chmod 700 /app/data/logs /app/data/keys
exec "$@"
