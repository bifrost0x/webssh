#!/bin/bash
set -e

# Create required directories with correct permissions
mkdir -p /app/data/logs /app/data/keys
chmod 700 /app/data/logs /app/data/keys

# Execute the main command
exec "$@"
