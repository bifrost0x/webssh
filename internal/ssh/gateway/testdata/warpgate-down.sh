#!/bin/sh
# Removes the throwaway Warpgate of warpgate-up.sh and its state directory.
set -u
dir=${1:-/tmp/webssh-warpgate}
docker rm -f webssh-warpgate >/dev/null 2>&1
docker volume rm webssh-warpgate-data >/dev/null 2>&1
rm -f "$dir"/admin "$dir"/jar "$dir"/otp.hex "$dir"/bob.password
rmdir "$dir" 2>/dev/null
exit 0
