#!/bin/sh
# Starts a throwaway Warpgate for the gateway lab test and provisions it.
# It joins the test lab's front network to reach ssh-modern; the lab itself
# is not started, stopped or changed. State and synthetic secrets go to $1
# (default /tmp/webssh-warpgate). Remove everything with warpgate-down.sh.
#
#   internal/ssh/gateway/testdata/warpgate-up.sh /tmp/webssh-warpgate
#   WEBSSH_WARPGATE_DIR=/tmp/webssh-warpgate go test -tags warpgate -run Warpgate ./internal/ssh/gateway
set -eu
dir=${1:-/tmp/webssh-warpgate}
image=${WEBSSH_WARPGATE_IMAGE:-ghcr.io/warp-tech/warpgate:0.30.6@sha256:0725845d25a70520c1024f53f1514b5c6c6159ff2d05c5d0e8566089f3481025}
umask 077
mkdir -p "$dir"
head -c 18 /dev/urandom | base64 | tr -d '/+=' > "$dir/admin"
docker volume create webssh-warpgate-data >/dev/null
docker run --rm -v webssh-warpgate-data:/data -e WARPGATE_ADMIN_PASSWORD="$(cat "$dir/admin")" "$image" \
	unattended-setup --data-path /data --http-port 8888 --ssh-port 2222 \
	--host-key-verification prompt --external-host localhost >/dev/null 2>&1
docker run -d --name webssh-warpgate --network webssh-lab_front \
	-p 127.0.0.1:18888:8888 -p 127.0.0.1:12222:2222 -v webssh-warpgate-data:/data "$image" run >/dev/null
for _ in $(seq 30); do
	curl -sk -o /dev/null https://localhost:18888/@warpgate/api/info && break
	sleep 1
done
"$(dirname "$0")/warpgate-provision.sh" "$dir"
