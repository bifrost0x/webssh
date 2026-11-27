#!/bin/sh
# Starts the disposable Herdr host, runs the Go Herdr lab test against it
# and removes the containers, volumes and built image again, also when the
# test fails. Passwords and host keys are created for this run only.
#
#   tests/integration/herdr/run-go-lab.sh [go test flags]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
project=${HERDR_LAB_PROJECT:-webssh-herdr-lab}
compose() { docker compose -p "$project" -f "$here/compose.yml" "$@"; }
HERDR_LAB_PASSWORD=$(head -c 18 /dev/urandom | base64 | tr -d '/+=')
export HERDR_LAB_PASSWORD
cleanup() { compose down -v --rmi local --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
trap 'exit 130' INT TERM
compose up -d --build --wait --quiet-pull
port=$(compose port herdr 22 | sed 's/.*://')
fingerprint=$(compose exec -T herdr ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $2}')
cd "$root"
WEBSSH_HERDR_ADDR="127.0.0.1:$port" WEBSSH_HERDR_PASSWORD="$HERDR_LAB_PASSWORD" \
	WEBSSH_HERDR_FINGERPRINT="$fingerprint" \
	go test -tags herdr -count=1 -p 2 -run Herdr "$@" ./cmd/webssh
