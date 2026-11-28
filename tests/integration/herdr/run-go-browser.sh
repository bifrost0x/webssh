#!/bin/sh
# Starts the disposable Herdr host, runs the Herdr browser spec
# (tests/integration/herdr-session-browser.spec.js) against the Go server
# and removes the containers, volumes and built image again, also when the
# spec fails. The password and host keys are created for this run only.
#
#   WEBSSH_E2E_M1_SERVER_COMMAND='.test-run.tmp/webssh serve' \
#   WEBSSH_E2E_M1_ADMIN_COMMAND='.test-run.tmp/webssh' \
#   tests/integration/herdr/run-go-browser.sh [playwright flags]
#
# The probe of the spec (herdr_lab_probe.py) needs paramiko: set PYTHON to
# the interpreter of the repository's virtual environment.
set -eu
: "${WEBSSH_E2E_M1_SERVER_COMMAND:?the Go server command, for example .test-run.tmp/webssh serve}"
: "${WEBSSH_E2E_M1_ADMIN_COMMAND:?the Go admin command, for example .test-run.tmp/webssh}"
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
project=${HERDR_LAB_PROJECT:-webssh-herdr-browser}
compose() { docker compose -p "$project" -f "$here/compose.yml" "$@"; }
HERDR_LAB_PASSWORD=$(head -c 18 /dev/urandom | base64 | tr -d '/+=')
export HERDR_LAB_PASSWORD
cleanup() { compose down -v --rmi local --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
trap 'exit 130' INT TERM
compose up -d --build --wait --quiet-pull
WEBSSH_HERDR_PORT=$(compose port herdr 22 | sed 's/.*://')
cd "$root"
PARAMIKO5_DISPOSABLE_LAB=1 WEBSSH_HERDR_PORT="$WEBSSH_HERDR_PORT" WEBSSH_HERDR_PASSWORD="$HERDR_LAB_PASSWORD" \
	WEBSSH_HERDR_COMPOSE_FILE="$here/compose.yml" WEBSSH_HERDR_COMPOSE_PROJECT="$project" \
	npx playwright test -c tests/integration/playwright.herdr.config.js "$@"
