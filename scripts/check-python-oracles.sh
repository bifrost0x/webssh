#!/bin/sh
# Records every Python oracle of the Go packages again from the unchanged
# Python release (scripts/record-python-oracles.sh), checks that the
# recordings come out byte for byte as they are checked in, and runs the
# differential tests against the live release (WEBSSH_PYTHON_ORACLE=live).
#
#   PYTHON              interpreter with requirements-test.txt
#                       (default: .venv/bin/python)
#   WEBSSH_PYTHON_ROOT  checkout of the Python release (default: this
#                       repository)
#
# The host-key oracle uses fresh random keys, so only the Go tests judge
# its new recording, which is reverted afterwards.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
PYTHON=${PYTHON:-$root/.venv/bin/python}
export PYTHON

random="internal/ssh/hostkey/testdata/oracle.json"
trap 'git checkout -- $random' EXIT
scripts/record-python-oracles.sh

# shellcheck disable=SC2046 # one pathspec per random recording, split on purpose
if ! git diff --exit-code --stat -- . $(for f in $random; do printf ':(exclude)%s ' "$f"; done); then
	echo "The recorded Python answers changed; the Python release and the Go vectors disagree." >&2
	exit 1
fi

# The differential tests against the live release; the other tests of
# these packages run in the race job.
export WEBSSH_PYTHON="$PYTHON" WEBSSH_PYTHON_ORACLE=live
go test -count=1 -p 2 -run 'Python|Oracle|Entrypoint|WayBack|RestoreBesideLegacyData|SystemCommands' \
	./cmd/webssh ./internal/audit ./internal/automation ./internal/commands ./internal/config \
	./internal/cron ./internal/hosts ./internal/idna2003 ./internal/migrate/legacy ./internal/netpolicy \
	./internal/operations ./internal/qrcode ./internal/quota ./internal/settings ./internal/ssh/hostkey
