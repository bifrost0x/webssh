#!/bin/sh
# Re-records every Python oracle of the Go packages from the unchanged
# Python modules and checks the Go side against the fresh answers.
#
#   PYTHON  the interpreter with requirements-test.txt (default: .venv)
#
# Recordings that are deterministic must come out byte for byte as they
# are checked in. The host-key oracle and the configuration probe use
# fresh random keys, so only the Go tests judge their new recordings,
# which are reverted afterwards. internal/config and internal/idna2003
# also compare live against the interpreter.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
PYTHON=${PYTHON:-$root/.venv/bin/python}
export WS="$root" WEBSSH_PYTHON="$PYTHON" WEBSSH_REQUIRE_PYTHON=1

record() {
	echo "recording $1"
	"$PYTHON" -I "$@" >/dev/null
}
record internal/hosts/testdata/oracle.py internal/hosts/testdata/oracle.json
record internal/hosts/testdata/recovery_oracle.py internal/hosts/testdata/recovery_oracle.json
record internal/settings/testdata/oracle.py internal/settings/testdata/oracle.json
record internal/automation/testdata/command_line.py internal/automation/testdata/command_line.json
record internal/ssh/hostkey/testdata/golden.py internal/ssh/hostkey/testdata/golden.json
(cd internal/qrcode/testdata && echo "recording internal/qrcode" && "$PYTHON" -I python_vectors.py >/dev/null)
echo "recording internal/netpolicy"
"$PYTHON" -I internal/netpolicy/testdata/python_vectors.py . >internal/netpolicy/testdata/python_vectors.json
echo "recording internal/idna2003"
"$PYTHON" -I internal/idna2003/testdata/oracle.py tables >internal/idna2003/tables.go
"$PYTHON" -I internal/idna2003/testdata/oracle.py vectors tests/golden/fixture/legacy/*.tar \
	>internal/idna2003/testdata/python_vectors.jsonl
"$PYTHON" -I internal/idna2003/testdata/oracle.py digests >internal/idna2003/testdata/python_digests.json
go test -count=1 -run TestCLIMatchesPython ./cmd/webssh -update-cli

if ! git diff --exit-code --stat; then
	echo "The recorded Python answers changed; the Python release and the Go vectors disagree." >&2
	exit 1
fi

random="internal/ssh/hostkey/testdata/oracle.json internal/config/testdata/python_env.jsonl internal/config/testdata/python_primitives.jsonl"
trap 'git checkout -- $random' EXIT
record internal/ssh/hostkey/testdata/oracle.py internal/ssh/hostkey/testdata/oracle.json
go test -count=1 -run '.' ./internal/config -update
go test -count=1 ./cmd/webssh ./internal/config ./internal/hosts ./internal/settings ./internal/automation ./internal/qrcode \
	./internal/netpolicy ./internal/idna2003 ./internal/ssh/hostkey
