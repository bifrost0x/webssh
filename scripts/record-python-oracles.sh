#!/bin/sh
# Records every answer of the Python release that the Go differential
# tests compare with. Without Python the Go tests replay these recordings
# (internal/oracletest); this script is the only place that needs the
# Python release, which leaves main with the cut-over and stays reachable
# through the tag of the last Python release.
#
#   PYTHON              interpreter with requirements-test.txt
#                       (default: .venv/bin/python)
#   WEBSSH_PYTHON_ROOT  checkout of the Python release, for example a
#                       worktree of the last Python tag (default: this
#                       repository)
#   NETNS=crafted       also record the kernel route answers of
#                       internal/netpolicy/testdata/netns-test.sh in its own
#                       namespace (Docker); NETNS=lab also inside the
#                       running test lab (tests/lab)
#
# Each recording names the interpreter and the commit of the Python
# sources in its header. scripts/check-python-oracles.sh records, checks
# that nothing changed and compares Go with the live release.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
PYTHON=${PYTHON:-$root/.venv/bin/python}
pyroot=${WEBSSH_PYTHON_ROOT:-$root}
pyroot=$(cd "$pyroot" && pwd)
sources="app config.py start.py entrypoint.sh deployment"

if [ ! -x "$PYTHON" ]; then
	echo "record-python-oracles: no interpreter at $PYTHON (set PYTHON)" >&2
	exit 1
fi
if [ ! -f "$pyroot/app/__init__.py" ]; then
	echo "record-python-oracles: no Python release in $pyroot (set WEBSSH_PYTHON_ROOT)" >&2
	exit 1
fi
# shellcheck disable=SC2086 # sources is a list of paths, split on purpose
if ! git -C "$pyroot" diff --quiet HEAD -- $sources; then
	echo "record-python-oracles: the Python sources in $pyroot have uncommitted changes" >&2
	exit 1
fi
# shellcheck disable=SC2086
commit=$(git -C "$pyroot" log -1 --format=%H -- $sources)
tree=$(git -C "$pyroot" rev-parse HEAD:app)
version=$("$PYTHON" -I -c 'import platform; print(platform.python_implementation(), platform.python_version())')
export WEBSSH_PYTHON="$PYTHON" WEBSSH_PYTHON_ROOT="$pyroot" WS="$pyroot"
export WEBSSH_PYTHON_ORACLE_SOURCE="$commit (app/ tree $tree)"
export WEBSSH_PYTHON_ORACLE_VERSION="$version"
echo "recording with $version from $WEBSSH_PYTHON_ORACLE_SOURCE"

record() {
	echo "recording $1"
	"$PYTHON" -I "$@" >/dev/null
}
# Recorders in Python that write their own files.
record internal/hosts/testdata/oracle.py internal/hosts/testdata/oracle.json
record internal/hosts/testdata/recovery_oracle.py internal/hosts/testdata/recovery_oracle.json
record internal/settings/testdata/oracle.py internal/settings/testdata/oracle.json
record internal/automation/testdata/command_line.py internal/automation/testdata/command_line.json
record internal/ssh/hostkey/testdata/golden.py internal/ssh/hostkey/testdata/golden.json
record internal/ssh/hostkey/testdata/oracle.py internal/ssh/hostkey/testdata/oracle.json
(cd internal/qrcode/testdata && echo "recording internal/qrcode" && "$PYTHON" -I python_vectors.py >/dev/null)
echo "recording internal/netpolicy"
"$PYTHON" -I internal/netpolicy/testdata/python_vectors.py "$pyroot" >internal/netpolicy/testdata/python_vectors.json
echo "recording internal/idna2003"
"$PYTHON" -I internal/idna2003/testdata/oracle.py tables >internal/idna2003/tables.go
"$PYTHON" -I internal/idna2003/testdata/oracle.py vectors tests/golden/fixture/legacy/*.tar \
	>internal/idna2003/testdata/python_vectors.jsonl
"$PYTHON" -I internal/idna2003/testdata/oracle.py digests >internal/idna2003/testdata/python_digests.json

# Go tests with their own -update flags.
go test -count=1 -run TestCLIMatchesPython ./cmd/webssh -update-cli
go test -count=1 -run 'TestPython.*Vectors' ./internal/config -update
go test -count=1 -run TestPythonVectors ./internal/cron ./internal/quota -update
go test -count=1 -run TestNextDueOverAYearMatchesPython ./internal/automation -update-next
go test -count=1 -run TestMatchesPython ./internal/auth/github -update

# Recordings of internal/oracletest.
export WEBSSH_PYTHON_ORACLE=record
go test -count=1 -p 2 -run 'TestBuildMigrationShowsWhatPythonShows|TestBuildWayBackToPython|TestRestoreBesideLegacyDataKeepsTheSecret' ./cmd/webssh
go test -count=1 -p 2 -run 'TestExportAndViewMatchPython' ./internal/audit
go test -count=1 -p 2 -run 'TestSystemCommandsEqualPythonResource' ./internal/commands
go test -count=1 -p 2 -run 'TestEntrypointDifferential' ./internal/config
go test -count=1 -p 2 -run 'TestAppSettingsStartupMigrationsMatchPython|TestHostContextReadMatchesPython|TestPythonISOFormatDifferential' ./internal/migrate/legacy
go test -count=1 -p 2 -run 'TestSupportReportMatchesPython' ./internal/operations
unset WEBSSH_PYTHON_ORACLE

case "${NETNS:-}" in
"") ;;
crafted) WEBSSH_PYTHON_ORACLE=record internal/netpolicy/testdata/netns-test.sh crafted ;;
lab)
	WEBSSH_PYTHON_ORACLE=record internal/netpolicy/testdata/netns-test.sh crafted
	WEBSSH_PYTHON_ORACLE=record internal/netpolicy/testdata/netns-test.sh lab
	;;
*) echo "record-python-oracles: NETNS=$NETNS; want crafted or lab" >&2; exit 2 ;;
esac
echo "recorded; review the changes with git diff"
