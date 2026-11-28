#!/bin/sh
# Records every answer of the Python release that the Go differential
# tests compare with. Without Python the Go tests replay these recordings
# (internal/oracletest); this script and the oracle modes are the only
# places that need the Python release, which left the repository with
# 3.4.0. It runs against a worktree of that release:
#
#   git worktree add --detach ../py-3.3.1 "$PYTHON_RELEASE"
#   (cd ../py-3.3.1 && uvx uv@0.13.5 venv && \
#     VIRTUAL_ENV=$PWD/.venv uvx uv@0.13.5 pip install --require-hashes -r requirements-test.txt)
#   WEBSSH_PYTHON_ROOT=../py-3.3.1 scripts/record-python-oracles.sh
#
#   WEBSSH_PYTHON_ROOT  worktree of the Python release at PYTHON_RELEASE
#                       (required); the application comes from there, the
#                       recorders and the golden data sets from this
#                       repository
#   PYTHON              interpreter with that release's requirements-test.txt
#                       (default: .venv/bin/python in WEBSSH_PYTHON_ROOT)
#   NETNS=crafted       also record the kernel route answers of
#                       internal/netpolicy/testdata/netns-test.sh in its own
#                       namespace (Docker); NETNS=lab also inside the
#                       running test lab (tests/lab)
#
# Each recording names the interpreter and the commit of the Python
# sources in its header. scripts/check-python-oracles.sh records, checks
# that nothing changed and compares Go with the live release.
set -eu
# The last Python release: the commit of 3.3.1 on main until the tag
# v3.3.1 exists, then the tag.
PYTHON_RELEASE=7d8831353ec44d7e5ed7b3e7644fa09c608bfc01
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
if [ -z "${WEBSSH_PYTHON_ROOT:-}" ]; then
	echo "record-python-oracles: set WEBSSH_PYTHON_ROOT to a worktree of $PYTHON_RELEASE" >&2
	exit 1
fi
pyroot=$(cd "$WEBSSH_PYTHON_ROOT" && pwd)
PYTHON=${PYTHON:-$pyroot/.venv/bin/python}
sources="app config.py start.py entrypoint.sh deployment"

if [ "$(git -C "$pyroot" rev-parse HEAD)" != "$(git -C "$pyroot" rev-parse "$PYTHON_RELEASE^{commit}")" ]; then
	echo "record-python-oracles: $pyroot is not at the Python release $PYTHON_RELEASE" >&2
	exit 1
fi
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

# The variable names of config.py, for TestRegistryCoversConfigPy.
echo "recording internal/config names"
{
	printf '# Every quoted upper-case name in config.py of the last Python release\n'
	printf '# (%s), one per line. scripts/record-python-oracles.sh writes it.\n' "$(git -C "$pyroot" rev-parse --short=8 "$commit")"
	grep -o -E "['\"][A-Z][A-Z0-9_]{3,}['\"]" "$pyroot/config.py" | tr -d "'\"" | LC_ALL=C sort -u
} >internal/config/testdata/python_config_names.txt

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
