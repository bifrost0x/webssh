"""Exercise the CI package installer without changing system packages."""
import os
from pathlib import Path
import shutil
import subprocess

import pytest


pytestmark = pytest.mark.skipif(os.name == "nt", reason="requires POSIX bash and fake executable commands")
SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "install_ci_test_system_deps.sh"
APT = "apt-get -o Acquire::http::Timeout=2 -o Acquire::https::Timeout=5 -o Acquire::Retries=0"
INSTALL = APT + " install --yes --no-install-recommends libldap2-dev libsasl2-dev"


def run_installer(tmp_path, *, installed="all", install_failures=0, update_failure=0):
    commands = tmp_path / "bin"
    commands.mkdir()
    log = tmp_path / "calls"
    for name, source in {
        "dpkg-query": '''#!/bin/bash
case "$INSTALLED:$*" in
  all:*|ldap:*libldap2-dev) printf 'install ok installed';;
  *) exit 1;;
esac
''',
        "sudo": '''#!/bin/bash
printf '%s\\n' "$*" >> "$CALL_LOG"
if [[ " $* " == *' update '* ]]; then exit "$UPDATE_FAILURE"; fi
count=0
[[ ! -f "$COUNT_FILE" ]] || read -r count < "$COUNT_FILE"
count=$((count + 1))
printf '%s\\n' "$count" > "$COUNT_FILE"
if (( count <= INSTALL_FAILURES )); then exit 42; fi
''',
    }.items():
        command = commands / name
        command.write_text(source, encoding="utf-8")
        command.chmod(0o755)
    env = {
        **os.environ,
        "GITHUB_ACTIONS": "false",
        "PATH": str(commands) + os.pathsep + os.environ["PATH"],
        "INSTALLED": installed,
        "INSTALL_FAILURES": str(install_failures),
        "UPDATE_FAILURE": str(update_failure),
        "CALL_LOG": str(log),
        "COUNT_FILE": str(tmp_path / "count"),
    }
    result = subprocess.run([shutil.which("bash"), str(SCRIPT)], env=env, text=True, capture_output=True, check=False)
    return result, log.read_text().splitlines() if log.exists() else []


def test_installed_headers_do_not_call_apt(tmp_path):
    result, calls = run_installer(tmp_path)
    assert result.returncode == 0, result.stderr
    assert calls == []


def test_missing_headers_use_existing_indexes_without_update(tmp_path):
    result, calls = run_installer(tmp_path, installed="none")
    assert result.returncode == 0, result.stderr
    assert calls == [INSTALL]


def test_one_missing_header_still_installs_requirements(tmp_path):
    result, calls = run_installer(tmp_path, installed="ldap")
    assert result.returncode == 0, result.stderr
    assert calls == [INSTALL]


def test_stale_indexes_are_refreshed_and_install_retried(tmp_path):
    result, calls = run_installer(tmp_path, installed="none", install_failures=1)
    assert result.returncode == 0, result.stderr
    assert calls == [INSTALL, APT + " update", INSTALL]


def test_second_install_failure_is_not_hidden(tmp_path):
    result, calls = run_installer(tmp_path, installed="none", install_failures=2)
    assert result.returncode == 42
    assert calls == [INSTALL, APT + " update", INSTALL]


def test_update_failure_is_not_hidden(tmp_path):
    result, calls = run_installer(tmp_path, installed="none", install_failures=1, update_failure=43)
    assert result.returncode == 43
    assert calls == [INSTALL, APT + " update"]
