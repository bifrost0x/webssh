"""Keep all protocol checks mandatory while sharing one CI runner."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event, Lock
from types import SimpleNamespace
import sys

import pytest


def test_fixed_groups_preserve_every_original_command():
    from scripts import run_ci_protocol_checks as checks

    assert checks.GROUPS == {
        'ssh': (
            ('bash', 'scripts/install_ci_test_system_deps.sh'),
            (sys.executable, '-m', 'pip', 'install', '--require-hashes', '-r', 'requirements-test.txt'),
            ('npm', 'ci'),
            ('node', 'scripts/install-ci-chromium.js'),
            (sys.executable, 'scripts/run_integration_tests.py', '--browser'),
        ),
        'smb': ((sys.executable, 'scripts/run_smb_integration_tests.py'),),
        'release': ((sys.executable, 'scripts/check_release_promotion.py'),),
    }


def test_all_three_groups_start_together_and_use_project_root():
    from scripts import run_ci_protocol_checks as checks

    started = Barrier(3)
    calls = []
    lock = Lock()
    first = {commands[0] for commands in checks.GROUPS.values()}

    def run(command, *, cwd, check):
        assert cwd == checks.PROJECT_ROOT
        assert check is False
        command = tuple(command)
        if command in first:
            started.wait(timeout=5)
        with lock:
            calls.append(command)
        return SimpleNamespace(returncode=0)

    assert checks.main(run=run) == 0
    assert sorted(calls) == sorted(command for commands in checks.GROUPS.values() for command in commands)
    ssh = set(checks.GROUPS['ssh'])
    assert tuple(command for command in calls if command in ssh) == checks.GROUPS['ssh']


@pytest.mark.parametrize('group,index', [
    ('ssh', index) for index in range(5)
] + [('smb', 0), ('release', 0)])
def test_command_failure_stops_only_its_group(group, index):
    from scripts import run_ci_protocol_checks as checks

    failing = checks.GROUPS[group][index]
    calls = []

    def run(command, **_kwargs):
        calls.append(tuple(command))
        return SimpleNamespace(returncode=17 if tuple(command) == failing else 0)

    assert checks.main(run=run) == 1
    expected = [
        command
        for name, commands in checks.GROUPS.items()
        for command in (commands[:index + 1] if name == group else commands)
    ]
    assert sorted(calls) == sorted(expected)


@pytest.mark.parametrize('raises', [False, True])
def test_failure_waits_for_every_other_group(raises):
    from scripts import run_ci_protocol_checks as checks

    started = Barrier(3)
    failure_seen = Event()
    release = Event()
    first = {commands[0] for commands in checks.GROUPS.values()}

    def run(command, **_kwargs):
        command = tuple(command)
        if command in first:
            started.wait(timeout=5)
            if command == checks.GROUPS['ssh'][0]:
                failure_seen.set()
                if raises:
                    raise OSError('controlled process startup failure')
                return SimpleNamespace(returncode=1)
            assert release.wait(timeout=5)
        return SimpleNamespace(returncode=0)

    with ThreadPoolExecutor(max_workers=1) as executor:
        result = executor.submit(checks.main, run=run)
        try:
            assert failure_seen.wait(timeout=5)
            assert not result.done()
        finally:
            release.set()
        assert result.result(timeout=5) == 1
