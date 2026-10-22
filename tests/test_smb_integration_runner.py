"""Verify bounded SMB lab image builds and cleanup without running Docker."""

from types import SimpleNamespace

import pytest

from scripts import run_smb_integration_tests as runner


def expected_commands(project='webssh-smb-0123456789ab'):
    compose = [
        'docker', 'compose', '--parallel', '2', '-f', runner.COMPOSE_FILE,
        '--project-name', project,
    ]
    return [
        [*compose, 'build', 'samba', 'client'],
        [*compose, 'up', '-d', '--no-build', '--wait', 'samba'],
        [*compose, 'run', '--rm', 'client'],
        [*compose, 'down', '--volumes', '--remove-orphans'],
    ]


@pytest.fixture
def calls(monkeypatch):
    commands = []
    monkeypatch.setattr(runner.secrets, 'token_hex', lambda size: '0123456789ab')

    def run(command):
        commands.append(command)
        return 0

    monkeypatch.setattr(runner, '_run', run)
    return commands


def test_both_images_build_before_samba_start_and_client_test(calls):
    assert runner.main() == 0
    assert calls == expected_commands()


@pytest.mark.parametrize('stage', [0, 1, 2])
def test_failure_stops_remaining_stages_and_still_cleans_up(monkeypatch, calls, stage):
    def run(command):
        calls.append(command)
        return 19 if command == expected_commands()[stage] else 0

    monkeypatch.setattr(runner, '_run', run)
    assert runner.main() == 19
    assert calls == expected_commands()[:stage + 1] + expected_commands()[-1:]


@pytest.mark.parametrize('stage', [0, 1, 2])
def test_process_exception_still_cleans_up_its_project(monkeypatch, calls, stage):
    failure = OSError('process startup failed')

    def run(command):
        calls.append(command)
        if command == expected_commands()[stage]:
            raise failure
        return 0

    monkeypatch.setattr(runner, '_run', run)
    with pytest.raises(OSError) as caught:
        runner.main()
    assert caught.value is failure
    assert calls == expected_commands()[:stage + 1] + expected_commands()[-1:]


def test_each_run_uses_its_own_random_project_for_all_operations(monkeypatch, calls):
    tokens = iter(['first', 'second'])

    def token_hex(size):
        assert size == 6
        return next(tokens)

    monkeypatch.setattr(runner.secrets, 'token_hex', token_hex)
    assert runner.main() == runner.main() == 0
    assert calls == expected_commands('webssh-smb-first') + expected_commands('webssh-smb-second')


def test_subprocesses_run_in_project_root_without_shell(monkeypatch):
    command = ['docker', 'compose', 'version']

    def run(actual, *, cwd, check):
        assert actual is command
        assert cwd == runner.PROJECT_ROOT
        assert check is False
        return SimpleNamespace(returncode=23)

    monkeypatch.setattr(runner.subprocess, 'run', run)
    assert runner._run(command) == 23
