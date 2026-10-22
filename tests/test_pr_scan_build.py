"""PR scan builds stay native, fresh, local and fail closed."""
import os
from pathlib import Path
import subprocess

import pytest

pytestmark = pytest.mark.skipif(os.name == 'nt', reason='requires POSIX bash and fake Docker executable')
SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/build_pr_scan_image.sh'


def run_build(tmp_path, arch='amd64', *, event='pull_request', fail=False, metadata=None):
    binary = tmp_path / 'docker'
    log = tmp_path / 'docker.log'
    binary.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$COMMAND_LOG"\nexit ' + ('19' if fail else '0') + '\n')
    binary.chmod(0o700)
    env = {**os.environ, 'PATH': str(tmp_path) + os.pathsep + os.environ['PATH'],
           'COMMAND_LOG': str(log), 'GITHUB_EVENT_NAME': event, 'GITHUB_SHA': 'a' * 40,
           'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '2'}
    env.update(metadata or {})
    result = subprocess.run(['bash', str(SCRIPT), arch], cwd=tmp_path, env=env, capture_output=True, text=True)
    return result, log.read_text().splitlines() if log.exists() else []


@pytest.mark.parametrize('arch', ['amd64', 'arm64'])
def test_pr_scan_build_keeps_native_platform_and_fresh_inputs(tmp_path, arch):
    result, commands = run_build(tmp_path, arch)
    assert result.returncode == 0, result.stderr
    build = commands[0]
    for value in ('build --pull', '--platform linux/' + arch, 'VCS_REF=' + 'a' * 40, 'OS_PACKAGE_REFRESH=123-2'):
        assert value in build
    assert '--push' not in build and 'cache-to' not in build
    assert len(commands) == (2 if arch == 'arm64' else 1)
    if arch == 'arm64':
        assert commands[1] == 'image save --output /tmp/webssh-arm64.tar webssh-security:' + 'a' * 40


@pytest.mark.parametrize('arch,event', [('s390x', 'pull_request'), ('amd64', 'push')])
def test_pr_scan_build_refuses_other_platforms_and_events(tmp_path, arch, event):
    result, commands = run_build(tmp_path, arch, event=event)
    assert result.returncode != 0 and commands == []


def test_failed_build_never_exports_an_arm64_image(tmp_path):
    result, commands = run_build(tmp_path, 'arm64', fail=True)
    assert result.returncode == 19
    assert len(commands) == 1


@pytest.mark.parametrize('metadata', [
    {'GITHUB_SHA': 'invalid'}, {'GITHUB_RUN_ID': '../other'},
    {'GITHUB_RUN_ATTEMPT': ''},
])
def test_pr_scan_build_rejects_invalid_metadata_before_docker(tmp_path, metadata):
    result, commands = run_build(tmp_path, metadata=metadata)
    assert result.returncode == 2 and commands == []
