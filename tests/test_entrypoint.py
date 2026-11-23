"""Container entrypoint persistence-boundary tests."""

import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest


pytestmark = pytest.mark.skipif(
    sys.platform != 'linux',
    reason='Container entrypoint requires Linux Bash and POSIX file permissions',
)


ENTRYPOINT = Path(__file__).parents[1] / 'entrypoint.sh'


PRINT_STATE = (
    'import os; '
    'print(os.environ["DATA_DIR"]); '
    'print(os.environ["SECRET_KEY"])'
)


def _run_entrypoint(data_dir, *, secret=None, extra=None, code=PRINT_STATE):
    environment = {
        **os.environ,
        'PATH': f'{Path(sys.executable).parent}:{os.environ.get("PATH", "")}',
        'DATA_DIR': str(data_dir),
    }
    if secret is None:
        environment.pop('SECRET_KEY', None)
    else:
        environment['SECRET_KEY'] = secret
    for key, value in (extra or {}).items():
        if value is None:
            environment.pop(key, None)
        else:
            environment[key] = value
    return subprocess.run(
        ['/bin/bash', str(ENTRYPOINT), sys.executable, '-c', code],
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )


def test_custom_data_dir_owns_generated_secret_and_runtime_directories(tmp_path):
    data_dir = tmp_path / 'custom-data'

    result = _run_entrypoint(data_dir)

    assert result.returncode == 0, result.stderr
    secret_file = data_dir / 'secret_key'
    secret = secret_file.read_text(encoding='utf-8').strip()
    assert len(secret) == 64
    assert result.stdout.splitlines()[-2:] == [str(data_dir.resolve()), secret]
    assert stat.S_IMODE(secret_file.stat().st_mode) == 0o600
    assert (data_dir / 'logs').is_dir()
    assert (data_dir / 'keys').is_dir()


def test_explicit_secret_wins_without_creating_a_split_secret_file(tmp_path):
    data_dir = tmp_path / 'external-secret-data'

    result = _run_entrypoint(data_dir, secret='external-secret-value')

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[-2:] == [
        str(data_dir.resolve()),
        'external-secret-value',
    ]
    assert not (data_dir / 'secret_key').exists()


def test_relative_data_dir_is_rejected_before_writing_state(tmp_path):
    result = _run_entrypoint(Path('relative-data'))

    assert result.returncode == 1
    assert result.stdout == ''
    assert 'DATA_DIR must be an absolute path' in result.stderr


unprivileged = pytest.mark.skipif(
    sys.platform == 'linux' and os.geteuid() == 0,
    reason='Root bypasses the directory permissions under test',
)
PRINT_RUNTIME = 'import os; print(os.environ.get("XDG_RUNTIME_DIR", ""))'


@unprivileged
def test_unwritable_data_dir_names_the_container_user_and_fix(tmp_path):
    data_dir = tmp_path / 'foreign-mount'
    data_dir.mkdir(mode=0o500)
    try:
        result = _run_entrypoint(data_dir)
    finally:
        data_dir.chmod(0o700)

    identity = f'{os.getuid()}:{os.getgid()}'
    assert result.returncode == 1
    assert result.stdout == ''
    assert f'must be owned and writable by the container user {identity}' in result.stderr
    assert f'chown -R {identity} <host directory>' in result.stderr
    assert not (data_dir / 'secret_key').exists()


@unprivileged
def test_runtime_directory_is_private_when_home_is_not_writable(tmp_path):
    home = tmp_path / 'read-only-home'
    home.mkdir(mode=0o500)
    scratch = tmp_path / 'scratch'
    scratch.mkdir()
    try:
        result = _run_entrypoint(tmp_path / 'data', code=PRINT_RUNTIME, extra={
            'HOME': str(home), 'XDG_RUNTIME_DIR': None, 'TMPDIR': str(scratch),
        })
    finally:
        home.chmod(0o700)

    assert result.returncode == 0, result.stderr
    runtime = Path(result.stdout.splitlines()[-1])
    assert runtime.parent == scratch and runtime.name.startswith('webssh-runtime.')
    assert stat.S_IMODE(runtime.stat().st_mode) == 0o700
    assert runtime.stat().st_uid == os.getuid()


@pytest.mark.parametrize('extra, expected', [
    ({'XDG_RUNTIME_DIR': None}, ''),
    ({'XDG_RUNTIME_DIR': '/run/webssh'}, '/run/webssh'),
])
def test_existing_runtime_settings_are_left_unchanged(tmp_path, extra, expected):
    home = tmp_path / 'home'
    home.mkdir()

    result = _run_entrypoint(tmp_path / 'data', code=PRINT_RUNTIME,
                             extra={'HOME': str(home), **extra})

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[-1] == expected


@pytest.mark.parametrize(('secret', 'source'), [
    (None, 'file'),
    ('external-secret-value', 'environment'),
    ('changeme', 'file'),
])
def test_entrypoint_records_where_the_secret_key_came_from(tmp_path, secret, source):
    result = _run_entrypoint(
        tmp_path / 'source-data',
        secret=secret,
        code='import os; print(os.environ["WEBSSH_SECRET_KEY_SOURCE"])',
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[-1] == source
