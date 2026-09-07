"""Container entrypoint persistence-boundary tests."""

import os
from pathlib import Path
import stat
import subprocess
import sys


ENTRYPOINT = Path(__file__).parents[1] / 'entrypoint.sh'


def _run_entrypoint(data_dir, *, secret=None):
    environment = {
        **os.environ,
        'PATH': f'{Path(sys.executable).parent}:{os.environ.get("PATH", "")}',
        'DATA_DIR': str(data_dir),
    }
    if secret is None:
        environment.pop('SECRET_KEY', None)
    else:
        environment['SECRET_KEY'] = secret
    return subprocess.run(
        [
            '/bin/bash',
            str(ENTRYPOINT),
            sys.executable,
            '-c',
            (
                'import os; '
                'print(os.environ["DATA_DIR"]); '
                'print(os.environ["SECRET_KEY"])'
            ),
        ],
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
