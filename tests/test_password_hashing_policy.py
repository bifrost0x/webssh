"""Contracts for fast test hashing and production bcrypt strength."""

import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _bcrypt_rounds(password_hash):
    return int(password_hash.split('$')[2])


def test_pytest_password_hashing_uses_the_fast_work_factor():
    from app.models import User

    user = User(username='pytest-hash-policy')
    user.set_password('test-password')

    assert _bcrypt_rounds(user.password_hash) == 4
    assert user.check_password('test-password') is True


def test_production_password_hashing_keeps_the_default_work_factor():
    """The pytest-only patch must never weaken a normal application process."""
    probe = subprocess.run(
        [
            sys.executable,
            '-c',
            (
                'from app.models import User; '
                "user = User(username='production-hash-policy'); "
                "user.set_password('test-password'); "
                "assert user.check_password('test-password'); "
                "print(user.password_hash.split('$')[2])"
            ),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.splitlines()[-1] == '12'

def test_browser_fixture_hashing_is_explicit_and_confined_to_its_process():
    probe = subprocess.run(
        [sys.executable, '-c', (
            'import importlib.util; '
            'from app.models import User; '
            "spec = importlib.util.spec_from_file_location('e2e_test_hashing', 'tests/e2e/test_hashing.py'); "
            'helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper); '
            "assert helper.bcrypt.gensalt().split(b'$')[2] == b'12'; "
            'helper.enable_fast_password_hashing(); '
            "user = User(username='browser-hash-policy'); user.set_password('test-password'); "
            "assert user.check_password('test-password'); print(user.password_hash.split('$')[2])"
        )],
        cwd=PROJECT_ROOT, capture_output=True, text=True, check=False,
    )
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.splitlines()[-1] == '04'


def test_browser_fixture_starts_with_nonoverlapping_temporary_storage():
    """Exercise the fixture storage plan against the real backup safety guard."""
    probe = subprocess.run(
        [sys.executable, '-c', '''
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path('tests/e2e').resolve()))
from run_app import _temporary_storage_environment

with tempfile.TemporaryDirectory(prefix='webssh-e2e-storage-test-') as root:
    environment = _temporary_storage_environment(root)
    os.environ.update(environment)
    import config
    from app.backup_coordination import ensure_backup_temp_dir
    data = Path(config.DATA_DIR).resolve()
    backup = Path(config.BACKUP_TEMP_DIR).resolve()
    transfer = Path(config.TRANSFER_TEMP_DIR).resolve()
    assert data.parent == backup.parent == transfer.parent == Path(root).resolve()
    assert len({data, backup, transfer}) == 3
    assert ensure_backup_temp_dir().is_relative_to(backup)
    print('fixture-storage-ok')
'''],
        cwd=PROJECT_ROOT, capture_output=True, text=True, check=False, timeout=15,
    )
    assert probe.returncode == 0, probe.stderr
    assert 'fixture-storage-ok' in probe.stdout.splitlines()
