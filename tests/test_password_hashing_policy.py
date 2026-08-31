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
