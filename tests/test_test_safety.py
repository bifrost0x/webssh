"""Regression tests for isolation from live deployment resources."""

import os
import subprocess
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _run_pytest(*arguments, environment):
    return subprocess.run(
        [sys.executable, "-m", "pytest", *arguments],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_pytest_neutralizes_deployment_environment_before_collection(tmp_path):
    sentinel = tmp_path / "live-data"
    sentinel.mkdir()
    marker = sentinel / "app.db"
    marker.write_bytes(b"must-not-be-opened-by-tests")
    environment = os.environ.copy()
    environment.update({
        "DATA_DIR": str(sentinel),
        "TRANSFER_TEMP_DIR": str(sentinel / "transfer-tmp"),
        "BACKUP_TEMP_DIR": str(sentinel / "backup-tmp"),
        "RATELIMIT_STORAGE_URL": "redis://redis.production.example:6379/0",
        "LDAP_ENABLED": "true",
        "OIDC_ENABLED": "true",
        "TAILSCALE_SSH_ENABLED": "true",
        "WEBSSH_TEST_SENTINEL_DATA_DIR": str(sentinel),
    })

    result = _run_pytest(
        "tests/fixtures/environment_probe.py",
        "-q",
        environment=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert marker.read_bytes() == b"must-not-be-opened-by-tests"


@pytest.mark.parametrize(
    "test_redis_url",
    (
        "redis://redis.production.example:6379/15",
        "redis://127.0.0.1:6379/0",
        "redis://localhost:6379",
    ),
)
def test_pytest_rejects_unsafe_real_redis_targets(test_redis_url):
    environment = os.environ.copy()
    environment["TEST_REDIS_URL"] = test_redis_url

    result = _run_pytest(
        "--collect-only",
        "tests/test_rate_limiter.py",
        "-q",
        environment=environment,
    )

    assert result.returncode != 0
    assert "TEST_REDIS_URL must use loopback and an explicit non-zero database" in (
        result.stdout + result.stderr
    )
