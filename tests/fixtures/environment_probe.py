"""Probe imported by the test-suite isolation regression test."""

import os
from pathlib import Path

import config


def test_deployment_environment_is_neutralized_before_collection():
    sentinel = Path(os.environ["WEBSSH_TEST_SENTINEL_DATA_DIR"])

    assert Path(config.DATA_DIR).resolve() != sentinel.resolve()
    assert not Path(config.TRANSFER_TEMP_DIR).resolve().is_relative_to(
        sentinel.resolve()
    )
    assert not Path(config.BACKUP_TEMP_DIR).resolve().is_relative_to(
        sentinel.resolve()
    )
    assert config.RATELIMIT_STORAGE_URL == "memory://"
    assert config.LDAP_ENABLED is False
    assert config.OIDC_ENABLED is False
    assert config.TAILSCALE_SSH_ENABLED is False
