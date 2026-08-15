"""Fail-closed guards for tests that open real SSH and SFTP connections."""

import os

import pytest


_DISPOSABLE_PARAMIKO_ENVIRONMENT = {
    'PARAMIKO5_DISPOSABLE_LAB': '1',
    'PARAMIKO5_TARGET_HOST': '127.0.0.1',
    'PARAMIKO5_TARGET_PORT': '2223',
    'PARAMIKO5_PROXY_TARGET_HOST': 'target',
    'PARAMIKO5_PROXY_TARGET_PORT': '22',
    'PARAMIKO5_BASTION_HOST': '127.0.0.1',
    'PARAMIKO5_BASTION_PORT': '2222',
    'PARAMIKO5_CHANGED_HOST': '127.0.0.1',
    'PARAMIKO5_CHANGED_PORT': '2224',
    'PROXY_JUMP_REMOTE_DNS_ALLOWLIST': 'target',
}


def pytest_configure(config):
    del config
    if os.environ.get('PARAMIKO5_INTEGRATION') != '1':
        return
    if any(
        os.environ.get(name) != expected
        for name, expected in _DISPOSABLE_PARAMIKO_ENVIRONMENT.items()
    ):
        raise pytest.UsageError(
            'Paramiko integration requires the disposable runner targets'
        )
