"""Durable recovery storage gates for online restore."""

from pathlib import Path
from types import SimpleNamespace

import pytest


def test_web_restore_rejects_missing_durability_acknowledgement(
    monkeypatch,
):
    import config
    from app.backup_coordination import require_durable_recovery_storage

    monkeypatch.setattr(config, 'BACKUP_RECOVERY_DURABLE', False)

    with pytest.raises(RuntimeError, match='durable recovery storage'):
        require_durable_recovery_storage()


def test_web_restore_recovery_root_must_be_absolute_and_outside_data(
    tmp_path,
    monkeypatch,
):
    import config
    from app.backup_coordination import require_durable_recovery_storage

    monkeypatch.setattr(config, 'BACKUP_RECOVERY_DURABLE', True)
    monkeypatch.setattr(config, 'BACKUP_TEMP_DIR', tmp_path / 'data' / 'recovery')
    monkeypatch.setattr(config, 'DATA_DIR', tmp_path / 'data')

    with pytest.raises(RuntimeError, match='outside DATA_DIR'):
        require_durable_recovery_storage()

    monkeypatch.setattr(config, 'BACKUP_TEMP_DIR', Path('relative'))
    with pytest.raises(RuntimeError, match='must be absolute'):
        require_durable_recovery_storage()


def test_start_restore_does_not_create_worker_without_durable_storage(
    monkeypatch,
):
    import config
    from app import restore_service

    monkeypatch.setattr(config, 'BACKUP_RECOVERY_DURABLE', False)
    started = []

    class UnexpectedThread:
        def __init__(self, *args, **kwargs):
            started.append((args, kwargs))

    monkeypatch.setattr(restore_service.threading, 'Thread', UnexpectedThread)

    with pytest.raises(RuntimeError, match='durable recovery storage'):
        restore_service.start_restore(
            SimpleNamespace(),
            SimpleNamespace(),
            SimpleNamespace(),
            'admin',
            '127.0.0.1',
        )
    assert started == []
