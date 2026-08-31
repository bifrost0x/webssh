from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import config


def _configure_temp_root(monkeypatch, tmp_path):
    import config
    import app.maintenance_mode as maintenance

    monkeypatch.setattr(config, 'BACKUP_TEMP_DIR', tmp_path / 'operations')
    monkeypatch.setattr(config, 'DATA_DIR', tmp_path / 'data')
    config.DATA_DIR.mkdir()
    maintenance._state = None
    maintenance._state_path = None
    return maintenance


def test_maintenance_status_survives_memory_reset_and_blocks_writes(
    app, client, monkeypatch, tmp_path
):
    maintenance = _configure_temp_root(monkeypatch, tmp_path)
    maintenance.begin_preparing('restore-test')
    status_path = maintenance._status_path()

    assert status_path.is_file()
    assert not status_path.is_relative_to(Path(config.DATA_DIR))
    maintenance._state = None
    maintenance._state_path = None
    assert maintenance.public_status()['state'] == 'preparing'
    assert client.post('/api/upload').status_code == 503
    assert client.get('/ready').status_code == 503

    maintenance.mark_failed('restore-test', 'cancelled safely')
    assert not maintenance.is_active()


def test_session_epoch_invalidates_existing_login(app, client):
    from app.auth import register_user
    from app.models import db
    from app.session_epoch import rotate_epoch

    with app.app_context():
        user, error = register_user('epoch_admin', 'password123')
        assert error is None
        user.is_admin = True
        db.session.commit()
    assert client.post('/login', data={
        'username': 'epoch_admin', 'password': 'password123'
    }).status_code == 302
    admin = client.get('/admin')
    assert admin.status_code == 302
    assert admin.headers['Location'].endswith('/settings#users')

    rotate_epoch()

    response = client.get('/admin')
    assert response.status_code == 302
    assert '/login?next=' in response.headers['Location']


def test_rollback_failure_archive_survives_orphan_cleanup(
    monkeypatch, tmp_path
):
    maintenance = _configure_temp_root(monkeypatch, tmp_path)
    from app.backup_operations import BackupOperationRegistry

    root = maintenance._status_path().parent
    operation = root / 'operation-preserved'
    operation.mkdir()
    (operation / 'rollback.zip').write_bytes(b'emergency')
    maintenance.begin_preparing('preserved')
    maintenance.mark_in_progress('preserved', 'operation-preserved/rollback.zip')
    maintenance.mark_failed(
        'preserved',
        'Restore and rollback failed',
        rollback_failed=True,
    )

    BackupOperationRegistry().cleanup_orphans()

    assert (operation / 'rollback.zip').read_bytes() == b'emergency'
    maintenance.clear_failed_status_after_cli_restore()
    assert maintenance.public_status()['state'] == 'idle'


def test_interrupted_restore_sanitizes_rollback_before_epoch_rotation(
    monkeypatch, tmp_path
):
    import app.backup_manager as backup_manager
    import app.restore_sanitizer as restore_sanitizer
    import app.session_epoch as session_epoch

    maintenance = _configure_temp_root(monkeypatch, tmp_path)
    root = maintenance._status_path().parent
    operation = root / 'operation-interrupted'
    operation.mkdir()
    rollback = operation / 'rollback.zip'
    rollback.write_bytes(b'rollback')
    maintenance.begin_preparing('interrupted')
    maintenance.mark_in_progress(
        'interrupted', 'operation-interrupted/rollback.zip'
    )
    events = []

    @contextmanager
    def fake_operation_lock():
        yield object()

    monkeypatch.setattr(maintenance, 'operation_lock', fake_operation_lock)
    monkeypatch.setattr(
        backup_manager,
        'restore_backup',
        lambda source, destination: events.append(
            ('restore', Path(source), Path(destination))
        ),
    )
    monkeypatch.setattr(
        restore_sanitizer,
        'sanitize_restored_authentication_state',
        lambda database: events.append(('sanitize', Path(database))),
    )
    monkeypatch.setattr(
        session_epoch, 'reset_cache', lambda: events.append(('reset',))
    )
    monkeypatch.setattr(
        session_epoch, 'rotate_epoch', lambda: events.append(('rotate',))
    )

    maintenance.recover_interrupted_restore()

    assert events == [
        ('restore', rollback, Path(config.DATA_DIR)),
        ('sanitize', Path(config.DATA_DIR) / 'app.db'),
        ('reset',),
        ('rotate',),
    ]
    assert maintenance.public_status()['state'] == 'failed'


def test_failed_restore_runs_emergency_rollback_and_restarts(
    app, monkeypatch, tmp_path
):
    import config
    import app.restore_service as service

    data_dir = tmp_path / 'data'
    data_dir.mkdir()
    monkeypatch.setattr(config, 'DATA_DIR', data_dir)
    operation_dir = tmp_path / 'operation'
    operation_dir.mkdir()
    archive = operation_dir / 'archive.zip'
    archive.write_bytes(b'uploaded')
    record = SimpleNamespace(
        operation_id='restore-failure',
        directory=operation_dir,
        archive_path=archive,
    )
    events = []

    @contextmanager
    def fake_operation_lock():
        yield object()

    monkeypatch.setattr(service, 'operation_lock', fake_operation_lock)
    restore_app = SimpleNamespace(
        extensions={
            'runtime_lifecycle': SimpleNamespace(
                begin_shutdown=lambda grace: (
                    events.append('shutdown')
                    or SimpleNamespace(remaining=())
                )
            )
        },
        app_context=app.app_context,
    )
    monkeypatch.setattr(service, '_close_active_ssh_sessions', lambda: None)
    monkeypatch.setattr(
        service.connection_pool.temp_connection_pool,
        'close_all_connections',
        lambda: None,
    )
    monkeypatch.setattr(service, '_disconnect_sockets', lambda socketio: None)

    def create_rollback(data, destination, held_token=None):
        destination.write_bytes(b'rollback')
        events.append('snapshot')

    monkeypatch.setattr(service, 'create_online_backup', create_rollback)
    restores = []

    def restore(source, destination):
        restores.append(Path(source).name)
        if Path(source) == archive:
            raise RuntimeError('restore failed')

    monkeypatch.setattr(service, 'restore_backup', restore)
    monkeypatch.setattr(service, 'reset_cache', lambda: None)
    monkeypatch.setattr(service, 'rotate_epoch', lambda: None)
    monkeypatch.setattr(service, '_clear_restored_runtime_sessions', lambda path: None)
    monkeypatch.setattr(service, 'begin_preparing', lambda operation_id: events.append('preparing'))
    monkeypatch.setattr(service, 'mark_in_progress', lambda *args: events.append('restore'))
    monkeypatch.setattr(service, 'mark_failed', lambda *args, **kwargs: events.append(('failed', kwargs)))
    monkeypatch.setattr(service.backup_operations, 'remove', lambda operation_id: events.append('cleanup'))
    monkeypatch.setattr(service, 'log_security_event', lambda name, **kwargs: events.append(name))

    service._perform_restore(
        restore_app,
        SimpleNamespace(),
        record,
        'admin',
        '127.0.0.1',
        lambda: events.append('restart'),
    )

    assert restores == ['archive.zip', 'rollback.zip']
    assert ('failed', {'rollback_failed': False}) in events
    assert 'RESTORE_FAILED' in events
    assert events[-2:] == ['cleanup', 'restart']
