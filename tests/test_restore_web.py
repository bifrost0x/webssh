from contextlib import contextmanager
import os
from pathlib import Path
from types import SimpleNamespace

import config
import pytest


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
    assert admin.headers['Location'].endswith('/settings?section=users')

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


@pytest.mark.parametrize('status_payload', [
    b'{not-json',
    b'null',
    b'[]',
    b'{}',
    b'{"state":"unexpected"}',
])
def test_corrupt_maintenance_status_preserves_all_recovery_archives(
    client,
    monkeypatch,
    tmp_path,
    status_payload,
):
    maintenance = _configure_temp_root(monkeypatch, tmp_path)
    from app.backup_operations import BackupOperationRegistry

    root = maintenance._status_path().parent
    operation = root / 'operation-unknown'
    operation.mkdir()
    rollback = operation / 'rollback.zip'
    rollback.write_bytes(b'emergency')
    maintenance._status_path().write_bytes(status_payload)
    maintenance._state = None
    maintenance._state_path = None

    BackupOperationRegistry().cleanup_orphans()

    assert rollback.read_bytes() == b'emergency'
    assert maintenance.public_status()['state'] == 'rollback_failed'
    assert client.get('/ready').status_code == 503


@pytest.mark.parametrize('status_payload', [
    b'{not-json',
    b'null',
    b'[]',
    b'{}',
    b'{"state":"unexpected"}',
])
def test_corrupt_maintenance_status_blocks_all_startup_initialization(
    monkeypatch,
    tmp_path,
    status_payload,
):
    import app as app_module

    maintenance = _configure_temp_root(monkeypatch, tmp_path)
    maintenance._status_path().write_bytes(status_payload)
    maintenance._state = None
    maintenance._state_path = None
    initialized = []
    runtime_jobs = []
    monkeypatch.setattr(
        app_module,
        '_initialize_persistent_storage',
        lambda created_app: initialized.append(created_app),
    )
    monkeypatch.setattr(
        app_module.RuntimeLifecycle,
        'start_job',
        lambda self, name, target: runtime_jobs.append(name),
    )

    created_app = app_module.create_app(
        initialize_storage=True,
        start_runtime=True,
        initialize_oidc=False,
    )

    assert initialized == []
    assert runtime_jobs == []
    assert created_app.test_client().get('/ready').status_code == 503


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
        '_restore_recovery_snapshot',
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


def test_interrupted_restore_with_mismatched_data_dir_stays_fail_closed(
    monkeypatch, tmp_path
):
    import json

    maintenance = _configure_temp_root(monkeypatch, tmp_path)
    root = maintenance._status_path().parent
    operation = root / 'operation-mismatch'
    operation.mkdir()
    rollback = operation / 'rollback.zip'
    rollback.write_bytes(b'emergency')
    maintenance.begin_preparing('mismatch')
    maintenance.mark_in_progress(
        'mismatch', 'operation-mismatch/rollback.zip'
    )
    document = json.loads(maintenance._status_path().read_text('utf-8'))
    document['data_fingerprint'] = '0' * 64
    maintenance._status_path().write_text(json.dumps(document), 'utf-8')
    maintenance._state = None
    maintenance._state_path = None

    maintenance.recover_interrupted_restore()

    assert maintenance.is_active() is True
    assert maintenance.public_status()['state'] == 'rollback_failed'
    assert maintenance.protected_operation_directory_name() == (
        'operation-mismatch'
    )
    assert rollback.read_bytes() == b'emergency'


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
            'data_access': app.extensions['data_access'],
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
    monkeypatch.setattr(service, '_restore_recovery_snapshot', restore)
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


def test_repeated_maintenance_checks_do_not_touch_the_namespace(
    monkeypatch, tmp_path
):
    import os
    import app.backup_coordination as coordination

    maintenance = _configure_temp_root(monkeypatch, tmp_path)
    validations = []
    real_ensure = coordination.ensure_backup_temp_dir

    def counting_ensure():
        validations.append(1)
        return real_ensure()

    monkeypatch.setattr(maintenance, 'ensure_backup_temp_dir', counting_ensure)
    assert maintenance.is_active() is False
    assert validations == [1]

    filesystem_changes = []
    real_mkdir = Path.mkdir
    real_chmod = os.chmod

    def recording_mkdir(self, *args, **kwargs):
        filesystem_changes.append(('mkdir', self))
        return real_mkdir(self, *args, **kwargs)

    def recording_chmod(path, *args, **kwargs):
        filesystem_changes.append(('chmod', path))
        return real_chmod(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'mkdir', recording_mkdir)
    monkeypatch.setattr(os, 'chmod', recording_chmod)
    for _ in range(25):
        assert maintenance.is_active() is False
        assert maintenance.public_status() == {'state': 'idle', 'message': None}

    assert validations == [1]
    assert filesystem_changes == []


def test_status_written_by_another_process_is_still_detected(
    monkeypatch, tmp_path
):
    import json
    import time

    maintenance = _configure_temp_root(monkeypatch, tmp_path)
    assert maintenance.is_active() is False
    status_path = maintenance._status_path()
    assert not status_path.exists()

    # Another process writes the shared status file; this process holds no
    # cached status document for it.
    status_path.write_text(json.dumps({
        'state': 'rollback_failed',
        'operation_id': 'external-restore',
        'message': 'Restore and rollback failed',
        'updated_at': time.time(),
    }), 'utf-8')

    assert maintenance.is_active() is True
    status_path.unlink()
    maintenance._state = None
    maintenance._state_path = None
    assert maintenance.is_active() is False


def test_maintenance_location_is_validated_again_after_configuration_change(
    monkeypatch, tmp_path
):
    maintenance = _configure_temp_root(monkeypatch, tmp_path)
    assert maintenance.is_active() is False
    first = maintenance._read_status_path()

    monkeypatch.setattr(config, 'BACKUP_TEMP_DIR', tmp_path / 'other-operations')
    assert maintenance.is_active() is False
    second = maintenance._read_status_path()

    assert second != first
    assert second.parent.is_dir()
    assert second.parent.is_relative_to(
        (tmp_path / 'other-operations').resolve()
    )


def test_unsafe_maintenance_location_is_never_cached(monkeypatch, tmp_path):
    maintenance = _configure_temp_root(monkeypatch, tmp_path)
    monkeypatch.setattr(config, 'BACKUP_TEMP_DIR', config.DATA_DIR / 'operations')

    for _ in range(2):
        with pytest.raises(RuntimeError, match='outside DATA_DIR'):
            maintenance.is_active()


def _plant_failed_status(directory):
    import json
    import time

    directory.mkdir(parents=True)
    (directory / 'restore-status.json').write_text(json.dumps({
        'state': 'rollback_failed',
        'operation_id': 'planted',
        'message': 'Restore and rollback failed',
        'updated_at': time.time(),
    }), 'utf-8')


@pytest.mark.skipif(os.name == 'nt', reason='POSIX symlink semantics')
def test_cached_maintenance_location_rejects_a_replaced_namespace(
    monkeypatch, tmp_path
):
    import shutil

    maintenance = _configure_temp_root(monkeypatch, tmp_path)
    assert maintenance.is_active() is False
    namespace = maintenance._read_status_path().parent

    # A temp cleaner removed the namespace and another account put a link to
    # its own status file in its place.
    planted = tmp_path / 'planted'
    _plant_failed_status(planted)
    shutil.rmtree(namespace)
    namespace.symlink_to(planted, target_is_directory=True)

    for _ in range(2):
        with pytest.raises(RuntimeError, match='symbolic link'):
            maintenance.is_active()


@pytest.mark.skipif(os.name == 'nt', reason='POSIX ownership and modes')
def test_cached_maintenance_location_rejects_a_foreign_namespace(
    monkeypatch, tmp_path
):
    import app.backup_coordination as coordination

    maintenance = _configure_temp_root(monkeypatch, tmp_path)
    assert maintenance.is_active() is False
    namespace = maintenance._read_status_path().parent
    validations = []
    real_ensure = coordination.ensure_backup_temp_dir

    def counting_ensure():
        validations.append(1)
        return real_ensure()

    monkeypatch.setattr(maintenance, 'ensure_backup_temp_dir', counting_ensure)

    os.chmod(namespace, 0o777)
    assert maintenance.is_active() is False
    assert len(validations) == 1
    assert namespace.stat().st_mode & 0o777 == 0o700

    # Owned by another account: every read runs the full validation, whose
    # chmod is refused for a directory this process does not own.
    real_uid = os.geteuid()
    monkeypatch.setattr(os, 'geteuid', lambda: real_uid + 1)

    def refusing_chmod(path, mode):
        raise PermissionError('not the owner')

    monkeypatch.setattr(os, 'chmod', refusing_chmod)
    for _ in range(2):
        with pytest.raises(PermissionError):
            maintenance.is_active()
    assert len(validations) == 3


def test_cached_maintenance_location_keeps_the_document_of_a_removed_namespace(
    monkeypatch, tmp_path
):
    import shutil

    maintenance = _configure_temp_root(monkeypatch, tmp_path)
    maintenance.begin_preparing('restore-test')
    assert maintenance.is_active() is True
    namespace = maintenance._read_status_path().parent

    # A tmp cleaner removing the namespace must not end maintenance.
    shutil.rmtree(namespace)

    assert maintenance.is_active() is True
    assert namespace.is_dir()


@pytest.mark.skipif(os.name == 'nt', reason='POSIX ownership')
def test_cached_maintenance_location_accepts_a_foreign_owner_for_root(
    monkeypatch, tmp_path
):
    maintenance = _configure_temp_root(monkeypatch, tmp_path)
    maintenance.is_active()
    # Root may run with a temp directory owned by another account, such as a
    # bind mount; the read cache must still be used.
    monkeypatch.setattr(os, 'geteuid', lambda: 0)
    maintenance._read_location = None
    maintenance.is_active()
    assert maintenance._read_location is not None
