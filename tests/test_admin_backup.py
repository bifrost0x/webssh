import json
import sqlite3
import time
from pathlib import Path
import zipfile

import pytest

from app.backup_manager import create_backup
from tests.step_up_helpers import password_step_up_headers


def _create_user(app, username, *, admin):
    from app.auth import register_user
    from app.models import db

    with app.app_context():
        user, error = register_user(username, 'password123')
        assert error is None
        user.is_admin = admin
        db.session.commit()
        return user.id


def _login(client, username):
    response = client.post('/login', data={
        'username': username,
        'password': 'password123',
    })
    assert response.status_code == 302


def _step_up(client, action, target):
    return password_step_up_headers(client, action, target)[0]


def _wait_for_status(client, operation_id, expected, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = client.get(f'/admin/api/backups/{operation_id}')
        if response.status_code == 200 and response.json['status'] in expected:
            return response
        time.sleep(0.03)
    raise AssertionError(f'operation did not reach {expected}')


@pytest.fixture
def isolated_operations(app, monkeypatch, tmp_path):
    import config
    from app.backup_operations import backup_operations

    backup_operations.close()
    monkeypatch.setattr(config, 'BACKUP_TEMP_DIR', tmp_path / 'operations')
    monkeypatch.setattr(config, 'BACKUP_DOWNLOAD_TTL', 60)
    monkeypatch.setattr(config, 'BACKUP_OPERATION_TIMEOUT', 60)
    monkeypatch.setattr(config, 'RATELIMIT_ENABLED', False)
    yield backup_operations
    backup_operations.close()


def _valid_archive(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    database = sqlite3.connect(source / 'app.db')
    try:
        database.execute(
            'CREATE TABLE users ('
            'id INTEGER PRIMARY KEY, '
            'username TEXT NOT NULL, '
            'password_hash TEXT NOT NULL'
            ')'
        )
        database.commit()
    finally:
        database.close()
    (source / 'settings.json').write_text('{}', encoding='utf-8')
    archive = tmp_path / 'upload.zip'
    create_backup(source, archive)
    return archive


def _archive_with_data_schema(source, destination, data_schema_version):
    with zipfile.ZipFile(source, 'r') as archive:
        entries = {
            info.filename: archive.read(info)
            for info in archive.infolist()
        }
    manifest = json.loads(entries['manifest.json'])
    manifest['data_schema_version'] = data_schema_version
    entries['manifest.json'] = json.dumps(
        manifest, sort_keys=True, separators=(',', ':')
    ).encode('utf-8')
    with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)
    return destination


def _archive_as_legacy_v1(source, destination):
    with zipfile.ZipFile(source, 'r') as archive:
        entries = {
            info.filename: archive.read(info)
            for info in archive.infolist()
        }
    manifest = json.loads(entries['manifest.json'])
    manifest = {
        'files': manifest['files'],
        'format_version': 1,
    }
    entries['manifest.json'] = json.dumps(
        manifest, sort_keys=True, separators=(',', ':')
    ).encode('utf-8')
    with zipfile.ZipFile(
        destination, 'w', compression=zipfile.ZIP_DEFLATED
    ) as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)
    return destination


def test_backup_endpoints_require_admin(app, client, isolated_operations):
    _create_user(app, 'normal_backup_user', admin=False)

    assert client.post('/admin/api/backups').status_code == 302
    _login(client, 'normal_backup_user')
    assert client.post('/admin/api/backups').status_code == 403
    assert client.post('/admin/api/backups/upload', data=b'PK').status_code == 403


def test_restore_mutations_reject_non_object_json(
    app, client, isolated_operations
):
    del isolated_operations
    _create_user(app, 'restore_json_admin', admin=True)
    _login(client, 'restore_json_admin')
    operation_id = 'missing-operation'

    prepared = client.post(
        f'/admin/api/backups/{operation_id}/restore/prepare',
        json=['unexpected'],
        headers=_step_up(client, 'backup.restore_prepare', operation_id),
    )
    restored = client.post(
        f'/admin/api/backups/{operation_id}/restore',
        json=['unexpected'],
        headers=_step_up(client, 'backup.restore', operation_id),
    )

    assert prepared.status_code == 400
    assert restored.status_code == 400


@pytest.mark.parametrize(
    'endpoint',
    ('/admin/api/backups', '/admin/api/backups/upload'),
)
def test_busy_backup_response_does_not_expose_exception_details(
    app, client, isolated_operations, monkeypatch, endpoint
):
    from app.backup_coordination import OperationBusyError

    _create_user(app, 'busy_backup_admin', admin=True)
    _login(client, 'busy_backup_admin')

    def reject_operation(*_args, **_kwargs):
        raise OperationBusyError('sensitive/server/path')

    monkeypatch.setattr(isolated_operations, 'create', reject_operation)

    action, target = (
        ('backup.create', 'new')
        if endpoint == '/admin/api/backups'
        else ('backup.upload', 'upload')
    )
    response = client.post(
        endpoint,
        data=b'PK\x03\x04',
        headers=_step_up(client, action, target),
    )

    assert response.status_code == 409
    assert response.json == {
        'error': 'another backup or restore operation is active'
    }
    assert 'sensitive' not in response.get_data(as_text=True)


def test_upload_limit_response_does_not_expose_exception_details(
    app, client, isolated_operations, monkeypatch
):
    import app.admin_backup as admin_backup

    _create_user(app, 'limited_upload_admin', admin=True)
    _login(client, 'limited_upload_admin')

    def reject_upload(_destination):
        raise ValueError('sensitive/server/path')

    monkeypatch.setattr(admin_backup, '_stream_upload', reject_upload)

    response = client.post(
        '/admin/api/backups/upload',
        data=b'PK\x03\x04',
        headers=_step_up(client, 'backup.upload', 'upload'),
    )

    assert response.status_code == 413
    assert response.json == {'error': 'Backup upload is too large'}
    assert 'sensitive' not in response.get_data(as_text=True)
    assert not isolated_operations._records


def test_admin_can_create_and_one_time_download_online_backup(
    app, client, isolated_operations
):
    _create_user(app, 'backup_admin', admin=True)
    _login(client, 'backup_admin')

    created = client.post(
        '/admin/api/backups',
        headers=_step_up(client, 'backup.create', 'new'),
    )
    assert created.status_code == 202
    operation_id = created.json['operation_id']
    ready = _wait_for_status(client, operation_id, {'ready', 'failed'})
    assert ready.json['status'] == 'ready'

    download = client.post(
        f'/admin/api/backups/{operation_id}/download',
        buffered=False,
        headers=_step_up(client, 'backup.download', operation_id),
    )
    assert download.status_code == 200
    assert download.mimetype == 'application/zip'
    assert download.headers['Cache-Control'] == 'no-store'
    assert download.headers['X-Content-Type-Options'] == 'nosniff'
    assert b''.join(download.response).startswith(b'PK')
    assert operation_id not in isolated_operations._records
    download.close()
    assert client.post(
        f'/admin/api/backups/{operation_id}/download',
        headers=_step_up(client, 'backup.download', operation_id),
    ).status_code == 404


def test_interrupted_download_invalidates_server_archive(
    app, client, isolated_operations
):
    _create_user(app, 'disconnect_backup_admin', admin=True)
    _login(client, 'disconnect_backup_admin')
    created = client.post(
        '/admin/api/backups',
        headers=_step_up(client, 'backup.create', 'new'),
    )
    operation_id = created.json['operation_id']
    ready = _wait_for_status(client, operation_id, {'ready', 'failed'})
    assert ready.json['status'] == 'ready'

    download = client.post(
        f'/admin/api/backups/{operation_id}/download',
        buffered=False,
        headers=_step_up(client, 'backup.download', operation_id),
    )
    download.close()

    assert operation_id not in isolated_operations._records


def test_uploaded_backup_is_session_bound_and_requires_two_step_reauth(
    app, client, isolated_operations, tmp_path, monkeypatch
):
    _create_user(app, 'restore_admin', admin=True)
    archive = _valid_archive(tmp_path)
    _login(client, 'restore_admin')

    uploaded = client.post(
        '/admin/api/backups/upload',
        data=archive.read_bytes(),
        content_type='application/zip',
        headers=_step_up(client, 'backup.upload', 'upload'),
    )
    assert uploaded.status_code == 202
    operation_id = uploaded.json['operation_id']
    verified = _wait_for_status(client, operation_id, {'verified', 'failed'})
    assert verified.json['status'] == 'verified'
    assert set(verified.json['summary']) == {
        'compatibility_reason', 'compatible', 'created_at',
        'current_data_schema_version', 'data_schema_version', 'file_count',
        'format_version', 'legacy', 'total_uncompressed_size',
    }

    first = client.post(
        f'/admin/api/backups/{operation_id}/restore/prepare',
        json={'acknowledge_sensitive_restore': True},
        headers=_step_up(client, 'backup.restore_prepare', operation_id),
    )
    assert first.status_code == 200
    token = first.json['confirmation_token']
    assert client.post(
        f'/admin/api/backups/{operation_id}/restore',
        json={
            'confirmation_token': token,
            'confirmation_phrase': 'RESTORE',
            'confirm_destructive_restore': True,
        },
    ).status_code == 403

    started = []
    import app.restore_service as restore_service
    monkeypatch.setattr(
        restore_service,
        'start_restore',
        lambda app, socketio, record, username, source_ip: started.append(record),
    )
    response = client.post(
        f'/admin/api/backups/{operation_id}/restore',
        json={
            'confirmation_token': token,
            'confirmation_phrase': 'RESTORE',
            'confirm_destructive_restore': True,
        },
        headers=_step_up(client, 'backup.restore', operation_id),
    )
    assert response.status_code == 202
    assert len(started) == 1
    assert started[0].status == 'restoring'

    other_session = app.test_client()
    _login(other_session, 'restore_admin')
    assert other_session.get(
        f'/admin/api/backups/{operation_id}'
    ).status_code in {302, 404}


@pytest.mark.parametrize(
    'failure',
    ('durability_recheck', 'thread_start', 'thread_start_control_flow'),
)
def test_restore_start_failure_recovery_matches_launch_certainty(
    app,
    client,
    isolated_operations,
    tmp_path,
    monkeypatch,
    failure,
):
    import app.backup_coordination as backup_coordination
    import app.restore_service as restore_service

    username = {
        'thread_start_control_flow': 'restore_start_control',
    }.get(failure, f'restore_start_{failure}')
    user_id = _create_user(app, username, admin=True)
    _login(client, username)
    backup_session_id = 'restore-start-test-session-id-000000000001'
    with client.session_transaction() as browser_session:
        browser_session['_backup_admin_session_id'] = backup_session_id

    record = isolated_operations.create(
        'uploaded_backup',
        user_id,
        backup_session_id,
        status='verified',
    )
    record.archive_path.write_bytes(_valid_archive(tmp_path).read_bytes())
    token = isolated_operations.prepare_restore(
        record.operation_id,
        user_id,
        backup_session_id,
    )

    # The endpoint's first durability gate succeeds. Exercise failures that
    # occur only after begin_restore() has consumed the confirmation token.
    monkeypatch.setattr(
        backup_coordination,
        'require_durable_recovery_storage',
        lambda: None,
    )
    if failure == 'durability_recheck':
        monkeypatch.setattr(
            restore_service,
            'require_durable_recovery_storage',
            lambda: (_ for _ in ()).throw(
                RuntimeError('recovery storage changed')
            ),
        )

        class UnexpectedThread:
            def __init__(self, *_args, **_kwargs):
                raise AssertionError('worker must not be created')

        monkeypatch.setattr(restore_service.threading, 'Thread', UnexpectedThread)
    else:
        monkeypatch.setattr(
            restore_service,
            'require_durable_recovery_storage',
            lambda: None,
        )

        class FailedThread:
            def __init__(self, *_args, **_kwargs):
                pass

            def start(self):
                if failure == 'thread_start_control_flow':
                    raise KeyboardInterrupt
                raise RuntimeError('thread capacity unavailable')

        monkeypatch.setattr(restore_service.threading, 'Thread', FailedThread)

    request_kwargs = {
        'json': {
            'confirmation_token': token,
            'confirmation_phrase': 'RESTORE',
            'confirm_destructive_restore': True,
        },
        'headers': _step_up(client, 'backup.restore', record.operation_id),
    }
    if failure == 'thread_start_control_flow':
        with pytest.raises(KeyboardInterrupt):
            client.post(
                f'/admin/api/backups/{record.operation_id}/restore',
                **request_kwargs,
            )
    else:
        response = client.post(
            f'/admin/api/backups/{record.operation_id}/restore',
            **request_kwargs,
        )
        assert response.status_code == 503
        assert response.json == {
            'error': 'Restore could not be started',
            'code': 'RESTORE_START_FAILED',
        }
    if failure == 'thread_start_control_flow':
        # A control-flow interruption may occur immediately after CPython has
        # created the OS thread but before ident or the target is observable.
        # Keep the consumed operation fail-closed instead of permitting two
        # workers against the same archive.
        assert record.status == 'restoring'
        with pytest.raises(KeyError):
            isolated_operations.prepare_restore(
                record.operation_id,
                user_id,
                backup_session_id,
            )
        isolated_operations.reset_unstarted_restore(record.operation_id)
        return
    assert record.status == 'verified'
    assert record.error is None
    assert record.metadata == {}

    # A failed launch must require a fresh confirmation but keep the verified
    # archive available for an ordinary retry.
    with pytest.raises(KeyError):
        isolated_operations.begin_restore(
            record.operation_id,
            user_id,
            backup_session_id,
            token,
        )
    replacement_token = isolated_operations.prepare_restore(
        record.operation_id,
        user_id,
        backup_session_id,
    )
    started = []
    monkeypatch.setattr(
        restore_service,
        'start_restore',
        lambda app, socketio, retry_record, username, source_ip: (
            started.append(retry_record)
        ),
    )
    retried = client.post(
        f'/admin/api/backups/{record.operation_id}/restore',
        json={
            'confirmation_token': replacement_token,
            'confirmation_phrase': 'RESTORE',
            'confirm_destructive_restore': True,
        },
        headers=_step_up(client, 'backup.restore', record.operation_id),
    )

    assert retried.status_code == 202
    assert started == [record]
    assert record.status == 'restoring'


def test_restore_start_interruption_after_launch_never_enables_retry(
    app,
    client,
    isolated_operations,
    tmp_path,
    monkeypatch,
):
    import threading

    import app.backup_coordination as backup_coordination
    import app.restore_service as restore_service

    username = 'restore_launched_interrupt'
    user_id = _create_user(app, username, admin=True)
    _login(client, username)
    backup_session_id = 'restore-launched-test-session-id-0000000001'
    with client.session_transaction() as browser_session:
        browser_session['_backup_admin_session_id'] = backup_session_id

    record = isolated_operations.create(
        'uploaded_backup',
        user_id,
        backup_session_id,
        status='verified',
    )
    record.archive_path.write_bytes(_valid_archive(tmp_path).read_bytes())
    token = isolated_operations.prepare_restore(
        record.operation_id,
        user_id,
        backup_session_id,
    )
    monkeypatch.setattr(
        backup_coordination,
        'require_durable_recovery_storage',
        lambda: None,
    )
    monkeypatch.setattr(
        restore_service,
        'require_durable_recovery_storage',
        lambda: None,
    )

    worker_entered = threading.Event()
    allow_worker_exit = threading.Event()
    monkeypatch.setattr(
        restore_service,
        '_perform_restore',
        lambda *_args: (
            worker_entered.set(),
            allow_worker_exit.wait(2),
        ),
    )
    real_thread = threading.Thread
    started_threads = []

    class StartedThenInterruptedThread(real_thread):
        def start(self):
            started_threads.append(self)
            super().start()
            raise KeyboardInterrupt

    monkeypatch.setattr(
        restore_service.threading,
        'Thread',
        StartedThenInterruptedThread,
    )

    with pytest.raises(KeyboardInterrupt):
        client.post(
            f'/admin/api/backups/{record.operation_id}/restore',
            json={
                'confirmation_token': token,
                'confirmation_phrase': 'RESTORE',
                'confirm_destructive_restore': True,
            },
            headers=_step_up(client, 'backup.restore', record.operation_id),
        )

    assert worker_entered.wait(1)
    assert record.status == 'restoring'
    with pytest.raises(KeyError):
        isolated_operations.prepare_restore(
            record.operation_id,
            user_id,
            backup_session_id,
        )

    allow_worker_exit.set()
    for worker in started_threads:
        worker.join(2)
        assert not worker.is_alive()
    isolated_operations.reset_unstarted_restore(record.operation_id)


def test_future_schema_is_verified_but_blocked_at_both_restore_gates(
    app, client, isolated_operations, tmp_path, monkeypatch
):
    user_id = _create_user(app, 'future_restore_admin', admin=True)
    current = _valid_archive(tmp_path)
    future = _archive_with_data_schema(current, tmp_path / 'future.zip', 3)
    _login(client, 'future_restore_admin')

    uploaded = client.post(
        '/admin/api/backups/upload',
        data=future.read_bytes(),
        content_type='application/zip',
        headers=_step_up(client, 'backup.upload', 'upload'),
    )
    operation_id = uploaded.json['operation_id']
    verified = _wait_for_status(client, operation_id, {'verified', 'failed'})

    assert verified.json['status'] == 'verified'
    assert verified.json['summary']['compatible'] is False
    assert verified.json['summary']['data_schema_version'] == 3
    assert verified.json['summary']['current_data_schema_version'] == 2
    assert verified.json['summary']['compatibility_reason'] == (
        'backup data schema is newer than this WebSSH version'
    )
    assert client.post(
        f'/admin/api/backups/{operation_id}/restore/prepare',
        json={'acknowledge_sensitive_restore': True},
        headers=_step_up(client, 'backup.restore_prepare', operation_id),
    ).status_code == 409

    with client.session_transaction() as browser_session:
        session_id = browser_session['_backup_admin_session_id']
    token = isolated_operations.prepare_restore(
        operation_id, user_id, session_id
    )
    started = []
    import app.restore_service as restore_service
    monkeypatch.setattr(
        restore_service,
        'start_restore',
        lambda *args: started.append(args),
    )
    response = client.post(
        f'/admin/api/backups/{operation_id}/restore',
        json={
            'confirmation_token': token,
            'confirmation_phrase': 'RESTORE',
            'confirm_destructive_restore': True,
        },
        headers=_step_up(client, 'backup.restore', operation_id),
    )

    assert response.status_code == 409
    assert started == []


def test_legacy_v1_upload_remains_restore_compatible(
    app, client, isolated_operations, tmp_path
):
    _create_user(app, 'legacy_restore_admin', admin=True)
    current = _valid_archive(tmp_path)
    legacy = _archive_as_legacy_v1(current, tmp_path / 'legacy-v1.zip')
    _login(client, 'legacy_restore_admin')

    uploaded = client.post(
        '/admin/api/backups/upload',
        data=legacy.read_bytes(),
        content_type='application/zip',
        headers=_step_up(client, 'backup.upload', 'upload'),
    )
    operation_id = uploaded.json['operation_id']
    verified = _wait_for_status(client, operation_id, {'verified', 'failed'})

    assert verified.json['status'] == 'verified'
    assert verified.json['summary']['format_version'] == 1
    assert verified.json['summary']['data_schema_version'] == 0
    assert verified.json['summary']['legacy'] is True
    assert verified.json['summary']['compatible'] is True
    prepared = client.post(
        f'/admin/api/backups/{operation_id}/restore/prepare',
        json={'acknowledge_sensitive_restore': True},
        headers=_step_up(client, 'backup.restore_prepare', operation_id),
    )
    assert prepared.status_code == 200


def test_upload_limit_and_csrf_are_enforced(
    app, client, isolated_operations, monkeypatch
):
    import config

    _create_user(app, 'bounded_backup_admin', admin=True)
    _login(client, 'bounded_backup_admin')
    monkeypatch.setattr(config, 'BACKUP_UPLOAD_MAX_SIZE', 4)
    oversized = client.post(
        '/admin/api/backups/upload',
        data=b'PK123',
        content_type='application/zip',
        headers=_step_up(client, 'backup.upload', 'upload'),
    )
    assert oversized.status_code == 413
    assert not tuple(Path(config.BACKUP_TEMP_DIR).glob('operation-*'))

    app.config['WTF_CSRF_ENABLED'] = True
    assert client.post('/admin/api/backups').status_code == 400


def test_admin_backup_ui_is_native_and_has_destructive_confirmations():
    template = Path('templates/admin.html').read_text(encoding='utf-8')

    assert 'data-tab="backup"' in template
    assert 'restoreFirstConfirmModal' in template
    assert 'restoreSecondConfirmModal' in template
    assert 'restorePassword' not in template
    assert 'X-WebSSH-Step-Up' in Path('static/js/admin.js').read_text(
        encoding='utf-8'
    )
    assert 'backupDataSchemaVersion' in template
    assert 'backupCurrentDataSchemaVersion' in template
    assert 'backupCreatedAt' in template
    assert 'backupLegacy' in template
    assert 'backupCompatibilityReason' in template
