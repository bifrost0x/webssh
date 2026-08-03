import json
import sqlite3
import time
from pathlib import Path
import zipfile

import pytest

from app.backup_manager import create_backup


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

    response = client.post(endpoint, data=b'PK\x03\x04')

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

    response = client.post('/admin/api/backups/upload', data=b'PK\x03\x04')

    assert response.status_code == 413
    assert response.json == {'error': 'Backup upload is too large'}
    assert 'sensitive' not in response.get_data(as_text=True)
    assert not isolated_operations._records


def test_admin_can_create_and_one_time_download_online_backup(
    app, client, isolated_operations
):
    _create_user(app, 'backup_admin', admin=True)
    _login(client, 'backup_admin')

    created = client.post('/admin/api/backups')
    assert created.status_code == 202
    operation_id = created.json['operation_id']
    ready = _wait_for_status(client, operation_id, {'ready', 'failed'})
    assert ready.json['status'] == 'ready'

    download = client.post(
        f'/admin/api/backups/{operation_id}/download', buffered=False
    )
    assert download.status_code == 200
    assert download.mimetype == 'application/zip'
    assert download.headers['Cache-Control'] == 'no-store'
    assert download.headers['X-Content-Type-Options'] == 'nosniff'
    assert b''.join(download.response).startswith(b'PK')
    assert operation_id not in isolated_operations._records
    download.close()
    assert client.post(
        f'/admin/api/backups/{operation_id}/download'
    ).status_code == 404


def test_interrupted_download_invalidates_server_archive(
    app, client, isolated_operations
):
    _create_user(app, 'disconnect_backup_admin', admin=True)
    _login(client, 'disconnect_backup_admin')
    created = client.post('/admin/api/backups')
    operation_id = created.json['operation_id']
    ready = _wait_for_status(client, operation_id, {'ready', 'failed'})
    assert ready.json['status'] == 'ready'

    download = client.post(
        f'/admin/api/backups/{operation_id}/download', buffered=False
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

    other_session = app.test_client()
    _login(other_session, 'restore_admin')
    assert other_session.get(
        f'/admin/api/backups/{operation_id}'
    ).status_code == 404

    first = client.post(
        f'/admin/api/backups/{operation_id}/restore/prepare',
        json={'acknowledge_sensitive_restore': True},
    )
    assert first.status_code == 200
    token = first.json['confirmation_token']
    assert client.post(
        f'/admin/api/backups/{operation_id}/restore',
        json={
            'confirmation_token': token,
            'confirmation_phrase': 'RESTORE',
            'confirm_destructive_restore': True,
            'password': 'wrong-password',
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
            'password': 'password123',
        },
    )
    assert response.status_code == 202
    assert len(started) == 1
    assert started[0].status == 'restoring'


def test_future_schema_is_verified_but_blocked_at_both_restore_gates(
    app, client, isolated_operations, tmp_path, monkeypatch
):
    user_id = _create_user(app, 'future_restore_admin', admin=True)
    current = _valid_archive(tmp_path)
    future = _archive_with_data_schema(current, tmp_path / 'future.zip', 2)
    _login(client, 'future_restore_admin')

    uploaded = client.post(
        '/admin/api/backups/upload',
        data=future.read_bytes(),
        content_type='application/zip',
    )
    operation_id = uploaded.json['operation_id']
    verified = _wait_for_status(client, operation_id, {'verified', 'failed'})

    assert verified.json['status'] == 'verified'
    assert verified.json['summary']['compatible'] is False
    assert verified.json['summary']['data_schema_version'] == 2
    assert verified.json['summary']['current_data_schema_version'] == 1
    assert verified.json['summary']['compatibility_reason'] == (
        'backup data schema is newer than this WebSSH version'
    )
    assert client.post(
        f'/admin/api/backups/{operation_id}/restore/prepare',
        json={'acknowledge_sensitive_restore': True},
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
            'password': 'password123',
        },
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
    assert 'restorePassword' in template
    assert 'backupDataSchemaVersion' in template
    assert 'backupCurrentDataSchemaVersion' in template
    assert 'backupCreatedAt' in template
    assert 'backupLegacy' in template
    assert 'backupCompatibilityReason' in template
