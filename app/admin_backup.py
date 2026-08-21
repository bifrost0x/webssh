"""Administrator HTTP API for backup creation, upload, and verification."""

from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import secrets

from flask import (
    Blueprint,
    current_app,
    jsonify,
    request,
    session,
)
from flask_login import current_user, login_required

import config

from .audit_logger import log_rate_limit_exceeded, log_security_event
from .auth import check_reauth_rate_limit
from .backup_coordination import OperationBusyError, operation_lock
from .backup_manager import (
    BackupIntegrityError,
    evaluate_backup_compatibility,
    verify_backup,
)
from .backup_operations import backup_operations
from .decorators import admin_required, step_up_required
from .online_backup import create_online_backup
from . import socketio


admin_backup_blueprint = Blueprint('admin_backup', __name__)
_UPLOAD_CHUNK_SIZE = 1024 * 1024
_OPERATION_BUSY_MESSAGE = 'another backup or restore operation is active'
_UPLOAD_TOO_LARGE_MESSAGE = 'Backup upload is too large'


class _ArchiveDownloadStream:
    """Stream one archive and invalidate it on EOF or disconnect."""

    def __init__(self, record):
        self._record = record
        self._handle = record.archive_path.open('rb')
        self._closed = False

    def __iter__(self):
        return self

    def __next__(self):
        chunk = self._handle.read(_UPLOAD_CHUNK_SIZE)
        if chunk:
            return chunk
        self.close()
        raise StopIteration

    def close(self):
        if self._closed:
            return
        self._closed = True
        self._handle.close()
        backup_operations.remove(self._record.operation_id)


def _admin_session_id():
    value = session.get('_backup_admin_session_id')
    if not isinstance(value, str) or len(value) < 32:
        value = secrets.token_urlsafe(32)
        session['_backup_admin_session_id'] = value
    return value


def _rate_limited(endpoint, limit):
    if not config.RATELIMIT_ENABLED:
        return False
    blocked = check_reauth_rate_limit(
        current_user.id,
        request.remote_addr or 'unknown',
        endpoint,
        limit,
    )
    if blocked:
        log_rate_limit_exceeded(
            endpoint,
            request.remote_addr or 'unknown',
            user=current_user.username,
        )
    return blocked


def _operation_payload(record):
    return {
        'operation_id': record.operation_id,
        'kind': record.kind,
        'status': record.status,
        'size': record.size,
        'summary': record.summary,
        'error': record.error,
    }


def _archive_summary(manifest):
    compatibility = evaluate_backup_compatibility(manifest)
    return {
        'format_version': manifest.format_version,
        'data_schema_version': compatibility.data_schema_version,
        'current_data_schema_version': (
            compatibility.current_data_schema_version
        ),
        'created_at': manifest.created_at,
        'legacy': compatibility.legacy,
        'file_count': len(manifest.files),
        'total_uncompressed_size': sum(item.size for item in manifest.files),
        'compatible': compatibility.compatible,
        'compatibility_reason': compatibility.reason,
    }


def _restore_compatibility(record):
    manifest = verify_backup(record.archive_path)
    return evaluate_backup_compatibility(manifest)


def _incompatible_restore_response(record):
    try:
        compatibility = _restore_compatibility(record)
    except BackupIntegrityError:
        return jsonify({'error': 'Backup archive is no longer valid'}), 409
    if not compatibility.compatible:
        return jsonify({
            'error': 'Backup is not compatible with this WebSSH version',
            'reason': compatibility.reason,
        }), 409
    return None


def _no_store(response):
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


@admin_backup_blueprint.after_request
def add_backup_headers(response):
    return _no_store(response)


@admin_backup_blueprint.post('/admin/api/backups')
@admin_required
@login_required
@step_up_required('backup.create', 'new')
def create_backup_operation():
    if _rate_limited('backup_create', config.RATELIMIT_BACKUP_CREATE):
        return jsonify({'error': 'Too many backup requests'}), 429
    try:
        record = backup_operations.create(
            'created_backup', current_user.id, _admin_session_id()
        )
    except OperationBusyError:
        return jsonify({'error': _OPERATION_BUSY_MESSAGE}), 409

    username = current_user.username
    source_ip = request.remote_addr or 'unknown'
    log_security_event(
        'BACKUP_CREATION_STARTED', user=username, ip=source_ip
    )

    def create_worker(cancel_event):
        backup_operations.set_status(record.operation_id, 'running')
        try:
            manifest = create_online_backup(config.DATA_DIR, record.archive_path)
            if cancel_event.is_set():
                backup_operations.remove(record.operation_id)
                return
            size = record.archive_path.stat().st_size
            summary = _archive_summary(manifest)
            backup_operations.set_status(
                record.operation_id,
                'ready',
                summary=summary,
                size=size,
                ttl=config.BACKUP_DOWNLOAD_TTL,
            )
            log_security_event(
                'BACKUP_CREATION_SUCCEEDED',
                user=username,
                ip=source_ip,
                size=size,
                files=summary['file_count'],
            )
        except Exception as error:
            record.archive_path.unlink(missing_ok=True)
            backup_operations.set_status(
                record.operation_id,
                'failed',
                error='Backup creation failed',
                ttl=config.BACKUP_DOWNLOAD_TTL,
            )
            log_security_event(
                'BACKUP_CREATION_FAILED',
                level=logging.ERROR,
                user=username,
                ip=source_ip,
                error_type=type(error).__name__,
            )

    try:
        current_app.extensions['runtime_lifecycle'].start_job(
            'web-backup-create',
            create_worker,
            owner_id=current_user.id,
        )
    except Exception:
        backup_operations.remove(record.operation_id)
        raise
    return jsonify(_operation_payload(record)), 202


@admin_backup_blueprint.get('/admin/api/backups/<operation_id>')
@admin_required
@login_required
def backup_operation_status(operation_id):
    try:
        record = backup_operations.get(
            operation_id, current_user.id, _admin_session_id()
        )
    except KeyError:
        return jsonify({'error': 'Backup operation not found'}), 404
    return jsonify(_operation_payload(record))


@admin_backup_blueprint.post('/admin/api/backups/<operation_id>/download')
@admin_required
@login_required
@step_up_required('backup.download', lambda operation_id: operation_id)
def download_backup(operation_id):
    if _rate_limited('backup_download', config.RATELIMIT_BACKUP_DOWNLOAD):
        return jsonify({'error': 'Too many backup download requests'}), 429
    try:
        record = backup_operations.claim_download(
            operation_id, current_user.id, _admin_session_id()
        )
    except KeyError:
        return jsonify({'error': 'Backup operation not found'}), 404

    filename = 'webssh-backup-' + datetime.now(timezone.utc).strftime(
        '%Y%m%dT%H%M%SZ.zip'
    )
    try:
        stream = _ArchiveDownloadStream(record)
        response = current_app.response_class(
            stream,
            mimetype='application/zip',
        )
        response.headers['Content-Disposition'] = (
            f'attachment; filename="{filename}"'
        )
        response.headers['Content-Length'] = str(record.size)
    except Exception:
        backup_operations.remove(record.operation_id)
        raise
    log_security_event(
        'BACKUP_DOWNLOADED',
        user=current_user.username,
        ip=request.remote_addr or 'unknown',
        size=record.size,
    )
    return response


def _stream_upload(destination: Path):
    declared_size = request.content_length
    if declared_size is not None and declared_size > config.BACKUP_UPLOAD_MAX_SIZE:
        raise ValueError('Backup upload is too large')
    total = 0
    descriptor = os.open(
        destination,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_BINARY', 0),
        0o600,
    )
    with os.fdopen(descriptor, 'wb') as handle:
        while chunk := request.stream.read(_UPLOAD_CHUNK_SIZE):
            total += len(chunk)
            if total > config.BACKUP_UPLOAD_MAX_SIZE:
                raise ValueError('Backup upload is too large')
            handle.write(chunk)
        handle.flush()
        os.fsync(handle.fileno())
    if total < 4:
        raise BackupIntegrityError('Backup upload is malformed')
    return total


@admin_backup_blueprint.post('/admin/api/backups/upload')
@admin_required
@login_required
@step_up_required('backup.upload', 'upload')
def upload_backup():
    if _rate_limited('backup_upload', config.RATELIMIT_BACKUP_UPLOAD):
        return jsonify({'error': 'Too many backup upload requests'}), 429
    try:
        record = backup_operations.create(
            'uploaded_backup',
            current_user.id,
            _admin_session_id(),
            status='uploading',
        )
    except OperationBusyError:
        return jsonify({'error': _OPERATION_BUSY_MESSAGE}), 409

    try:
        size = _stream_upload(record.archive_path)
    except ValueError:
        backup_operations.remove(record.operation_id)
        return jsonify({'error': _UPLOAD_TOO_LARGE_MESSAGE}), 413
    except Exception:
        backup_operations.remove(record.operation_id)
        return jsonify({'error': 'Backup upload failed'}), 400

    username = current_user.username
    source_ip = request.remote_addr or 'unknown'
    log_security_event(
        'BACKUP_UPLOADED', user=username, ip=source_ip, size=size
    )

    def verify_worker(cancel_event):
        backup_operations.set_status(record.operation_id, 'verifying', size=size)
        try:
            with operation_lock():
                manifest = verify_backup(record.archive_path)
            if cancel_event.is_set():
                backup_operations.remove(record.operation_id)
                return
            summary = _archive_summary(manifest)
            backup_operations.set_status(
                record.operation_id,
                'verified',
                summary=summary,
                size=size,
                ttl=config.BACKUP_DOWNLOAD_TTL,
            )
            log_security_event(
                'BACKUP_VERIFICATION_SUCCEEDED',
                user=username,
                ip=source_ip,
                size=size,
                files=summary['file_count'],
            )
        except Exception as error:
            record.archive_path.unlink(missing_ok=True)
            backup_operations.set_status(
                record.operation_id,
                'failed',
                error='Backup verification failed',
                ttl=config.BACKUP_DOWNLOAD_TTL,
            )
            log_security_event(
                'BACKUP_VERIFICATION_FAILED',
                level=logging.WARNING,
                user=username,
                ip=source_ip,
                error_type=type(error).__name__,
            )

    try:
        current_app.extensions['runtime_lifecycle'].start_job(
            'web-backup-verify',
            verify_worker,
            owner_id=current_user.id,
        )
    except Exception:
        backup_operations.remove(record.operation_id)
        raise
    return jsonify(_operation_payload(record)), 202


@admin_backup_blueprint.post('/admin/api/backups/<operation_id>/cancel')
@admin_required
@login_required
@step_up_required('backup.cancel', lambda operation_id: operation_id)
def cancel_backup_operation(operation_id):
    try:
        record = backup_operations.get(
            operation_id, current_user.id, _admin_session_id()
        )
    except KeyError:
        return jsonify({'error': 'Backup operation not found'}), 404
    if record.status in {
        'pending', 'running', 'uploading', 'verifying', 'downloading',
        'restoring',
    }:
        return jsonify({'error': 'Active operation cannot be cancelled safely'}), 409
    backup_operations.remove(operation_id)
    return jsonify({'ok': True})


@admin_backup_blueprint.post(
    '/admin/api/backups/<operation_id>/restore/prepare'
)
@admin_required
@login_required
@step_up_required('backup.restore_prepare', lambda operation_id: operation_id)
def prepare_restore(operation_id):
    data = request.get_json(silent=True) or {}
    if data.get('acknowledge_sensitive_restore') is not True:
        return jsonify({'error': 'Restore acknowledgement is required'}), 400
    try:
        record = backup_operations.get(
            operation_id, current_user.id, _admin_session_id()
        )
    except KeyError:
        return jsonify({'error': 'Backup operation not found'}), 404
    if record.kind != 'uploaded_backup' or record.status != 'verified':
        return jsonify({'error': 'A verified upload is required'}), 409
    incompatible = _incompatible_restore_response(record)
    if incompatible is not None:
        return incompatible
    try:
        token = backup_operations.prepare_restore(
            operation_id, current_user.id, _admin_session_id()
        )
    except KeyError:
        return jsonify({'error': 'A verified upload is required'}), 409
    return jsonify({
        'confirmation_token': token,
        'confirmation_phrase': 'RESTORE',
        'warning': 'Restore replaces the current persistent state.',
    })


@admin_backup_blueprint.post('/admin/api/backups/<operation_id>/restore')
@admin_required
@login_required
@step_up_required('backup.restore', lambda operation_id: operation_id)
def restore_uploaded_backup(operation_id):
    if _rate_limited('backup_restore', config.RATELIMIT_BACKUP_RESTORE):
        return jsonify({'error': 'Too many restore attempts'}), 429
    data = request.get_json(silent=True) or {}
    if (
        data.get('confirm_destructive_restore') is not True
        or data.get('confirmation_phrase') != 'RESTORE'
    ):
        return jsonify({'error': 'Explicit restore confirmation is required'}), 400
    try:
        record = backup_operations.get(
            operation_id, current_user.id, _admin_session_id()
        )
    except KeyError:
        return jsonify({'error': 'Backup operation not found'}), 404
    incompatible = _incompatible_restore_response(record)
    if incompatible is not None:
        return incompatible
    try:
        record = backup_operations.begin_restore(
            operation_id,
            current_user.id,
            _admin_session_id(),
            data.get('confirmation_token'),
        )
    except KeyError:
        return jsonify({'error': 'Restore confirmation expired or invalid'}), 409

    username = current_user.username
    source_ip = request.remote_addr or 'unknown'
    log_security_event('RESTORE_STARTED', user=username, ip=source_ip)
    from .restore_service import start_restore
    start_restore(current_app._get_current_object(), socketio, record,
                  username, source_ip)
    return jsonify(_operation_payload(record)), 202


@admin_backup_blueprint.get('/admin/api/backups/restore/status')
@admin_required
@login_required
def restore_status():
    from .maintenance_mode import public_status

    return jsonify(public_status())
