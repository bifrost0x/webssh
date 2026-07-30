"""Bounded HTTP routes for user-owned SFTP transfers."""

import os
import posixpath
import re
import secrets
import shlex
import stat
import threading
import time
import unicodedata
from urllib.parse import quote

from flask import Blueprint, Response, abort, jsonify, request, stream_with_context
from flask_login import current_user, login_required

import config
from . import connection_pool, sftp_handler
from .audit_logger import log_error, log_file_download, log_file_upload
from .models import SSHSession
from . import ssh_manager
from .quota_manager import QuotaKind, quota_manager
from .transfer_manager import InvalidTransferToken, TransferManager
from .runtime_lifecycle import RuntimeShuttingDown


TRANSFER_CHUNK_SIZE = config.CHUNK_SIZE
transfer_blueprint = Blueprint('transfers', __name__)
# This manager intentionally lives for the worker lifetime.  A request-local
# instance would make one-use tokens and reservations meaningless.
transfer_manager = TransferManager()


class DownloadLimitExceeded(RuntimeError):
    """The remote file exceeded its configured download limit while streaming."""


class TransferCancelled(RuntimeError):
    """The record was cancelled while a request was in flight."""


class FolderUnavailable(RuntimeError):
    """A folder transfer target is not a readable directory."""


def _current_user_id():
    return str(current_user.id)


def session_is_owned(session_id, user_id):
    """Fail closed for both normal SSH sessions and Quick Connections."""
    if not session_id or user_id is None:
        return False
    user_id = str(user_id)
    with ssh_manager.sessions_lock:
        session = ssh_manager.sessions.get(session_id)
        if session is not None and session.get('user_id') is not None:
            return str(session['user_id']) == user_id
    persisted = SSHSession.query.filter_by(session_id=session_id).first()
    if persisted is not None:
        return str(persisted.user_id) == user_id
    connection = connection_pool.temp_connection_pool.get_connection_info(session_id)
    return bool(connection and str(connection.get('user_id')) == user_id)


def prepare_transfer(user_id, direction, session_id, remote_path, owner_sid=None,
                     archive=False):
    """Validate a socket control request before giving out a one-use token."""
    if (
        owner_sid is None
        or direction not in {'upload', 'download'}
        or not session_is_owned(session_id, user_id)
    ):
        return None
    safe_path = sftp_handler.sanitize_path(remote_path)
    if safe_path is None or safe_path in {'', '.'}:
        return None
    return transfer_manager.create(
        user_id=user_id,
        session_id=session_id,
        direction=direction,
        owner_sid=owner_sid,
        metadata={
            'remote_path': safe_path,
            'filename': posixpath.basename(safe_path),
            'archive': bool(archive),
        },
    )


def read_bounded_remote(remote_file, *, chunk_size, max_bytes, cancelled=None):
    """Yield fixed-size remote reads, enforcing a limit even after ``stat``."""
    total = 0
    while True:
        if cancelled and cancelled():
            raise TransferCancelled()
        chunk = remote_file.read(chunk_size)
        if not chunk:
            return
        total += len(chunk)
        if total > max_bytes:
            raise DownloadLimitExceeded()
        yield chunk


def _unavailable(record=None, user_id=None):
    if record is not None and user_id is not None:
        try:
            transfer_manager.fail(record.transfer_id, user_id)
        except Exception as error:
            log_error('Failed to release transfer reservation',
                      exception_type=type(error).__name__)
    abort(404)


def _consume(token, expected_direction):
    user_id = _current_user_id()
    try:
        record = transfer_manager.consume_token(token, user_id)
    except (InvalidTransferToken, RuntimeShuttingDown):
        _unavailable()
    if record.direction != expected_direction:
        _unavailable(record, user_id)
    # This is deliberately repeated after token consumption.  Session ownership
    # can change between the socket preparation request and the HTTP request.
    if not session_is_owned(record.session_id, user_id):
        _unavailable(record, user_id)
    return record, user_id


def _terminalize(record, user_id, outcome, manager=None):
    """Ask the manager for precisely one terminal state; it releases once."""
    manager = transfer_manager if manager is None else manager
    previous_attempt_raised = False
    for attempt in range(2):
        try:
            if outcome == 'completed':
                transitioned = manager.complete(
                    record.transfer_id, user_id
                )
            elif outcome == 'cancelled':
                transitioned = manager.cancel(
                    record.transfer_id, user_id
                )
            else:
                transitioned = manager.fail(
                    record.transfer_id, user_id
                )
            if not transitioned:
                return previous_attempt_raised
            break
        except Exception as error:
            previous_attempt_raised = True
            log_error('Failed to finalize transfer',
                      exception_type=type(error).__name__, attempt=attempt + 1)
    else:
        return False
    from . import socketio
    socketio.emit('transfer_finished', {
        'transfer_id': record.transfer_id,
        'direction': record.direction,
        'status': outcome,
    }, room=f'user_{user_id}')
    return True


def _request_finalizer(record, user_id, cleanup=None):
    """Return an idempotent finalizer for every post-consumption exit path."""
    state_lock = threading.Lock()
    finished = False

    def finish(outcome):
        nonlocal finished
        with state_lock:
            if finished:
                return
            finished = True
        try:
            if cleanup is not None:
                cleanup()
        finally:
            try:
                _terminalize(record, user_id, outcome)
            finally:
                record.request_done_event.set()

    return finish


def _content_disposition(filename):
    original = str(filename).rsplit('/', 1)[-1] or 'download'
    normalized = unicodedata.normalize('NFKD', original)
    ascii_name = normalized.encode('ascii', 'ignore').decode('ascii')
    ascii_name = ''.join(
        '' if ord(character) < 32 or ord(character) == 127
        else character if re.match(r'[A-Za-z0-9._ -]', character)
        else '_'
        for character in ascii_name
    ) or 'download'
    return (
        f'attachment; filename="{ascii_name}"; '
        f"filename*=UTF-8''{quote(original, safe='')}"
    )


@transfer_blueprint.route('/api/transfers/<token>/download', methods=['GET'])
@login_required
def download_transfer(token):
    record, user_id = _consume(token, 'download')
    finish = _request_finalizer(record, user_id)
    remote_path = record.metadata.get('remote_path')
    if not remote_path:
        finish('failed')
        abort(404)

    # Validate ownership before headers and before touching the remote endpoint.
    if not session_is_owned(record.session_id, user_id):
        finish('failed')
        abort(404)
    try:
        with sftp_handler.sftp_session(record.session_id) as (sftp, _source):
            size = sftp.stat(remote_path).st_size
    except Exception:
        finish('failed')
        abort(404)
    if size > config.MAX_DOWNLOAD_SIZE:
        finish('failed')
        return jsonify({'error': 'Transfer unavailable'}), 413

    def generate():
        outcome = 'failed'
        transferred = 0
        try:
            # Recheck directly before remote I/O because response iteration starts
            # after headers have been constructed.
            if not session_is_owned(record.session_id, user_id):
                return
            with sftp_handler.sftp_session(record.session_id) as (sftp, _source):
                with sftp.file(remote_path, 'rb') as remote_file:
                    for chunk in read_bounded_remote(
                        remote_file,
                        chunk_size=TRANSFER_CHUNK_SIZE,
                        max_bytes=config.MAX_DOWNLOAD_SIZE,
                        cancelled=record.cancel_event.is_set,
                    ):
                        transferred += len(chunk)
                        from . import socketio
                        socketio.emit('transfer_progress', {
                            'transfer_id': record.transfer_id,
                            'direction': 'download',
                            'transferred': transferred,
                            'total': size,
                        }, room=f'user_{user_id}')
                        yield chunk
            outcome = 'completed'
            log_file_download(
                current_user.username, target_host='via-sftp',
                filename=record.metadata['filename'], size=transferred,
                success=True, ip_address=request.remote_addr,
            )
        except (GeneratorExit, TransferCancelled):
            outcome = 'cancelled'
            raise
        except Exception as error:
            log_error('HTTP download failed', user_id=user_id,
                      exception_type=type(error).__name__)
        finally:
            finish(outcome)

    response = Response(stream_with_context(generate()), mimetype='application/octet-stream')
    response.headers['Content-Disposition'] = _content_disposition(record.metadata['filename'])
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.call_on_close(lambda: finish('cancelled'))
    return response


def _remote_zip_path(sftp, ssh_client, remote_path, cancel_event=None):
    """Create a ZIP beside no user data and return its remote path and size."""
    if ssh_client is None:
        return None
    folder_name = posixpath.basename(remote_path.rstrip('/')) or 'download'
    archive_path = f'/tmp/{folder_name}_{secrets.token_hex(8)}.zip'
    parent = posixpath.dirname(remote_path.rstrip('/')) or '/'
    command = (
        f'umask 077 && cd {shlex.quote(parent)} && '
        f'zip -r -q {shlex.quote(archive_path)} {shlex.quote(folder_name)} && '
        f'chmod 600 {shlex.quote(archive_path)}'
    )
    _stdin, stdout, _stderr = ssh_client.exec_command(command)
    channel = stdout.channel
    channel.settimeout(300)
    if hasattr(channel, 'exit_status_ready'):
        deadline = time.monotonic() + 300
        while not channel.exit_status_ready():
            if cancel_event is not None and cancel_event.wait(0.1):
                channel.close()
                try:
                    sftp.remove(archive_path)
                except Exception:
                    pass
                raise sftp_handler.TransferCancelled()
            if time.monotonic() >= deadline:
                channel.close()
                try:
                    sftp.remove(archive_path)
                except Exception:
                    pass
                raise sftp_handler.SFTPOperationError(
                    'remote ZIP command timed out'
                )
    if channel.recv_exit_status() != 0:
        try:
            sftp.remove(archive_path)
        except Exception:
            pass
        return None
    try:
        size = sftp.stat(archive_path).st_size
    except Exception:
        try:
            sftp.remove(archive_path)
        except Exception:
            pass
        raise
    if size > config.MAX_ZIP_DOWNLOAD_SIZE:
        try:
            sftp.remove(archive_path)
        except Exception:
            pass
        raise sftp_handler.TransferSizeExceeded()
    return archive_path, size


@transfer_blueprint.route('/api/transfers/<token>/folder-download', methods=['GET'])
@login_required
def download_folder_transfer(token):
    """Download a directory without routing archive bytes through Socket.IO."""
    record, user_id = _consume(token, 'download')
    metadata = record.metadata
    remote_path = metadata.get('remote_path', '')
    folder_name = posixpath.basename(remote_path.rstrip('/')) or 'download'
    remote_archive = None
    archive_size = None
    local_archive = None
    temp_reservation = None

    def cleanup_resources():
        if remote_archive is not None:
            try:
                with sftp_handler.sftp_session(record.session_id) as (sftp, _source):
                    sftp.remove(remote_archive)
            except Exception as error:
                log_error('Remote ZIP cleanup failed', user_id=user_id,
                          exception_type=type(error).__name__)
        if local_archive is not None:
            try:
                local_archive.unlink(missing_ok=True)
            except Exception as error:
                log_error('Local ZIP cleanup failed', user_id=user_id,
                          exception_type=type(error).__name__)
        if temp_reservation is not None:
            try:
                temp_reservation.release()
            except Exception as error:
                log_error('Temporary quota release failed', user_id=user_id,
                          exception_type=type(error).__name__)

    finish = _request_finalizer(record, user_id, cleanup_resources)
    if not metadata.get('archive') or not remote_path:
        finish('failed')
        abort(404)

    try:
        with sftp_handler.sftp_session(record.session_id) as (sftp, _source):
            remote_stat = sftp.stat(remote_path)
            if not stat.S_ISDIR(remote_stat.st_mode):
                raise FolderUnavailable()
            _declared_size, has_symlink = sftp_handler.inspect_remote_tree(
                sftp,
                remote_path,
                cancel_event=record.cancel_event,
                max_bytes=config.MAX_ZIP_DOWNLOAD_SIZE,
            )
            remote_result = None
            if not has_symlink:
                try:
                    remote_result = _remote_zip_path(
                        sftp,
                        sftp_handler.get_ssh_client(record.session_id),
                        remote_path,
                        record.cancel_event,
                    )
                except (
                    sftp_handler.TransferSizeExceeded,
                    sftp_handler.TransferCancelled,
                ):
                    raise
                except Exception:
                    remote_result = None
            if remote_result is not None:
                remote_archive, archive_size = remote_result
            else:
                temp_reservation = quota_manager.reserve(
                    QuotaKind.TEMP_BYTES,
                    user_id,
                    config.MAX_ZIP_DOWNLOAD_SIZE,
                )
                try:
                    local_archive = sftp_handler.build_fallback_zip_to_disk(
                        sftp,
                        remote_path,
                        folder_name,
                        cancel_event=record.cancel_event,
                        max_bytes=config.MAX_ZIP_DOWNLOAD_SIZE,
                        chunk_size=TRANSFER_CHUNK_SIZE,
                        temp_dir=config.TRANSFER_TEMP_DIR,
                    )
                    archive_size = local_archive.stat().st_size
                except Exception:
                    try:
                        if local_archive is not None:
                            local_archive.unlink(missing_ok=True)
                    finally:
                        temp_reservation.release()
                        temp_reservation = None
                    raise
    except FolderUnavailable:
        finish('failed')
        abort(404)
    except sftp_handler.TransferSizeExceeded:
        finish('failed')
        return jsonify({'error': 'Transfer unavailable'}), 413
    except sftp_handler.TransferCancelled:
        finish('cancelled')
        return jsonify({'error': 'Transfer unavailable'}), 409
    except Exception as error:
        log_error('Folder download preparation failed', user_id=user_id,
                  exception_type=type(error).__name__)
        finish('failed')
        return jsonify({'error': 'Transfer unavailable'}), 500

    def generate():
        outcome = 'failed'
        transferred = 0
        try:
            if remote_archive is not None:
                with sftp_handler.sftp_session(record.session_id) as (sftp, _source):
                    with sftp.file(remote_archive, 'rb') as remote_file:
                        for chunk in sftp_handler.stream_remote_zip(
                            remote_file,
                            cancel_event=record.cancel_event,
                            max_bytes=config.MAX_ZIP_DOWNLOAD_SIZE,
                            chunk_size=TRANSFER_CHUNK_SIZE,
                        ):
                            transferred += len(chunk)
                            _emit_download_progress(
                                record, user_id, transferred, archive_size
                            )
                            yield chunk
            else:
                with open(local_archive, 'rb') as archive:
                    while True:
                        if record.cancel_event.is_set():
                            raise sftp_handler.TransferCancelled()
                        chunk = archive.read(TRANSFER_CHUNK_SIZE)
                        if not chunk:
                            break
                        transferred += len(chunk)
                        _emit_download_progress(
                            record, user_id, transferred, archive_size
                        )
                        yield chunk
            outcome = 'completed'
            log_file_download(
                current_user.username,
                target_host='via-sftp-folder',
                filename=f'{folder_name}.zip',
                size=transferred,
                success=True,
                ip_address=request.remote_addr,
            )
        except (GeneratorExit, sftp_handler.TransferCancelled):
            outcome = 'cancelled'
            raise
        except Exception as error:
            log_error('Folder download stream failed', user_id=user_id,
                      exception_type=type(error).__name__)
        finally:
            finish(outcome)

    response = Response(
        stream_with_context(generate()), mimetype='application/zip'
    )
    response.headers['Content-Disposition'] = _content_disposition(
        f'{folder_name}.zip'
    )
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.call_on_close(lambda: finish('cancelled'))
    return response


@transfer_blueprint.route('/api/transfers/<token>/upload', methods=['POST'])
@login_required
def upload_transfer(token):
    record, user_id = _consume(token, 'upload')
    try:
        if not session_is_owned(record.session_id, user_id):
            _unavailable(record, user_id)
        if (
            request.content_length is None
            or request.content_length > config.MAX_UPLOAD_SIZE
        ):
            _terminalize(record, user_id, 'failed')
            return jsonify({'error': 'Transfer unavailable'}), 413

        transferred = 0
        try:
            transferred = sftp_handler.upload_request_stream(
                record.session_id,
                record.metadata['remote_path'],
                request.stream,
                chunk_size=TRANSFER_CHUNK_SIZE,
                max_bytes=config.MAX_UPLOAD_SIZE,
                cancelled=record.cancel_event.is_set,
                progress=lambda count: _emit_upload_progress(
                    record, user_id, count
                ),
            )
        except sftp_handler.TransferCancelled:
            _terminalize(record, user_id, 'cancelled')
            return jsonify({'error': 'Transfer unavailable'}), 409
        except sftp_handler.UploadSizeExceeded:
            _terminalize(record, user_id, 'failed')
            return jsonify({'error': 'Transfer unavailable'}), 413
        except Exception as error:
            log_error('HTTP upload failed', user_id=user_id,
                      exception_type=type(error).__name__)
            _terminalize(record, user_id, 'failed')
            return jsonify({'error': 'Transfer unavailable'}), 500

        if not _terminalize(record, user_id, 'completed'):
            return jsonify({'error': 'Transfer unavailable'}), 500
        log_file_upload(
            current_user.username, target_host='via-sftp',
            filename=record.metadata['filename'], size=transferred,
            success=True, ip_address=request.remote_addr,
        )
        return jsonify({'success': True}), 200
    finally:
        record.request_done_event.set()


def _emit_upload_progress(record, user_id, transferred):
    from . import socketio
    socketio.emit('transfer_progress', {
        'transfer_id': record.transfer_id,
        'direction': 'upload',
        'transferred': transferred,
        'total': request.content_length,
    }, room=f'user_{user_id}')


def _emit_download_progress(record, user_id, transferred, total):
    from . import socketio
    socketio.emit('transfer_progress', {
        'transfer_id': record.transfer_id,
        'direction': 'download',
        'transferred': transferred,
        'total': total,
    }, room=f'user_{user_id}')
