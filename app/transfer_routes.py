"""Bounded HTTP routes for user-owned SFTP transfers."""

import posixpath
import re
import secrets
import shlex
import stat
import tempfile
import threading
import time
import unicodedata
from urllib.parse import quote
import zipfile
from pathlib import Path

from flask import Blueprint, Response, abort, jsonify, request, stream_with_context
from flask_login import current_user, login_required

import config
from . import sftp_handler
from .audit_logger import log_error, log_file_source_operation
from .file_sources import (
    FileCapability,
    FileSourceUnavailable,
    file_source_audit_identity,
    file_source_resolver,
)
from .file_service import file_service
from . import ssh_manager
from .quota_manager import QuotaKind, quota_manager
from .transfer_manager import InvalidTransferToken, TransferManager
from .runtime_lifecycle import RuntimeShuttingDown
from .remote_transfer import (
    RemoteTransferCancelled,
    RemoteTransferError,
    RemoteTransferLimitExceeded,
    TransferBudget,
)


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


def _transfer_capabilities(direction, *, archive=False):
    if direction == 'download':
        capabilities = [FileCapability.READ]
        if archive:
            capabilities.append(FileCapability.RECURSIVE)
        return tuple(capabilities)
    if direction == 'upload':
        return (FileCapability.WRITE,)
    raise FileSourceUnavailable()


def _resolve_transfer_source(record, user_id):
    source = None
    for capability in _transfer_capabilities(
        record.direction,
        archive=bool(record.metadata.get('archive')),
    ):
        source = file_service.resolve(record.source_id, user_id, capability)
    return source


def prepare_transfer(user_id, direction, source_id, remote_path, owner_sid=None,
                     archive=False):
    """Validate a socket control request before giving out a one-use token."""
    if (
        owner_sid is None
        or direction not in {'upload', 'download'}
    ):
        return None
    try:
        source = None
        for capability in _transfer_capabilities(
            direction,
            archive=bool(archive),
        ):
            source = file_service.resolve(source_id, user_id, capability)
        backend = _transfer_backend(source)
        if backend is None:
            safe_path = sftp_handler.sanitize_path(remote_path)
        else:
            safe_path = backend.normalize_path(remote_path)
        if safe_path is None or safe_path in {'', '.'}:
            return None
        source_holds = file_source_resolver.acquire_transfer_holds(
            user_id,
            (source_id,),
        )
        return transfer_manager.create(
            user_id=user_id,
            source_id=source_id,
            direction=direction,
            owner_sid=owner_sid,
            source_holds=source_holds,
            metadata={
                'remote_path': safe_path,
                'filename': posixpath.basename(safe_path),
                'archive': bool(archive),
            },
        )
    except (FileSourceUnavailable, RuntimeShuttingDown, ValueError):
        return None


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


def _transfer_backend(source):
    return getattr(source, 'backend', None)


def _audit_transfer_source(
    source,
    *,
    username,
    ip_address,
    operation,
    result,
    filename,
    size,
):
    result = str(result).upper()
    try:
        log_file_source_operation(
            username=username,
            operation=operation,
            result=result,
            filename=filename,
            size=size,
            ip_address=ip_address,
            **file_source_audit_identity(source),
        )
    except Exception as error:
        log_error(
            'File source transfer audit failed',
            operation=operation,
            result=result,
            exception_type=type(error).__name__,
        )


def _write_all_remote(remote_file, chunk):
    view = memoryview(chunk)
    offset = 0
    while offset < len(view):
        written = remote_file.write(view[offset:])
        if written is None:
            written = len(view) - offset
        if isinstance(written, bool) or not isinstance(written, int) or written <= 0:
            raise OSError('remote write made no progress')
        offset += written


def _upload_to_backend(
    source,
    remote_path,
    input_stream,
    *,
    chunk_size,
    max_bytes,
    cancel_event,
    cancelled,
    progress,
):
    transferred = 0
    backend = _transfer_backend(source)
    if backend is None:
        raise ValueError('resolved source has no backend')
    with backend.open_atomic_writer(
        source,
        remote_path,
        replace=False,
        cancel_event=cancel_event,
    ) as remote_file:
        while True:
            if cancelled():
                raise sftp_handler.TransferCancelled()
            chunk = input_stream.read(chunk_size)
            if not chunk:
                break
            transferred += len(chunk)
            if transferred > max_bytes:
                raise sftp_handler.UploadSizeExceeded()
            _write_all_remote(remote_file, chunk)
            progress(transferred)
        if cancelled():
            raise sftp_handler.TransferCancelled()
    return transferred


def _stream_download_chunks(remote_file, record, user_id, size):
    transferred = 0
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
    return transferred


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
    # This is deliberately repeated after token consumption. Ownership and
    # capabilities can change between the Socket control request and HTTP.
    try:
        source = _resolve_transfer_source(record, user_id)
    except FileSourceUnavailable:
        _unavailable(record, user_id)
    return record, user_id, source


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
                try:
                    record.release_source_holds()
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
    record, user_id, source = _consume(token, 'download')
    audit_username = current_user.username
    audit_ip = request.remote_addr
    finish = _request_finalizer(record, user_id)
    remote_path = record.metadata.get('remote_path')
    if not remote_path:
        _audit_transfer_source(
            source,
            username=audit_username,
            ip_address=audit_ip,
            operation='download',
            result='FAILED',
            filename=record.metadata.get('filename'),
            size=0,
        )
        finish('failed')
        abort(404)

    try:
        backend = _transfer_backend(source)
        if backend is None:
            with sftp_handler.sftp_session(source.handle_id) as (sftp, _source):
                size = sftp.stat(remote_path).st_size
        else:
            file_stat, error = backend.stat(
                source,
                remote_path,
                follow_links=False,
            )
            if error or not file_stat or file_stat.get('is_dir'):
                raise FolderUnavailable()
            size = int(file_stat.get('size', 0))
    except Exception:
        _audit_transfer_source(
            source,
            username=audit_username,
            ip_address=audit_ip,
            operation='download',
            result='FAILED',
            filename=record.metadata.get('filename'),
            size=0,
        )
        finish('failed')
        abort(404)
    if size > config.MAX_DOWNLOAD_SIZE:
        _audit_transfer_source(
            source,
            username=audit_username,
            ip_address=audit_ip,
            operation='download',
            result='LIMIT_EXCEEDED',
            filename=record.metadata.get('filename'),
            size=size,
        )
        finish('failed')
        return jsonify({'error': 'Transfer unavailable'}), 413

    def generate():
        outcome = 'failed'
        transferred = 0
        try:
            # Recheck directly before remote I/O because response iteration starts
            # after headers have been constructed.
            active_source = _resolve_transfer_source(record, user_id)
            backend = _transfer_backend(active_source)
            if backend is None:
                reader_context = sftp_handler.sftp_session(
                    active_source.handle_id
                )
                with reader_context as (sftp, _source):
                    with sftp.file(remote_path, 'rb') as remote_file:
                        transferred = yield from _stream_download_chunks(
                            remote_file, record, user_id, size
                        )
            else:
                with backend.open_reader(
                    active_source,
                    remote_path,
                ) as remote_file:
                    transferred = yield from _stream_download_chunks(
                        remote_file, record, user_id, size
                    )
            outcome = 'completed'
        except (GeneratorExit, TransferCancelled):
            outcome = 'cancelled'
            raise
        except Exception as error:
            log_error('HTTP download failed', user_id=user_id,
                      exception_type=type(error).__name__)
            raise
        finally:
            _audit_transfer_source(
                source,
                username=audit_username,
                ip_address=audit_ip,
                operation='download',
                result=outcome,
                filename=record.metadata['filename'],
                size=transferred,
            )
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
    zip_member = f'./{folder_name}' if folder_name.startswith('-') else folder_name
    # The remote target is random and created under umask 077, then mode 0600.
    archive_path = (
        f'/tmp/webssh_{secrets.token_hex(16)}.zip'  # nosec B108
    )
    parent = posixpath.dirname(remote_path.rstrip('/')) or '/'
    command = (
        f'umask 077 && cd {shlex.quote(parent)} && '
        f'zip -r -q {shlex.quote(archive_path)} {shlex.quote(zip_member)} && '
        f'chmod 600 {shlex.quote(archive_path)}'
    )
    transport = ssh_client.get_transport()
    if transport is None:
        return None
    channel = ssh_manager._open_exec_channel(
        transport,
        command,
        timeout=config.SSH_CONNECT_TIMEOUT,
    )
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


def _build_backend_zip_to_disk(
    source,
    remote_folder,
    folder_name,
    *,
    cancel_event,
    max_bytes,
    chunk_size,
    temp_dir,
):
    """Build a bounded local ZIP through only the FileBackend contract."""
    temp_directory = Path(temp_dir)
    temp_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = tempfile.NamedTemporaryFile(
        suffix='.zip',
        delete=False,
        dir=temp_directory,
    )
    archive_path = Path(temporary.name)
    temporary.close()
    archive_path.chmod(0o600)
    budget = TransferBudget(
        max_bytes=max_bytes,
        max_members=config.MAX_TRANSFER_MEMBERS,
    )
    root = remote_folder.rstrip('/')

    try:
        entries = list(source.backend.iter_tree(
            source,
            remote_folder,
            budget=budget,
            cancel_event=cancel_event,
            follow_links=False,
        ))
        if any(entry.get('is_symlink') for entry in entries):
            raise RemoteTransferError('Reparse points are not supported')
        declared_total = 0
        for entry in entries:
            if entry.get('is_dir'):
                continue
            size = int(entry.get('size', 0))
            if size < 0:
                raise RemoteTransferLimitExceeded('Invalid remote file size')
            declared_total += size
            if declared_total > max_bytes:
                raise RemoteTransferLimitExceeded(
                    'Folder exceeds transfer size limit'
                )

        transferred = 0
        with zipfile.ZipFile(
            archive_path,
            'w',
            zipfile.ZIP_DEFLATED,
            compresslevel=6,
        ) as archive:
            for entry in entries:
                if cancel_event.is_set():
                    raise RemoteTransferCancelled('Transfer cancelled')
                entry_path = entry.get('path')
                if (
                    not isinstance(entry_path, str)
                    or not entry_path.startswith(root + '/')
                ):
                    raise RemoteTransferError('Unsafe recursive source path')
                relative = entry_path[len(root) + 1:]
                archive_name = posixpath.join(folder_name, relative)
                if entry.get('is_dir'):
                    archive.writestr(archive_name.rstrip('/') + '/', b'')
                    continue
                with source.backend.open_reader(source, entry_path) as reader:
                    with archive.open(archive_name, 'w') as archive_member:
                        while True:
                            if cancel_event.is_set():
                                raise RemoteTransferCancelled(
                                    'Transfer cancelled'
                                )
                            chunk = reader.read(chunk_size)
                            if not chunk:
                                break
                            transferred += len(chunk)
                            if transferred > max_bytes:
                                raise RemoteTransferLimitExceeded(
                                    'Folder exceeds transfer size limit'
                                )
                            archive_member.write(chunk)
                if archive_path.stat().st_size > max_bytes:
                    raise RemoteTransferLimitExceeded(
                        'Archive exceeds transfer size limit'
                    )
        if archive_path.stat().st_size > max_bytes:
            raise RemoteTransferLimitExceeded(
                'Archive exceeds transfer size limit'
            )
        return archive_path
    except Exception:
        archive_path.unlink(missing_ok=True)
        raise


@transfer_blueprint.route('/api/transfers/<token>/folder-download', methods=['GET'])
@login_required
def download_folder_transfer(token):
    """Download a directory without routing archive bytes through Socket.IO."""
    record, user_id, source = _consume(token, 'download')
    audit_username = current_user.username
    audit_ip = request.remote_addr
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
                with sftp_handler.sftp_session(source.handle_id) as (sftp, _source):
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
        _audit_transfer_source(
            source,
            username=audit_username,
            ip_address=audit_ip,
            operation='folder_download',
            result='FAILED',
            filename=f'{folder_name}.zip',
            size=0,
        )
        finish('failed')
        abort(404)

    try:
        backend = _transfer_backend(source)
        if backend is not None:
            remote_stat, stat_error = backend.stat(
                source,
                remote_path,
                follow_links=False,
            )
            if (
                stat_error
                or remote_stat is None
                or not remote_stat.get('is_dir')
                or remote_stat.get('is_symlink')
            ):
                raise FolderUnavailable()
            temp_reservation = quota_manager.reserve(
                QuotaKind.TEMP_BYTES,
                user_id,
                config.MAX_ZIP_DOWNLOAD_SIZE,
            )
            try:
                local_archive = _build_backend_zip_to_disk(
                    source,
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
        else:
            with sftp_handler.sftp_session(source.handle_id) as (sftp, _source):
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
                            sftp_handler.get_ssh_client(source.handle_id),
                            remote_path,
                            record.cancel_event,
                        )
                    except (
                        sftp_handler.TransferSizeExceeded,
                        sftp_handler.TransferMemberLimitExceeded,
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
        _audit_transfer_source(
            source, username=audit_username, ip_address=audit_ip,
            operation='folder_download', result='FAILED',
            filename=f'{folder_name}.zip', size=0,
        )
        finish('failed')
        abort(404)
    except (
        sftp_handler.TransferSizeExceeded,
        sftp_handler.TransferMemberLimitExceeded,
        RemoteTransferLimitExceeded,
    ):
        _audit_transfer_source(
            source, username=audit_username, ip_address=audit_ip,
            operation='folder_download', result='LIMIT_EXCEEDED',
            filename=f'{folder_name}.zip', size=0,
        )
        finish('failed')
        return jsonify({'error': 'Transfer unavailable'}), 413
    except (sftp_handler.TransferCancelled, RemoteTransferCancelled):
        _audit_transfer_source(
            source, username=audit_username, ip_address=audit_ip,
            operation='folder_download', result='CANCELLED',
            filename=f'{folder_name}.zip', size=0,
        )
        finish('cancelled')
        return jsonify({'error': 'Transfer unavailable'}), 409
    except RemoteTransferError:
        _audit_transfer_source(
            source, username=audit_username, ip_address=audit_ip,
            operation='folder_download', result='FAILED',
            filename=f'{folder_name}.zip', size=0,
        )
        finish('failed')
        return jsonify({'error': 'Transfer unavailable'}), 500
    except Exception as error:
        log_error('Folder download preparation failed', user_id=user_id,
                  exception_type=type(error).__name__)
        _audit_transfer_source(
            source, username=audit_username, ip_address=audit_ip,
            operation='folder_download', result='FAILED',
            filename=f'{folder_name}.zip', size=0,
        )
        finish('failed')
        return jsonify({'error': 'Transfer unavailable'}), 500

    def generate():
        outcome = 'failed'
        transferred = 0
        try:
            if remote_archive is not None:
                active_source = _resolve_transfer_source(record, user_id)
                with sftp_handler.sftp_session(active_source.handle_id) as (sftp, _source):
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
        except (GeneratorExit, sftp_handler.TransferCancelled):
            outcome = 'cancelled'
            raise
        except Exception as error:
            log_error('Folder download stream failed', user_id=user_id,
                      exception_type=type(error).__name__)
            raise
        finally:
            _audit_transfer_source(
                source,
                username=audit_username,
                ip_address=audit_ip,
                operation='folder_download',
                result=outcome,
                filename=f'{folder_name}.zip',
                size=transferred,
            )
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
    record, user_id, source = _consume(token, 'upload')
    audit_username = current_user.username
    audit_ip = request.remote_addr
    try:
        if (
            request.content_length is None
            or request.content_length > config.MAX_UPLOAD_SIZE
        ):
            _audit_transfer_source(
                source, username=audit_username, ip_address=audit_ip,
                operation='upload', result='LIMIT_EXCEEDED',
                filename=record.metadata.get('filename'), size=0,
            )
            _terminalize(record, user_id, 'failed')
            return jsonify({'error': 'Transfer unavailable'}), 413

        transferred = 0
        try:
            active_source = _resolve_transfer_source(record, user_id)
            if _transfer_backend(active_source) is None:
                transferred = sftp_handler.upload_request_stream(
                    active_source.handle_id,
                    record.metadata['remote_path'],
                    request.stream,
                    chunk_size=TRANSFER_CHUNK_SIZE,
                    max_bytes=config.MAX_UPLOAD_SIZE,
                    cancelled=record.cancel_event.is_set,
                    progress=lambda count: _emit_upload_progress(
                        record, user_id, count
                    ),
                )
            else:
                transferred = _upload_to_backend(
                    active_source,
                    record.metadata['remote_path'],
                    request.stream,
                    chunk_size=TRANSFER_CHUNK_SIZE,
                    max_bytes=config.MAX_UPLOAD_SIZE,
                    cancel_event=record.cancel_event,
                    cancelled=record.cancel_event.is_set,
                    progress=lambda count: _emit_upload_progress(
                        record, user_id, count
                    ),
                )
        except sftp_handler.TransferCancelled:
            _audit_transfer_source(
                source, username=audit_username, ip_address=audit_ip,
                operation='upload', result='CANCELLED',
                filename=record.metadata.get('filename'), size=transferred,
            )
            _terminalize(record, user_id, 'cancelled')
            return jsonify({'error': 'Transfer unavailable'}), 409
        except sftp_handler.UploadSizeExceeded:
            _audit_transfer_source(
                source, username=audit_username, ip_address=audit_ip,
                operation='upload', result='LIMIT_EXCEEDED',
                filename=record.metadata.get('filename'), size=transferred,
            )
            _terminalize(record, user_id, 'failed')
            return jsonify({'error': 'Transfer unavailable'}), 413
        except Exception as error:
            log_error('HTTP upload failed', user_id=user_id,
                      exception_type=type(error).__name__)
            _audit_transfer_source(
                source, username=audit_username, ip_address=audit_ip,
                operation='upload', result='FAILED',
                filename=record.metadata.get('filename'), size=transferred,
            )
            _terminalize(record, user_id, 'failed')
            return jsonify({'error': 'Transfer unavailable'}), 500

        if not _terminalize(record, user_id, 'completed'):
            return jsonify({'error': 'Transfer unavailable'}), 500
        _audit_transfer_source(
            source,
            username=audit_username,
            ip_address=audit_ip,
            operation='upload',
            result='COMPLETED',
            filename=record.metadata['filename'],
            size=transferred,
        )
        return jsonify({'success': True}), 200
    finally:
        try:
            record.release_source_holds()
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
