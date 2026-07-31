import os
import stat
import posixpath
import secrets
import tempfile
import zipfile
from pathlib import Path
from threading import Lock
from contextlib import contextmanager
from paramiko import SFTPClient
from paramiko.message import Message
from paramiko.sftp import (
    CMD_CLOSE,
    CMD_HANDLE,
    CMD_NAME,
    CMD_OPENDIR,
    CMD_READDIR,
    SFTPError,
)
from paramiko.sftp_attr import SFTPAttributes
import config
from . import ssh_manager
from .audit_logger import log_info, log_warning, log_error, log_debug

_sftp_cache = {}
_sftp_cache_lock = Lock()

_sftp_session_locks = {}
_sftp_session_locks_lock = Lock()

def _get_sftp_lock(session_id):
    """Get or create a per-session lock for serializing SFTP operations."""
    with _sftp_session_locks_lock:
        if session_id not in _sftp_session_locks:
            _sftp_session_locks[session_id] = Lock()
        return _sftp_session_locks[session_id]

def _cleanup_sftp_lock(session_id):
    """Remove the per-session lock when session is closed."""
    with _sftp_session_locks_lock:
        _sftp_session_locks.pop(session_id, None)

@contextmanager
def sftp_session(identifier):
    """Context manager: acquire per-session lock and provide SFTP client.

    Ensures only one execution context uses the cached SFTPClient at a time,
    preventing Paramiko's internal request/response queue corruption.

    Usage:
        with sftp_session(session_id) as (sftp, source_type):
            files = sftp.listdir_attr(path)

    Raises SFTPOperationError if no connection is available.
    """
    lock = _get_sftp_lock(identifier)
    lock.acquire()
    try:
        sftp, error, source_type = get_any_sftp_client(identifier)
        if error:
            raise SFTPOperationError(error)
        yield sftp, source_type
    finally:
        lock.release()

class SFTPOperationError(Exception):
    """Raised when an SFTP operation cannot be performed (no connection, etc.)."""
    pass


class UploadSizeExceeded(SFTPOperationError):
    """The streamed upload exceeded its configured byte limit."""


class TransferCancelled(SFTPOperationError):
    """A caller cancelled a streamed SFTP operation."""


class TransferSizeExceeded(SFTPOperationError):
    """A streamed SFTP operation exceeded its configured byte limit."""


class TransferMemberLimitExceeded(SFTPOperationError):
    """A recursive SFTP operation exceeded its entry-count limit."""


class _TransferMemberBudget:
    def __init__(self, limit):
        if type(limit) is not int or limit < 1:
            raise ValueError('transfer member limit must be a positive integer')
        self.limit = limit
        self.used = 0

    def consume(self):
        self.used += 1
        if self.used > self.limit:
            raise TransferMemberLimitExceeded()


def _iter_paramiko_directory_entries(sftp, remote_path):
    """Stream one directory and always close its remote SFTP handle."""
    adjusted_path = sftp._adjust_cwd(remote_path)
    sftp._log(10, f'listdir({adjusted_path!r})')
    response_type, message = sftp._request(CMD_OPENDIR, adjusted_path)
    if response_type != CMD_HANDLE:
        raise SFTPError('Expected handle')
    handle = message.get_binary()
    try:
        while True:
            try:
                response_type, message = sftp._request(CMD_READDIR, handle)
            except EOFError:
                return
            if response_type != CMD_NAME:
                raise SFTPError('Expected name response')
            for _index in range(message.get_int()):
                filename = message.get_text()
                longname = message.get_text()
                attributes = SFTPAttributes._from_msg(
                    message, filename, longname
                )
                if filename not in ('.', '..'):
                    yield attributes
    finally:
        try:
            sftp._request(CMD_CLOSE, handle)
        except Exception as error:
            try:
                sftp.close()
            except Exception:
                pass
            log_warning(
                'SFTP directory handle close failed; channel closed',
                exception_type=type(error).__name__,
            )


@contextmanager
def _directory_entries(sftp, remote_path):
    if isinstance(sftp, SFTPClient):
        iterator = _iter_paramiko_directory_entries(sftp, remote_path)
    else:
        factory = getattr(sftp, 'listdir_iter', None)
        iterator = (
            factory(remote_path)
            if callable(factory)
            else iter(sftp.listdir_attr(remote_path))
        )
    try:
        yield iterator
    finally:
        close = getattr(iterator, 'close', None)
        if callable(close):
            close()


def _is_cancelled(cancel_event):
    return cancel_event is not None and cancel_event.is_set()


def copy_sftp_stream(source, destination, *, cancel_event, max_bytes,
                     chunk_size, progress=None):
    """Copy between file-like objects without an unbounded read."""
    transferred = 0
    while True:
        if _is_cancelled(cancel_event):
            raise TransferCancelled()
        chunk = source.read(chunk_size)
        if not chunk:
            return transferred
        next_size = transferred + len(chunk)
        if next_size > max_bytes:
            raise TransferSizeExceeded()
        destination.write(chunk)
        transferred = next_size
        if progress:
            progress(transferred)
        if _is_cancelled(cancel_event):
            raise TransferCancelled()


def stream_remote_zip(remote_file, *, cancel_event, max_bytes, chunk_size):
    """Yield a remotely generated ZIP in bounded chunks."""
    transferred = 0
    while True:
        if _is_cancelled(cancel_event):
            raise TransferCancelled()
        chunk = remote_file.read(chunk_size)
        if not chunk:
            return
        transferred += len(chunk)
        if transferred > max_bytes:
            raise TransferSizeExceeded()
        yield chunk


def inspect_remote_tree(sftp, remote_folder, *, cancel_event, max_bytes,
                        max_members=None, depth=0, _member_budget=None):
    """Validate archive entry names and bound declared uncompressed bytes."""
    if _member_budget is None:
        _member_budget = _TransferMemberBudget(
            config.MAX_TRANSFER_MEMBERS if max_members is None else max_members
        )
    if depth > 50:
        raise SFTPOperationError('maximum directory depth exceeded')
    if _is_cancelled(cancel_event):
        raise TransferCancelled()
    total = 0
    has_symlink = False
    with _directory_entries(sftp, remote_folder) as entries:
        for entry in entries:
            _member_budget.consume()
            name = entry.filename
            if (
                not isinstance(name, str)
                or name in {'', '.', '..'}
                or '/' in name
                or '\\' in name
                or '\x00' in name
            ):
                raise SFTPOperationError('unsafe archive entry name')
            path = posixpath.join(remote_folder, name)
            try:
                entry_stat = sftp.lstat(path)
            except Exception:
                entry_stat = entry
            if stat.S_ISLNK(entry_stat.st_mode):
                has_symlink = True
                continue
            if stat.S_ISDIR(entry_stat.st_mode):
                child_total, child_symlink = inspect_remote_tree(
                    sftp,
                    path,
                    cancel_event=cancel_event,
                    max_bytes=max_bytes - total,
                    max_members=max_members,
                    depth=depth + 1,
                    _member_budget=_member_budget,
                )
                total += child_total
                has_symlink = has_symlink or child_symlink
            else:
                total += getattr(entry_stat, 'st_size', 0) or 0
            if total > max_bytes:
                raise TransferSizeExceeded()
    return total, has_symlink


def build_fallback_zip_to_disk(sftp, remote_folder, folder_name, *,
                               cancel_event, max_bytes, chunk_size,
                               max_members=None, temp_dir=None, progress=None):
    """Build a ZIP on disk while bounding every remote read and total input."""
    if temp_dir is not None:
        temp_dir = Path(temp_dir)
        temp_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(temp_dir, 0o700)
    temporary = tempfile.NamedTemporaryFile(
        suffix='.zip', delete=False, dir=temp_dir
    )
    archive_path = Path(temporary.name)
    temporary.close()
    os.chmod(archive_path, 0o600)
    transferred = 0
    member_budget = _TransferMemberBudget(
        config.MAX_TRANSFER_MEMBERS if max_members is None else max_members
    )

    def add_directory(archive, remote_path, archive_prefix, depth=0):
        nonlocal transferred
        if depth > 50:
            raise SFTPOperationError('maximum directory depth exceeded')
        if _is_cancelled(cancel_event):
            raise TransferCancelled()
        saw_entry = False
        with _directory_entries(sftp, remote_path) as entries:
            for entry in entries:
                saw_entry = True
                member_budget.consume()
                if _is_cancelled(cancel_event):
                    raise TransferCancelled()
                name = entry.filename
                if (
                    not isinstance(name, str)
                    or name in {'', '.', '..'}
                    or '/' in name
                    or '\\' in name
                    or '\x00' in name
                ):
                    raise SFTPOperationError('unsafe archive entry name')
                source_path = posixpath.join(remote_path, name)
                archive_pathname = posixpath.join(archive_prefix, name)
                try:
                    entry_stat = sftp.lstat(source_path)
                except Exception:
                    entry_stat = entry
                if stat.S_ISLNK(entry_stat.st_mode):
                    continue
                if stat.S_ISDIR(entry_stat.st_mode):
                    add_directory(
                        archive, source_path, archive_pathname, depth + 1
                    )
                    continue
                declared_size = getattr(entry_stat, 'st_size', 0) or 0
                if transferred + declared_size > max_bytes:
                    raise TransferSizeExceeded()
                with sftp.file(source_path, 'rb') as remote_file:
                    with archive.open(archive_pathname, 'w') as zip_entry:
                        copied = copy_sftp_stream(
                            remote_file,
                            zip_entry,
                            cancel_event=cancel_event,
                            max_bytes=max_bytes - transferred,
                            chunk_size=chunk_size,
                            progress=(
                                (lambda count: progress(transferred + count))
                                if progress else None
                            ),
                        )
                transferred += copied
                if archive_path.stat().st_size > max_bytes:
                    raise TransferSizeExceeded()
        if not saw_entry and archive_prefix:
            archive.writestr(archive_prefix.rstrip('/') + '/', b'')
            if archive_path.stat().st_size > max_bytes:
                raise TransferSizeExceeded()

    try:
        with zipfile.ZipFile(
            archive_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=6
        ) as archive:
            add_directory(archive, remote_folder, folder_name)
        if archive_path.stat().st_size > max_bytes:
            raise TransferSizeExceeded()
        return archive_path
    except Exception:
        archive_path.unlink(missing_ok=True)
        raise

def get_sftp_client(session_id):
    """Get cached or create new SFTP client from existing SSH session.

    SFTP clients are cached per session to avoid the overhead of opening
    a new SFTP channel for every operation (list, stat, read, etc.).
    The cache is invalidated when the SFTP channel breaks or the session closes.
    """
    try:
        cached_sftp = None
        with _sftp_cache_lock:
            if session_id in _sftp_cache:
                cached_sftp = _sftp_cache[session_id]

        if cached_sftp is not None:
            try:
                cached_sftp.stat('.')
                return cached_sftp, None
            except Exception:
                with _sftp_cache_lock:
                    if _sftp_cache.get(session_id) is cached_sftp:
                        del _sftp_cache[session_id]
                try:
                    cached_sftp.close()
                except Exception:
                    pass

        with ssh_manager.sessions_lock:
            if session_id not in ssh_manager.sessions:
                return None, "Session not found"

            session = ssh_manager.sessions[session_id]
            if not session['connected']:
                return None, "Session not connected"

            client = session['client']

        sftp = client.open_sftp()

        with _sftp_cache_lock:
            _sftp_cache[session_id] = sftp

        return sftp, None
    except Exception as e:
        return None, str(e)

def get_sftp_client_fresh(session_id):
    """Get a NEW (uncached) SFTP client. Used for concurrent operations like S2S transfers."""
    try:
        with ssh_manager.sessions_lock:
            if session_id not in ssh_manager.sessions:
                return None, "Session not found"

            session = ssh_manager.sessions[session_id]
            if not session['connected']:
                return None, "Session not connected"

            client = session['client']

        sftp = client.open_sftp()

        return sftp, None
    except Exception as e:
        return None, str(e)


def get_ssh_client(identifier):
    """Get the live Paramiko SSH client behind a session or quick connection."""
    with ssh_manager.sessions_lock:
        session = ssh_manager.sessions.get(identifier)
        if session is not None and session.get('connected'):
            return session.get('client')
    from .connection_pool import temp_connection_pool
    return temp_connection_pool.get_ssh_client(identifier)

def close_sftp_cache(session_id):
    """Close and remove cached SFTP client for a session. Called on session close."""
    with _sftp_cache_lock:
        sftp = _sftp_cache.pop(session_id, None)
        if sftp:
            try:
                sftp.close()
            except Exception:
                pass
    _cleanup_sftp_lock(session_id)

def sanitize_path(remote_path):
    """Sanitize and validate remote path to prevent path traversal attacks.

    SECURITY: Blocks path traversal attempts (../) and null bytes.
    Absolute paths are ALLOWED for SFTP operations on remote servers.
    Returns None if path is invalid/malicious.
    """
    if not remote_path or remote_path.strip() == '':
        return '.'

    if '\x00' in remote_path:
        log_warning(f"SECURITY: Null byte in path BLOCKED", path=repr(remote_path))
        return None

    # SFTP/remote paths are always POSIX-style, regardless of the OS this
    # process runs on. Use posixpath so normalization stays correct even when
    # the server itself is hosted on Windows (os.path would emit backslashes).
    normalized = posixpath.normpath(remote_path)

    if '..' in normalized:
        log_warning(f"SECURITY: Path traversal attempt blocked", path=remote_path)
        return None

    return normalized

def list_directory(session_id, remote_path='.'):
    """List files in remote directory with path validation."""
    try:
        safe_path = sanitize_path(remote_path)
        if safe_path is None:
            return None, "Invalid path: path traversal detected"

        with sftp_session(session_id) as (sftp, source_type):
            files = []
            entries = sftp.listdir_attr(safe_path)
            for entry in entries:
                is_symlink = stat.S_ISLNK(entry.st_mode)
                files.append({
                    'name': entry.filename,
                    'size': entry.st_size,
                    'mode': entry.st_mode,
                    'is_dir': stat.S_ISDIR(entry.st_mode),
                    'is_symlink': is_symlink,
                    'modified': entry.st_mtime
                })
        return files, None
    except SFTPOperationError as e:
        return None, str(e)
    except Exception as e:
        return None, str(e)

def create_directory(session_id, remote_path):
    """Create a directory on remote server."""
    try:
        safe_path = sanitize_path(remote_path)
        if safe_path is None:
            return False, "Invalid path: path traversal detected"

        with sftp_session(session_id) as (sftp, source_type):
            sftp.mkdir(safe_path)
        return True, None
    except SFTPOperationError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)


def upload_request_stream(session_id, remote_path, source, *, chunk_size,
                          max_bytes, cancelled=None, progress=None):
    """Write a request stream to a temporary remote file and atomically rename it.

    ``source`` is purposely consumed only with an explicit ``chunk_size``.
    The final path is never opened for writing: an interrupted or oversized
    request can leave at most a best-effort-cleaned temporary sibling.
    """
    safe_path = sanitize_path(remote_path)
    if safe_path is None:
        raise SFTPOperationError('invalid remote path')
    temporary_path = f'{safe_path}.webssh-upload-{secrets.token_hex(12)}.tmp'
    transferred = 0

    with sftp_session(session_id) as (sftp, _source_type):
        try:
            with sftp.file(temporary_path, 'wb') as remote_file:
                while True:
                    if cancelled and cancelled():
                        raise TransferCancelled()
                    chunk = source.read(chunk_size)
                    if not chunk:
                        break
                    next_size = transferred + len(chunk)
                    if next_size > max_bytes:
                        raise UploadSizeExceeded()
                    remote_file.write(chunk)
                    transferred = next_size
                    if progress:
                        progress(transferred)
                    if cancelled and cancelled():
                        raise TransferCancelled()

            if cancelled and cancelled():
                raise TransferCancelled()
            try:
                sftp.stat(safe_path)
                destination_exists = True
            except (FileNotFoundError, IOError, OSError):
                destination_exists = False
            if destination_exists:
                # ``rename`` must not be used for replacement: standard SFTP
                # servers may reject it, and deleting first loses the original.
                # The OpenSSH posix-rename extension is atomic replacement.
                try:
                    sftp.posix_rename(temporary_path, safe_path)
                except (AttributeError, IOError, OSError) as error:
                    raise SFTPOperationError(
                        'atomic replacement is unavailable'
                    ) from error
            else:
                sftp.rename(temporary_path, safe_path)
        except Exception:
            try:
                sftp.remove(temporary_path)
            except Exception:
                pass
            raise

    return transferred

def rename_item(session_id, old_path, new_path):
    """Rename a file or directory on remote server."""
    try:
        safe_old = sanitize_path(old_path)
        safe_new = sanitize_path(new_path)
        if safe_old is None or safe_new is None:
            return False, "Invalid path"

        with sftp_session(session_id) as (sftp, source_type):
            sftp.rename(safe_old, safe_new)
        return True, None
    except SFTPOperationError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)

def delete_directory_recursive(session_id, path):
    """Recursively delete a directory and all its contents."""
    import stat as stat_module

    try:
        safe_path = sanitize_path(path)
        if safe_path is None:
            return False, "Invalid path"

        def _delete_recursive(sftp_client, dir_path, base_path, depth=0):
            """
            Internal recursive delete function with security checks.

            SECURITY: Validates each path to prevent symlink attacks and
            limits recursion depth to prevent stack overflow.
            """
            if depth > 50:
                raise ValueError("Maximum recursion depth exceeded")

            for entry in sftp_client.listdir_attr(dir_path):
                full_path = f"{dir_path}/{entry.filename}"

                if stat_module.S_ISLNK(entry.st_mode):
                    sftp_client.remove(full_path)
                    continue

                if stat_module.S_ISDIR(entry.st_mode):
                    _delete_recursive(sftp_client, full_path, base_path, depth + 1)
                    sftp_client.rmdir(full_path)
                else:
                    sftp_client.remove(full_path)

        with sftp_session(session_id) as (sftp, source_type):
            stat_result = sftp.lstat(safe_path)
            if stat_module.S_ISDIR(stat_result.st_mode):
                _delete_recursive(sftp, safe_path, safe_path)
                sftp.rmdir(safe_path)
            elif stat_module.S_ISLNK(stat_result.st_mode):
                sftp.remove(safe_path)
            else:
                sftp.remove(safe_path)

        return True, None
    except SFTPOperationError as e:
        return False, str(e)
    except FileNotFoundError:
        return False, "File or directory not found"
    except Exception as e:
        return False, str(e)

def get_home_directory(session_id):
    """Get the home directory (current working directory) of the SFTP session."""
    try:
        with sftp_session(session_id) as (sftp, source_type):
            home_path = sftp.normalize('.')
        return home_path, None
    except SFTPOperationError as e:
        return None, str(e)
    except Exception as e:
        return None, str(e)

def check_exists(session_id, path):
    """Check if a file or directory exists on remote server."""
    try:
        safe_path = sanitize_path(path)
        if safe_path is None:
            return None, "Invalid path"

        with sftp_session(session_id) as (sftp, source_type):
            try:
                file_stat = sftp.stat(safe_path)
                is_dir = file_stat.st_mode & 0o040000 != 0
                return {'exists': True, 'is_dir': is_dir, 'size': file_stat.st_size}, None
            except FileNotFoundError:
                return {'exists': False, 'is_dir': False, 'size': 0}, None
    except SFTPOperationError as e:
        return None, str(e)
    except Exception as e:
        return None, str(e)

def get_file_stat(session_id, path):
    """Get detailed file/directory statistics."""
    try:
        safe_path = sanitize_path(path)
        if safe_path is None:
            return None, "Invalid path"

        with sftp_session(session_id) as (sftp, source_type):
            file_stat = sftp.stat(safe_path)

        return {
            'name': os.path.basename(safe_path),
            'path': safe_path,
            'size': file_stat.st_size,
            'mode': file_stat.st_mode,
            'is_dir': file_stat.st_mode & 0o040000 != 0,
            'modified': file_stat.st_mtime,
            'permissions': oct(file_stat.st_mode)[-3:]
        }, None
    except SFTPOperationError as e:
        return None, str(e)
    except FileNotFoundError:
        return None, "File not found"
    except Exception as e:
        return None, str(e)

def read_file_preview(session_id, path, max_bytes=512000, offset=0, tail_lines=None):
    """
    Read file content for preview purposes.

    Args:
        session_id: Session ID or connection ID
        path: File path on remote server
        max_bytes: Maximum bytes to read (default 500KB)
        offset: Byte offset to start reading from
        tail_lines: If set, read last N lines instead of from beginning

    Returns:
        tuple: (content_dict, error)
               content_dict contains: content, size, truncated, is_binary
    """
    try:
        safe_path = sanitize_path(path)
        if safe_path is None:
            return None, "Invalid path"

        with sftp_session(session_id) as (sftp, source_type):
            file_stat = sftp.stat(safe_path)
            file_size = file_stat.st_size

            max_preview_size = getattr(config, 'MAX_PREVIEW_SIZE', 512000)
            max_bytes = min(max_bytes, max_preview_size)

            max_supported_file = getattr(config, 'MAX_SUPPORTED_FILE_SIZE', 1024 * 1024 * 1024)
            if file_size > max_supported_file:
                return None, f"File too large ({file_size} bytes). Maximum supported size is {max_supported_file} bytes."

            truncated = file_size > max_bytes
            read_size = min(file_size, max_bytes)

            content = b''

            with sftp.file(safe_path, 'rb') as remote_file:
                if tail_lines:
                    seek_pos = max(0, file_size - max_bytes)
                    remote_file.seek(seek_pos)
                    content = remote_file.read(max_bytes)

                    lines = content.split(b'\n')
                    if len(lines) > tail_lines:
                        content = b'\n'.join(lines[-tail_lines:])
                        truncated = True
                else:
                    if offset > 0:
                        remote_file.seek(offset)
                    content = remote_file.read(read_size)

        is_binary = False
        try:
            sample = content[:1024]
            if b'\x00' in sample:
                is_binary = True
            else:
                sample.decode('utf-8')
        except UnicodeDecodeError:
            is_binary = True

        if is_binary:
            content_str = None
        else:
            try:
                content_str = content.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    content_str = content.decode('latin-1')
                except Exception:
                    is_binary = True
                    content_str = None

        return {
            'content': content_str,
            'size': file_size,
            'read_size': len(content),
            'truncated': truncated,
            'is_binary': is_binary,
            'offset': offset
        }, None

    except SFTPOperationError as e:
        return None, str(e)
    except FileNotFoundError:
        return None, "File not found"
    except PermissionError:
        return None, "Permission denied"
    except Exception as e:
        return None, str(e)

def read_file_for_edit(session_id, path, max_bytes=None):
    """
    Read a full text file for editing.

    Unlike read_file_preview, this never truncates: files larger than the
    editor limit or detected as binary are rejected, so that a later save
    cannot silently shorten or corrupt the original file.

    Returns:
        tuple: (content_dict, error)
               content_dict contains: content, size, encoding, newline
    """
    try:
        safe_path = sanitize_path(path)
        if safe_path is None:
            return None, "Invalid path"

        if max_bytes is None:
            max_bytes = getattr(config, 'MAX_EDITOR_FILE_SIZE', 5 * 1024 * 1024)

        with sftp_session(session_id) as (sftp, source_type):
            file_stat = sftp.stat(safe_path)
            file_size = file_stat.st_size

            if file_size > max_bytes:
                max_mb = max_bytes // (1024 * 1024)
                return None, (f"File too large to edit ({file_size // (1024 * 1024)}MB). "
                              f"Maximum: {max_mb}MB")

            with sftp.file(safe_path, 'rb') as remote_file:
                raw = remote_file.read(file_size)

        # Binary detection mirrors read_file_preview.
        is_binary = b'\x00' in raw[:1024]

        encoding = 'utf-8'
        content_str = None
        if not is_binary:
            try:
                content_str = raw.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    content_str = raw.decode('latin-1')
                    encoding = 'latin-1'
                except Exception:
                    is_binary = True

        if is_binary or content_str is None:
            return None, "Binary file cannot be edited"

        # Remember the original newline style, then normalize to LF for the
        # browser textarea; the original style is restored on save.
        newline = 'crlf' if b'\r\n' in raw else 'lf'
        content_str = content_str.replace('\r\n', '\n')

        return {
            'content': content_str,
            'size': file_size,
            'encoding': encoding,
            'newline': newline
        }, None

    except SFTPOperationError as e:
        return None, str(e)
    except FileNotFoundError:
        return None, "File not found"
    except PermissionError:
        return None, "Permission denied"
    except Exception as e:
        return None, str(e)

def write_file_text(session_id, path, content_str, encoding='utf-8', newline='lf'):
    """
    Write edited text content back to a remote file.

    Writes atomically: content is written to a temp file in the same directory
    first, then renamed over the target, so an interrupted transfer cannot leave
    a half-written or empty file. Falls back to a direct overwrite if the server
    does not support the posix-rename extension.
    """
    try:
        safe_path = sanitize_path(path)
        if safe_path is None:
            return False, "Invalid path"

        # The browser textarea always uses LF; restore the original style.
        text = content_str.replace('\r\n', '\n')
        if newline == 'crlf':
            text = text.replace('\n', '\r\n')

        if encoding not in ('utf-8', 'latin-1'):
            encoding = 'utf-8'
        try:
            data = text.encode(encoding)
        except UnicodeEncodeError:
            data = text.encode('utf-8')

        tmp_path = safe_path + '.webssh-tmp-' + os.urandom(4).hex()

        with sftp_session(session_id) as (sftp, source_type):
            try:
                with sftp.file(tmp_path, 'wb') as remote_file:
                    remote_file.write(data)
                try:
                    sftp.posix_rename(tmp_path, safe_path)
                except (IOError, OSError, AttributeError):
                    # Server lacks posix-rename; fall back to direct overwrite.
                    with sftp.file(safe_path, 'wb') as remote_file:
                        remote_file.write(data)
                    try:
                        sftp.remove(tmp_path)
                    except Exception:
                        pass
            except Exception:
                # Best-effort cleanup of the temp file on failure.
                try:
                    sftp.remove(tmp_path)
                except Exception:
                    pass
                raise

        return True, None
    except SFTPOperationError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)

def get_sftp_client_from_pool(connection_id):
    """Get SFTP client from temporary connection pool."""
    from . import connection_pool
    return connection_pool.temp_connection_pool.get_sftp_client(connection_id)

def get_any_sftp_client(identifier):
    """
    Get SFTP client from either an SSH session or temporary connection pool.
    Tries the shared cache first, then SSH session, then connection pool.
    Pool clients are cached to avoid opening a new SFTP channel per operation.

    Args:
        identifier (str): Session ID or connection ID

    Returns:
        tuple: (sftp_client, error, source_type)
               source_type is 'session' or 'pool'
    """
    sftp, error = get_sftp_client(identifier)
    if sftp:
        return sftp, None, 'session'

    sftp, error = get_sftp_client_from_pool(identifier)
    if sftp:
        with _sftp_cache_lock:
            _sftp_cache[identifier] = sftp
        return sftp, None, 'pool'

    return None, f"No active connection found for: {identifier}", None


def _remove_sftp_tree(sftp, remote_path):
    """Best-effort removal for a generated temporary SFTP tree."""
    try:
        entries = sftp.listdir_attr(remote_path)
    except Exception:
        try:
            sftp.remove(remote_path)
        except Exception:
            pass
        return
    for entry in entries:
        child = posixpath.join(remote_path, entry.filename)
        try:
            child_stat = sftp.lstat(child)
        except Exception:
            child_stat = entry
        if stat.S_ISDIR(child_stat.st_mode) and not stat.S_ISLNK(
            child_stat.st_mode
        ):
            _remove_sftp_tree(sftp, child)
        else:
            try:
                sftp.remove(child)
            except Exception:
                pass
    try:
        sftp.rmdir(remote_path)
    except Exception:
        pass

def transfer_server_to_server(source_session_id, source_path, dest_session_id,
                              dest_path, transfer_id, socketio_instance=None,
                              is_dir=False, user_room=None, cancel_event=None,
                              max_bytes=None, max_members=None, chunk_size=None):
    """
    Direct server-to-server SFTP streaming transfer.
    Streams data from source SSH host to destination SSH host without
    buffering the entire file locally.

    Args:
        source_session_id: Session/connection ID for source server
        source_path: File/directory path on source server
        dest_session_id: Session/connection ID for destination server
        dest_path: Target path on destination server
        transfer_id: Unique transfer ID for progress tracking
        socketio_instance: SocketIO instance for emitting progress events
        is_dir: Whether the source is a directory (recursive transfer)
        user_room: Socket room to emit events to

    Returns:
        tuple: (success: bool, error: str or None)
    """
    max_bytes = config.MAX_ZIP_DOWNLOAD_SIZE if max_bytes is None else max_bytes
    max_members = (
        config.MAX_TRANSFER_MEMBERS if max_members is None else max_members
    )
    chunk_size = config.CHUNK_SIZE if chunk_size is None else chunk_size
    total_transferred = 0
    sftp_source = None
    sftp_dest = None
    source_type = None
    dest_type = None
    directory_total = None

    try:
        sftp_source, error = get_sftp_client_fresh(source_session_id)
        source_type = 'session' if sftp_source else None
        if error:
            sftp_source, error = get_sftp_client_from_pool(source_session_id)
            source_type = 'pool' if sftp_source else None
        if error:
            return False, f"Source connection error: {error}"

        sftp_dest, error = get_sftp_client_fresh(dest_session_id)
        dest_type = 'session' if sftp_dest else None
        if error:
            sftp_dest, error = get_sftp_client_from_pool(dest_session_id)
            dest_type = 'pool' if sftp_dest else None
        if error:
            sftp_source.close()
            return False, f"Destination connection error: {error}"

        def emit_progress(filename, transferred, total, status='transferring'):
            """Emit progress update to client."""
            if socketio_instance and user_room:
                safe_total = max(int(total), int(transferred), 0)
                percent = (
                    min(100, max(0, int((transferred / safe_total) * 100)))
                    if safe_total > 0 else 0
                )
                socketio_instance.emit('s2s_transfer_progress', {
                    'transfer_id': transfer_id,
                    'filename': filename,
                    'transferred': transferred,
                    'total': safe_total,
                    'percent': percent,
                    'status': status
                }, room=user_room)

        def transfer_single_file(src_path, dst_path):
            """Transfer a single file from source to destination."""
            nonlocal sftp_source, sftp_dest, total_transferred

            try:
                source_stat = sftp_source.stat(src_path)
                file_size = source_stat.st_size
            except FileNotFoundError:
                return False, f"Source file not found: {src_path}"

            filename = os.path.basename(src_path)
            if total_transferred + file_size > max_bytes:
                return False, 'Transfer exceeds configured size limit'
            temporary_path = (
                f'{dst_path}.webssh-transfer-{secrets.token_hex(12)}.tmp'
            )
            transferred = 0

            def report(count):
                nonlocal transferred
                transferred = count
                aggregate_total = (
                    directory_total if directory_total is not None else file_size
                )
                emit_progress(
                    filename,
                    total_transferred + count,
                    aggregate_total,
                )

            try:
                with sftp_source.open(src_path, 'rb') as src_file:
                    with sftp_dest.open(temporary_path, 'wb') as dst_file:
                        transferred = copy_sftp_stream(
                            src_file,
                            dst_file,
                            cancel_event=cancel_event,
                            max_bytes=max_bytes - total_transferred,
                            chunk_size=chunk_size,
                            progress=report,
                        )
                if _is_cancelled(cancel_event):
                    raise TransferCancelled()
                try:
                    sftp_dest.stat(dst_path)
                    destination_exists = True
                except (FileNotFoundError, IOError, OSError):
                    destination_exists = False
                if destination_exists:
                    try:
                        sftp_dest.posix_rename(temporary_path, dst_path)
                    except (AttributeError, IOError, OSError) as error:
                        raise SFTPOperationError(
                            'atomic replacement is unavailable'
                        ) from error
                else:
                    sftp_dest.rename(temporary_path, dst_path)
                total_transferred += transferred
            except Exception:
                try:
                    sftp_dest.remove(temporary_path)
                except Exception:
                    pass
                raise

            aggregate_total = (
                directory_total if directory_total is not None else file_size
            )
            emit_progress(
                filename,
                total_transferred,
                aggregate_total,
                'completed',
            )
            return True, None

        preflight_member_budget = _TransferMemberBudget(max_members)

        def calculate_directory_total(src_dir, depth=0):
            """Calculate a bounded directory total before copying any data."""
            if depth > 50:
                raise SFTPOperationError(
                    'Maximum directory depth exceeded (50 levels)'
                )
            if _is_cancelled(cancel_event):
                raise TransferCancelled()

            total = 0
            with _directory_entries(sftp_source, src_dir) as entries:
                for entry in entries:
                    preflight_member_budget.consume()
                    if _is_cancelled(cancel_event):
                        raise TransferCancelled()
                    name = entry.filename
                    if (
                        not isinstance(name, str)
                        or name in {'', '.', '..'}
                        or '/' in name
                        or '\\' in name
                        or '\x00' in name
                    ):
                        raise SFTPOperationError('unsafe transfer entry name')
                    entry_path = posixpath.join(src_dir, name)
                    try:
                        entry_stat = sftp_source.lstat(entry_path)
                    except Exception:
                        entry_stat = entry
                    if stat.S_ISLNK(entry_stat.st_mode):
                        continue
                    if stat.S_ISDIR(entry_stat.st_mode):
                        total += calculate_directory_total(
                            entry_path, depth + 1
                        )
                    else:
                        size = int(getattr(entry_stat, 'st_size', 0))
                        if size < 0:
                            raise SFTPOperationError(
                                'invalid transfer entry size'
                            )
                        total += size
                    if total > max_bytes:
                        raise TransferSizeExceeded()
            return total

        transfer_member_budget = _TransferMemberBudget(max_members)

        def transfer_directory_recursive(src_dir, dst_dir, depth=0):
            """Recursively transfer a directory."""
            nonlocal sftp_source, sftp_dest

            if depth > 50:
                return False, "Maximum directory depth exceeded (50 levels)"
            if _is_cancelled(cancel_event):
                raise TransferCancelled()

            sftp_dest.mkdir(dst_dir)

            with _directory_entries(sftp_source, src_dir) as entries:
                for entry in entries:
                    transfer_member_budget.consume()
                    if _is_cancelled(cancel_event):
                        raise TransferCancelled()
                    name = entry.filename
                    if (
                        not isinstance(name, str)
                        or name in {'', '.', '..'}
                        or '/' in name
                        or '\\' in name
                        or '\x00' in name
                    ):
                        raise SFTPOperationError(
                            'unsafe transfer entry name'
                        )
                    src_entry_path = posixpath.join(src_dir, name)
                    dst_entry_path = posixpath.join(dst_dir, name)
                    try:
                        entry_stat = sftp_source.lstat(src_entry_path)
                    except Exception:
                        entry_stat = entry
                    if stat.S_ISLNK(entry_stat.st_mode):
                        continue
                    if stat.S_ISDIR(entry_stat.st_mode):
                        success, error = transfer_directory_recursive(
                            src_entry_path, dst_entry_path, depth + 1
                        )
                        if not success:
                            return False, error
                    else:
                        success, error = transfer_single_file(
                            src_entry_path, dst_entry_path
                        )
                        if not success:
                            return False, error

            return True, None

        if socketio_instance and user_room:
            socketio_instance.emit('s2s_transfer_started', {
                'transfer_id': transfer_id,
                'source_path': source_path,
                'dest_path': dest_path,
                'is_dir': is_dir
            }, room=user_room)

        if is_dir:
            directory_total = calculate_directory_total(source_path)
            temporary_root = (
                f'{dest_path}.webssh-transfer-{secrets.token_hex(12)}.tmp'
            )
            try:
                success, error = transfer_directory_recursive(
                    source_path, temporary_root
                )
                if not success:
                    raise SFTPOperationError(error or 'directory transfer failed')
                if _is_cancelled(cancel_event):
                    raise TransferCancelled()
                try:
                    sftp_dest.stat(dest_path)
                    destination_exists = True
                except (FileNotFoundError, IOError, OSError):
                    destination_exists = False
                if destination_exists:
                    raise SFTPOperationError('destination already exists')
                sftp_dest.rename(temporary_root, dest_path)
                emit_progress(
                    os.path.basename(source_path.rstrip('/')) or source_path,
                    total_transferred,
                    total_transferred,
                    'completed',
                )
            except Exception:
                _remove_sftp_tree(sftp_dest, temporary_root)
                raise
        else:
            success, error = transfer_single_file(source_path, dest_path)

        return success, error

    except TransferCancelled:
        return False, 'Transfer cancelled'
    except TransferSizeExceeded:
        return False, 'Transfer exceeds configured size limit'
    except TransferMemberLimitExceeded:
        return False, 'Transfer exceeds configured member limit'
    except Exception as e:
        log_error("S2S transfer failed", error=str(e), transfer_id=transfer_id)
        return False, "Transfer failed"
    finally:
        if source_type == 'session' and sftp_source is not None:
            try:
                sftp_source.close()
            except Exception:
                pass
        if dest_type == 'session' and sftp_dest is not None:
            try:
                sftp_dest.close()
            except Exception:
                pass
