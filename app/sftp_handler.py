import os
import stat
from pathlib import Path
import config
from . import ssh_manager
from .audit_logger import log_info, log_warning, log_error, log_debug

def get_sftp_client(session_id):
    """Get SFTP client from existing SSH session."""
    try:
        sftp = None
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

def upload_file(session_id, local_file_path, remote_path, socketio_instance=None):
    """Upload a file via SFTP with progress tracking."""
    try:
        sftp, error = get_sftp_client(session_id)
        if error:
            return False, error

        file_size = os.path.getsize(local_file_path)
        transferred = 0

        def progress_callback(transferred_bytes, total_bytes):
            """Callback for progress updates."""
            if socketio_instance:
                percent = int((transferred_bytes / total_bytes) * 100)
                socketio_instance.emit('file_progress', {
                    'session_id': session_id,
                    'type': 'upload',
                    'filename': os.path.basename(local_file_path),
                    'transferred': transferred_bytes,
                    'total': total_bytes,
                    'percent': percent
                })

        # Upload file
        sftp.put(
            local_file_path,
            remote_path,
            callback=progress_callback
        )

        sftp.close()

        # Emit completion
        if socketio_instance:
            socketio_instance.emit('file_complete', {
                'session_id': session_id,
                'type': 'upload',
                'filename': os.path.basename(local_file_path),
                'remote_path': remote_path
            })

        return True, None
    except Exception as e:
        return False, str(e)

def download_file(session_id, remote_path, local_file_path, socketio_instance=None):
    """Download a file via SFTP with progress tracking."""
    try:
        sftp, error = get_sftp_client(session_id)
        if error:
            return False, error

        # Get remote file size
        file_stat = sftp.stat(remote_path)
        file_size = file_stat.st_size

        def progress_callback(transferred_bytes, total_bytes):
            """Callback for progress updates."""
            if socketio_instance:
                percent = int((transferred_bytes / total_bytes) * 100)
                socketio_instance.emit('file_progress', {
                    'session_id': session_id,
                    'type': 'download',
                    'filename': os.path.basename(remote_path),
                    'transferred': transferred_bytes,
                    'total': total_bytes,
                    'percent': percent
                })

        # Download file
        sftp.get(
            remote_path,
            local_file_path,
            callback=progress_callback
        )

        sftp.close()

        # Emit completion
        if socketio_instance:
            socketio_instance.emit('file_complete', {
                'session_id': session_id,
                'type': 'download',
                'filename': os.path.basename(remote_path),
                'local_path': local_file_path
            })

        return True, None
    except FileNotFoundError:
        return False, "Remote file not found"
    except Exception as e:
        return False, str(e)

def sanitize_path(remote_path):
    """Sanitize and validate remote path to prevent path traversal attacks.

    SECURITY: Blocks path traversal attempts (../) and null bytes.
    Absolute paths are ALLOWED for SFTP operations on remote servers.
    Returns None if path is invalid/malicious.
    """
    if not remote_path or remote_path.strip() == '':
        return '.'

    # Block null bytes (can bypass validation in some systems)
    if '\x00' in remote_path:
        log_warning(f"SECURITY: Null byte in path BLOCKED", path=repr(remote_path))
        return None

    # Normalize the path (remove redundant slashes, etc.)
    normalized = os.path.normpath(remote_path)

    # SECURITY: Block path traversal attempts
    # Check for '..' in any path component (both relative and absolute)
    # e.g., "../etc", "/home/../etc", "foo/../../bar"
    if '..' in normalized:
        log_warning(f"SECURITY: Path traversal attempt blocked", path=remote_path)
        return None

    # NOTE: Absolute paths (starting with /) are ALLOWED for SFTP
    # because we're operating on a remote server where the user
    # has already authenticated. The remote server's permissions
    # control what they can access.

    return normalized

def list_directory(session_id, remote_path='.'):
    """List files in remote directory with path validation."""
    try:
        # Sanitize path
        safe_path = sanitize_path(remote_path)
        if safe_path is None:
            return None, "Invalid path: path traversal detected"

        # Try SSH session first, then connection pool
        sftp, error, source_type = get_any_sftp_client(session_id)
        if error:
            return None, error

        # List directory contents
        files = []
        try:
            entries = sftp.listdir_attr(safe_path)
            for entry in entries:
                # SECURITY: Detect symlinks for client-side warning
                is_symlink = stat.S_ISLNK(entry.st_mode)
                files.append({
                    'name': entry.filename,
                    'size': entry.st_size,
                    'mode': entry.st_mode,
                    'is_dir': stat.S_ISDIR(entry.st_mode),
                    'is_symlink': is_symlink,  # Symlink detection
                    'modified': entry.st_mtime
                })
        except Exception as listdir_error:
            sftp.close()
            raise

        # Close SFTP channel after use
        sftp.close()
        return files, None
    except Exception as e:
        return None, str(e)

def create_directory(session_id, remote_path):
    """Create a directory on remote server."""
    try:
        # SECURITY: Validate path before operation
        safe_path = sanitize_path(remote_path)
        if safe_path is None:
            return False, "Invalid path: path traversal or absolute path detected"

        sftp, error, source_type = get_any_sftp_client(session_id)
        if error:
            return False, error

        sftp.mkdir(safe_path)
        sftp.close()
        return True, None
    except Exception as e:
        return False, str(e)

def delete_file(session_id, remote_path):
    """Delete a file on remote server."""
    try:
        # SECURITY: Validate path before operation
        safe_path = sanitize_path(remote_path)
        if safe_path is None:
            return False, "Invalid path: path traversal or absolute path detected"

        sftp, error, source_type = get_any_sftp_client(session_id)
        if error:
            return False, error

        sftp.remove(safe_path)
        sftp.close()
        return True, None
    except Exception as e:
        return False, str(e)

def upload_file_chunked(session_id, filename, chunks, remote_path, socketio_instance=None):
    """Upload file from chunks sent by client."""
    try:
        sftp, error, source_type = get_any_sftp_client(session_id)
        if error:
            return False, error

        # SECURITY: Sanitize remote path to prevent path traversal
        safe_path = sanitize_path(remote_path)
        if safe_path is None:
            return False, "Invalid remote path"

        # Write chunks to remote file
        total_size = sum(len(chunk) for chunk in chunks)
        transferred = 0

        with sftp.file(safe_path, 'wb') as remote_file:
            for i, chunk in enumerate(chunks):
                remote_file.write(chunk)
                transferred += len(chunk)

                # Emit progress
                if socketio_instance:
                    percent = int((transferred / total_size) * 100)
                    socketio_instance.emit('file_progress', {
                        'session_id': session_id,
                        'type': 'upload',
                        'filename': filename,
                        'transferred': transferred,
                        'total': total_size,
                        'percent': percent
                    })

        sftp.close()

        # Emit completion
        if socketio_instance:
            socketio_instance.emit('file_complete', {
                'session_id': session_id,
                'type': 'upload',
                'filename': filename,
                'remote_path': safe_path
            })

        return True, None
    except Exception as e:
        return False, str(e)

def download_file_chunked(session_id, remote_path, socketio_instance=None):
    """Download file and send in chunks to client."""
    try:
        sftp, error, source_type = get_any_sftp_client(session_id)
        if error:
            return None, error

        # SECURITY: Sanitize remote path to prevent path traversal
        safe_path = sanitize_path(remote_path)
        if safe_path is None:
            return None, "Invalid remote path"

        # Get file size
        file_stat = sftp.stat(safe_path)
        file_size = file_stat.st_size
        filename = os.path.basename(remote_path)

        chunks = []
        transferred = 0

        with sftp.file(safe_path, 'rb') as remote_file:
            while True:
                chunk = remote_file.read(config.CHUNK_SIZE)
                if not chunk:
                    break

                chunks.append(chunk)
                transferred += len(chunk)

                # Emit progress
                if socketio_instance:
                    percent = int((transferred / file_size) * 100)
                    socketio_instance.emit('file_progress', {
                        'session_id': session_id,
                        'type': 'download',
                        'filename': filename,
                        'transferred': transferred,
                        'total': file_size,
                        'percent': percent
                    })

        sftp.close()
        return {'filename': filename, 'chunks': chunks, 'size': file_size}, None
    except Exception as e:
        return None, str(e)


def rename_item(session_id, old_path, new_path):
    """Rename a file or directory on remote server."""
    try:
        sftp, error, source_type = get_any_sftp_client(session_id)
        if error:
            return False, error

        # Sanitize paths
        safe_old = sanitize_path(old_path)
        safe_new = sanitize_path(new_path)
        if safe_old is None or safe_new is None:
            return False, "Invalid path"

        sftp.rename(safe_old, safe_new)
        sftp.close()
        return True, None
    except Exception as e:
        return False, str(e)


def delete_directory_recursive(session_id, path):
    """Recursively delete a directory and all its contents."""
    import stat as stat_module

    try:
        sftp, error, source_type = get_any_sftp_client(session_id)
        if error:
            return False, error

        safe_path = sanitize_path(path)
        if safe_path is None:
            return False, "Invalid path"

        def _delete_recursive(sftp_client, dir_path, base_path, depth=0):
            """
            Internal recursive delete function with security checks.

            SECURITY: Validates each path to prevent symlink attacks and
            limits recursion depth to prevent stack overflow.
            """
            # SECURITY: Prevent excessive recursion (defense against deeply nested structures)
            if depth > 50:
                raise ValueError("Maximum recursion depth exceeded")

            for entry in sftp_client.listdir_attr(dir_path):
                full_path = f"{dir_path}/{entry.filename}"

                # SECURITY: Skip symlinks to prevent following links outside directory
                if stat_module.S_ISLNK(entry.st_mode):
                    # Remove the symlink itself, but don't follow it
                    sftp_client.remove(full_path)
                    continue

                if stat_module.S_ISDIR(entry.st_mode):
                    _delete_recursive(sftp_client, full_path, base_path, depth + 1)
                    sftp_client.rmdir(full_path)
                else:
                    sftp_client.remove(full_path)

        # Check if it's a directory (using lstat to not follow symlinks)
        stat_result = sftp.lstat(safe_path)
        if stat_module.S_ISDIR(stat_result.st_mode):
            _delete_recursive(sftp, safe_path, safe_path)
            sftp.rmdir(safe_path)
        elif stat_module.S_ISLNK(stat_result.st_mode):
            # If target is a symlink, just remove the link
            sftp.remove(safe_path)
        else:
            sftp.remove(safe_path)

        sftp.close()
        return True, None
    except FileNotFoundError:
        return False, "File or directory not found"
    except Exception as e:
        return False, str(e)


def get_home_directory(session_id):
    """Get the home directory (current working directory) of the SFTP session."""
    try:
        # Try SSH session first, then connection pool
        sftp, error, source_type = get_any_sftp_client(session_id)
        if error:
            return None, error

        # normalize('.') returns the absolute path of current directory
        home_path = sftp.normalize('.')

        sftp.close()
        return home_path, None
    except Exception as e:
        return None, str(e)


def check_exists(session_id, path):
    """Check if a file or directory exists on remote server."""
    try:
        sftp, error, source_type = get_any_sftp_client(session_id)
        if error:
            return None, error

        safe_path = sanitize_path(path)
        if safe_path is None:
            return None, "Invalid path"

        try:
            stat = sftp.stat(safe_path)
            is_dir = stat.st_mode & 0o040000 != 0
            sftp.close()
            return {'exists': True, 'is_dir': is_dir, 'size': stat.st_size}, None
        except FileNotFoundError:
            sftp.close()
            return {'exists': False, 'is_dir': False, 'size': 0}, None
    except Exception as e:
        return None, str(e)


def get_file_stat(session_id, path):
    """Get detailed file/directory statistics."""
    try:
        sftp, error, source_type = get_any_sftp_client(session_id)
        if error:
            return None, error

        safe_path = sanitize_path(path)
        if safe_path is None:
            return None, "Invalid path"

        stat = sftp.stat(safe_path)
        sftp.close()

        return {
            'name': os.path.basename(safe_path),
            'path': safe_path,
            'size': stat.st_size,
            'mode': stat.st_mode,
            'is_dir': stat.st_mode & 0o040000 != 0,
            'modified': stat.st_mtime,
            'permissions': oct(stat.st_mode)[-3:]
        }, None
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
        sftp, error, source_type = get_any_sftp_client(session_id)
        if error:
            return None, error

        safe_path = sanitize_path(path)
        if safe_path is None:
            return None, "Invalid path"

        # Get file info
        file_stat = sftp.stat(safe_path)
        file_size = file_stat.st_size

        # SECURITY: Limit max_bytes to configured limit
        max_preview_size = getattr(config, 'MAX_PREVIEW_SIZE', 512000)  # 500KB default
        max_bytes = min(max_bytes, max_preview_size)

        # SECURITY: Sanity check - reject absurdly large files immediately
        # This prevents memory issues even if we're only reading max_bytes
        max_supported_file = getattr(config, 'MAX_SUPPORTED_FILE_SIZE', 1024 * 1024 * 1024)  # 1GB
        if file_size > max_supported_file:
            return None, f"File too large ({file_size} bytes). Maximum supported size is {max_supported_file} bytes."

        # Check if file is too large and we need to truncate
        truncated = file_size > max_bytes
        read_size = min(file_size, max_bytes)

        content = b''

        with sftp.file(safe_path, 'rb') as remote_file:
            if tail_lines:
                # Read last N lines (for log files)
                # Read a chunk from the end and find line breaks
                seek_pos = max(0, file_size - max_bytes)
                remote_file.seek(seek_pos)
                content = remote_file.read(max_bytes)

                # Find line breaks and keep last N lines
                lines = content.split(b'\n')
                if len(lines) > tail_lines:
                    content = b'\n'.join(lines[-tail_lines:])
                    truncated = True
            else:
                # Read from offset
                if offset > 0:
                    remote_file.seek(offset)
                content = remote_file.read(read_size)

        sftp.close()

        # Detect if binary
        is_binary = False
        try:
            # Check for null bytes or non-text characters
            sample = content[:1024]
            if b'\x00' in sample:
                is_binary = True
            else:
                # Try to decode as UTF-8
                sample.decode('utf-8')
        except UnicodeDecodeError:
            is_binary = True

        # Convert to string if not binary
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

    except FileNotFoundError:
        return None, "File not found"
    except PermissionError:
        return None, "Permission denied"
    except Exception as e:
        return None, str(e)


def get_sftp_client_from_pool(connection_id):
    """Get SFTP client from temporary connection pool."""
    from . import connection_pool
    return connection_pool.temp_connection_pool.get_sftp_client(connection_id)


def get_any_sftp_client(identifier):
    """
    Get SFTP client from either an SSH session or temporary connection pool.
    Tries SSH session first, then temporary connection pool.

    Args:
        identifier (str): Session ID or connection ID

    Returns:
        tuple: (sftp_client, error, source_type)
               source_type is 'session' or 'pool'
    """
    # First try as SSH session
    sftp, error = get_sftp_client(identifier)
    if sftp:
        return sftp, None, 'session'

    # Then try as temporary connection from pool
    sftp, error = get_sftp_client_from_pool(identifier)
    if sftp:
        return sftp, None, 'pool'

    return None, f"No active session or connection found for ID: {identifier}", None


def transfer_server_to_server(source_session_id, source_path, dest_session_id,
                              dest_path, transfer_id, socketio_instance=None,
                              is_dir=False, user_room=None):
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
    CHUNK_SIZE = 65536  # 64KB chunks

    try:
        # Get source SFTP client
        sftp_source, error, source_type = get_any_sftp_client(source_session_id)
        if error:
            return False, f"Source connection error: {error}"

        # Get destination SFTP client
        sftp_dest, error, dest_type = get_any_sftp_client(dest_session_id)
        if error:
            # Close source if it was from session (pool connections persist)
            if source_type == 'session':
                sftp_source.close()
            return False, f"Destination connection error: {error}"

        def emit_progress(filename, transferred, total, status='transferring'):
            """Emit progress update to client."""
            if socketio_instance and user_room:
                socketio_instance.emit('s2s_transfer_progress', {
                    'transfer_id': transfer_id,
                    'filename': filename,
                    'transferred': transferred,
                    'total': total,
                    'percent': int((transferred / total) * 100) if total > 0 else 0,
                    'status': status
                }, room=user_room)

        def transfer_single_file(src_path, dst_path):
            """Transfer a single file from source to destination."""
            nonlocal sftp_source, sftp_dest

            # Get source file info
            try:
                source_stat = sftp_source.stat(src_path)
                file_size = source_stat.st_size
            except FileNotFoundError:
                return False, f"Source file not found: {src_path}"

            filename = os.path.basename(src_path)
            transferred = 0

            # Stream from source to destination
            with sftp_source.open(src_path, 'rb') as src_file:
                with sftp_dest.open(dst_path, 'wb') as dst_file:
                    while True:
                        chunk = src_file.read(CHUNK_SIZE)
                        if not chunk:
                            break

                        dst_file.write(chunk)
                        transferred += len(chunk)

                        # Emit progress every 256KB to reduce overhead
                        if transferred % (CHUNK_SIZE * 4) == 0 or transferred == file_size:
                            emit_progress(filename, transferred, file_size)

            # Final progress update
            emit_progress(filename, file_size, file_size, 'completed')
            return True, None

        def transfer_directory_recursive(src_dir, dst_dir):
            """Recursively transfer a directory."""
            nonlocal sftp_source, sftp_dest

            # Create destination directory
            try:
                sftp_dest.mkdir(dst_dir)
            except IOError:
                # Directory might already exist
                pass

            # List source directory
            for entry in sftp_source.listdir_attr(src_dir):
                src_entry_path = f"{src_dir}/{entry.filename}"
                dst_entry_path = f"{dst_dir}/{entry.filename}"

                if entry.st_mode & 0o040000:  # Is directory
                    success, error = transfer_directory_recursive(src_entry_path, dst_entry_path)
                    if not success:
                        return False, error
                else:
                    success, error = transfer_single_file(src_entry_path, dst_entry_path)
                    if not success:
                        return False, error

            return True, None

        # Emit transfer started
        if socketio_instance and user_room:
            socketio_instance.emit('s2s_transfer_started', {
                'transfer_id': transfer_id,
                'source_path': source_path,
                'dest_path': dest_path,
                'is_dir': is_dir
            }, room=user_room)

        # Perform transfer
        if is_dir:
            success, error = transfer_directory_recursive(source_path, dest_path)
        else:
            success, error = transfer_single_file(source_path, dest_path)

        # Close SFTP connections that came from sessions (pool ones persist)
        if source_type == 'session':
            sftp_source.close()
        if dest_type == 'session':
            sftp_dest.close()

        # Emit completion
        if success and socketio_instance and user_room:
            socketio_instance.emit('s2s_transfer_complete', {
                'transfer_id': transfer_id,
                'source_path': source_path,
                'dest_path': dest_path
            }, room=user_room)

        return success, error

    except Exception as e:
        error_msg = str(e)
        if socketio_instance and user_room:
            socketio_instance.emit('s2s_transfer_error', {
                'transfer_id': transfer_id,
                'error': error_msg
            }, room=user_room)
        return False, error_msg
