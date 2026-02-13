"""
Binary File Transfer Module

Handles efficient binary file transfers over WebSocket without base64 encoding.
Provides 33% reduction in transfer size and better performance.

Features:
- Direct binary streaming to/from SFTP
- Chunked transfer with progress tracking
- Pause/resume capability (future enhancement)
- Memory-efficient streaming
"""

import os
import io
from . import sftp_handler
import config

def handle_binary_upload(session_id, filename, binary_data, remote_path, socketio_instance=None):
    """
    Upload binary data directly to SFTP without base64 encoding.

    Args:
        session_id (str): SSH session ID
        filename (str): Name of the file being uploaded
        binary_data (bytes): Raw binary file data
        remote_path (str): Target path on remote server
        socketio_instance: SocketIO instance for progress updates

    Returns:
        tuple: (success: bool, error: str or None)
    """
    try:
        max_size_mb = config.MAX_UPLOAD_SIZE // (1024 * 1024)
        valid, error = validate_binary_data(binary_data, max_size_mb=max_size_mb)
        if not valid:
            return False, error

        safe_path = sftp_handler.sanitize_path(remote_path)
        if safe_path is None:
            return False, "Invalid remote path"

        total_size = len(binary_data)
        chunk_size = 65536
        transferred = 0

        with sftp_handler.sftp_session(session_id) as (sftp, source_type):
            with sftp.file(safe_path, 'wb') as remote_file:
                data_stream = io.BytesIO(binary_data)

                while True:
                    chunk = data_stream.read(chunk_size)
                    if not chunk:
                        break

                    remote_file.write(chunk)
                    transferred += len(chunk)

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

            if socketio_instance:
                socketio_instance.emit('file_complete', {
                    'session_id': session_id,
                    'type': 'upload',
                    'filename': filename,
                    'remote_path': safe_path
                })

        return True, None

    except sftp_handler.SFTPOperationError as e:
        return False, str(e)
    except PermissionError:
        return False, "Permission denied: Cannot write to remote path"
    except FileNotFoundError:
        return False, "Remote directory not found"
    except Exception as e:
        return False, str(e)

def handle_binary_download(session_id, remote_path, socketio_instance=None):
    """
    Download file as binary data without base64 encoding.

    Args:
        session_id (str): SSH session ID or connection ID (for Quick Connect)
        remote_path (str): Path to file on remote server
        socketio_instance: SocketIO instance for progress updates

    Returns:
        tuple: (binary_data: bytes or None, error: str or None)
    """
    try:
        safe_path = sftp_handler.sanitize_path(remote_path)
        if safe_path is None:
            return None, "Invalid remote path"

        with sftp_handler.sftp_session(session_id) as (sftp, source_type):
            try:
                file_stat = sftp.stat(safe_path)
                file_size = file_stat.st_size
            except FileNotFoundError:
                return None, "Remote file not found"

            if file_size > config.MAX_DOWNLOAD_SIZE:
                max_mb = config.MAX_DOWNLOAD_SIZE // (1024 * 1024)
                return None, f"File too large for download ({file_size // (1024*1024)}MB). Maximum: {max_mb}MB"

            filename = os.path.basename(safe_path)
            chunk_size = 65536
            transferred = 0

            binary_data = io.BytesIO()

            with sftp.file(safe_path, 'rb') as remote_file:
                while True:
                    chunk = remote_file.read(chunk_size)
                    if not chunk:
                        break

                    binary_data.write(chunk)
                    transferred += len(chunk)

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

            return binary_data.getvalue(), None

    except sftp_handler.SFTPOperationError as e:
        return None, str(e)
    except PermissionError:
        return None, "Permission denied: Cannot read from remote path"
    except FileNotFoundError:
        return None, "Remote file not found"
    except Exception as e:
        return None, str(e)

def stream_binary_upload_chunked(session_id, filename, chunks, remote_path, socketio_instance=None):
    """
    Handle streaming upload of large files sent in multiple chunks.

    This is useful for very large files that cannot be sent in a single WebSocket message.

    Args:
        session_id (str): SSH session ID
        filename (str): Name of the file being uploaded
        chunks (list): List of binary chunks
        remote_path (str): Target path on remote server
        socketio_instance: SocketIO instance for progress updates

    Returns:
        tuple: (success: bool, error: str or None)
    """
    try:
        safe_path = sftp_handler.sanitize_path(remote_path)
        if safe_path is None:
            return False, "Invalid remote path"

        total_size = sum(len(chunk) for chunk in chunks)
        transferred = 0

        with sftp_handler.sftp_session(session_id) as (sftp, source_type):
            with sftp.file(safe_path, 'wb') as remote_file:
                for i, chunk in enumerate(chunks):
                    remote_file.write(chunk)
                    transferred += len(chunk)

                    if socketio_instance and (i % 10 == 0 or i == len(chunks) - 1):
                        percent = int((transferred / total_size) * 100)
                        socketio_instance.emit('file_progress', {
                            'session_id': session_id,
                            'type': 'upload',
                            'filename': filename,
                            'transferred': transferred,
                            'total': total_size,
                            'percent': percent
                        })

            if socketio_instance:
                socketio_instance.emit('file_complete', {
                    'session_id': session_id,
                    'type': 'upload',
                    'filename': filename,
                    'remote_path': safe_path
                })

        return True, None

    except sftp_handler.SFTPOperationError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)

def get_file_info(session_id, remote_path):
    """
    Get information about a remote file.

    Args:
        session_id (str): SSH session ID
        remote_path (str): Path to file on remote server

    Returns:
        tuple: (file_info: dict or None, error: str or None)
    """
    try:
        safe_path = sftp_handler.sanitize_path(remote_path)
        if safe_path is None:
            return None, "Invalid remote path"

        with sftp_handler.sftp_session(session_id) as (sftp, source_type):
            stat = sftp.stat(safe_path)

            info = {
                'filename': os.path.basename(safe_path),
                'size': stat.st_size,
                'modified': stat.st_mtime,
                'is_dir': stat.st_mode & 0o040000 != 0,
                'permissions': oct(stat.st_mode)[-3:]
            }

            return info, None

    except sftp_handler.SFTPOperationError as e:
        return None, str(e)
    except FileNotFoundError:
        return None, "File not found"
    except Exception as e:
        return None, str(e)

def validate_binary_data(binary_data, max_size_mb=1024):
    """
    Validate binary data before transfer.

    Args:
        binary_data (bytes): Binary data to validate
        max_size_mb (int): Maximum allowed size in megabytes

    Returns:
        tuple: (valid: bool, error: str or None)
    """
    if not isinstance(binary_data, (bytes, bytearray)):
        return False, "Data must be bytes or bytearray"

    max_size_bytes = max_size_mb * 1024 * 1024
    if len(binary_data) > max_size_bytes:
        return False, f"File size exceeds maximum allowed size of {max_size_mb}MB"

    return True, None
