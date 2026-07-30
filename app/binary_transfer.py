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

import io
import os
from . import sftp_handler
import config

def handle_binary_download(session_id, remote_path, socketio_instance=None,
                           max_size=None):
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

            limit = config.MAX_DOWNLOAD_SIZE if max_size is None else max_size
            if file_size > limit:
                max_mb = limit // (1024 * 1024)
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

                    observed_size = transferred + len(chunk)
                    if observed_size > limit:
                        max_mb = limit // (1024 * 1024)
                        return None, (
                            "File too large for download "
                            f"({observed_size // (1024 * 1024)}MB). "
                            f"Maximum: {max_mb}MB"
                        )

                    binary_data.write(chunk)
                    transferred = observed_size

                    if socketio_instance:
                        progress_total = max(file_size, transferred, 1)
                        percent = min(
                            100,
                            int((transferred / progress_total) * 100),
                        )
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
