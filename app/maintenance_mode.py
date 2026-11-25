"""Restore maintenance and restart-surviving operation status."""

from hashlib import sha256
import json
import os
from pathlib import Path, PurePath
import stat
import tempfile
import threading
import time

import config

from .audit_logger import log_error
from .backup_coordination import ensure_backup_temp_dir, operation_lock


_lock = threading.RLock()
_state = None
_state_path = None
# Resolved status file per configured location. Only the read path uses it:
# is_active() runs on every request and socket event, and the full namespace
# validation creates, chmods and resolves directories each time. Cached reads
# still lstat the operation root and namespace. Writers and the operation
# lock keep validating on every call.
_read_location = None
_STATUS_NAME = 'restore-status.json'
_KNOWN_STATES = {
    'preparing', 'in_progress', 'succeeded', 'failed', 'rollback_failed',
}


def _unreadable_status():
    return {
        'state': 'rollback_failed',
        'message': 'Restore status is unreadable',
        'updated_at': time.time(),
    }


def _valid_status_document(document) -> bool:
    """Reject every malformed persisted state instead of failing open."""
    if not isinstance(document, dict):
        return False
    state = document.get('state')
    if state not in _KNOWN_STATES:
        return False
    if (
        not isinstance(document.get('operation_id'), str)
        or not document['operation_id']
        or len(document['operation_id']) > 256
        or not isinstance(document.get('message'), str)
        or type(document.get('updated_at')) not in {int, float}
    ):
        return False
    fingerprint = document.get('data_fingerprint')
    if fingerprint is not None and (
        not isinstance(fingerprint, str)
        or len(fingerprint) != 64
        or any(character not in '0123456789abcdef' for character in fingerprint)
    ):
        return False
    rollback_relative = document.get('rollback_relative')
    if rollback_relative is not None:
        if not isinstance(rollback_relative, str):
            return False
        path = PurePath(rollback_relative)
        if path.is_absolute() or '..' in path.parts or len(path.parts) != 2:
            return False
    if state == 'in_progress' and (
        fingerprint is None or rollback_relative is None
    ):
        return False
    if state == 'preparing' and fingerprint is None:
        return False
    return True


def _status_path() -> Path:
    return ensure_backup_temp_dir() / _STATUS_NAME


def _status_location_key():
    return (
        str(config.BACKUP_TEMP_DIR),
        str(config.DATA_DIR),
        str(config.BASE_DIR),
    )


def _directory_identity(directory: Path):
    """Return the lstat identity of a private directory, or None if unsafe.

    Mirrors what ensure_backup_temp_dir() establishes: a real directory, not
    a symlink, owned by this process and without group or other access. Root
    may use a directory owned by another account, such as a bind mount,
    because ensure_backup_temp_dir() accepts and restricts it as well.
    """
    try:
        metadata = os.lstat(directory)
    except OSError:
        return None
    if not stat.S_ISDIR(metadata.st_mode):
        return None
    if os.name != 'nt' and (
        metadata.st_mode & 0o077
        or (os.geteuid() != 0 and metadata.st_uid != os.geteuid())
    ):
        return None
    return (metadata.st_dev, metadata.st_ino)


def _status_directory_identities(path: Path):
    identities = tuple(
        _directory_identity(directory)
        for directory in (path.parent.parent, path.parent)
    )
    return None if None in identities else identities


def _read_status_path() -> Path:
    global _read_location
    key = _status_location_key()
    cached = _read_location
    if cached is not None and cached[0] == key:
        if _status_directory_identities(cached[1]) == cached[2]:
            return cached[1]
        # The namespace was removed, replaced or changed ownership or mode
        # since it was validated. A document this process wrote or read stays
        # in force for the same path, so removing the directory cannot end
        # maintenance; only a file planted while none was cached is read anew
        # after full validation.
    # Unknown or changed locations run the full validation again, so an
    # unsafe directory raises here.
    _read_location = None
    path = _status_path().resolve(strict=False)
    identities = _status_directory_identities(path)
    if identities is not None:
        _read_location = (key, path, identities)
    return path


def _data_fingerprint() -> str:
    value = str(Path(config.DATA_DIR).resolve(strict=False)).encode('utf-8')
    return sha256(value).hexdigest()


def _write(document) -> None:
    global _state, _state_path
    root = ensure_backup_temp_dir()
    target = root / _STATUS_NAME
    temporary = None
    payload = json.dumps(
        document, sort_keys=True, separators=(',', ':')
    ).encode('utf-8')
    try:
        with tempfile.NamedTemporaryFile(
            mode='wb', dir=root, prefix='.restore-status-', delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
        from .storage_utils import fsync_parent_directory
        fsync_parent_directory(target)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    _state = dict(document)
    _state_path = target.resolve(strict=False)


def _read():
    global _state, _state_path
    path = _read_status_path()
    if _state is not None and _state_path == path:
        return dict(_state)
    try:
        payload = path.read_bytes()
        document = json.loads(payload.decode('utf-8'))
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError, json.JSONDecodeError):
        return _unreadable_status()
    if not _valid_status_document(document):
        return _unreadable_status()
    _state = document
    _state_path = path
    return dict(document)


def is_active() -> bool:
    document = _read()
    return bool(document and document.get('state') in {
        'preparing', 'in_progress', 'rollback_failed',
    })


def begin_preparing(operation_id: str) -> None:
    _write({
        'state': 'preparing',
        'operation_id': str(operation_id),
        'data_fingerprint': _data_fingerprint(),
        'message': 'Preparing restore safety snapshot',
        'updated_at': time.time(),
    })


def mark_in_progress(operation_id: str, rollback_relative: str) -> None:
    path = PurePath(rollback_relative)
    if path.is_absolute() or '..' in path.parts or len(path.parts) != 2:
        raise ValueError('unsafe rollback reference')
    _write({
        'state': 'in_progress',
        'operation_id': str(operation_id),
        'data_fingerprint': _data_fingerprint(),
        'rollback_relative': path.as_posix(),
        'message': 'Restoring persistent state',
        'updated_at': time.time(),
    })


def mark_succeeded(operation_id: str) -> None:
    _write({
        'state': 'succeeded',
        'operation_id': str(operation_id),
        'message': 'Restore completed; application restart requested',
        'updated_at': time.time(),
    })


def mark_failed(operation_id: str, message: str, *, rollback_failed=False) -> None:
    previous = _read() if rollback_failed else None
    document = {
        'state': 'rollback_failed' if rollback_failed else 'failed',
        'operation_id': str(operation_id),
        'message': str(message)[:256],
        'updated_at': time.time(),
    }
    if (
        rollback_failed
        and previous
        and previous.get('operation_id') == str(operation_id)
    ):
        for key in ('data_fingerprint', 'rollback_relative'):
            if key in previous:
                document[key] = previous[key]
    _write(document)


def protected_operation_directory_name():
    """Return the rollback-failure directory that startup must preserve."""
    document = _read()
    if not document or document.get('state') != 'rollback_failed':
        return None
    operation_id = str(document.get('operation_id') or '')
    path = PurePath(operation_id)
    if (
        not operation_id
        or path.is_absolute()
        or len(path.parts) != 1
        or operation_id in {'.', '..'}
    ):
        return None
    return f'operation-{operation_id}'


def clear_failed_status_after_cli_restore() -> None:
    """Leave recovery maintenance after a successful explicit CLI restore."""
    global _state, _state_path
    document = _read()
    if not document or document.get('state') != 'rollback_failed':
        return
    path = _status_path()
    path.unlink(missing_ok=True)
    from .storage_utils import fsync_parent_directory
    fsync_parent_directory(path)
    _state = None
    _state_path = None


def public_status():
    document = _read()
    if document is None:
        return {'state': 'idle', 'message': None}
    if (
        document.get('state') not in {'preparing', 'in_progress', 'rollback_failed'}
        and time.time() - float(document.get('updated_at', 0))
        > config.BACKUP_OPERATION_TIMEOUT
    ):
        try:
            _status_path().unlink()
        except FileNotFoundError:
            pass
        global _state, _state_path
        _state = None
        _state_path = None
        return {'state': 'idle', 'message': None}
    return {
        'state': document.get('state', 'failed'),
        'message': document.get('message'),
    }


def recover_interrupted_restore() -> None:
    """Rollback an interrupted restore before database initialization."""
    document = _read()
    if not document or document.get('state') not in {'preparing', 'in_progress'}:
        return
    operation_id = str(document.get('operation_id') or 'unknown')
    if document.get('data_fingerprint') != _data_fingerprint():
        mark_failed(
            operation_id,
            'Interrupted restore belongs to another data directory',
            rollback_failed=True,
        )
        return
    if document.get('state') == 'preparing':
        mark_failed(operation_id, 'Restore stopped before persistent state changed')
        return

    relative = PurePath(str(document.get('rollback_relative') or ''))
    if relative.is_absolute() or '..' in relative.parts or len(relative.parts) != 2:
        mark_failed(
            operation_id,
            'Interrupted restore has no safe rollback reference',
            rollback_failed=True,
        )
        return
    rollback = ensure_backup_temp_dir() / Path(*relative.parts)
    try:
        from .backup_manager import _restore_recovery_snapshot
        from .restore_sanitizer import sanitize_restored_authentication_state
        from .session_epoch import reset_cache, rotate_epoch

        with operation_lock():
            _restore_recovery_snapshot(rollback, config.DATA_DIR)
            sanitize_restored_authentication_state(
                Path(config.DATA_DIR) / 'app.db'
            )
            reset_cache()
            rotate_epoch()
        mark_failed(operation_id, 'Interrupted restore rolled back automatically')
    except Exception as exc:
        log_error(
            'Interrupted restore rollback failed',
            error_type=type(exc).__name__,
        )
        mark_failed(
            operation_id,
            'Interrupted restore rollback failed; use the CLI recovery path',
            rollback_failed=True,
        )
