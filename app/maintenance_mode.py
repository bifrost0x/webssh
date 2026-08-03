"""Restore maintenance and restart-surviving operation status."""

from hashlib import sha256
import json
import os
from pathlib import Path, PurePath
import tempfile
import threading
import time

import config

from .backup_coordination import ensure_backup_temp_dir, operation_lock


_lock = threading.RLock()
_state = None
_state_path = None
_STATUS_NAME = 'restore-status.json'


def _status_path() -> Path:
    return ensure_backup_temp_dir() / _STATUS_NAME


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
    path = _status_path().resolve(strict=False)
    if _state is not None and _state_path == path:
        return dict(_state)
    try:
        payload = path.read_bytes()
        document = json.loads(payload.decode('utf-8'))
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {
            'state': 'rollback_failed',
            'message': 'Restore status is unreadable',
            'updated_at': time.time(),
        }
    if not isinstance(document, dict):
        return None
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
        mark_failed(operation_id, 'Interrupted restore belongs to another data directory')
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
        from .backup_manager import restore_backup
        from .session_epoch import reset_cache, rotate_epoch

        with operation_lock():
            restore_backup(rollback, config.DATA_DIR)
            reset_cache()
            rotate_epoch()
        mark_failed(operation_id, 'Interrupted restore rolled back automatically')
    except Exception:
        mark_failed(
            operation_id,
            'Interrupted restore rollback failed; use the CLI recovery path',
            rollback_failed=True,
        )
