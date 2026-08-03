"""Server-side generation used to invalidate every browser login session."""

from pathlib import Path
import secrets
import threading

import config

from .storage_utils import atomic_write_bytes


_lock = threading.RLock()
_cached = None
_cached_path = None


def _path() -> Path:
    return Path(config.DATA_DIR) / 'session_epoch'


def _valid(value: str) -> bool:
    return (
        len(value) == 64
        and all(character in '0123456789abcdef' for character in value)
    )


def current_epoch() -> str:
    global _cached, _cached_path
    with _lock:
        path = _path().resolve(strict=False)
        if _cached is not None and _cached_path == path:
            return _cached
        try:
            value = path.read_text(encoding='ascii').strip()
        except FileNotFoundError:
            return rotate_epoch()
        if not _valid(value):
            raise RuntimeError('persisted session epoch is invalid')
        _cached = value
        _cached_path = path
        return value


def rotate_epoch() -> str:
    global _cached, _cached_path
    with _lock:
        value = secrets.token_hex(32)
        path = _path()
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_bytes(path, (value + '\n').encode('ascii'), mode=0o600)
        _cached = value
        _cached_path = path.resolve(strict=False)
        return value


def reset_cache() -> None:
    global _cached, _cached_path
    with _lock:
        _cached = None
        _cached_path = None
