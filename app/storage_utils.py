"""Shared helpers for per-user JSON storage: atomic writes and per-key locks.

Writes go to a temp file and are swapped in with os.replace, so a crash mid-write
can never leave a truncated (and thus silently emptied) file. A per-key lock
serializes the load-modify-save cycle so two concurrent events for the same user
(e.g. two browser tabs) cannot lose an update. The locks are process-local native
thread locks in the gthread runtime; dependency resolution remains
platform-neutral.
"""
import json
import os
from pathlib import Path
import tempfile
import threading
from typing import Callable, TypeVar

from .storage_errors import StorageCorruptionError


T = TypeVar('T')

_locks = {}
_locks_guard = threading.Lock()


def safe_reference_name(value):
    """Return bounded printable display text for cross-store references."""
    value = value if isinstance(value, str) else ''
    return ''.join(
        character if character.isprintable() else '\ufffd'
        for character in value
    )[:128]


def storage_lock(key):
    """Return a process-wide lock for a logical storage key (e.g. 'profiles:3').

    Use as a context manager around a full load-modify-save cycle:
        with storage_lock(f'profiles:{user_id}'):
            items = load(...); items.append(...); save(...)
    """
    with _locks_guard:
        lock = _locks.get(key)
        if lock is None:
            lock = threading.Lock()
            _locks[key] = lock
    return lock


def load_json_strict(
    path: Path,
    default_factory: Callable[[], T],
    validator: Callable[[object], bool],
) -> T:
    """Load and validate JSON without treating corrupt data as missing."""
    path = Path(path)
    try:
        handle = path.open('r', encoding='utf-8')
    except FileNotFoundError:
        return default_factory()
    except OSError as exc:
        raise StorageCorruptionError(path, 'read failed') from exc

    try:
        with handle:
            value = json.load(handle)
    except json.JSONDecodeError as exc:
        raise StorageCorruptionError(path, 'invalid JSON') from exc
    except UnicodeError as exc:
        raise StorageCorruptionError(path, 'invalid Unicode') from exc
    except OSError as exc:
        raise StorageCorruptionError(path, 'read failed') from exc

    try:
        valid = validator(value)
    except Exception as exc:
        raise StorageCorruptionError(path, 'validation failed') from exc
    if not valid:
        raise StorageCorruptionError(path, 'validation failed')
    return value


def load_json_migrated(
    path: Path,
    store_name: str,
    default_factory: Callable[[], T],
    validator: Callable[[object], bool],
) -> T:
    """Load a current document, migrating an existing legacy file in place.

    The caller must hold the store's ``storage_lock`` so backup, migration, and
    the active-file replace are part of the same serialized operation.
    """
    path = Path(path)
    from .storage_migrations import migrate_file

    return migrate_file(
        path,
        store_name,
        validator,
        default_factory=default_factory,
    )


def fsync_parent_directory(path: Path) -> None:
    """Persist a directory-entry change on platforms supporting directory FDs."""
    if os.name == 'nt' or not hasattr(os, 'O_DIRECTORY'):
        return

    directory = Path(path).parent
    descriptor = os.open(
        directory,
        os.O_RDONLY | os.O_DIRECTORY,
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write_bytes(path: Path, payload: bytes, mode: int = 0o600) -> None:
    """Durably replace ``path`` with ``payload`` using a sibling temp file.

    If the final directory fsync fails, the exception is surfaced even though
    ``os.replace`` has already made the new file active.
    """
    path = Path(path)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='wb',
            dir=path.parent,
            prefix=f'.{path.name}.',
            suffix='.tmp',
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, path)
        temporary_path = None
        fsync_parent_directory(path)
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass


def atomic_write_json(path, data, indent=2):
    """Atomically write ``data`` as JSON to ``path`` via a temp file + os.replace.

    Callers should hold the relevant storage_lock around a load-modify-save
    cycle so concurrent writers cannot lose updates.
    """
    payload = json.dumps(data, indent=indent).encode('utf-8')
    atomic_write_bytes(Path(path), payload)
