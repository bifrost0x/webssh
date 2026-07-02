"""Shared helpers for per-user JSON storage: atomic writes and per-key locks.

Writes go to a temp file and are swapped in with os.replace, so a crash mid-write
can never leave a truncated (and thus silently emptied) file. A per-key lock
serializes the load-modify-save cycle so two concurrent events for the same user
(e.g. two browser tabs) cannot lose an update. The locks are cooperative greenlet
locks under eventlet's monkey-patched threading.
"""
import json
import os
import threading

_locks = {}
_locks_guard = threading.Lock()


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


def atomic_write_json(path, data, indent=2):
    """Atomically write ``data`` as JSON to ``path`` via a temp file + os.replace.

    Callers should hold the relevant storage_lock so the fixed .tmp name cannot
    be contended by a concurrent writer to the same file.
    """
    path = str(path)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=indent)
    os.replace(tmp, path)
