"""Backend-neutral, bounded remote-to-remote file streaming."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import posixpath
import threading

import config

from .smb_backend import FileConflict, NonAtomicOverwriteRequired
from .smb_protocol import SMBProtocolError


class RemoteTransferError(RuntimeError):
    """A remote copy failed without exposing backend-specific details."""


class RemoteTransferCancelled(RemoteTransferError):
    pass


class RemoteTransferLimitExceeded(RemoteTransferError):
    pass


class RemoteTransferConflict(RemoteTransferError):
    pass


class TransferBudget:
    """Shared byte/member limits for one copy operation."""

    def __init__(self, *, max_bytes, max_members, max_depth=50):
        if type(max_bytes) is not int or max_bytes < 1:
            raise ValueError('max_bytes must be a positive integer')
        if type(max_members) is not int or max_members < 1:
            raise ValueError('max_members must be a positive integer')
        if type(max_depth) is not int or max_depth < 0:
            raise ValueError('max_depth must be a non-negative integer')
        self.max_bytes = max_bytes
        self.max_members = max_members
        self.max_depth = max_depth
        self.bytes_used = 0
        self.members_used = 0

    def consume(self):
        self.members_used += 1
        if self.members_used > self.max_members:
            raise RemoteTransferLimitExceeded('Transfer member limit exceeded')

    def ensure_declared_bytes(self, count):
        if type(count) is not int or count < 0:
            raise RemoteTransferLimitExceeded('Invalid remote file size')
        if self.bytes_used + count > self.max_bytes:
            raise RemoteTransferLimitExceeded('Transfer size limit exceeded')

    def consume_bytes(self, count):
        if type(count) is not int or count < 0:
            raise RemoteTransferLimitExceeded('Invalid transfer chunk')
        self.bytes_used += count
        if self.bytes_used > self.max_bytes:
            raise RemoteTransferLimitExceeded('Transfer size limit exceeded')


_SOURCE_LOCKS_GUARD = threading.Lock()
_SOURCE_LOCKS = {}


@contextmanager
def _ordered_source_locks(source_ids, cancel_event):
    """Serialize transfers touching the same sources in canonical order."""
    source_ids = tuple(source_ids)
    if not source_ids or any(
        not isinstance(source_id, str) or not source_id
        for source_id in source_ids
    ):
        raise RemoteTransferError('Invalid file source')
    canonical_ids = tuple(sorted(set(source_ids)))

    with _SOURCE_LOCKS_GUARD:
        entries = []
        for source_id in canonical_ids:
            entry = _SOURCE_LOCKS.get(source_id)
            if entry is None:
                entry = [threading.Lock(), 0]
                _SOURCE_LOCKS[source_id] = entry
            entry[1] += 1
            entries.append((source_id, entry))

    acquired = []
    try:
        for _source_id, entry in entries:
            while not entry[0].acquire(timeout=0.1):
                _check_cancelled(cancel_event)
            acquired.append(entry[0])
            _check_cancelled(cancel_event)
        yield
    finally:
        for lock in reversed(acquired):
            lock.release()
        with _SOURCE_LOCKS_GUARD:
            for source_id, entry in entries:
                entry[1] -= 1
                if entry[1] == 0:
                    _SOURCE_LOCKS.pop(source_id, None)


@dataclass(frozen=True)
class TransferResult:
    bytes_transferred: int
    members: int
    sha256: str


def _cancelled(cancel_event):
    return cancel_event is not None and cancel_event.is_set()


def _check_cancelled(cancel_event):
    if _cancelled(cancel_event):
        raise RemoteTransferCancelled('Transfer cancelled')


def _normalize(source, path):
    normalized = source.backend.normalize_path(path)
    if not isinstance(normalized, str) or not normalized.startswith('/'):
        raise RemoteTransferError('Invalid remote path')
    return normalized


def _write_all(remote_file, chunk):
    view = memoryview(chunk)
    offset = 0
    while offset < len(view):
        written = remote_file.write(view[offset:])
        if written is None:
            written = len(view) - offset
        if isinstance(written, bool) or not isinstance(written, int) or written <= 0:
            raise RemoteTransferError('Destination write failed')
        offset += written


def _stat_or_raise(source, path):
    operation = getattr(source.backend, 'stat_or_raise', None)
    if callable(operation):
        return operation(source, path, follow_links=False)
    file_stat, error = source.backend.stat(
        source, path, follow_links=False
    )
    if error:
        raise RemoteTransferError('Source unavailable')
    return file_stat


def _copy_file(
    source,
    source_path,
    destination,
    destination_path,
    *,
    replace,
    budget,
    cancel_event,
    progress,
    chunk_size,
    digest,
):
    file_stat = _stat_or_raise(source, source_path)
    if not file_stat or file_stat.get('is_dir'):
        raise RemoteTransferError('Source file unavailable')
    if file_stat.get('is_symlink'):
        raise RemoteTransferError('Reparse points are not supported')
    declared_size = int(file_stat.get('size', 0))
    budget.ensure_declared_bytes(declared_size)
    _check_cancelled(cancel_event)

    copied = 0
    try:
        with source.backend.open_reader(
            source, source_path, io_lane='transfer'
        ) as reader:
            with destination.backend.open_atomic_writer(
                destination,
                destination_path,
                replace=replace,
                cancel_event=cancel_event,
                io_lane='transfer',
            ) as writer:
                while True:
                    _check_cancelled(cancel_event)
                    chunk = reader.read(chunk_size)
                    if not chunk:
                        break
                    if not isinstance(chunk, (bytes, bytearray, memoryview)):
                        raise RemoteTransferError('Source read failed')
                    chunk = bytes(chunk)
                    budget.consume_bytes(len(chunk))
                    _check_cancelled(cancel_event)
                    _write_all(writer, chunk)
                    copied += len(chunk)
                    digest.update(chunk)
                    if progress is not None:
                        progress({
                            'path': source_path,
                            'transferred': budget.bytes_used,
                            'file_transferred': copied,
                            'file_size': declared_size,
                        })
                _check_cancelled(cancel_event)
    except (
        RemoteTransferError,
        RemoteTransferCancelled,
        FileConflict,
        NonAtomicOverwriteRequired,
        SMBProtocolError,
        PermissionError,
        FileNotFoundError,
        TimeoutError,
        ConnectionError,
    ):
        raise
    except FileExistsError as exc:
        raise RemoteTransferConflict('Destination exists') from exc
    except Exception as exc:
        if _cancelled(cancel_event):
            raise RemoteTransferCancelled('Transfer cancelled') from exc
        raise RemoteTransferError('Remote copy failed') from exc
    return copied


def _relative_child(root, child):
    prefix = root.rstrip('/')
    if not prefix:
        return child.lstrip('/')
    if child == prefix or not child.startswith(prefix + '/'):
        raise RemoteTransferError('Unsafe recursive source path')
    return child[len(prefix) + 1:]


def _destination_child(root, relative):
    result = posixpath.join(root.rstrip('/') or '/', relative)
    return result if result.startswith('/') else '/' + result


def _ensure_directory(destination, path, *, allow_existing=True):
    check_exists = getattr(
        destination.backend, 'check_exists_or_raise', None
    )
    if callable(check_exists):
        exists = check_exists(destination, path)
    else:
        exists, error = destination.backend.check_exists(destination, path)
        if error:
            raise RemoteTransferError('Destination unavailable')
    if exists and exists.get('exists'):
        if (
            not exists.get('is_dir')
            or not allow_existing
        ):
            raise RemoteTransferConflict('Destination exists')
        return
    mkdir = getattr(destination.backend, 'mkdir_or_raise', None)
    if callable(mkdir):
        mkdir(destination, path)
    else:
        success, error = destination.backend.mkdir(destination, path)
        if not success or error:
            raise RemoteTransferError('Destination directory unavailable')


def _copy_remote_entry_locked(
    source,
    source_path,
    destination,
    destination_path,
    conflict_policy,
    budget,
    cancel_event,
    progress,
    *,
    chunk_size=None,
):
    """Copy one file or directory while its source set is admitted."""
    if not isinstance(budget, TransferBudget):
        raise ValueError('budget must be a TransferBudget')
    if conflict_policy not in {'error', 'replace'}:
        raise ValueError('unsupported conflict policy')
    chunk_size = config.CHUNK_SIZE if chunk_size is None else chunk_size
    if type(chunk_size) is not int or chunk_size < 1:
        raise ValueError('chunk_size must be a positive integer')

    source_path = _normalize(source, source_path)
    destination_path = _normalize(destination, destination_path)
    if (
        source.source_id == destination.source_id
        and source_path == destination_path
    ):
        raise RemoteTransferConflict('Source and destination are identical')
    _check_cancelled(cancel_event)

    source_stat = _stat_or_raise(source, source_path)
    if not source_stat:
        raise RemoteTransferError('Source unavailable')
    if source_stat.get('is_symlink'):
        raise RemoteTransferError('Reparse points are not supported')

    digest = hashlib.sha256()
    if not source_stat.get('is_dir'):
        copied = _copy_file(
            source,
            source_path,
            destination,
            destination_path,
            replace=conflict_policy == 'replace',
            budget=budget,
            cancel_event=cancel_event,
            progress=progress,
            chunk_size=chunk_size,
            digest=digest,
        )
        return TransferResult(copied, 1, digest.hexdigest())

    entries = list(source.backend.iter_tree(
        source,
        source_path,
        budget=budget,
        cancel_event=cancel_event,
        follow_links=False,
        io_lane='transfer',
    ))
    if any(entry.get('is_symlink') for entry in entries):
        raise RemoteTransferError('Reparse points are not supported')
    declared_total = 0
    for entry in entries:
        relative = _relative_child(source_path, entry.get('path'))
        depth = relative.count('/') + 1
        if depth > budget.max_depth:
            raise RemoteTransferLimitExceeded('Transfer depth limit exceeded')
        if not entry.get('is_dir'):
            declared_size = entry.get('size', 0)
            if (
                isinstance(declared_size, bool)
                or not isinstance(declared_size, int)
                or declared_size < 0
            ):
                raise RemoteTransferLimitExceeded('Invalid remote file size')
            declared_total += declared_size
            if budget.bytes_used + declared_total > budget.max_bytes:
                raise RemoteTransferLimitExceeded(
                    'Transfer size limit exceeded'
                )

    _check_cancelled(cancel_event)
    _ensure_directory(
        destination,
        destination_path,
        allow_existing=conflict_policy == 'replace',
    )
    directories = sorted(
        (entry for entry in entries if entry.get('is_dir')),
        key=lambda entry: entry['path'].count('/'),
    )
    for entry in directories:
        _check_cancelled(cancel_event)
        _ensure_directory(
            destination,
            _destination_child(
                destination_path,
                _relative_child(source_path, entry['path']),
            ),
        )

    for entry in entries:
        if entry.get('is_dir'):
            continue
        relative = _relative_child(source_path, entry['path'])
        digest.update(relative.encode('utf-8'))
        _copy_file(
            source,
            entry['path'],
            destination,
            _destination_child(destination_path, relative),
            replace=conflict_policy == 'replace',
            budget=budget,
            cancel_event=cancel_event,
            progress=progress,
            chunk_size=chunk_size,
            digest=digest,
        )
    return TransferResult(
        budget.bytes_used,
        budget.members_used,
        digest.hexdigest(),
    )


def copy_remote_entry(
    source,
    source_path,
    destination,
    destination_path,
    conflict_policy,
    budget,
    cancel_event,
    progress,
    *,
    chunk_size=None,
):
    """Copy one entry after deadlock-safe admission for both file sources."""
    with _ordered_source_locks(
        (source.source_id, destination.source_id),
        cancel_event,
    ):
        return _copy_remote_entry_locked(
            source,
            source_path,
            destination,
            destination_path,
            conflict_policy,
            budget,
            cancel_event,
            progress,
            chunk_size=chunk_size,
        )
