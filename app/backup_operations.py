"""Private, session-bound lifecycle for web backup archives."""

from dataclasses import dataclass, field
from pathlib import Path
import os
import secrets
import shutil
import stat
import threading
import time

import config

from .backup_coordination import (
    OperationBusyError,
    ensure_backup_temp_dir,
    operation_lock,
)


_ACTIVE_STATUSES = frozenset({
    'pending', 'running', 'uploading', 'verifying', 'downloading', 'restoring',
})


@dataclass
class BackupOperation:
    operation_id: str
    kind: str
    owner_id: int
    session_id: str
    directory: Path
    archive_path: Path
    status: str
    created_at: float
    expires_at: float
    size: int = 0
    summary: dict | None = None
    error: str | None = None
    metadata: dict = field(default_factory=dict)


def _is_reparse_point(metadata) -> bool:
    attributes = getattr(metadata, 'st_file_attributes', 0)
    reparse = getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)
    return bool(attributes & reparse)


def _remove_private_tree(root: Path, directory: Path) -> None:
    root = root.resolve(strict=True)
    directory = Path(directory)
    try:
        metadata = directory.lstat()
    except FileNotFoundError:
        return
    resolved = directory.resolve(strict=True)
    if (
        resolved.parent != root
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse_point(metadata)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise RuntimeError('refusing unsafe backup operation cleanup')
    shutil.rmtree(resolved)


class BackupOperationRegistry:
    def __init__(self):
        self._lock = threading.RLock()
        self._records = {}
        self._root = None

    def _operation_root(self) -> Path:
        configured_root = ensure_backup_temp_dir()
        if self._root != configured_root:
            if self._records:
                raise RuntimeError(
                    'BACKUP_TEMP_DIR changed while operations were active'
                )
            self._root = configured_root
        return self._root

    def _cleanup_expired_locked(self, now=None):
        now = time.time() if now is None else now
        expired = [
            operation_id
            for operation_id, record in self._records.items()
            if record.expires_at <= now and record.status not in _ACTIVE_STATUSES
        ]
        for operation_id in expired:
            self._remove_locked(operation_id)

    def create(self, kind, owner_id, session_id, status='pending'):
        with self._lock:
            self._cleanup_expired_locked()
            if any(
                record.status in _ACTIVE_STATUSES
                for record in self._records.values()
            ):
                raise OperationBusyError(
                    'another backup or restore operation is active'
                )
            root = self._operation_root()
            for _attempt in range(4):
                operation_id = secrets.token_urlsafe(32)
                directory = root / f'operation-{operation_id}'
                try:
                    directory.mkdir(mode=0o700)
                except FileExistsError:
                    continue
                break
            else:
                raise RuntimeError('could not allocate backup operation')
            now = time.time()
            record = BackupOperation(
                operation_id=operation_id,
                kind=kind,
                owner_id=int(owner_id),
                session_id=str(session_id),
                directory=directory,
                archive_path=directory / 'archive.zip',
                status=status,
                created_at=now,
                expires_at=now + config.BACKUP_OPERATION_TIMEOUT,
            )
            self._records[operation_id] = record
            return record

    def get(self, operation_id, owner_id, session_id):
        with self._lock:
            self._cleanup_expired_locked()
            record = self._records.get(str(operation_id))
            if (
                record is None
                or record.owner_id != int(owner_id)
                or not secrets.compare_digest(record.session_id, str(session_id))
            ):
                raise KeyError(operation_id)
            return record

    def set_status(self, operation_id, status, *, summary=None, size=None,
                   error=None, ttl=None):
        with self._lock:
            record = self._records.get(operation_id)
            if record is None:
                return None
            record.status = status
            if summary is not None:
                record.summary = dict(summary)
            if size is not None:
                record.size = int(size)
            record.error = error
            if ttl is not None:
                record.expires_at = time.time() + ttl
            return record

    def claim_download(self, operation_id, owner_id, session_id):
        with self._lock:
            record = self.get(operation_id, owner_id, session_id)
            if (
                record.kind != 'created_backup'
                or record.status != 'ready'
                or not record.archive_path.is_file()
            ):
                raise KeyError(operation_id)
            record.status = 'downloading'
            return record

    def begin_restore(self, operation_id, owner_id, session_id,
                      confirmation_token):
        with self._lock:
            record = self.get(operation_id, owner_id, session_id)
            expected = record.metadata.get('restore_confirmation_token')
            expires = record.metadata.get('restore_confirmation_expires', 0)
            if (
                record.kind != 'uploaded_backup'
                or record.status != 'verified'
                or not isinstance(expected, str)
                or not secrets.compare_digest(expected, str(confirmation_token))
                or expires <= time.time()
                or any(
                    candidate.operation_id != record.operation_id
                    and candidate.status in _ACTIVE_STATUSES
                    for candidate in self._records.values()
                )
            ):
                raise KeyError(operation_id)
            record.metadata.clear()
            record.status = 'restoring'
            record.expires_at = time.time() + config.BACKUP_OPERATION_TIMEOUT
            return record

    def prepare_restore(self, operation_id, owner_id, session_id, ttl=300):
        with self._lock:
            record = self.get(operation_id, owner_id, session_id)
            if record.kind != 'uploaded_backup' or record.status != 'verified':
                raise KeyError(operation_id)
            token = secrets.token_urlsafe(32)
            record.metadata = {
                'restore_confirmation_token': token,
                'restore_confirmation_expires': time.time() + ttl,
            }
            return token

    def remove(self, operation_id):
        with self._lock:
            self._remove_locked(operation_id)

    def _remove_locked(self, operation_id):
        record = self._records.pop(operation_id, None)
        if record is not None:
            _remove_private_tree(self._operation_root(), record.directory)

    def cleanup_orphans(self):
        root = self._operation_root()
        from .maintenance_mode import protected_operation_directory_name
        protected_name = protected_operation_directory_name()
        try:
            lock_context = operation_lock(timeout=0)
            lock_context.__enter__()
        except OperationBusyError:
            return
        try:
            with self._lock:
                active_directories = {
                    record.directory.resolve(strict=False)
                    for record in self._records.values()
                }
                for child in root.iterdir():
                    if (
                        not child.name.startswith('operation-')
                        or child.name == protected_name
                        or child.resolve(strict=False) in active_directories
                    ):
                        continue
                    _remove_private_tree(root, child)
        finally:
            lock_context.__exit__(None, None, None)

    def cleanup_expired(self):
        with self._lock:
            self._cleanup_expired_locked()

    def cleanup_loop(self, cancel_event):
        interval = max(5, min(60, config.BACKUP_DOWNLOAD_TTL // 2))
        while not cancel_event.wait(interval):
            self.cleanup_expired()

    def close(self, _deadline=None):
        with self._lock:
            operation_ids = tuple(self._records)
            for operation_id in operation_ids:
                self._remove_locked(operation_id)
        return ()


backup_operations = BackupOperationRegistry()
