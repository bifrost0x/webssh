"""Online-consistent backup creation for the running WebSSH application."""

import os
from pathlib import Path
import sqlite3
import stat
import tempfile


from .backup_coordination import (
    ensure_backup_temp_dir,
    operation_lock,
    snapshot_barrier,
)
from .backup_manager import (
    BackupIntegrityError,
    _stage_source,
    create_backup,
)


_SQLITE_RUNTIME_FILES = frozenset({
    'app.db',
    'app.db-journal',
    'app.db-shm',
    'app.db-wal',
})


def _snapshot_sqlite(source_path: Path, destination_path: Path) -> None:
    source_path = Path(source_path)
    metadata = source_path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise BackupIntegrityError('SQLite source must be a regular file')

    source = sqlite3.connect(str(source_path), timeout=30)
    destination = sqlite3.connect(str(destination_path), timeout=30)
    try:
        source.execute('PRAGMA query_only = ON')
        source.backup(destination, pages=256, sleep=0.01)
        result = destination.execute('PRAGMA quick_check').fetchone()
        if result != ('ok',):
            raise BackupIntegrityError('SQLite snapshot integrity check failed')
    finally:
        destination.close()
        source.close()
    os.chmod(destination_path, 0o600)


def create_online_backup(data_dir, destination, *, held_token=None):
    """Create and verify a current-format archive without copying live SQLite."""
    data_dir = Path(data_dir).resolve(strict=True)
    destination = Path(destination)
    if destination.resolve(strict=False).is_relative_to(data_dir):
        raise ValueError('backup destination must be outside DATA_DIR')

    operation_root = ensure_backup_temp_dir()
    with operation_lock(held_token=held_token):
        with tempfile.TemporaryDirectory(
            dir=operation_root,
            prefix='snapshot-',
        ) as working_directory:
            snapshot = Path(working_directory) / 'data'
            snapshot.mkdir(mode=0o700)
            with snapshot_barrier():
                _stage_source(
                    data_dir,
                    snapshot,
                    excluded_relative_paths=_SQLITE_RUNTIME_FILES,
                )
                _snapshot_sqlite(data_dir / 'app.db', snapshot / 'app.db')
            return create_backup(snapshot, destination)
