"""Process and thread coordination for backup-sensitive persistent state."""

from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import stat
import threading
import time
from uuid import uuid4

import config


class OperationBusyError(RuntimeError):
    """Raised when another backup-sensitive operation owns the process lock."""


@dataclass(frozen=True)
class OperationToken:
    value: str


class _SnapshotBarrier:
    def __init__(self):
        self._condition = threading.Condition(threading.Lock())
        self._readers = 0
        self._writer = False
        self._waiting_writers = 0
        self._local = threading.local()

    @contextmanager
    def persistent_write(self):
        depth = getattr(self._local, 'write_depth', 0)
        if depth:
            self._local.write_depth = depth + 1
            try:
                yield
            finally:
                self._local.write_depth -= 1
            return

        with self._condition:
            while self._writer or self._waiting_writers:
                self._condition.wait()
            self._readers += 1
        self._local.write_depth = 1
        try:
            yield
        finally:
            self._local.write_depth = 0
            with self._condition:
                self._readers -= 1
                if self._readers == 0:
                    self._condition.notify_all()

    @contextmanager
    def snapshot(self):
        if getattr(self._local, 'write_depth', 0):
            raise RuntimeError('snapshot barrier cannot begin during a write')
        with self._condition:
            self._waiting_writers += 1
            try:
                while self._writer or self._readers:
                    self._condition.wait()
                self._writer = True
            finally:
                self._waiting_writers -= 1
        try:
            yield
        finally:
            with self._condition:
                self._writer = False
                self._condition.notify_all()


_barrier = _SnapshotBarrier()
_operation_local = threading.local()
_sqlalchemy_guard = threading.Lock()
_sqlalchemy_installed = False


def _paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def ensure_backup_temp_dir() -> Path:
    """Create the private, per-DATA_DIR operation namespace."""
    root = Path(config.BACKUP_TEMP_DIR).expanduser()
    if root.exists() and root.is_symlink():
        raise RuntimeError('BACKUP_TEMP_DIR must not be a symbolic link')
    root = root.resolve(strict=False)
    protected = (
        Path(config.DATA_DIR).resolve(strict=False),
        (Path(config.BASE_DIR) / 'static').resolve(strict=False),
        (Path(config.DATA_DIR) / 'logs').resolve(strict=False),
    )
    if any(_paths_overlap(root, path) for path in protected):
        raise RuntimeError(
            'BACKUP_TEMP_DIR must be outside DATA_DIR, static, and logs'
        )
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise RuntimeError('BACKUP_TEMP_DIR must be a real directory')
    try:
        os.chmod(root, 0o700)
    except OSError:
        if os.name != 'nt':
            raise

    data_dir = Path(config.DATA_DIR).expanduser().resolve(strict=False)
    identity = os.path.normcase(str(data_dir)).encode('utf-8')
    namespace = root / f'instance-{sha256(identity).hexdigest()[:32]}'
    if namespace.exists() and namespace.is_symlink():
        raise RuntimeError('backup operation namespace must not be a symbolic link')
    namespace.mkdir(mode=0o700, exist_ok=True)
    metadata = namespace.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise RuntimeError('backup operation namespace must be a real directory')
    try:
        os.chmod(namespace, 0o700)
    except OSError:
        if os.name != 'nt':
            raise
    return namespace.resolve(strict=True)


def _try_lock(descriptor: int) -> bool:
    if os.name == 'nt':
        import msvcrt

        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True

    import fcntl

    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True


def _unlock(descriptor: int) -> None:
    if os.name == 'nt':
        import msvcrt

        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        return

    import fcntl

    fcntl.flock(descriptor, fcntl.LOCK_UN)


@contextmanager
def operation_lock(*, timeout=None, held_token=None):
    """Hold the cross-process lock for one backup-sensitive operation."""
    active = getattr(_operation_local, 'token', None)
    if active is not None:
        if held_token != active:
            raise RuntimeError('nested operation requires its active token')
        _operation_local.depth += 1
        try:
            yield active
        finally:
            _operation_local.depth -= 1
        return

    root = ensure_backup_temp_dir()
    lock_path = root / 'operation.lock'
    flags = os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise RuntimeError('backup operation lock must be a regular file')
        if os.fstat(descriptor).st_size < 1:
            os.write(descriptor, b'0')
            os.fsync(descriptor)
        deadline = time.monotonic() + (
            config.BACKUP_OPERATION_TIMEOUT if timeout is None else timeout
        )
        while not _try_lock(descriptor):
            if time.monotonic() >= deadline:
                raise OperationBusyError(
                    'another backup or restore operation is active'
                )
            time.sleep(0.05)

        token = OperationToken(uuid4().hex)
        _operation_local.token = token
        _operation_local.depth = 1
        try:
            yield token
        finally:
            _operation_local.depth = 0
            _operation_local.token = None
            _unlock(descriptor)
    finally:
        os.close(descriptor)


def persistent_write():
    """Coordinate one persistent mutation with online snapshots."""
    return _barrier.persistent_write()


def snapshot_barrier():
    """Pause coordinated writes while a consistent snapshot is captured."""
    return _barrier.snapshot()


def install_sqlalchemy_coordination() -> None:
    """Hold the persistent-write barrier around SQLAlchemy commits."""
    global _sqlalchemy_installed
    with _sqlalchemy_guard:
        if _sqlalchemy_installed:
            return
        from sqlalchemy import event
        from sqlalchemy.orm import Session

        def acquire(session, *_args):
            if '_webssh_persistent_write' in session.info:
                return
            context = persistent_write()
            context.__enter__()
            session.info['_webssh_persistent_write'] = context

        def release(session, *_args):
            context = session.info.pop('_webssh_persistent_write', None)
            if context is not None:
                context.__exit__(None, None, None)

        event.listen(Session, 'before_commit', acquire)
        event.listen(Session, 'after_commit', release)
        event.listen(Session, 'after_rollback', release)
        event.listen(Session, 'after_soft_rollback', release)
        _sqlalchemy_installed = True
