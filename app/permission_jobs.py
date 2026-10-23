"""Bounded, socket-owned previews for explicit remote permission changes."""
from contextlib import contextmanager
from dataclasses import dataclass, field
import posixpath
import secrets
import stat
from threading import Event, RLock
import time
from .file_mutations import FileMutationError, mutation_failure, parse_mode, permission_snapshot, validate_leaf, validate_path
MAX_MEMBERS = 10000
MAX_DEPTH = 64
MAX_NAME_BYTES = 4 * 1024 * 1024
SCAN_SECONDS = 90
APPLY_SECONDS = 300
PREVIEW_SECONDS = 120
TERMINAL_SECONDS = 120
MAX_RETAINED = 64
_ACTIVE = {'scanning', 'ready', 'running'}

class _Cancelled(Exception):
    pass

@dataclass
class _Job:
    job_id: str
    user_id: str
    socket_sid: str
    source_id: str
    handle_id: str
    recursive: bool
    file_mode: str
    directory_mode: str
    created: float
    state: str = 'scanning'
    files: int = 0
    directories: int = 0
    skipped: int = 0
    changed: int = 0
    processed: int = 0
    unchanged: int = 0
    total: int = 0
    touched: float = 0
    name_bytes: int = 0
    code: str = ''
    error: str = ''
    cancel_event: Event = field(default_factory=Event)
    plan: list = field(default_factory=list)
    guards: dict = field(default_factory=dict)
    handle: object = None
    current_modes: dict = field(default_factory=lambda: {'files': {}, 'directories': {}})

class PermissionJobManager:
    """Own immutable, expiring plans; remote changes never accept a new target."""

    def __init__(self, lifecycle, *, clock=time.monotonic, quotas=None):
        self.lifecycle = lifecycle
        self.clock = clock
        self.quotas = quotas
        self._lock = RLock()
        self._jobs = {}

    def _cleanup(self):
        now = self.clock()
        for identifier, job in list(self._jobs.items()):
            if job.state == 'ready' and now - job.touched > PREVIEW_SECONDS:
                job.state = 'cancelled'
                job.code = 'EXPIRED'
                job.plan.clear()
                job.guards.clear()
                job.touched = now
            elif job.state not in _ACTIVE and now - job.touched > TERMINAL_SECONDS:
                del self._jobs[identifier]
        terminal = sorted((j for j in self._jobs.values() if j.state not in _ACTIVE), key=lambda j: j.touched)
        for job in terminal[:max(0, len(self._jobs) - MAX_RETAINED)]:
            self._jobs.pop(job.job_id, None)

    def _public(self, job):
        status = {name: getattr(job, name) for name in ('job_id', 'state', 'files', 'directories', 'skipped', 'changed', 'processed', 'unchanged', 'total', 'recursive', 'file_mode', 'directory_mode')}
        status['current_modes'] = {kind: dict(modes) for kind, modes in job.current_modes.items()}
        status['expires_in'] = max(0, int(PREVIEW_SECONDS - (self.clock() - job.touched))) if job.state == 'ready' else 0
        if job.code:
            status.update(code=job.code, error=job.error)
        return status

    def _owned(self, user_id, socket_sid, source_id, job_id):
        self._cleanup()
        job = self._jobs.get(job_id) if isinstance(job_id, str) else None
        if job is None or (job.user_id, job.socket_sid, job.source_id) != (str(user_id), socket_sid, source_id):
            raise FileMutationError('NOT_FOUND')
        return job

    def get(self, user_id, socket_sid, source_id, job_id):
        with self._lock:
            return self._public(self._owned(user_id, socket_sid, source_id, job_id))

    def cancel(self, user_id, socket_sid, source_id, job_id):
        with self._lock:
            job = self._owned(user_id, socket_sid, source_id, job_id)
            job.cancel_event.set()
            if job.state == 'ready':
                job.state = 'cancelled'
                job.plan.clear()
                job.guards.clear()
                job.touched = self.clock()
            if job.handle is not None:
                job.handle.cancel()
            return self._public(job)

    def cancel_socket(self, socket_sid):
        with self._lock:
            for job in self._jobs.values():
                if job.socket_sid == socket_sid and job.state in _ACTIVE:
                    job.cancel_event.set()
                    if job.state == 'ready':
                        job.state = 'cancelled'
                        job.plan.clear()
                        job.guards.clear()
                        job.touched = self.clock()
                    if job.handle is not None:
                        job.handle.cancel()

    def prepare(self, *, user_id, socket_sid, source_id, paths, recursive, file_mode, directory_mode, authorize, worker_wrap=lambda fn: fn, audit=None):
        if type(recursive) is not bool or not isinstance(paths, list) or (not 1 <= len(paths) <= MAX_MEMBERS):
            raise FileMutationError('INVALID_REQUEST')
        parse_mode(file_mode)
        parse_mode(directory_mode)
        roots = []
        seen = set()
        name_bytes = 0
        for value in paths:
            path = validate_path(value, mutation=True)
            if not path.startswith('/') or len(path.split('/')) - 1 > MAX_DEPTH:
                raise FileMutationError('INVALID_REQUEST')
            name_bytes += len(path.encode('utf-8'))
            if name_bytes > MAX_NAME_BYTES:
                raise FileMutationError('INVALID_REQUEST')
            if path not in seen:
                roots.append(path)
                seen.add(path)
        if recursive:
            minimal = []
            for path in sorted(roots, key=lambda value: tuple(value.split('/'))):
                if not minimal or not path.startswith(minimal[-1] + '/'):
                    minimal.append(path)
            roots = minimal
        source = authorize()
        with self._lock:
            self._cleanup()
            active = [j for j in self._jobs.values() if j.state in _ACTIVE]
            if len(active) >= 2 or any((j.user_id == str(user_id) or j.source_id == source_id for j in active)):
                raise FileMutationError('CONFLICT')
            job = _Job(secrets.token_urlsafe(24), str(user_id), socket_sid, source_id, source.handle_id, recursive, file_mode, directory_mode, self.clock(), touched=self.clock())
            self._jobs[job.job_id] = job
            self._schedule(job, lambda check: self._scan(job, roots, source, check), authorize, worker_wrap, audit, SCAN_SECONDS)
            return self._public(job)

    def apply(self, user_id, socket_sid, source_id, job_id, *, authorize, worker_wrap=lambda fn: fn, audit=None):
        with self._lock:
            job = self._owned(user_id, socket_sid, source_id, job_id)
            if job.state != 'ready' or job.cancel_event.is_set():
                raise FileMutationError('CONFLICT')
            source = authorize()
            if source.handle_id != job.handle_id:
                raise FileMutationError('METADATA_CHANGED')
            job.state = 'running'
            job.touched = self.clock()
            self._schedule(job, lambda check: self._apply(job, source, check, audit), authorize, worker_wrap, audit, APPLY_SECONDS)
            return self._public(job)

    def _schedule(self, job, operation, authorize, worker_wrap, audit, seconds):
        reservation = None
        try:
            if not self.lifecycle.accepting_work():
                raise FileMutationError('OPERATION_FAILED')
            if self.quotas is not None:
                from .quota_manager import QuotaKind
                reservation = self.quotas.reserve(QuotaKind.BACKGROUND_JOB, job.user_id)
            deadline = self.clock() + seconds

            def run(runtime_cancel):

                def check():
                    if job.cancel_event.is_set() or runtime_cancel.is_set():
                        raise _Cancelled()
                    if self.clock() >= deadline:
                        raise FileMutationError('TIMEOUT')
                    if not self.lifecycle.accepting_work():
                        raise _Cancelled()
                    current = authorize()
                    if current.handle_id != job.handle_id:
                        raise FileMutationError('METADATA_CHANGED')
                try:
                    check()
                    operation(check)
                    check()
                    with self._lock:
                        if job.state == 'scanning':
                            job.state = 'ready'
                        elif job.state == 'running':
                            job.state = 'completed'
                except _Cancelled:
                    with self._lock:
                        job.state = 'cancelled'
                except Exception as error:
                    failure = mutation_failure(error)
                    with self._lock:
                        job.state = 'failed'
                        job.code = failure.code
                        job.error = str(failure)
                finally:
                    with self._lock:
                        job.touched = self.clock()
                        if job.state != 'ready':
                            job.plan.clear()
                            job.guards.clear()
                    if reservation is not None:
                        reservation.release()
                    if audit is not None:
                        audit(job.state, None, None, None)
            job.handle = self.lifecycle.start_job('file_permissions_job', worker_wrap(run), owner_id=job.user_id)
            future = getattr(job.handle, '_future', None)
            if future is not None:

                def completed(result):
                    if result.cancelled():
                        if reservation is not None:
                            reservation.release()
                        with self._lock:
                            job.state = 'cancelled'
                            job.touched = self.clock()
                            job.plan.clear()
                            job.guards.clear()
                future.add_done_callback(completed)
        except Exception:
            if reservation is not None:
                reservation.release()
            job.state = 'failed'
            job.code = 'OPERATION_FAILED'
            job.error = str(FileMutationError(job.code))
            job.touched = self.clock()
            job.plan.clear()
            job.guards.clear()
            raise FileMutationError('OPERATION_FAILED') from None

    @staticmethod
    def _parents(path):
        parents = []
        while path != '/':
            path = posixpath.dirname(path)
            parents.append(path)
        return reversed(parents)

    @staticmethod
    def _snapshot(io, path):
        value = permission_snapshot(io.lstat(path))
        if value['special_bits']:
            raise FileMutationError('UNSUPPORTED_OPERATION')
        return value

    def _guards(self, job, io, path, check):
        for parent in self._parents(path):
            check()
            snapshot = permission_snapshot(io.lstat(parent))
            if snapshot['object_type'] != 'directory':
                raise FileMutationError('METADATA_CHANGED')
            if parent in job.guards and snapshot != job.guards[parent]:
                raise FileMutationError('METADATA_CHANGED')
            if parent not in job.guards:
                if len(job.guards) >= MAX_MEMBERS or job.name_bytes + len(parent.encode('utf-8')) > MAX_NAME_BYTES:
                    raise FileMutationError('INVALID_REQUEST')
                job.guards[parent] = snapshot
                job.name_bytes += len(parent.encode('utf-8'))

    def _scan(self, job, roots, source, check):
        names = sum((len(path.encode('utf-8')) for path in roots))
        members = 0
        visited = set()
        with source.backend.permission_job_session(source, authorize=check, timeout=SCAN_SECONDS) as io:
            pending = [(path, 0) for path in reversed(roots)]
            while pending:
                check()
                path, depth = pending.pop()
                if path in visited:
                    continue
                if depth > MAX_DEPTH:
                    raise FileMutationError('INVALID_REQUEST')
                visited.add(path)
                members += 1
                if members > MAX_MEMBERS or names > MAX_NAME_BYTES:
                    raise FileMutationError('INVALID_REQUEST')
                self._guards(job, io, path, check)
                check()
                info = io.lstat(path)
                if stat.S_ISLNK(info.st_mode):
                    with self._lock:
                        job.skipped += 1
                    continue
                snapshot = permission_snapshot(info)
                if snapshot['special_bits']:
                    raise FileMutationError('UNSUPPORTED_OPERATION')
                with self._lock:
                    job.name_bytes += len(path.encode('utf-8'))
                    if job.name_bytes > MAX_NAME_BYTES:
                        raise FileMutationError('INVALID_REQUEST')
                    job.plan.append((path, snapshot))
                    if snapshot['object_type'] == 'directory':
                        job.directories += 1
                    else:
                        job.files += 1
                    job.total = job.files + job.directories
                    modes = job.current_modes['directories' if snapshot['object_type'] == 'directory' else 'files']
                    modes[snapshot['mode']] = modes.get(snapshot['mode'], 0) + 1
                if snapshot['object_type'] == 'directory' and job.recursive:
                    job.guards.setdefault(path, snapshot)
                    self._guards(job, io, path, check)
                    check()
                    with io.entries(path) as entries:
                        for entry in entries:
                            check()
                            name = validate_leaf(entry.filename)
                            child = validate_path(posixpath.join(path, name), mutation=True)
                            if len(pending) + members >= MAX_MEMBERS:
                                raise FileMutationError('INVALID_REQUEST')
                            names += len(child.encode('utf-8'))
                            if names > MAX_NAME_BYTES:
                                raise FileMutationError('INVALID_REQUEST')
                            pending.append((child, depth + 1))
            self._preflight(job, io, check)
            job.plan.sort(key=lambda item: (item[1]['object_type'] == 'directory', -item[0].count('/') if item[1]['object_type'] == 'directory' else 0, item[0]))

    def _preflight(self, job, io, check):
        for path, snapshot in job.guards.items():
            check()
            if permission_snapshot(io.lstat(path)) != snapshot:
                raise FileMutationError('METADATA_CHANGED')
        for path, snapshot in job.plan:
            self._guards(job, io, path, check)
            check()
            if self._snapshot(io, path) != snapshot:
                raise FileMutationError('METADATA_CHANGED')

    def _apply(self, job, source, check, audit):
        with source.backend.permission_job_session(source, authorize=check, timeout=APPLY_SECONDS) as io:
            self._preflight(job, io, check)
            for path, snapshot in job.plan:
                self._guards(job, io, path, check)
                check()
                if self._snapshot(io, path) != snapshot:
                    raise FileMutationError('METADATA_CHANGED')
                mode = job.directory_mode if snapshot['object_type'] == 'directory' else job.file_mode
                if mode == snapshot['mode']:
                    with self._lock:
                        job.processed += 1
                        job.unchanged += 1
                    continue
                check()
                try:
                    io.chmod(path, parse_mode(mode))
                    after = self._snapshot(io, path)
                except Exception as error:
                    raise mutation_failure(error, uncertain=True) from None
                if after != {**snapshot, 'mode': mode}:
                    raise FileMutationError('OUTCOME_UNKNOWN')
                with self._lock:
                    job.changed += 1
                    job.processed += 1
                if path in job.guards:
                    job.guards[path] = after
                if audit is not None:
                    audit('COMPLETED', path, snapshot['mode'], mode)
