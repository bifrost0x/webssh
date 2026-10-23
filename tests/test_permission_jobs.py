"""Permission job ownership, immutable previews and mutation boundaries."""
from contextlib import contextmanager
from types import SimpleNamespace
from threading import Event
import stat
import pytest

class Runtime:

    def __init__(self):
        self.pending = []
        self.accept = True

    def accepting_work(self):
        return self.accept

    def start_job(self, name, target, **kwargs):
        event = Event()
        self.pending.append((target, event))
        return SimpleNamespace(cancel=event.set)

    def run(self):
        target, event = self.pending.pop(0)
        target(event)

class Remote:

    def __init__(self):
        self.objects = {'/': self.attr(True), '/tree': self.attr(True), '/tree/a': self.attr(False), '/tree/sub': self.attr(True), '/tree/sub/b': self.attr(False)}
        self.writes = []

    @staticmethod
    def attr(directory=False, mode=None):
        return SimpleNamespace(st_mode=(stat.S_IFDIR if directory else stat.S_IFREG) | (mode if mode is not None else 493 if directory else 384), st_size=0, st_mtime=1, st_uid=1, st_gid=1)

    def lstat(self, path):
        return self.objects[path]

    @contextmanager
    def entries(self, path):
        yield iter([SimpleNamespace(filename=p.rsplit('/', 1)[1]) for p in self.objects if p != '/' and p.rsplit('/', 1)[0] == path])

    def chmod(self, path, mode):
        self.writes.append((path, mode))
        self.objects[path].st_mode = self.objects[path].st_mode & ~511 | mode

@pytest.fixture
def setup():
    from app.permission_jobs import PermissionJobManager
    remote = Remote()
    runtime = Runtime()

    @contextmanager
    def session(source, **kwargs):
        yield remote
    source = SimpleNamespace(handle_id='handle', source_id='sftp-session:a', backend=SimpleNamespace(permission_job_session=session))
    manager = PermissionJobManager(runtime)
    authorize = lambda: source

    def prepare(**kwargs):
        return manager.prepare(user_id=7, socket_sid='sid', source_id=source.source_id, paths=['/tree'], recursive=True, file_mode='644', directory_mode='750', authorize=authorize, **kwargs)
    return (manager, runtime, remote, prepare, authorize)

def test_recursive_preview_is_read_only_then_applies_files_before_directories(setup):
    manager, runtime, remote, prepare, authorize = setup
    status = prepare()
    assert status['state'] == 'scanning'
    runtime.run()
    status = manager.get(7, 'sid', 'sftp-session:a', status['job_id'])
    assert (status['state'], status['files'], status['directories']) == ('ready', 2, 2)
    assert remote.writes == []
    manager.apply(7, 'sid', 'sftp-session:a', status['job_id'], authorize=authorize)
    runtime.run()
    assert remote.writes == [('/tree/a', 420), ('/tree/sub/b', 420), ('/tree/sub', 488), ('/tree', 488)]
    assert manager.get(7, 'sid', 'sftp-session:a', status['job_id'])['changed'] == 4

def test_foreign_socket_or_owner_cannot_read_or_apply(setup):
    from app.file_mutations import FileMutationError
    manager, runtime, remote, prepare, authorize = setup
    job = prepare()['job_id']
    runtime.run()
    for owner, sid, source in [(8, 'sid', 'sftp-session:a'), (7, 'other', 'sftp-session:a'), (7, 'sid', 'sftp-session:b')]:
        with pytest.raises(FileMutationError):
            manager.get(owner, sid, source, job)
        with pytest.raises(FileMutationError):
            manager.apply(owner, sid, source, job, authorize=authorize)
    assert not remote.writes

def test_metadata_change_before_apply_fails_without_writes(setup):
    manager, runtime, remote, prepare, authorize = setup
    job = prepare()['job_id']
    runtime.run()
    remote.objects['/tree/sub/b'].st_mtime = 2
    manager.apply(7, 'sid', 'sftp-session:a', job, authorize=authorize)
    runtime.run()
    status = manager.get(7, 'sid', 'sftp-session:a', job)
    assert status['state'] == 'failed' and status['code'] == 'METADATA_CHANGED'
    assert not remote.writes

def test_cancel_ready_and_single_use(setup):
    from app.file_mutations import FileMutationError
    manager, runtime, remote, prepare, authorize = setup
    job = prepare()['job_id']
    runtime.run()
    assert manager.cancel(7, 'sid', 'sftp-session:a', job)['state'] == 'cancelled'
    with pytest.raises(FileMutationError):
        manager.apply(7, 'sid', 'sftp-session:a', job, authorize=authorize)
    assert not remote.writes

def test_more_than_twenty_selected_files_are_supported(setup):
    manager, runtime, remote, prepare, authorize = setup
    paths = []
    for index in range(25):
        path = f'/item{index}'
        paths.append(path)
        remote.objects[path] = remote.attr()
    status = manager.prepare(user_id=7, socket_sid='sid', source_id='sftp-session:a', paths=paths, recursive=False, file_mode='644', directory_mode='755', authorize=authorize)
    runtime.run()
    assert manager.get(7, 'sid', 'sftp-session:a', status['job_id'])['files'] == 25

@pytest.mark.parametrize('recursive,paths', [(True, ['/']), (False, ['relative']), (False, ['/' + '/'.join(['x'] * 65)]), ('yes', ['/tree']), (False, []), (False, ['/x'] * 10001)])
def test_invalid_requests_fail_before_remote_inspection(setup, recursive, paths):
    from app.file_mutations import FileMutationError
    manager, runtime, remote, prepare, authorize = setup
    with pytest.raises(FileMutationError):
        manager.prepare(user_id=7, socket_sid='sid', source_id='sftp-session:a', paths=paths, recursive=recursive, file_mode='644', directory_mode='755', authorize=authorize)
    assert not runtime.pending and (not remote.writes)

def test_symlink_entries_are_skipped_and_never_traversed(setup):
    manager, runtime, remote, prepare, authorize = setup
    remote.objects['/tree/link'] = remote.attr()
    remote.objects['/tree/link'].st_mode = stat.S_IFLNK | 511
    job = prepare()['job_id']
    runtime.run()
    status = manager.get(7, 'sid', 'sftp-session:a', job)
    assert status['state'] == 'ready' and status['skipped'] == 1 and (status['total'] == 4)
    manager.apply(7, 'sid', 'sftp-session:a', job, authorize=authorize)
    runtime.run()
    assert all((path != '/tree/link' for path, _ in remote.writes))

def test_symlink_ancestor_is_rejected_before_leaf_read(setup):
    manager, runtime, remote, prepare, authorize = setup
    remote.objects['/tree'].st_mode = stat.S_IFLNK | 511
    job = manager.prepare(user_id=7, socket_sid='sid', source_id='sftp-session:a', paths=['/tree/a'], recursive=False, file_mode='644', directory_mode='755', authorize=authorize)['job_id']
    runtime.run()
    assert manager.get(7, 'sid', 'sftp-session:a', job)['state'] == 'failed'
    assert not remote.writes

def test_special_mode_selected_object_fails_closed_but_ancestor_sticky_bit_is_allowed(setup):
    manager, runtime, remote, prepare, authorize = setup
    remote.objects['/'].st_mode |= 512
    job = prepare()['job_id']
    runtime.run()
    assert manager.get(7, 'sid', 'sftp-session:a', job)['state'] == 'ready'
    manager.cancel(7, 'sid', 'sftp-session:a', job)
    remote.objects['/tree/a'].st_mode |= 2048
    job = prepare()['job_id']
    runtime.run()
    assert manager.get(7, 'sid', 'sftp-session:a', job)['state'] == 'failed'
    assert not remote.writes

def test_prepared_plan_cannot_be_applied_twice(setup):
    from app.file_mutations import FileMutationError
    manager, runtime, remote, prepare, authorize = setup
    job = prepare()['job_id']
    runtime.run()
    manager.apply(7, 'sid', 'sftp-session:a', job, authorize=authorize)
    with pytest.raises(FileMutationError):
        manager.apply(7, 'sid', 'sftp-session:a', job, authorize=authorize)
    runtime.run()
    with pytest.raises(FileMutationError):
        manager.apply(7, 'sid', 'sftp-session:a', job, authorize=authorize)
    assert len(remote.writes) == 4

def test_preview_expires_and_does_not_hold_admission_forever(setup):
    from app.file_mutations import FileMutationError
    manager, runtime, remote, prepare, authorize = setup
    now = [100]
    manager.clock = lambda: now[0]
    job = prepare()['job_id']
    runtime.run()
    now[0] += 121
    status = manager.get(7, 'sid', 'sftp-session:a', job)
    assert status['state'] == 'cancelled' and status['code'] == 'EXPIRED'
    with pytest.raises(FileMutationError):
        manager.apply(7, 'sid', 'sftp-session:a', job, authorize=authorize)
    assert prepare()['state'] == 'scanning'

def test_single_user_or_source_admission_is_bounded(setup):
    from app.file_mutations import FileMutationError
    manager, runtime, remote, prepare, authorize = setup
    prepare()
    with pytest.raises(FileMutationError):
        prepare()
    assert len(runtime.pending) == 1

def test_source_rebind_and_revocation_stop_before_writes(setup):
    manager, runtime, remote, prepare, authorize = setup
    job = prepare()['job_id']
    runtime.run()

    def revoked():
        raise PermissionError('secret')
    with pytest.raises(PermissionError):
        manager.apply(7, 'sid', 'sftp-session:a', job, authorize=revoked)
    source = authorize()
    source.handle_id = 'rebound'
    from app.file_mutations import FileMutationError
    with pytest.raises(FileMutationError):
        manager.apply(7, 'sid', 'sftp-session:a', job, authorize=authorize)
    assert not remote.writes

def test_disconnect_and_shutdown_cancel_scanning_job(setup):
    manager, runtime, remote, prepare, authorize = setup
    job = prepare()['job_id']
    manager.cancel_socket('sid')
    runtime.run()
    assert manager.get(7, 'sid', 'sftp-session:a', job)['state'] == 'cancelled'
    job = prepare()['job_id']
    runtime.accept = False
    runtime.run()
    assert manager.get(7, 'sid', 'sftp-session:a', job)['state'] == 'cancelled'
    assert not remote.writes

def test_unconfirmed_mutation_stops_without_retry_and_retains_partial_count(setup):
    manager, runtime, remote, prepare, authorize = setup
    job = prepare()['job_id']
    runtime.run()
    original = remote.chmod

    def uncertain(path, mode):
        original(path, mode)
        if len(remote.writes) == 2:
            raise OSError('credentials private')
    remote.chmod = uncertain
    manager.apply(7, 'sid', 'sftp-session:a', job, authorize=authorize)
    runtime.run()
    status = manager.get(7, 'sid', 'sftp-session:a', job)
    assert status['state'] == 'failed' and status['code'] == 'OUTCOME_UNKNOWN' and (status['changed'] == 1)
    assert len(remote.writes) == 2 and 'private' not in str(status)

def test_overlapping_roots_deduplicate_and_summary_preserves_modes(setup):
    manager, runtime, remote, prepare, authorize = setup
    job = manager.prepare(user_id=7, socket_sid='sid', source_id='sftp-session:a', paths=['/tree/a', '/tree', '/tree/sub', '/tree'], recursive=True, file_mode='644', directory_mode='755', authorize=authorize)['job_id']
    runtime.run()
    status = manager.get(7, 'sid', 'sftp-session:a', job)
    assert status['total'] == 4 and status['current_modes'] == {'files': {'600': 2}, 'directories': {'755': 2}}
    assert 0 < status['expires_in'] <= 120

def test_tree_member_and_metadata_limits_fail_before_mutation(setup, monkeypatch):
    import app.permission_jobs as module
    manager, runtime, remote, prepare, authorize = setup
    monkeypatch.setattr(module, 'MAX_MEMBERS', 3)
    job = prepare()['job_id']
    runtime.run()
    assert manager.get(7, 'sid', 'sftp-session:a', job)['state'] == 'failed'
    assert not remote.writes

def test_deadline_covers_queue_wait_and_expired_queue_never_reads_remote(setup):
    manager, runtime, remote, prepare, authorize = setup
    now = [100]
    manager.clock = lambda: now[0]
    job = prepare()['job_id']
    now[0] += 91
    runtime.run()
    status = manager.get(7, 'sid', 'sftp-session:a', job)
    assert status['state'] == 'failed' and status['code'] == 'TIMEOUT' and (status['total'] == 0)

def test_cancellation_between_writes_stops_without_rolling_back(setup):
    manager, runtime, remote, prepare, authorize = setup
    job = prepare()['job_id']
    runtime.run()
    original = remote.chmod

    def cancel_after_first(path, mode):
        original(path, mode)
        manager.cancel_socket('sid')
    remote.chmod = cancel_after_first
    manager.apply(7, 'sid', 'sftp-session:a', job, authorize=authorize)
    runtime.run()
    status = manager.get(7, 'sid', 'sftp-session:a', job)
    assert status['state'] == 'cancelled' and status['changed'] == 1 and (len(remote.writes) == 1)

def test_ancestor_swap_during_apply_is_detected_before_next_write(setup):
    manager, runtime, remote, prepare, authorize = setup
    job = prepare()['job_id']
    runtime.run()
    original = remote.chmod

    def swap(path, mode):
        original(path, mode)
        remote.objects['/tree'].st_mode = stat.S_IFLNK | 511
    remote.chmod = swap
    manager.apply(7, 'sid', 'sftp-session:a', job, authorize=authorize)
    runtime.run()
    status = manager.get(7, 'sid', 'sftp-session:a', job)
    assert status['state'] == 'failed' and len(remote.writes) == 1

def test_same_permissions_are_counted_without_writes(setup):
    manager, runtime, remote, prepare, authorize = setup
    job = manager.prepare(user_id=7, socket_sid='sid', source_id='sftp-session:a', paths=['/tree'], recursive=True, file_mode='600', directory_mode='755', authorize=authorize)['job_id']
    runtime.run()
    manager.apply(7, 'sid', 'sftp-session:a', job, authorize=authorize)
    runtime.run()
    status = manager.get(7, 'sid', 'sftp-session:a', job)
    assert status['state'] == 'completed' and status['processed'] == 4 and (status['unchanged'] == 4) and (not remote.writes)

def test_permission_paths_have_a_specific_large_flat_envelope_without_weakening_other_lists():
    import config
    from app.socket_file_control import _file_control_payload_metrics
    paths = ['/file' + str(index) for index in range(2000)]
    payload = {'source_id': 'sftp-session:a', 'request_id': 'preview', 'paths': paths}
    cost, _ = _file_control_payload_metrics(payload, allow_permission_paths=True)
    assert cost < config.FILE_CONTROL_BYTES_PER_MINUTE
    assert _file_control_payload_metrics(payload)[0] > config.FILE_CONTROL_BYTES_PER_MINUTE
    assert _file_control_payload_metrics({'other': paths}, allow_permission_paths=True)[0] > config.FILE_CONTROL_BYTES_PER_MINUTE

def test_global_admission_and_terminal_retention_remain_bounded(setup):
    from app.file_mutations import FileMutationError
    manager, runtime, remote, prepare, authorize = setup
    first = prepare()['job_id']
    def new(owner, source):
        return manager.prepare(user_id=owner, socket_sid='sid'+str(owner), source_id=source, paths=['/tree/a'], recursive=False, file_mode='644', directory_mode='755', authorize=authorize)
    second = new(8, 'sftp-session:second')['job_id']
    with pytest.raises(FileMutationError):
        new(9, 'sftp-session:third')
    runtime.run(); runtime.run()
    manager.cancel(7, 'sid', 'sftp-session:a', first)
    manager.cancel(8, 'sid8', 'sftp-session:second', second)
    for _ in range(70):
        job = prepare()['job_id']; runtime.run()
        manager.cancel(7, 'sid', 'sftp-session:a', job)
    manager._cleanup()
    assert len(manager._jobs) <= 64

def test_malformed_remote_names_and_special_types_fail_closed(setup):
    manager, runtime, remote, prepare, authorize = setup
    remote.objects['/tree/device'] = remote.attr()
    remote.objects['/tree/device'].st_mode = stat.S_IFIFO | 0o600
    job = prepare()['job_id']; runtime.run()
    assert manager.get(7, 'sid', 'sftp-session:a', job)['state'] == 'failed'
    remote.objects.pop('/tree/device')
    original = remote.entries
    @contextmanager
    def malformed(path):
        yield iter([SimpleNamespace(filename='../outside')])
    remote.entries = malformed
    job = prepare()['job_id']; runtime.run()
    assert manager.get(7, 'sid', 'sftp-session:a', job)['state'] == 'failed'
    assert not remote.writes

def test_metadata_bytes_and_tree_depth_are_bounded(setup, monkeypatch):
    import app.permission_jobs as module
    manager, runtime, remote, prepare, authorize = setup
    monkeypatch.setattr(module, 'MAX_DEPTH', 1)
    job = prepare()['job_id']; runtime.run()
    assert manager.get(7, 'sid', 'sftp-session:a', job)['state'] == 'failed'
    monkeypatch.setattr(module, 'MAX_DEPTH', 64)
    monkeypatch.setattr(module, 'MAX_NAME_BYTES', 25)
    job = prepare()['job_id']; runtime.run()
    assert manager.get(7, 'sid', 'sftp-session:a', job)['state'] == 'failed'
    assert not remote.writes

def test_worker_quota_is_released_on_cancellation_and_rejected_submission(setup):
    manager, runtime, remote, prepare, authorize = setup
    class Quotas:
        released = 0
        def reserve(self, *args):
            return SimpleNamespace(release=lambda: setattr(self, 'released', self.released+1))
    quotas = Quotas(); manager.quotas = quotas
    prepare(); manager.cancel_socket('sid'); runtime.run()
    assert quotas.released == 1
    def reject(*args, **kwargs):
        raise RuntimeError('runtime unavailable')
    runtime.start_job = reject
    from app.file_mutations import FileMutationError
    with pytest.raises(FileMutationError): prepare()
    assert quotas.released == 2

def test_real_runtime_queued_cancel_releases_reservation(setup):
    from app.runtime_lifecycle import RuntimeLifecycle
    manager, _, remote, prepare, authorize = setup
    runtime = RuntimeLifecycle(1); manager.lifecycle = runtime
    blocked = Event(); started = Event()
    def hold(cancel):
        started.set(); blocked.wait(5)
    runtime.start_job('hold_test_worker', hold)
    assert started.wait(2)
    class Quotas:
        released = 0
        def reserve(self, *args):
            return SimpleNamespace(release=lambda: setattr(self, 'released', self.released+1))
    quotas = Quotas(); manager.quotas = quotas
    try:
        job = prepare()['job_id']
        manager.cancel_socket('sid')
        blocked.set()
        handle = manager._jobs[job].handle
        assert handle.join(3)
        assert manager.get(7, 'sid', 'sftp-session:a', job)['state'] == 'cancelled'
        assert quotas.released == 1 and not remote.writes
    finally:
        blocked.set(); runtime.begin_shutdown(2)
