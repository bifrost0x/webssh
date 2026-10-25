"""Maintenance must drain admitted work without crossing account incarnations."""

from concurrent.futures import ThreadPoolExecutor
import io
from threading import Event, Thread
import time
from types import SimpleNamespace

import paramiko
import pytest
from werkzeug.exceptions import ServiceUnavailable


def _wait_until(predicate):
    deadline = time.monotonic() + 5
    while not predicate() and time.monotonic() < deadline:
        time.sleep(0.001)
    assert predicate()


def test_queued_snapshot_does_not_invert_nested_storage_locks(monkeypatch):
    from app import backup_coordination, storage_utils

    barrier = backup_coordination._SnapshotBarrier()
    monkeypatch.setattr(backup_coordination, '_barrier', barrier)
    outer = storage_utils._CoordinatedStorageLock()
    inner = storage_utils._CoordinatedStorageLock()
    entered, resume, completed = Event(), Event(), Event()

    def nested():
        with outer:
            entered.set()
            assert resume.wait(5)
            with inner:
                completed.set()

    def snapshot():
        with barrier.snapshot():
            pass

    def listing():
        with inner:
            pass

    workers = [Thread(target=nested, daemon=True),
               Thread(target=snapshot, daemon=True),
               Thread(target=listing, daemon=True)]
    workers[0].start()
    assert entered.wait(5)
    workers[1].start()
    _wait_until(lambda: barrier._waiting_writers == 1)
    workers[2].start()
    # The contender must wait at the barrier without taking the inner mutex.
    time.sleep(0.05)
    resume.set()
    try:
        assert completed.wait(1), 'nested operation deadlocked behind snapshot'
    finally:
        # Release only this test-local barrier if exercising vulnerable code.
        if not completed.is_set():
            with barrier._condition:
                barrier._waiting_writers = 0
                barrier._condition.notify_all()
        for worker in workers:
            worker.join(5)
    assert all(not worker.is_alive() for worker in workers)


def test_failed_storage_lock_acquisition_releases_write_lease(monkeypatch):
    from app import backup_coordination, storage_utils

    barrier = backup_coordination._SnapshotBarrier()
    monkeypatch.setattr(backup_coordination, '_barrier', barrier)
    lock = storage_utils._CoordinatedStorageLock()
    with lock:
        assert lock.acquire(blocking=False) is False
        with pytest.raises(ValueError):
            lock.acquire(blocking=False, timeout=1)
    assert barrier._readers == 0
    with barrier.snapshot():
        assert barrier._writer


def test_global_drain_waits_for_nested_operations_and_blocks_new_users():
    from app.data_access import DataAccessGate

    gate = DataAccessGate()
    entered, resume, closed = Event(), Event(), Event()

    def existing():
        with gate.access(1):
            entered.set()
            assert resume.wait(5)
            with gate.access(1):
                pass

    def drain():
        closed.set()
        gate.close_and_drain(timeout=5)

    with ThreadPoolExecutor(max_workers=2) as executor:
        worker = executor.submit(existing)
        assert entered.wait(5)
        draining = executor.submit(drain)
        assert closed.wait(5)
        try:
            _wait_until(lambda: gate._closed)
            assert not draining.done()
            with pytest.raises(ServiceUnavailable):
                with gate.access(999):
                    pass
        finally:
            resume.set()
        worker.result(timeout=5)
        draining.result(timeout=5)
    with pytest.raises(ServiceUnavailable):
        with gate.access(1):
            pass


def test_global_drain_timeout_keeps_admission_closed():
    from app.data_access import DataAccessGate

    gate = DataAccessGate()
    entered, resume = Event(), Event()

    def existing():
        with gate.access(1):
            entered.set()
            assert resume.wait(5)

    with ThreadPoolExecutor(max_workers=1) as executor:
        worker = executor.submit(existing)
        assert entered.wait(5)
        try:
            with pytest.raises(ServiceUnavailable):
                gate.close_and_drain(timeout=0.01)
            with pytest.raises(ServiceUnavailable):
                with gate.access(2):
                    pass
        finally:
            resume.set()
        worker.result(timeout=5)


@pytest.mark.parametrize('reuse_id', [False, True])
def test_delayed_hostkey_write_cannot_recreate_retired_namespace(
    app, monkeypatch, rsa_private_key_pem, reuse_id,
):
    import config
    from app.auth import register_user
    from app.host_key_store import HostKeyStore
    from app.user_lifecycle import delete_user_account

    keeper, error = register_user('keeper', 'synthetic-password')
    assert error is None
    target, error = register_user('retiring', 'synthetic-password')
    assert error is None
    uid = target.id
    store = HostKeyStore(uid, config.KNOWN_HOSTS_FILE, config.USERS_DIR)
    key = paramiko.RSAKey.from_private_key(io.StringIO(rsa_private_key_pem))
    accepted, resume = Event(), Event()
    original_record = store.record

    def delayed_record(*args):
        accepted.set()
        assert resume.wait(5)
        return original_record(*args)

    monkeypatch.setattr(store, 'record', delayed_record)
    client = paramiko.SSHClient()
    policy = store.missing_key_policy(decision=lambda _: True)
    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(policy.missing_host_key, client, 'synthetic.invalid', key)
        try:
            assert accepted.wait(5)
            delete_user_account(target, SimpleNamespace(server=None))
            if reuse_id:
                replacement, error = register_user('replacement', 'synthetic-password')
                assert error is None and replacement.id == uid
        finally:
            resume.set()
        with pytest.raises(ServiceUnavailable):
            pending.result(timeout=5)
    assert not store.user_path.exists()


def test_stale_hostkey_store_cannot_delete_replacement_trust(app, rsa_private_key_pem):
    import config
    from app.auth import register_user
    from app.host_key_store import HostKeyStore
    from app.user_lifecycle import delete_user_account

    register_user('keeper', 'synthetic-password')
    target, error = register_user('retiring', 'synthetic-password')
    assert error is None
    uid = target.id
    stale = HostKeyStore(uid, config.KNOWN_HOSTS_FILE, config.USERS_DIR)
    delete_user_account(target, SimpleNamespace(server=None))
    replacement, error = register_user('replacement', 'synthetic-password')
    assert error is None and replacement.id == uid
    fresh = HostKeyStore(uid, config.KNOWN_HOSTS_FILE, config.USERS_DIR)
    key = paramiko.RSAKey.from_private_key(io.StringIO(rsa_private_key_pem))
    fresh.record('synthetic.invalid', key)
    before = fresh.user_path.read_bytes()
    entry_id = fresh.list_entries()[0]['id']
    with pytest.raises(ServiceUnavailable):
        stale.delete_entry(entry_id)
    assert fresh.user_path.read_bytes() == before


@pytest.mark.parametrize('outcome', ['success', 'restore_error', 'drain_timeout'])
def test_restore_drains_admitted_work_before_snapshot_and_stays_closed(
    app, monkeypatch, tmp_path, outcome,
):
    import config
    from app import restore_service as service

    gate = app.extensions['data_access']
    entered, resume = Event(), Event()
    events = []
    before = config.DATA_DIR / 'preserved-config.json'
    before.write_bytes(b'{"preserve":"existing configuration"}')
    original = before.read_bytes()
    operation = tmp_path / 'operation'
    operation.mkdir()
    record = SimpleNamespace(operation_id='synthetic', directory=operation,
                             archive_path=operation / 'archive.zip')
    monkeypatch.setattr(config, 'RUNTIME_SHUTDOWN_GRACE_SECONDS',
                        0.05 if outcome == 'drain_timeout' else 5)
    for name in ('begin_preparing', 'mark_in_progress', 'mark_succeeded',
                 'mark_failed', 'reset_cache', 'rotate_epoch',
                 '_clear_restored_runtime_sessions', 'log_security_event'):
        monkeypatch.setattr(service, name, lambda *a, **k: None)
    monkeypatch.setattr(service, '_close_active_ssh_sessions', lambda: None)
    monkeypatch.setattr(service, '_disconnect_sockets', lambda _s: None)
    monkeypatch.setattr(service.connection_pool.temp_connection_pool,
                        'close_all_connections', lambda: None)
    monkeypatch.setattr(service.backup_operations, 'remove', lambda _id: None)

    def snapshot(*args, **kwargs):
        assert not gate._active and not gate._operations
        events.append('snapshot')

    def restore(source, _destination):
        assert not gate._active and not gate._operations
        events.append(source.name)
        if outcome == 'restore_error' and source == record.archive_path:
            raise RuntimeError('synthetic restore failure')

    def restart():
        assert gate._closed
        events.append('restart')

    monkeypatch.setattr(service, 'create_online_backup', snapshot)
    monkeypatch.setattr(service, 'restore_backup', restore)

    def writer():
        with gate.operation(), gate.access(123):
            entered.set()
            assert resume.wait(5)
            # Admitted handlers must be able to finish nested work.
            with gate.access(123):
                before.write_bytes(original)

    with ThreadPoolExecutor(max_workers=2) as executor:
        pending = executor.submit(writer)
        assert entered.wait(5)
        restoring = executor.submit(service._perform_restore, app,
            SimpleNamespace(server=None), record, 'synthetic-admin',
            '127.0.0.1', restart)
        try:
            _wait_until(lambda: gate._closed)
            assert 'snapshot' not in events
            if outcome == 'drain_timeout':
                restoring.result(timeout=5)
                assert events == ['restart']
            else:
                assert not restoring.done()
        finally:
            resume.set()
        pending.result(timeout=5)
        restoring.result(timeout=5)
    assert before.read_bytes() == original
    assert events[-1] == 'restart'
    if outcome == 'restore_error':
        assert events == ['snapshot', 'archive.zip', 'rollback.zip', 'restart']
    if outcome == 'success':
        assert events == ['snapshot', 'archive.zip', 'restart']
    with pytest.raises(ServiceUnavailable):
        with gate.operation():
            pass


def test_http_request_is_counted_and_shutdown_does_not_reopen_admission(app):
    gate = app.extensions['data_access']

    @app.get('/synthetic-operation')
    def operation():
        assert gate._operations == 1
        return 'ok'

    client = app.test_client()
    assert client.get('/synthetic-operation').status_code == 200
    assert gate._operations == 0
    gate.close_and_drain(timeout=1)
    assert client.get('/synthetic-operation').status_code == 503
    assert client.get('/health').status_code == 200


def test_user_hostkey_class_helpers_reject_absent_account(app, tmp_path, rsa_private_key_pem):
    from app.host_key_store import HostKeyStore

    key = paramiko.RSAKey.from_private_key(io.StringIO(rsa_private_key_pem))
    value = f'synthetic.invalid {key.get_name()} {key.get_base64()}'
    path = tmp_path / 'user_999' / 'known_hosts'
    with pytest.raises(ServiceUnavailable):
        HostKeyStore.add_file_entry(path, value, scope='user', owner_id=999,
                                    lock_key='synthetic:999')
    assert not path.exists()
    # Global host trust is administrator-owned, not a per-account namespace.
    entry, error = HostKeyStore.add_file_entry(path, value, scope='global',
                                              owner_id=None, lock_key='synthetic:global')
    assert error is None and entry is not None
    before = path.read_bytes()
    with pytest.raises(ServiceUnavailable):
        HostKeyStore.delete_file_entry(path, 'a' * 64, scope='user', owner_id=999,
                                       lock_key='synthetic:999')
    assert path.read_bytes() == before


def test_closed_admission_rejects_untracked_database_commit(app):
    from app.models import User, db

    gate = app.extensions['data_access']
    gate.close_and_drain(timeout=1)
    db.session.add(User(username='late', password_hash='synthetic'))
    with pytest.raises(ServiceUnavailable):
        db.session.commit()
    db.session.rollback()
    assert User.query.filter_by(username='late').first() is None


def test_restore_diagnostics_do_not_probe_persistent_state(app, monkeypatch):
    from app import health

    def forbidden():
        pytest.fail('maintenance diagnostics must not touch persistent state')

    monkeypatch.setattr(health, '_probe_database', forbidden)
    monkeypatch.setattr(health, '_probe_data_directory', forbidden)
    app.extensions['data_access'].close_and_drain(timeout=1)
    client = app.test_client()
    assert client.get('/health').status_code == 200
    response = client.get('/ready')
    assert response.status_code == 503
    assert response.get_json()['failed'] == ['maintenance']
    # Status authentication reads SQLite. The existing browser flow treats
    # temporary unavailability as restart and polls /ready until sign-in.
    assert client.get('/admin/api/backups/restore/status').status_code == 503


@pytest.mark.parametrize(('path', 'status'), [
    ('/health', 200), ('/ready', 503),
    ('/admin/api/backups/restore/status', 503), ('/', 503),
])
def test_restore_responses_do_not_refresh_epoch_for_existing_browser(
    app, monkeypatch, path, status,
):
    from app import session_epoch

    client = app.test_client()
    with client.session_transaction() as browser:
        browser['_user_id'] = '123'
        browser['_auth_epoch'] = 'original-browser-generation'
    app.extensions['data_access'].close_and_drain(timeout=1)

    def forbidden():
        pytest.fail('closed restore admission must not read or create session_epoch')

    monkeypatch.setattr(session_epoch, 'current_epoch', forbidden)
    assert client.get(path).status_code == status
    with client.session_transaction() as browser:
        assert browser['_auth_epoch'] == 'original-browser-generation'


def test_disconnect_cleanup_is_drained_and_cannot_reenter_after_restore(app, monkeypatch):
    from app import socket_events

    gate = app.extensions['data_access']
    entered, resume = Event(), Event()
    calls = []

    def cleanup(sid):
        calls.append(sid)
        entered.set()
        assert resume.wait(5)

    monkeypatch.setattr(socket_events, '_cleanup_admitted_socket_session', cleanup)

    def disconnect():
        with app.app_context():
            socket_events._cleanup_socket_session('synthetic-sid')

    with ThreadPoolExecutor(max_workers=2) as executor:
        pending = executor.submit(disconnect)
        assert entered.wait(5)
        draining = executor.submit(gate.close_and_drain, timeout=5)
        try:
            _wait_until(lambda: gate.closed)
            assert not draining.done()
        finally:
            resume.set()
        pending.result(timeout=5)
        draining.result(timeout=5)
    socket_events._cleanup_socket_session('late-sid')
    assert calls == ['synthetic-sid']
