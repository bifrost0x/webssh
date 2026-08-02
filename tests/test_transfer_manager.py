import re
import threading

import pytest

from app.quota_manager import QuotaExceeded, QuotaKind, QuotaManager
from app.transfer_manager import (
    InvalidTransferToken,
    TransferManager,
    TransferState,
)
from app.runtime_lifecycle import RuntimeShuttingDown


class FakeClock:
    def __init__(self, value=100.0):
        self.value = value

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class SpyReservation:
    def __init__(self, release_failures=0):
        self.release_calls = 0
        self.release_failures = release_failures
        self.released = False
        self._lock = threading.Lock()

    def release(self):
        with self._lock:
            self.release_calls += 1
            if self.release_failures:
                self.release_failures -= 1
                raise RuntimeError('injected release failure')
            self.released = True


class SpyQuotaManager:
    def __init__(self, release_failures=0):
        self.release_failures = release_failures
        self.reservations = []
        self.reserve_calls = []

    def reserve(self, kind, user_id, amount=1):
        self.reserve_calls.append((kind, user_id, amount))
        reservation = SpyReservation(self.release_failures)
        self.reservations.append(reservation)
        return reservation


class ReleaseThenRaiseReservation:
    def __init__(self, reservation=None):
        self._reservation = reservation
        self.release_calls = 0
        self.actual_releases = 0
        self._released = False

    @property
    def released(self):
        if self._reservation is not None:
            return self._reservation.released
        return self._released

    def release(self):
        self.release_calls += 1
        if not self.released:
            if self._reservation is not None:
                self._reservation.release()
            else:
                self._released = True
            self.actual_releases += 1
            raise RuntimeError('injected post-release failure')
        if self._reservation is not None:
            self._reservation.release()


class ReleaseThenRaiseQuotaManager:
    def __init__(self, quota_manager=None):
        self._quota_manager = quota_manager
        self.reservations = []

    def reserve(self, kind, user_id, amount=1):
        reservation = None
        if self._quota_manager is not None:
            reservation = self._quota_manager.reserve(kind, user_id, amount)
        wrapped = ReleaseThenRaiseReservation(reservation)
        self.reservations.append(wrapped)
        return wrapped


def make_quota_manager(global_limit=3, per_user_limit=2):
    limits = {
        kind: {'global': 100, 'per_user': 50}
        for kind in QuotaKind
    }
    limits[QuotaKind.TRANSFER] = {
        'global': global_limit,
        'per_user': per_user_limit,
    }
    return QuotaManager(limits)


def make_manager(clock=None, ttl=60, quota_manager=None):
    return TransferManager(
        quota_manager=quota_manager or make_quota_manager(),
        token_ttl=ttl,
        clock=clock or FakeClock(),
    )


def test_create_reserves_quota_and_returns_bound_pending_record():
    quota = SpyQuotaManager()
    manager = make_manager(quota_manager=quota)
    metadata = {
        'path': '/remote/file.bin',
        'nested': {'name': 'original'},
    }

    record = manager.create(
        user_id=7,
        session_id='session-1',
        direction='download',
        metadata=metadata,
    )

    assert record.user_id == '7'
    assert record.session_id == 'session-1'
    assert record.direction == 'download'
    assert record.state is TransferState.PENDING
    assert record.cancel_event.is_set() is False
    assert re.fullmatch(r'[A-Za-z0-9_-]+', record.transfer_id)
    assert re.fullmatch(r'[A-Za-z0-9_-]+', record.token)
    assert len(record.token) >= 40
    assert quota.reserve_calls == [(QuotaKind.TRANSFER, '7', 1)]

    metadata['nested']['name'] = 'changed'
    assert record.metadata['nested']['name'] == 'original'
    returned_metadata = record.metadata
    returned_metadata['nested']['name'] = 'also-changed'
    assert record.metadata['nested']['name'] == 'original'


def test_record_identity_binding_is_read_only():
    record = make_manager().create(
        7, 'session-1', 'download', {}
    )

    with pytest.raises(AttributeError):
        record.user_id = '8'
    with pytest.raises(AttributeError):
        record.session_id = 'session-2'
    with pytest.raises(AttributeError):
        record.direction = 'upload'


def test_record_repr_omits_token_and_metadata_values():
    manager = make_manager()
    record = manager.create(
        7,
        'session-secret',
        'upload',
        {'credential': 'metadata-secret'},
    )

    rendered = repr(record)

    assert record.token not in rendered
    assert 'metadata-secret' not in rendered
    assert 'credential' not in rendered


def test_tokens_and_transfer_ids_are_unique():
    manager = make_manager(
        quota_manager=make_quota_manager(
            global_limit=20, per_user_limit=10
        )
    )

    records = [
        manager.create(7, f'session-{index}', 'upload', {})
        for index in range(10)
    ]

    assert len({record.token for record in records}) == 10
    assert len({record.transfer_id for record in records}) == 10


def test_consume_token_is_owner_only_and_one_use():
    manager = make_manager()
    record = manager.create(7, 'session-1', 'download', {})
    token = record.token

    with pytest.raises(InvalidTransferToken) as foreign_error:
        manager.consume_token(token, user_id=8)

    consumed = manager.consume_token(token, user_id=7)
    assert consumed is record
    assert record.state is TransferState.RUNNING
    assert record.user_id == '7'
    assert record.session_id == 'session-1'
    assert record.token is None

    with pytest.raises(InvalidTransferToken) as reused_error:
        manager.consume_token(token, user_id=7)

    assert str(foreign_error.value) == str(reused_error.value)
    assert token not in str(foreign_error.value)
    assert token not in repr(foreign_error.value)


def test_expired_token_uses_same_opaque_error():
    clock = FakeClock()
    manager = make_manager(clock=clock, ttl=5)
    record = manager.create(7, 'session-1', 'download', {})
    token = record.token
    clock.advance(6)

    with pytest.raises(InvalidTransferToken) as expired_error:
        manager.consume_token(token, user_id=7)
    with pytest.raises(InvalidTransferToken) as unknown_error:
        manager.consume_token('unknown-token', user_id=7)

    assert str(expired_error.value) == str(unknown_error.value)
    assert token not in repr(expired_error.value)
    assert record.token is None


@pytest.mark.parametrize(
    ('field', 'value'),
    [
        ('user_id', None),
        ('user_id', True),
        ('user_id', ''),
        ('user_id', '   '),
        ('user_id', 1.5),
        ('session_id', None),
        ('session_id', True),
        ('session_id', ''),
        ('session_id', '   '),
        ('session_id', 1.5),
        ('direction', None),
        ('direction', ''),
        ('direction', 'sideways'),
        ('metadata', None),
        ('metadata', []),
    ],
)
def test_create_rejects_invalid_input(field, value):
    manager = make_manager()
    arguments = {
        'user_id': 7,
        'session_id': 'session-1',
        'direction': 'upload',
        'metadata': {},
    }
    arguments[field] = value

    with pytest.raises(ValueError):
        manager.create(**arguments)


@pytest.mark.parametrize('ttl', [None, True, False, 0, -1, float('inf')])
def test_manager_rejects_invalid_token_ttl(ttl):
    with pytest.raises(ValueError):
        TransferManager(
            quota_manager=make_quota_manager(),
            token_ttl=ttl,
        )


@pytest.mark.parametrize(
    ('token', 'user_id'),
    [
        (None, 7),
        ('', 7),
        (b'token', 7),
        ('t\u00f6ken', 7),
        ('token', None),
        ('token', True),
        ('token', ''),
    ],
)
def test_consume_rejects_invalid_input_without_echoing_it(token, user_id):
    manager = make_manager()
    manager.create(7, 'session-1', 'download', {})

    with pytest.raises(InvalidTransferToken) as exc_info:
        manager.consume_token(token, user_id)

    assert repr(token) not in repr(exc_info.value)


@pytest.mark.parametrize('iteration', range(20))
def test_concurrent_token_consumption_has_exactly_one_winner(iteration):
    del iteration
    manager = make_manager()
    record = manager.create(7, 'session-1', 'download', {})
    token = record.token
    barrier = threading.Barrier(30)
    consumed = []
    rejected = []
    result_lock = threading.Lock()

    def consume():
        barrier.wait()
        try:
            result = manager.consume_token(token, 7)
        except InvalidTransferToken:
            with result_lock:
                rejected.append(True)
        else:
            with result_lock:
                consumed.append(result)

    threads = [threading.Thread(target=consume) for _ in range(30)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(2)

    assert all(not thread.is_alive() for thread in threads)
    assert consumed == [record]
    assert len(rejected) == 29
    assert record.state is TransferState.RUNNING
    assert record.token is None
    assert manager.complete(record.transfer_id, 7) is True


@pytest.mark.parametrize('initial_state', ['pending', 'running'])
def test_cancel_sets_event_and_releases_quota_once(initial_state):
    quota = SpyQuotaManager()
    manager = make_manager(quota_manager=quota)
    record = manager.create(7, 'session-1', 'download', {})
    if initial_state == 'running':
        manager.consume_token(record.token, 7)

    assert manager.cancel(record.transfer_id, 7) is True
    assert record.state is TransferState.CANCELLED
    assert record.cancel_event.is_set() is True
    assert quota.reservations[0].release_calls == 1

    assert manager.cancel(record.transfer_id, 7) is False
    assert manager.complete(record.transfer_id, 7) is False
    assert manager.fail(record.transfer_id, 7) is False
    assert quota.reservations[0].release_calls == 1


def test_foreign_cancel_does_not_change_or_release_record():
    quota = SpyQuotaManager()
    manager = make_manager(quota_manager=quota)
    record = manager.create(7, 'session-1', 'upload', {})

    assert manager.cancel(record.transfer_id, 8) is False
    assert record.state is TransferState.PENDING
    assert record.cancel_event.is_set() is False
    assert quota.reservations[0].release_calls == 0

    assert manager.cancel(record.transfer_id, 7) is True


def test_complete_requires_running_and_releases_once():
    quota = SpyQuotaManager()
    manager = make_manager(quota_manager=quota)
    record = manager.create(7, 'session-1', 'download', {})

    assert manager.complete(record.transfer_id, 7) is False
    assert record.state is TransferState.PENDING
    assert quota.reservations[0].release_calls == 0

    manager.consume_token(record.token, 7)
    assert manager.complete(record.transfer_id, 7) is True
    assert record.state is TransferState.COMPLETED
    assert record.cancel_event.is_set() is False
    assert quota.reservations[0].release_calls == 1
    assert manager.complete(record.transfer_id, 7) is False
    assert quota.reservations[0].release_calls == 1


@pytest.mark.parametrize('initial_state', ['pending', 'running'])
def test_fail_is_terminal_and_releases_once(initial_state):
    quota = SpyQuotaManager()
    manager = make_manager(quota_manager=quota)
    record = manager.create(7, 'session-1', 'upload', {})
    if initial_state == 'running':
        manager.consume_token(record.token, 7)

    assert manager.fail(record.transfer_id, 7) is True
    assert record.state is TransferState.FAILED
    assert quota.reservations[0].release_calls == 1
    assert manager.fail(record.transfer_id, 7) is False
    assert quota.reservations[0].release_calls == 1


@pytest.mark.parametrize('iteration', range(20))
def test_concurrent_terminal_transitions_have_one_winner(iteration):
    del iteration
    quota = SpyQuotaManager()
    manager = make_manager(quota_manager=quota)
    record = manager.create(7, 'session-1', 'download', {})
    manager.consume_token(record.token, 7)
    barrier = threading.Barrier(30)
    results = []
    results_lock = threading.Lock()
    operations = (manager.cancel, manager.complete, manager.fail)

    def transition(operation):
        barrier.wait()
        result = operation(record.transfer_id, 7)
        with results_lock:
            results.append(result)

    threads = [
        threading.Thread(target=transition, args=(operations[index % 3],))
        for index in range(30)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(2)

    assert all(not thread.is_alive() for thread in threads)
    assert results.count(True) == 1
    assert results.count(False) == 29
    assert record.state in {
        TransferState.CANCELLED,
        TransferState.COMPLETED,
        TransferState.FAILED,
    }
    assert quota.reservations[0].release_calls == 1
    assert record.cancel_event.is_set() is (
        record.state is TransferState.CANCELLED
    )


@pytest.mark.parametrize(
    ('transfer_id', 'user_id'),
    [
        (None, 7),
        ('', 7),
        ('unknown', None),
        ('unknown', True),
        ('unknown', ''),
    ],
)
def test_terminal_operations_reject_invalid_or_unknown_ids(
        transfer_id, user_id):
    manager = make_manager()

    assert manager.cancel(transfer_id, user_id) is False
    assert manager.complete(transfer_id, user_id) is False
    assert manager.fail(transfer_id, user_id) is False


def test_explicit_cleanup_expires_unused_record_and_releases_once():
    clock = FakeClock()
    quota = SpyQuotaManager()
    manager = make_manager(clock=clock, ttl=5, quota_manager=quota)
    record = manager.create(7, 'session-1', 'download', {})
    token = record.token
    clock.advance(5)

    assert manager.cleanup_expired() == 1
    assert record.state is TransferState.FAILED
    assert record.cancel_event.is_set() is True
    assert quota.reservations[0].release_calls == 1
    assert manager.cleanup_expired() == 0
    assert quota.reservations[0].release_calls == 1
    assert record.token is None

    with pytest.raises(InvalidTransferToken):
        manager.consume_token(token, 7)


def test_consumed_running_record_does_not_expire_with_token_ttl():
    clock = FakeClock()
    quota = SpyQuotaManager()
    manager = make_manager(clock=clock, ttl=5, quota_manager=quota)
    record = manager.create(7, 'session-1', 'upload', {})
    token = record.token
    manager.consume_token(token, 7)
    clock.advance(100)

    assert manager.cleanup_expired() == 0
    assert record.state is TransferState.RUNNING
    assert record.token is None
    assert quota.reservations[0].release_calls == 0
    assert manager.complete(record.transfer_id, 7) is True
    assert quota.reservations[0].release_calls == 1


def test_create_opportunistically_reclaims_expired_user_capacity():
    clock = FakeClock()
    quota = make_quota_manager(global_limit=3, per_user_limit=2)
    manager = make_manager(clock=clock, ttl=5, quota_manager=quota)
    first = manager.create(7, 'session-1', 'upload', {})
    second = manager.create(7, 'session-2', 'upload', {})

    with pytest.raises(QuotaExceeded):
        manager.create(7, 'session-3', 'upload', {})

    clock.advance(5)
    replacement = manager.create(7, 'session-3', 'upload', {})

    assert first.state is TransferState.FAILED
    assert second.state is TransferState.FAILED
    assert replacement.state is TransferState.PENDING


def test_consume_opportunistically_cleans_other_expired_records():
    clock = FakeClock()
    quota = SpyQuotaManager()
    manager = make_manager(clock=clock, ttl=5, quota_manager=quota)
    expired = manager.create(7, 'old-session', 'download', {})
    clock.advance(4)
    live = manager.create(8, 'live-session', 'download', {})
    live_token = live.token
    clock.advance(1)

    assert manager.consume_token(live_token, 8) is live
    assert expired.state is TransferState.FAILED
    assert quota.reservations[0].release_calls == 1
    assert quota.reservations[1].release_calls == 0


def test_malformed_token_attempt_still_runs_opportunistic_cleanup():
    clock = FakeClock()
    quota = SpyQuotaManager()
    manager = make_manager(clock=clock, ttl=1, quota_manager=quota)
    expired = manager.create(7, 'old-session', 'download', {})
    clock.advance(1)

    with pytest.raises(InvalidTransferToken):
        manager.consume_token('t\u00f6ken', 7)

    assert expired.state is TransferState.FAILED
    assert expired.token is None
    assert quota.reservations[0].release_calls == 1


@pytest.mark.parametrize('iteration', range(20))
def test_concurrent_cleanup_and_failure_release_expired_record_once(
        iteration):
    del iteration
    clock = FakeClock()
    quota = SpyQuotaManager()
    manager = make_manager(clock=clock, ttl=1, quota_manager=quota)
    record = manager.create(7, 'session-1', 'upload', {})
    clock.advance(1)
    barrier = threading.Barrier(20)
    results = []
    results_lock = threading.Lock()

    def cleanup():
        barrier.wait()
        result = manager.cleanup_expired()
        with results_lock:
            results.append(result)

    def fail():
        barrier.wait()
        result = manager.fail(record.transfer_id, 7)
        with results_lock:
            results.append(result)

    threads = [
        threading.Thread(target=cleanup)
        for _ in range(10)
    ] + [
        threading.Thread(target=fail)
        for _ in range(10)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(2)

    assert all(not thread.is_alive() for thread in threads)
    # A fail() contender may perform the opportunistic cleanup internally and
    # then return False because the record is already terminal.
    assert sum(int(value) for value in results) <= 1
    assert record.state is TransferState.FAILED
    assert quota.reservations[0].release_calls == 1


@pytest.mark.parametrize('iteration', range(10))
def test_concurrent_create_after_expiry_has_no_quota_slot_leak(iteration):
    del iteration
    clock = FakeClock()
    quota = make_quota_manager(global_limit=3, per_user_limit=2)
    manager = make_manager(clock=clock, ttl=1, quota_manager=quota)
    manager.create(7, 'old-1', 'upload', {})
    manager.create(7, 'old-2', 'upload', {})
    clock.advance(1)
    barrier = threading.Barrier(10)
    records = []
    rejected = []
    result_lock = threading.Lock()

    def create(index):
        barrier.wait()
        try:
            record = manager.create(
                7, f'replacement-{index}', 'upload', {}
            )
        except QuotaExceeded:
            with result_lock:
                rejected.append(index)
        else:
            with result_lock:
                records.append(record)

    threads = [
        threading.Thread(target=create, args=(index,))
        for index in range(10)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(2)

    assert all(not thread.is_alive() for thread in threads)
    assert len(records) == 2
    assert len(rejected) == 8
    for record in records:
        assert manager.cancel(record.transfer_id, 7) is True

    final = manager.create(7, 'final-session', 'upload', {})
    assert final.state is TransferState.PENDING


def test_terminal_records_and_raw_tokens_do_not_accumulate():
    quota = SpyQuotaManager()
    manager = make_manager(quota_manager=quota)

    for index in range(1000):
        record = manager.create(
            7, f'session-{index}', 'upload', {'index': index}
        )
        token = record.token
        if index % 3 == 0:
            assert manager.cancel(record.transfer_id, 7) is True
        elif index % 3 == 1:
            manager.consume_token(token, 7)
            assert manager.complete(record.transfer_id, 7) is True
        else:
            assert manager.fail(record.transfer_id, 7) is True

        assert record.token is None
        assert token not in repr(record)
        assert manager.cancel(record.transfer_id, 7) is False

    assert manager._records == {}
    assert all(
        reservation.release_calls == 1
        for reservation in quota.reservations
    )


def test_terminal_transition_remains_retryable_when_quota_release_fails():
    quota = SpyQuotaManager(release_failures=1)
    manager = make_manager(quota_manager=quota)
    record = manager.create(7, 'session-1', 'upload', {})

    with pytest.raises(RuntimeError, match='injected release failure'):
        manager.cancel(record.transfer_id, 7)

    assert record.state is TransferState.PENDING
    assert record.token is not None
    assert not record.cancel_event.is_set()
    assert manager.cancel(record.transfer_id, 7) is True
    assert record.state is TransferState.CANCELLED
    assert quota.reservations[0].release_calls == 2


def test_expiry_cleanup_remains_retryable_when_quota_release_fails():
    clock = FakeClock()
    quota = SpyQuotaManager(release_failures=1)
    manager = make_manager(clock=clock, ttl=1, quota_manager=quota)
    record = manager.create(7, 'session-1', 'upload', {})
    token = record.token
    clock.advance(1)

    with pytest.raises(RuntimeError, match='injected release failure'):
        manager.cleanup_expired()

    assert record.state is TransferState.PENDING
    assert record.token == token
    assert not record.cancel_event.is_set()
    assert manager.cleanup_expired() == 1
    assert record.state is TransferState.FAILED
    assert record.token is None
    assert quota.reservations[0].release_calls == 2


@pytest.mark.parametrize(
    ('terminal_action', 'expected_state'),
    [
        ('cancel', TransferState.CANCELLED),
        ('expiry', TransferState.FAILED),
    ],
)
def test_pending_record_terminalizes_when_release_raises_after_releasing(
        terminal_action, expected_state):
    clock = FakeClock()
    quota = ReleaseThenRaiseQuotaManager(
        make_quota_manager(global_limit=2, per_user_limit=1)
    )
    manager = make_manager(clock=clock, ttl=1, quota_manager=quota)
    record = manager.create(7, 'session-1', 'upload', {})
    token = record.token

    if terminal_action == 'expiry':
        clock.advance(1)
        operation = manager.cleanup_expired
    else:
        operation = lambda: manager.cancel(record.transfer_id, 7)

    with pytest.raises(RuntimeError, match='injected post-release failure'):
        operation()

    assert record.state is expected_state
    assert record.token is None
    assert record.transfer_id not in manager._records
    with pytest.raises(InvalidTransferToken):
        manager.consume_token(token, 7)
    if terminal_action == 'expiry':
        assert manager.cleanup_expired() == 0
    else:
        assert manager.cancel(record.transfer_id, 7) is False

    replacement = manager.create(7, 'session-2', 'upload', {})
    assert replacement.state is TransferState.PENDING
    assert quota.reservations[0].actual_releases == 1


@pytest.mark.parametrize(
    ('terminal_action', 'expected_state'),
    [
        ('complete', TransferState.COMPLETED),
        ('fail', TransferState.FAILED),
    ],
)
def test_running_record_terminalizes_when_release_raises_after_releasing(
        terminal_action, expected_state):
    quota = ReleaseThenRaiseQuotaManager(
        make_quota_manager(global_limit=2, per_user_limit=1)
    )
    manager = make_manager(quota_manager=quota)
    record = manager.create(7, 'session-1', 'upload', {})
    manager.consume_token(record.token, 7)
    operation = getattr(manager, terminal_action)

    with pytest.raises(RuntimeError, match='injected post-release failure'):
        operation(record.transfer_id, 7)

    assert record.state is expected_state
    assert record.token is None
    assert record.transfer_id not in manager._records
    assert operation(record.transfer_id, 7) is False
    replacement = manager.create(7, 'session-2', 'upload', {})
    assert replacement.state is TransferState.PENDING
    assert quota.reservations[0].actual_releases == 1


def test_create_allocates_fallible_record_data_before_reserving(monkeypatch):
    quota = SpyQuotaManager()
    manager = make_manager(quota_manager=quota)

    def fail_token_generation(_byte_count):
        raise RuntimeError('injected token generation failure')

    monkeypatch.setattr(
        'app.transfer_manager.secrets.token_urlsafe',
        fail_token_generation,
    )

    with pytest.raises(RuntimeError, match='injected token generation failure'):
        manager.create(7, 'session-1', 'upload', {})

    assert quota.reserve_calls == []
    assert manager._records == {}


def test_cancel_all_for_user_only_cancels_owned_pending_and_running_records():
    manager = make_manager()
    pending = manager.create(7, 'session-a', 'upload', {})
    running = manager.create(7, 'session-b', 'download', {})
    other = manager.create(8, 'session-c', 'upload', {})
    manager.consume_token(running.token, 7)

    assert manager.cancel_all_for_user(7) == 2
    assert pending.cancel_event.is_set()
    assert running.cancel_event.is_set()
    assert other.transfer_id in manager._records


def test_runtime_close_atomically_rejects_new_and_unconsumed_transfers():
    manager = make_manager()
    binding = manager.bind_runtime()
    pending = manager.create(7, 'session-a', 'upload', {})
    pending_token = pending.token
    running = manager.create(8, 'session-b', 'upload', {})
    manager.consume_token(running.token, 8)

    waiters = manager.close_and_cancel(binding)

    assert pending.cancel_event.is_set()
    assert running.cancel_event.is_set()
    assert waiters == (
        ('http_upload', running.transfer_id, running.request_done_event),
    )
    with pytest.raises(RuntimeShuttingDown):
        manager.create(9, 'session-c', 'download', {})
    with pytest.raises(RuntimeShuttingDown):
        manager.consume_token(pending_token, 7)


def test_stale_runtime_binding_cannot_close_the_current_app_transfers():
    manager = make_manager()
    stale_binding = manager.bind_runtime()
    current_binding = manager.bind_runtime()
    record = manager.create(7, 'session-a', 'upload', {})

    assert manager.close_and_cancel(stale_binding) == ()
    assert record.cancel_event.is_set() is False

    replacement = manager.create(7, 'session-b', 'download', {})
    assert replacement.state is TransferState.PENDING
    manager.close_and_cancel(current_binding)


@pytest.mark.parametrize('raise_after_release', [False, True])
def test_cancel_all_for_user_retries_release_and_finalizes(raise_after_release):
    class Reservation:
        def __init__(self):
            self.released = False
            self.calls = 0

        def release(self):
            self.calls += 1
            if raise_after_release:
                self.released = True
                raise RuntimeError('after release')
            if self.calls == 1:
                raise RuntimeError('before release')
            self.released = True

    class Quota:
        def __init__(self):
            self.reservations = []

        def reserve(self, *_args):
            reservation = Reservation()
            self.reservations.append(reservation)
            return reservation

    quota = Quota()
    manager = make_manager(quota_manager=quota)
    record = manager.create(7, 'session', 'upload', {})

    assert manager.cancel_all_for_user(7) == 1
    assert record.cancel_event.is_set()
    assert manager._records == {}
    assert quota.reservations[0].released is True
    assert quota.reservations[0].calls == (1 if raise_after_release else 2)
