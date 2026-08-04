import pytest
from threading import Event, Lock, Thread


from app import session_insights


VALID_PAYLOAD = """\
cpu=100 5 50 800 20 10 5 10
mem_total_kib=16384000
mem_available_kib=6144000
disk_total_kib=102400000
disk_used_kib=61440000
disk_available_kib=40960000
disk_percent=60
uptime_seconds=93784.75
os_name=Ubuntu 24.04.2 LTS
"""


def test_parse_linux_stats_returns_normalized_numeric_values():
    result = session_insights.parse_linux_stats(VALID_PAYLOAD)

    assert result == {
        'cpu': [100, 5, 50, 800, 20, 10, 5, 10],
        'memory': {
            'total_kib': 16384000,
            'available_kib': 6144000,
            'used_kib': 10240000,
        },
        'disk': {
            'total_kib': 102400000,
            'used_kib': 61440000,
            'available_kib': 40960000,
            'percent': 60,
        },
        'uptime_seconds': 93784,
        'os_name': 'Ubuntu 24.04.2 LTS',
    }


@pytest.mark.parametrize(
    'mutation',
    [
        lambda value: value.replace('cpu=100 5 50 800 20 10 5 10\n', ''),
        lambda value: value.replace('mem_total_kib=16384000', 'mem_total_kib=-1'),
        lambda value: value.replace('mem_available_kib=6144000', 'mem_available_kib=20000000'),
        lambda value: value.replace('disk_percent=60', 'disk_percent=101'),
        lambda value: value.replace('uptime_seconds=93784.75', 'uptime_seconds=unknown'),
        lambda value: value.replace('os_name=Ubuntu 24.04.2 LTS', 'os_name='),
    ],
)
def test_parse_linux_stats_rejects_missing_or_invalid_linux_values(mutation):
    with pytest.raises(ValueError):
        session_insights.parse_linux_stats(mutation(VALID_PAYLOAD))


def test_parse_linux_stats_rejects_output_above_bound():
    with pytest.raises(ValueError):
        session_insights.parse_linux_stats(
            VALID_PAYLOAD + ('x' * 20000),
            max_bytes=16384,
        )


def test_parse_linux_stats_ignores_unknown_keys_without_exposing_them():
    result = session_insights.parse_linux_stats(
        VALID_PAYLOAD + 'remote_secret=must-not-leak\n'
    )

    assert 'remote_secret' not in result


class FakeChannel:
    def __init__(self, payload=VALID_PAYLOAD.encode(), *, status=0,
                 recv_error=None):
        self.payload = bytearray(payload)
        self.status = status
        self.recv_error = recv_error
        self.closed = False

    def recv_ready(self):
        return bool(self.payload)

    def recv(self, size):
        if self.recv_error:
            raise self.recv_error
        chunk = bytes(self.payload[:size])
        del self.payload[:size]
        return chunk

    def exit_status_ready(self):
        return not self.payload

    def recv_exit_status(self):
        return self.status

    def close(self):
        self.closed = True


class FakeTransport:
    def __init__(self, active=True):
        self.active = active

    def is_active(self):
        return self.active


class FakeClient:
    def __init__(self, transport):
        self.transport = transport

    def get_transport(self):
        return self.transport


def install_session(monkeypatch, *, connected=True, transport_active=True):
    transport = FakeTransport(active=transport_active)
    monkeypatch.setitem(session_insights.ssh_manager.sessions, 'owned-session', {
        'connected': connected,
        'client': FakeClient(transport),
    })
    return transport


def test_collect_linux_stats_uses_separate_fixed_exec_channel(monkeypatch):
    transport = install_session(monkeypatch)
    channel = FakeChannel()
    observed = {}

    def open_channel(actual_transport, command, *, timeout):
        observed.update(
            transport=actual_transport,
            command=command,
            timeout=timeout,
        )
        return channel

    monkeypatch.setattr(
        session_insights.ssh_manager, '_open_exec_channel', open_channel
    )

    stats, error = session_insights.collect_linux_stats(
        'owned-session', timeout=0.2
    )

    assert error is None
    assert stats['memory']['used_kib'] == 10240000
    assert observed == {
        'transport': transport,
        'command': session_insights.LINUX_STATS_COMMAND,
        'timeout': 0.2,
    }
    assert channel.closed is True


@pytest.mark.parametrize(
    ('connected', 'transport_active', 'expected_error'),
    [
        (False, True, 'unavailable'),
        (True, False, 'unavailable'),
    ],
)
def test_collect_linux_stats_rejects_inactive_sessions(
        monkeypatch, connected, transport_active, expected_error):
    install_session(
        monkeypatch,
        connected=connected,
        transport_active=transport_active,
    )

    stats, error = session_insights.collect_linux_stats('owned-session')

    assert stats is None
    assert error == expected_error


def test_collect_linux_stats_rejects_missing_session(monkeypatch):
    monkeypatch.delitem(
        session_insights.ssh_manager.sessions, 'owned-session', raising=False
    )

    stats, error = session_insights.collect_linux_stats('owned-session')

    assert stats is None
    assert error == 'unavailable'


def test_collect_linux_stats_rejects_overlapping_collection(monkeypatch):
    install_session(monkeypatch)
    held_lock = Lock()
    held_lock.acquire()
    monkeypatch.setitem(
        session_insights._collector_locks,
        'owned-session',
        {'lock': held_lock, 'references': 1},
    )

    stats, error = session_insights.collect_linux_stats('owned-session')

    assert stats is None
    assert error == 'busy'


def test_session_collector_lock_survives_release_to_waiter_handoff(monkeypatch):
    class ControlledLock:
        def __init__(self):
            self.inner = Lock()
            self.acquire_calls = 0
            self.waiter_ready = Event()
            self.allow_waiter = Event()

        def acquire(self, blocking=False):
            self.acquire_calls += 1
            if self.acquire_calls == 2:
                self.waiter_ready.set()
                assert self.allow_waiter.wait(timeout=1)
            return self.inner.acquire(blocking=blocking)

        def release(self):
            self.inner.release()

    controlled = ControlledLock()
    monkeypatch.setitem(
        session_insights._collector_locks,
        'handoff-session',
        {'lock': controlled, 'references': 0},
    )
    first = session_insights._acquire_session_lock('handoff-session')
    waiter_result = []
    waiter = Thread(
        target=lambda: waiter_result.append(
            session_insights._acquire_session_lock('handoff-session')
        )
    )
    waiter.start()
    assert controlled.waiter_ready.wait(timeout=1)

    session_insights._release_session_lock('handoff-session', first)
    controlled.allow_waiter.set()
    waiter.join(timeout=1)

    assert waiter_result == [controlled]
    assert session_insights._acquire_session_lock('handoff-session') is None
    session_insights._release_session_lock('handoff-session', controlled)
    assert 'handoff-session' not in session_insights._collector_locks


def test_collect_linux_stats_rejects_nonzero_remote_status(monkeypatch):
    install_session(monkeypatch)
    channel = FakeChannel(status=1)
    monkeypatch.setattr(
        session_insights.ssh_manager,
        '_open_exec_channel',
        lambda *_args, **_kwargs: channel,
    )

    stats, error = session_insights.collect_linux_stats('owned-session')

    assert stats is None
    assert error == 'unavailable'
    assert channel.closed is True


def test_collect_linux_stats_rejects_output_above_collection_bound(monkeypatch):
    install_session(monkeypatch)
    channel = FakeChannel(payload=b'x' * 129)
    monkeypatch.setattr(
        session_insights.ssh_manager,
        '_open_exec_channel',
        lambda *_args, **_kwargs: channel,
    )

    stats, error = session_insights.collect_linux_stats(
        'owned-session', max_bytes=128
    )

    assert stats is None
    assert error == 'unavailable'
    assert channel.closed is True
