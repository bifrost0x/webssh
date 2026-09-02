import shutil
import subprocess
from threading import Event, Lock, Thread

import pytest


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


DIAGNOSTICS_PAYLOAD = VALID_PAYLOAD + """\
load_1=1.25
load_5=0.75
load_15=0.50
cpu_count=8
swap_total_kib=2097152
swap_free_kib=1572864
network_received_bytes=123456789
network_transmitted_bytes=98765432
process_total=215
process_zombies=2
process_cpu=812|postgres|postgres|32.5|4.1
process_cpu=924|deploy|python3|18.0|2.5
process_memory=177|redis|redis-server|3.5|12.4
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


def test_parse_linux_stats_keeps_supported_partial_metrics():
    result = session_insights.parse_linux_stats("""\
disk_total_kib=2048000
disk_used_kib=1024000
disk_available_kib=1024000
disk_percent=50
os_name=Network appliance OS
""")

    assert result == {
        'disk': {
            'total_kib': 2048000,
            'used_kib': 1024000,
            'available_kib': 1024000,
            'percent': 50,
        },
        'os_name': 'Network appliance OS',
    }


def test_parse_linux_stats_ignores_invalid_section_when_another_is_valid():
    result = session_insights.parse_linux_stats("""\
cpu=not counters
mem_total_kib=4096
mem_available_kib=1024
""")

    assert result == {
        'memory': {
            'total_kib': 4096,
            'available_kib': 1024,
            'used_kib': 3072,
        },
    }


def test_parse_linux_stats_rejects_payload_without_supported_metrics():
    with pytest.raises(ValueError, match='no supported metrics'):
        session_insights.parse_linux_stats('vendor_prompt=Switch#\n')


@pytest.mark.parametrize(
    ('mutation', 'omitted_section'),
    [
        (
            lambda value: value.replace('cpu=100 5 50 800 20 10 5 10\n', ''),
            'cpu',
        ),
        (
            lambda value: value.replace('mem_total_kib=16384000', 'mem_total_kib=-1'),
            'memory',
        ),
        (
            lambda value: value.replace('mem_available_kib=6144000', 'mem_available_kib=20000000'),
            'memory',
        ),
        (
            lambda value: value.replace('disk_percent=60', 'disk_percent=101'),
            'disk',
        ),
        (
            lambda value: value.replace('uptime_seconds=93784.75', 'uptime_seconds=unknown'),
            'uptime_seconds',
        ),
        (
            lambda value: value.replace('os_name=Ubuntu 24.04.2 LTS', 'os_name='),
            'os_name',
        ),
    ],
)
def test_parse_linux_stats_omits_only_missing_or_invalid_section(
        mutation, omitted_section):
    result = session_insights.parse_linux_stats(mutation(VALID_PAYLOAD))

    assert omitted_section not in result
    assert result


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


def test_parse_linux_stats_normalizes_optional_diagnostics():
    result = session_insights.parse_linux_stats(DIAGNOSTICS_PAYLOAD)

    assert result['load'] == {
        'one': 1.25,
        'five': 0.75,
        'fifteen': 0.5,
        'cpu_count': 8,
    }
    assert result['swap'] == {
        'total_kib': 2097152,
        'available_kib': 1572864,
        'used_kib': 524288,
    }
    assert result['network'] == {
        'received_bytes': 123456789,
        'transmitted_bytes': 98765432,
    }
    assert result['processes'] == {
        'total': 215,
        'zombies': 2,
        'top_cpu': [
            {
                'pid': 812,
                'user': 'postgres',
                'command': 'postgres',
                'cpu_percent': 32.5,
                'memory_percent': 4.1,
            },
            {
                'pid': 924,
                'user': 'deploy',
                'command': 'python3',
                'cpu_percent': 18.0,
                'memory_percent': 2.5,
            },
        ],
        'top_memory': [
            {
                'pid': 177,
                'user': 'redis',
                'command': 'redis-server',
                'cpu_percent': 3.5,
                'memory_percent': 12.4,
            },
        ],
    }
    assert 'permission_denied' not in result


def test_parse_linux_stats_omits_malformed_optional_sections_but_keeps_core():
    result = session_insights.parse_linux_stats(
        VALID_PAYLOAD
        + 'load_1=-1\nload_5=0.2\nload_15=0.1\ncpu_count=0\n'
        + 'swap_total_kib=100\nswap_free_kib=200\n'
        + 'process_total=-1\nprocess_zombies=0\n'
        + 'process_cpu=not-a-row\n'
    )

    assert result['os_name'] == 'Ubuntu 24.04.2 LTS'
    for key in ('load', 'swap', 'processes'):
        assert key not in result


def test_parse_linux_stats_exposes_only_deduplicated_known_permission_scopes():
    result = session_insights.parse_linux_stats(
        VALID_PAYLOAD
        + 'permission_denied=processes\n'
        + 'permission_denied=processes\n'
        + 'permission_denied=unknown\n'
    )

    assert result['permission_denied'] == ['processes']


def test_remote_diagnostics_use_a_fixed_safe_environment_without_elevation():
    assert session_insights.LINUX_STATS_COMMAND.startswith(
        'LC_ALL=C\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin\nexport LC_ALL PATH\n'
    )
    assert 'systemctl ' not in session_insights.LINUX_DIAGNOSTICS_COMMAND
    assert 'docker ' not in session_insights.LINUX_DIAGNOSTICS_COMMAND
    assert 'ps -e ' in session_insights.LINUX_DIAGNOSTICS_COMMAND
    assert '/proc/net/dev' in session_insights.LINUX_DIAGNOSTICS_COMMAND
    for forbidden in ('sudo ', 'su ', 'doas ', 'curl ', 'wget ', ' /proc/*/environ'):
        assert forbidden not in session_insights.LINUX_DIAGNOSTICS_COMMAND
    assert 'comm=' in session_insights.LINUX_DIAGNOSTICS_COMMAND
    assert 'args=' not in session_insights.LINUX_DIAGNOSTICS_COMMAND
    assert 'if [ -r /proc/stat ]' in session_insights.LINUX_STATS_COMMAND
    assert 'command -v df' in session_insights.LINUX_STATS_COMMAND
    assert 'command -v uname' in session_insights.LINUX_STATS_COMMAND


@pytest.mark.skipif(shutil.which('awk') is None, reason='awk is not installed')
def test_network_collector_reads_bytes_for_short_and_long_interface_names():
    proc_net_dev = """\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 99999999 9999 0 0 0 0 0 0 88888888 8888 0 0 0 0 0 0
  eth0: 10485760 1000 0 0 0 0 0 0 12345 100 0 0 0 0 0 0
enp0s31f6: 20971520 2000 0 0 0 0 0 0 54321 200 0 0 0 0 0 0
"""

    result = subprocess.run(
        ['awk', session_insights.LINUX_NETWORK_AWK_PROGRAM],
        input=proc_net_dev,
        text=True,
        capture_output=True,
        check=True,
    )

    assert result.stdout.splitlines() == [
        'network_received_bytes=31457280',
        'network_transmitted_bytes=66666',
    ]


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


def test_collect_linux_stats_accepts_bounded_metrics_without_exit_status(
        monkeypatch):
    install_session(monkeypatch)

    class NoExitStatusChannel(FakeChannel):
        def exit_status_ready(self):
            return False

    channel = NoExitStatusChannel()
    monkeypatch.setattr(
        session_insights.ssh_manager,
        '_open_exec_channel',
        lambda *_args, **_kwargs: channel,
    )

    stats, error = session_insights.collect_linux_stats(
        'owned-session', timeout=0.01
    )

    assert error is None
    assert stats['os_name'] == 'Ubuntu 24.04.2 LTS'
    assert channel.closed is True


def test_collect_linux_stats_uses_expanded_fixed_command_only_when_requested(
        monkeypatch):
    transport = install_session(monkeypatch)
    channel = FakeChannel(payload=DIAGNOSTICS_PAYLOAD.encode())
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
        'owned-session', timeout=0.2, include_diagnostics=True
    )

    assert error is None
    assert stats['processes']['total'] == 215
    assert observed == {
        'transport': transport,
        'command': session_insights.LINUX_DIAGNOSTICS_COMMAND,
        'timeout': 0.2,
    }
    assert channel.closed is True


@pytest.mark.parametrize(
    ('connected', 'transport_active', 'expected_error'),
    [
        (False, True, 'transient'),
        (True, False, 'transient'),
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
    assert error == 'transient'


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
    assert error == 'unsupported'
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
    assert error == 'unsupported'
    assert channel.closed is True


def test_collect_linux_stats_treats_generic_ssh_channel_race_as_transient(monkeypatch):
    from paramiko import SSHException

    install_session(monkeypatch)
    monkeypatch.setattr(
        session_insights.ssh_manager,
        '_open_exec_channel',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            SSHException('channel closed during transport race')
        ),
    )

    stats, error = session_insights.collect_linux_stats('owned-session')

    assert stats is None
    assert error == 'transient'
