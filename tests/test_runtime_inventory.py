import pytest


from app import runtime_inventory
from app.runtime_inventory import parse_runtime_inventory


VALID_INVENTORY = """systemd_state=degraded
systemd_total=3
systemd_active=2
systemd_failed=1
systemd_returned=3
systemd_service=nginx.service|loaded|active|running|A web server
systemd_service=backup.service|loaded|failed|failed|Nightly backup
systemd_service=cron.service|loaded|active|running|Job scheduler
docker_version=27.5.1
docker_total=2
docker_running=1
docker_returned=2
docker_container=webssh|Up 3 hours (healthy)
docker_container=worker|Exited (1) 2 hours ago
"""


def test_parse_runtime_inventory_returns_systemd_and_docker_rows():
    result = parse_runtime_inventory(VALID_INVENTORY)

    assert result['systemd'] == {
        'state': 'degraded', 'total': 3, 'active': 2, 'failed': 1,
        'returned': 3, 'truncated': False,
        'services': [
            {'unit': 'nginx.service', 'load': 'loaded', 'active': 'active',
             'sub': 'running', 'description': 'A web server'},
            {'unit': 'backup.service', 'load': 'loaded', 'active': 'failed',
             'sub': 'failed', 'description': 'Nightly backup'},
            {'unit': 'cron.service', 'load': 'loaded', 'active': 'active',
             'sub': 'running', 'description': 'Job scheduler'},
        ],
    }
    assert result['docker']['containers'][1] == {
        'name': 'worker', 'status': 'Exited (1) 2 hours ago'
    }


def test_parse_runtime_inventory_caps_systemd_and_docker_rows():
    systemd_rows = ''.join(
        'systemd_service=service{0}.service|loaded|active|running|Service {0}\n'
        .format(number)
        for number in range(1, 202)
    )
    docker_rows = ''.join(
        'docker_container=container{0}|Up {0} minutes\n'.format(number)
        for number in range(1, 52)
    )

    result = parse_runtime_inventory(
        'systemd_state=running\n'
        'systemd_total=201\n'
        'systemd_active=201\n'
        'systemd_failed=0\n'
        'systemd_returned=201\n'
        + systemd_rows
        + 'docker_version=27.5.1\n'
        'docker_total=51\n'
        'docker_running=51\n'
        'docker_returned=51\n'
        + docker_rows
    )

    assert len(result['systemd']['services']) == 200
    assert result['systemd']['services'][-1]['unit'] == 'service200.service'
    assert len(result['docker']['containers']) == 50
    assert result['docker']['containers'][-1]['name'] == 'container50'


def test_parse_runtime_inventory_marks_sections_truncated_when_total_exceeds_rows():
    result = parse_runtime_inventory(
        'systemd_state=running\n'
        'systemd_total=5\n'
        'systemd_active=5\n'
        'systemd_failed=0\n'
        'systemd_returned=2\n'
        'systemd_service=one.service|loaded|active|running|One\n'
        'systemd_service=two.service|loaded|active|running|Two\n'
        'docker_version=27.5.1\n'
        'docker_total=4\n'
        'docker_running=4\n'
        'docker_returned=1\n'
        'docker_container=webssh|Up 3 hours\n'
    )

    assert result['systemd']['truncated'] is True
    assert result['docker']['truncated'] is True


def test_parse_runtime_inventory_omits_hostile_or_malformed_rows_and_normalizes_returned():
    result = parse_runtime_inventory(
        'systemd_state=running\n'
        'systemd_total=4\n'
        'systemd_active=4\n'
        'systemd_failed=0\n'
        'systemd_returned=4\n'
        'systemd_service=good.service|loaded|active|running|Good service\n'
        'systemd_service=bad unit|loaded|active|running|Invalid unit\n'
        'systemd_service=control.service|loaded|active|running|Bad\x1f description\n'
        'systemd_service=long.service|loaded|active|running|' + ('x' * 241) + '\n'
        'systemd_service=malformed\n'
        'docker_version=27.5.1\n'
        'docker_total=4\n'
        'docker_running=1\n'
        'docker_returned=4\n'
        'docker_container=good|Up 3 hours\n'
        'docker_container=bad name|Up 3 hours\n'
        'docker_container=control|Bad\x1f status\n'
        'docker_container=malformed\n'
    )

    assert result['systemd']['returned'] == 1
    assert result['systemd']['truncated'] is True
    assert result['systemd']['services'] == [{
        'unit': 'good.service', 'load': 'loaded', 'active': 'active',
        'sub': 'running', 'description': 'Good service',
    }]
    assert result['docker']['returned'] == 1
    assert result['docker']['truncated'] is True
    assert result['docker']['containers'] == [
        {'name': 'good', 'status': 'Up 3 hours'},
    ]


@pytest.mark.parametrize(
    'payload',
    [
        'systemd_state=running\nsystemd_total=1\nsystemd_active=2\nsystemd_failed=0\nsystemd_returned=1\n',
        'docker_version=27\ndocker_total=1\ndocker_running=2\ndocker_returned=1\n',
    ],
)
def test_parse_runtime_inventory_omits_sections_with_impossible_counts(payload):
    assert parse_runtime_inventory(payload) == {}


def test_parse_runtime_inventory_returns_empty_inventory_for_unknown_output():
    assert parse_runtime_inventory('remote_secret=must-not-leak\n') == {}


def test_parse_runtime_inventory_deduplicates_permission_scopes_in_first_seen_order():
    assert parse_runtime_inventory(
        'permission_denied=systemd\n'
        'permission_denied=docker\n'
        'permission_denied=systemd\n'
        'permission_denied=unknown\n'
    ) == {'permission_denied': ['systemd', 'docker']}


def test_parse_runtime_inventory_rejects_payload_above_default_bound():
    with pytest.raises(ValueError, match='^inventory payload too large$'):
        parse_runtime_inventory('x' * (64 * 1024 + 1))


class FakeChannel:
    def __init__(self, payload=VALID_INVENTORY.encode(), *, status=0,
                 recv_error=None, exit_ready=None):
        self.payload = bytearray(payload)
        self.status = status
        self.recv_error = recv_error
        self.exit_ready = exit_ready
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
        if self.exit_ready is not None:
            return self.exit_ready
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
    monkeypatch.setitem(runtime_inventory.ssh_manager.sessions, 'owned-session', {
        'connected': connected,
        'client': FakeClient(transport),
    })
    return transport


def test_collect_runtime_inventory_uses_separate_bounded_exec_channel(monkeypatch):
    transport = install_session(monkeypatch)
    channel = FakeChannel()
    opened_commands = []

    def open_channel(actual_transport, command, *, timeout):
        assert actual_transport is transport
        opened_commands.append((command, timeout))
        return channel

    monkeypatch.setattr(
        runtime_inventory.ssh_manager, '_open_exec_channel', open_channel,
    )

    inventory, error = runtime_inventory.collect_runtime_inventory('owned-session')

    assert error is None
    assert inventory['systemd']['services'][0]['unit'] == 'nginx.service'
    assert opened_commands == [(runtime_inventory.RUNTIME_INVENTORY_COMMAND, 2.0)]
    assert channel.closed is True
    assert 'owned-session' not in runtime_inventory._collector_locks


@pytest.mark.parametrize(
    ('connected', 'transport_active'),
    [(False, True), (True, False)],
)
def test_collect_runtime_inventory_rejects_unavailable_sessions(
        monkeypatch, connected, transport_active):
    install_session(
        monkeypatch, connected=connected, transport_active=transport_active,
    )

    inventory, error = runtime_inventory.collect_runtime_inventory('owned-session')

    assert inventory is None
    assert error == 'unavailable'
    assert 'owned-session' not in runtime_inventory._collector_locks


def test_collect_runtime_inventory_rejects_busy_session(monkeypatch):
    install_session(monkeypatch)
    held_lock = runtime_inventory.Lock()
    held_lock.acquire()
    monkeypatch.setitem(
        runtime_inventory._collector_locks,
        'owned-session',
        {'lock': held_lock, 'references': 1},
    )

    inventory, error = runtime_inventory.collect_runtime_inventory('owned-session')

    assert inventory is None
    assert error == 'busy'


def test_collect_runtime_inventory_closes_channel_after_timeout(monkeypatch):
    install_session(monkeypatch)
    channel = FakeChannel(payload=b'', exit_ready=False)
    monkeypatch.setattr(
        runtime_inventory.ssh_manager,
        '_open_exec_channel',
        lambda *_args, **_kwargs: channel,
    )

    inventory, error = runtime_inventory.collect_runtime_inventory(
        'owned-session', timeout=0.01,
    )

    assert inventory is None
    assert error == 'unavailable'
    assert channel.closed is True
    assert 'owned-session' not in runtime_inventory._collector_locks


@pytest.mark.parametrize(
    ('payload', 'status', 'max_bytes'),
    [
        (b'x' * 129, 0, 128),
        (VALID_INVENTORY.encode(), 1, runtime_inventory.DEFAULT_MAX_BYTES),
        (b'\xff', 0, runtime_inventory.DEFAULT_MAX_BYTES),
    ],
)
def test_collect_runtime_inventory_rejects_unsafe_channel_output(
        monkeypatch, payload, status, max_bytes):
    install_session(monkeypatch)
    channel = FakeChannel(payload=payload, status=status)
    monkeypatch.setattr(
        runtime_inventory.ssh_manager,
        '_open_exec_channel',
        lambda *_args, **_kwargs: channel,
    )

    inventory, error = runtime_inventory.collect_runtime_inventory(
        'owned-session', max_bytes=max_bytes,
    )

    assert inventory is None
    assert error == 'unavailable'
    assert channel.closed is True
    assert 'owned-session' not in runtime_inventory._collector_locks


def test_collect_runtime_inventory_rejects_parser_failure(monkeypatch):
    install_session(monkeypatch)
    channel = FakeChannel()
    monkeypatch.setattr(
        runtime_inventory.ssh_manager,
        '_open_exec_channel',
        lambda *_args, **_kwargs: channel,
    )
    monkeypatch.setattr(
        runtime_inventory, 'parse_runtime_inventory',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError('invalid')),
    )

    inventory, error = runtime_inventory.collect_runtime_inventory('owned-session')

    assert inventory is None
    assert error == 'unavailable'
    assert channel.closed is True
    assert 'owned-session' not in runtime_inventory._collector_locks


@pytest.mark.parametrize(
    'failure',
    [
        __import__('socket').timeout(),
        RuntimeError('unexpected'),
    ],
)
def test_collect_runtime_inventory_rejects_channel_exceptions(monkeypatch, failure):
    install_session(monkeypatch)
    monkeypatch.setattr(
        runtime_inventory.ssh_manager,
        '_open_exec_channel',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(failure),
    )

    inventory, error = runtime_inventory.collect_runtime_inventory('owned-session')

    assert inventory is None
    assert error == 'unavailable'
    assert 'owned-session' not in runtime_inventory._collector_locks


@pytest.mark.parametrize(
    'setup',
    [
        lambda monkeypatch: None,
        lambda monkeypatch: monkeypatch.setattr(
            runtime_inventory.ssh_manager,
            '_open_exec_channel',
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError()),
        ),
    ],
)
def test_collect_runtime_inventory_releases_lock_after_success_and_exec_failure(
        monkeypatch, setup):
    install_session(monkeypatch)
    setup(monkeypatch)

    runtime_inventory.collect_runtime_inventory('owned-session')

    assert 'owned-session' not in runtime_inventory._collector_locks
