"""Host discovery: manual, bounded, paced, policy-checked and owner-scoped."""
import threading
import time

import pytest

import config
from app import discovery_routes as discovery
from tests.test_automation_service import context  # noqa: F401  (fixture)


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    discovery._SCANS.clear()
    monkeypatch.setattr(discovery, 'START_INTERVAL_SECONDS', 0)
    monkeypatch.setattr(discovery, '_reverse_name', lambda address: None)
    yield
    discovery.cancel_all()
    discovery._SCANS.clear()


def _wait(client, scan_id, state='done', timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        view = client.get(f'/api/discovery/scans/{scan_id}').json
        if view['state'] == state:
            return view
        time.sleep(0.02)
    raise AssertionError(f'scan did not reach {state}: {view}')


@pytest.mark.parametrize('value,count', [('192.168.1.0/24', 254), ('10.0.0.5', 1), ('10.0.0.4/30', 2), ('fd00::/120', 256)])
def test_network_size_is_bounded(value, count):
    assert len(discovery.parse_network(value)) == count


@pytest.mark.parametrize('value', ['10.0.0.0/23', '0.0.0.0/0', 'fd00::/64', 'example.com', '', None, 'x' * 80])
def test_networks_outside_the_limit_are_rejected(value):
    with pytest.raises(ValueError):
        discovery.parse_network(value)


@pytest.mark.parametrize('value', [[], [0], [70000], [22, 23, 24, 25], ['22'], [True], 'all'])
def test_ports_are_validated(value):
    with pytest.raises(ValueError):
        discovery.parse_ports(value)


def test_banner_parsing_keeps_only_printable_facts():
    described = discovery.describe_banner(b'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n')
    assert described == {'software': 'OpenSSH 9.6p1', 'comment': 'Ubuntu-3ubuntu13.5', 'platform': 'ubuntu'}
    assert discovery.describe_banner(b'SSH-2.0-dropbear_2022.83\r\n')['platform'] is None
    assert discovery.describe_banner(b'HTTP/1.1 400 Bad Request\r\n') is None
    assert discovery.describe_banner(b'SSH-2.0-\x1b[31mevil\r\n') is None


def test_probe_never_sends_and_respects_the_network_policy(monkeypatch):
    from app import network_policy
    monkeypatch.setattr(config, 'BLOCK_INTERNAL_SSH', True)
    monkeypatch.setattr(config, 'SSH_ALLOWED_INTERNAL_NETWORKS', ())
    assert discovery._probe('127.0.0.1', 22) == {'state': 'blocked'}
    events = []

    class Connection:
        def settimeout(self, value):
            events.append(('timeout', value))

        def recv(self, size):
            events.append('recv')
            return b'SSH-2.0-OpenSSH_9.2p1 Debian-2\r\n'

        def send(self, *args):  # pragma: no cover - must never be called
            events.append('send')

        sendall = send

        def close(self):
            events.append('close')

    monkeypatch.setattr(network_policy, 'resolve_allowed_target', lambda *args, **kwargs: object())
    monkeypatch.setattr(network_policy, 'open_validated_socket', lambda target, timeout: Connection())
    result = discovery._probe('host.example', 22)
    assert result['state'] == 'ssh' and result['platform'] == 'debian'
    assert 'send' not in events and events[-1] == 'close'


def test_scan_reports_ssh_endpoints_marks_saved_hosts_and_counts_blocked(app, client, context, monkeypatch):
    uid, _aid, _book, profile = context
    saved = profile['host']
    outcomes = {'10.9.0.1': {'state': 'ssh', 'software': 'OpenSSH 9.6', 'comment': '', 'platform': None},
                '10.9.0.2': {'state': 'blocked'}}
    calls = []

    def fake_probe(address, port):
        calls.append((address, port))
        return dict(outcomes.get(address, {'state': 'closed'}))

    monkeypatch.setattr(discovery, '_probe', fake_probe)
    monkeypatch.setattr(discovery, '_known_endpoints', lambda user_id: {('10.9.0.1', 2222), (saved, 22)})
    response = client.post('/api/discovery/scans', json={'network': '10.9.0.0/29', 'ports': [22, 2222]})
    assert response.status_code == 202
    view = _wait(client, response.json['id'])
    assert view['total'] == 12 and view['checked'] == 12 and len(calls) == 12
    assert view['blocked'] == 2
    assert [(item['address'], item['port'], item['known']) for item in view['found']] == [('10.9.0.1', 22, False), ('10.9.0.1', 2222, True)]


def test_one_running_scan_per_user_cancel_and_owner_scope(app, client, context, monkeypatch):
    release = threading.Event()

    def slow_probe(address, port):
        release.wait(2)
        return {'state': 'closed'}

    monkeypatch.setattr(discovery, '_probe', slow_probe)
    first = client.post('/api/discovery/scans', json={'network': '10.8.0.0/28'})
    assert first.status_code == 202
    assert client.post('/api/discovery/scans', json={'network': '10.8.1.0/28'}).status_code == 409
    scan_id = first.json['id']
    # Another account cannot see or stop the scan.
    from app.auth import register_user
    other, error = register_user('discovery_other', 'password123')
    assert error is None
    with discovery._LOCK:
        discovery._SCANS[scan_id].user_id = other.id
    assert client.get(f'/api/discovery/scans/{scan_id}').status_code == 404
    assert client.delete(f'/api/discovery/scans/{scan_id}').status_code == 404
    with discovery._LOCK:
        discovery._SCANS[scan_id].user_id = context[0]
    cancelled = client.delete(f'/api/discovery/scans/{scan_id}')
    assert cancelled.json['state'] == 'cancelled'
    release.set()
    view = _wait(client, scan_id, state='cancelled')
    assert view['checked'] < view['total']


def test_starts_are_paced(monkeypatch):
    monkeypatch.setattr(discovery, 'START_INTERVAL_SECONDS', 0.05)
    started = []
    monkeypatch.setattr(discovery, '_probe', lambda address, port: started.append(time.monotonic()) or {'state': 'closed'})
    scan = discovery.Scan(1, '10.7.0.0/29', discovery.parse_network('10.7.0.0/29'), [22], set())
    scan.run()
    gaps = [later - earlier for earlier, later in zip(started, started[1:])]
    assert len(started) == 6 and min(gaps) >= 0.04


@pytest.mark.parametrize('payload', [{}, [], {'network': '10.0.0.0/16'}, {'network': '10.0.0.0/24', 'ports': [0]},
                                     {'network': '10.0.0.0/24', 'extra': 1}])
def test_invalid_scan_requests_are_rejected(app, client, context, payload):
    assert client.post('/api/discovery/scans', json=payload).status_code == 400


def test_scans_require_login_and_running_app(app, client, context, monkeypatch):
    monkeypatch.setattr(app.extensions['runtime_lifecycle'], 'accepting_work', lambda: False)
    assert client.post('/api/discovery/scans', json={'network': '10.0.0.0/30'}).status_code == 503


def test_scans_require_login(client):
    assert client.post('/api/discovery/scans', json={'network': '10.0.0.0/30'}).status_code in (302, 401)


def test_real_probe_reads_the_greeting_from_a_local_server(monkeypatch):
    import socket
    monkeypatch.setattr(config, 'BLOCK_INTERNAL_SSH', False)
    server = socket.socket()
    server.bind(('127.0.0.1', 0))
    server.listen(1)
    server.settimeout(5)  # never leave a waiting thread behind if the probe is refused
    received = []

    def serve():
        try:
            connection, _ = server.accept()
        except OSError:
            return
        connection.sendall(b'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n')
        connection.settimeout(1)
        try:
            received.append(connection.recv(64))
        except OSError:
            received.append(b'')
        connection.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    result = discovery._probe('127.0.0.1', server.getsockname()[1])
    thread.join(3)
    server.close()
    assert result['state'] == 'ssh' and result['software'] == 'OpenSSH 9.6p1' and result['platform'] == 'ubuntu'
    assert received == [b''], 'the probe sends nothing before closing'


def test_invalid_input_gets_a_fixed_message(app, client, context):
    response = client.post('/api/discovery/scans', json={'network': '10.0.0.0/16'})
    assert response.status_code == 400
    assert response.json == {'error': 'Choose a range of at most 256 addresses (for example a /24).', 'code': 'invalid_network'}
    assert client.post('/api/discovery/scans', json={'network': 'not a network'}).json['error'] == 'Enter a network such as 192.168.1.0/24.'
