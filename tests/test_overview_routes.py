"""Overview readiness and reachability: own hosts only, bounded, policy-checked."""
import paramiko
import pytest

import config
from app import overview_routes
from tests.test_automation_service import context  # noqa: F401  (fixture)


@pytest.fixture(autouse=True)
def clear_cache():
    overview_routes._CACHE.clear()
    yield
    overview_routes._CACHE.clear()


@pytest.fixture
def real_trust(monkeypatch):
    from app.host_key_store import HostKeyStore
    monkeypatch.setattr(HostKeyStore, 'has_trusted_key', HOST_KEY_CHECK)


from app.host_key_store import HostKeyStore  # noqa: E402
HOST_KEY_CHECK = HostKeyStore.has_trusted_key


def test_endpoints_require_login(client):
    assert client.get('/api/overview/status').status_code in (302, 401)
    assert client.post('/api/overview/reachability', json={}).status_code in (302, 401)


def test_status_reports_readiness_from_stored_configuration(app, client, context, real_trust, monkeypatch):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from app.jump_host_manager import add_jump_host, load_jump_hosts
    from app.key_manager import load_keys, save_key
    from app.profile_manager import add_profile
    uid, _aid, _book, profile = context
    HostKeyStore(uid, config.KNOWN_HOSTS_FILE, config.USERS_DIR).record(profile['host'], paramiko.RSAKey.generate(1024))
    pem = ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()).decode()
    save_key(uid, 'Overview key', pem)
    key_id = load_keys(uid)[0]['id']
    unknown, error = add_profile(uid, 'Unknown key', 'unknown.example', 22, 'operator', 'key', key_id)
    assert error is None
    # The key disappears after the profile was saved.
    original = overview_routes._owned_inventory
    monkeypatch.setattr(overview_routes, '_owned_inventory', lambda user_id: (*original(user_id)[:2], []))
    add_jump_host(uid, 'Bastion', 'bastion.example', 22, 'ops', 'password')
    jump = load_jump_hosts(uid)[0]
    routed, error = add_profile(uid, 'Routed', 'routed.example', 22, 'operator', 'password', None, jump['id'])
    assert error is None

    hosts = {item['id']: item for item in client.get('/api/overview/status').json['hosts']}
    assert hosts[profile['id']]['host_key'] == 'trusted'
    assert hosts[profile['id']]['state'] == 'ready'
    assert hosts[unknown['id']]['host_key'] == 'unknown'
    assert hosts[unknown['id']]['auth'] == 'key_missing'
    assert hosts[unknown['id']]['state'] == 'action'
    assert hosts[routed['id']]['route'] == 'jump'


def test_status_never_lists_other_users_hosts(app, client, context):
    from app.auth import register_user
    from app.profile_manager import add_profile
    other, error = register_user('overview_other', 'password123')
    assert error is None
    foreign, error = add_profile(other.id, 'Foreign', 'foreign.example', 22, 'root', 'password')
    assert error is None
    ids = {item['id'] for item in client.get('/api/overview/status').json['hosts']}
    assert foreign['id'] not in ids


def _fake_probe(results, calls):
    def probe(host, port):
        calls.append((host, port))
        return dict(results.get(host, {'state': 'reachable', 'latency_ms': 4}))
    return probe


def test_reachability_probes_owned_hosts_and_jump_hosts_instead_of_targets(app, client, context, monkeypatch):
    from app.jump_host_manager import add_jump_host, load_jump_hosts
    from app.profile_manager import add_profile
    uid, _aid, _book, profile = context
    add_jump_host(uid, 'Bastion', 'bastion.example', 2222, 'ops', 'password')
    jump = load_jump_hosts(uid)[0]
    routed, _ = add_profile(uid, 'Routed', 'routed.example', 22, 'operator', 'password', None, jump['id'])
    calls = []
    monkeypatch.setattr(overview_routes, '_probe', _fake_probe({'server.example': {'state': 'unreachable'}}, calls))
    response = client.post('/api/overview/reachability', json={})
    assert response.status_code == 200
    results = response.json['results']
    assert results[profile['id']] == {'state': 'unreachable'}
    assert results[routed['id']]['via_jump'] is True
    assert ('routed.example', 22) not in calls
    assert ('bastion.example', 2222) in calls


def test_reachability_reuses_a_recent_result_and_is_rate_limited(app, client, context, monkeypatch):
    calls = []
    monkeypatch.setattr(overview_routes, '_probe', _fake_probe({}, calls))
    first = client.post('/api/overview/reachability', json={})
    second = client.post('/api/overview/reachability', json={})
    assert first.json['cached'] is False and second.json['cached'] is True
    assert len(calls) == 1
    overview_routes._CACHE.clear()
    statuses = []
    for _ in range(7):
        overview_routes._CACHE.clear()
        statuses.append(client.post('/api/overview/reachability', json={}).status_code)
    assert 429 in statuses


def test_reachability_rejects_oversized_or_malformed_requests(app, client, context):
    assert client.post('/api/overview/reachability', json={'ids': 'all'}).status_code == 400
    assert client.post('/api/overview/reachability', json={'ids': ['x'] * 51}).status_code == 400
    assert client.post('/api/overview/reachability', json=[1]).status_code == 400


def test_reachability_refuses_new_work_during_shutdown(app, client, context, monkeypatch):
    monkeypatch.setattr(app.extensions['runtime_lifecycle'], 'accepting_work', lambda: False)
    assert client.post('/api/overview/reachability', json={}).status_code == 503


def test_probe_applies_the_network_policy(monkeypatch):
    from app import network_policy
    monkeypatch.setattr(config, 'BLOCK_INTERNAL_SSH', True)
    monkeypatch.setattr(config, 'SSH_ALLOWED_INTERNAL_NETWORKS', ())
    assert overview_routes._probe('127.0.0.1', 22) == {'state': 'blocked'}

    def unresolved(*args, **kwargs):
        raise ValueError('Host could not be resolved')

    monkeypatch.setattr(network_policy, 'resolve_allowed_target', unresolved)
    # With internal targets blocked, a missing name is indistinguishable from a blocked one.
    assert overview_routes._probe('nowhere.invalid', 22) == {'state': 'blocked'}
    monkeypatch.setattr(config, 'BLOCK_INTERNAL_SSH', False)
    assert overview_routes._probe('nowhere.invalid', 22) == {'state': 'unresolved'}


def test_probe_only_opens_and_closes_a_tcp_connection(monkeypatch):
    from app import network_policy
    events = []

    class Connection:
        def close(self):
            events.append('close')

        def settimeout(self, value):
            assert 0 < value <= overview_routes.GREETING_TIMEOUT_SECONDS

        def recv(self, size):
            events.append('recv')
            return b''

        def send(self, *args):  # pragma: no cover - must never be called
            events.append('send')

    monkeypatch.setattr(network_policy, 'resolve_allowed_target', lambda *args, **kwargs: object())
    monkeypatch.setattr(network_policy, 'open_validated_socket', lambda target, timeout: (events.append(('open', timeout)), Connection())[1])
    result = overview_routes._probe('host.example', 22)
    assert result['state'] == 'reachable' and isinstance(result['latency_ms'], int)
    # It only listens for the server's greeting and never sends anything.
    assert events == [('open', overview_routes.PROBE_TIMEOUT_SECONDS), 'recv', 'close']

    def refused(target, timeout):
        raise OSError('refused')

    monkeypatch.setattr(network_policy, 'open_validated_socket', refused)
    assert overview_routes._probe('host.example', 22) == {'state': 'unreachable'}


@pytest.mark.parametrize('mode,status', [('off', 200), ('manual', 200), ('automatic', 200), ('always', 400), (True, 400)])
def test_reachability_preference_is_validated(app, client, context, mode, status):
    response = client.post('/api/account/preferences', json={'overview_reachability': mode})
    assert response.status_code == status
    if status == 200:
        assert response.json['settings']['overview_reachability'] == mode
        assert f'data-reachability="{mode}"'.encode() in client.get('/').data


def test_last_reachability_is_read_only_and_follows_the_current_hosts(app, client, context, monkeypatch):
    from app.profile_manager import add_profile
    uid, _aid, _book, _profile = context
    calls = []
    monkeypatch.setattr(overview_routes, '_probe', _fake_probe({}, calls))
    assert client.get('/api/overview/reachability').json == {'results': None}
    checked = client.post('/api/overview/reachability', json={}).json
    restored = client.get('/api/overview/reachability')
    assert restored.headers['Cache-Control'] == 'no-store'
    assert restored.json['results'] == checked['results']
    assert restored.json['checked_at'] == checked['checked_at']
    assert len(calls) == 1, 'reading the last result never probes'
    # A changed inventory makes the stored answer obsolete instead of misleading.
    add_profile(uid, 'Later', 'later.example', 22, 'operator', 'password')
    assert client.get('/api/overview/reachability').json == {'results': None}
    assert len(calls) == 1


def test_last_reachability_expires_and_stays_per_user(app, client, context, monkeypatch):
    monkeypatch.setattr(overview_routes, '_probe', _fake_probe({}, []))
    client.post('/api/overview/reachability', json={})
    uid = context[0]
    with overview_routes._CACHE_LOCK:
        entry = overview_routes._CACHE[uid]
        entry['at'] -= overview_routes.RESULT_RETENTION_SECONDS + 1
    assert client.get('/api/overview/reachability').json == {'results': None}
    with overview_routes._CACHE_LOCK:
        entry['at'] += overview_routes.RESULT_RETENTION_SECONDS + 1
        assert set(overview_routes._CACHE) == {uid}


def test_overview_preferences_round_trip_and_render(app, client, context):
    panels = [{'id': 'hosts', 'w': 8, 'h': None, 'hidden': False}, {'id': 'activity', 'w': 4, 'h': 40, 'hidden': True}]
    response = client.put('/api/overview/preferences', json={'panels': panels, 'dismissed': ['run-failed:r1', 'host-keys:a1b2']})
    assert response.status_code == 200
    assert response.json == {'panels': panels, 'dismissed': ['run-failed:r1', 'host-keys:a1b2']}
    # Partial updates keep the other value.
    assert client.put('/api/overview/preferences', json={'dismissed': []}).json['panels'] == panels
    page = client.get('/').data.decode()
    assert '"activity"' in page and 'id="overviewPreferences"' in page
    assert client.put('/api/overview/preferences', json={'panels': None}).json['panels'] is None


def test_continue_working_layout_persists_with_existing_panel_preferences(app, client, context):
    from app.user_settings import get_user_settings
    panels = [
        {'id': 'hosts', 'w': 8, 'h': None, 'hidden': False},
        {'id': 'continue', 'w': 6, 'h': 40, 'hidden': True},
    ]
    response = client.put('/api/overview/preferences', json={'panels': panels})
    assert response.status_code == 200
    assert response.json['panels'] == panels
    assert get_user_settings(context[0])['overview_panels'] == panels
    assert client.put('/api/overview/preferences', json={'dismissed': []}).json['panels'] == panels
    assert '"id": "continue"' in client.get('/').data.decode()


@pytest.mark.parametrize('kind', ['reboot', 'security-updates', 'socks-missing'])
def test_attention_dismissal_persists_with_existing_items_and_can_be_restored(app, client, context, kind):
    from app.user_settings import get_user_settings
    previous = ['run-failed:r1', 'host-keys:a1b2']
    assert client.put('/api/overview/preferences', json={'dismissed': previous}).status_code == 200
    expected = [*previous, f'{kind}:node-1']
    response = client.put('/api/overview/preferences', json={'dismissed': expected})
    assert response.status_code == 200
    assert response.json['dismissed'] == expected
    assert get_user_settings(context[0])['overview_dismissed'] == expected
    from app.auth import register_user
    other, error = register_user('dismissal_other', 'password123')
    assert error is None
    assert get_user_settings(other.id)['overview_dismissed'] == []
    # A fresh page embeds the persisted choices; rendering must not filter them out.
    assert f'{kind}:node-1' in client.get('/').data.decode()
    assert client.put('/api/overview/preferences', json={'dismissed': previous}).json['dismissed'] == previous
    assert get_user_settings(context[0])['overview_dismissed'] == previous
    assert f'{kind}:node-1' not in client.get('/').data.decode()


@pytest.mark.parametrize('kind', ['reboot', 'security-updates', 'socks-missing'])
@pytest.mark.parametrize('fingerprint', ['', '<script>', 'host:extra', 'x' * 160])
def test_attention_dismissal_rejects_malformed_keys(app, client, context, kind, fingerprint):
    from app.user_settings import get_user_settings
    previous = ['host-keys:existing']
    assert client.put('/api/overview/preferences', json={'dismissed': previous}).status_code == 200
    response = client.put('/api/overview/preferences', json={'dismissed': [*previous, f'{kind}:{fingerprint}']})
    assert response.status_code == 400
    assert response.json['code'] == 'invalid_dismissed'
    assert get_user_settings(context[0])['overview_dismissed'] == previous


@pytest.mark.parametrize('payload', [
    {}, [], {'other': 1}, {'panels': 'all'},
    {'panels': [{'id': 'hosts', 'w': 2, 'h': None, 'hidden': False}]},
    {'panels': [{'id': 'hosts', 'w': 13, 'h': None, 'hidden': False}]},
    {'panels': [{'id': 'hosts', 'w': 6, 'h': 4, 'hidden': False}]},
    {'panels': [{'id': 'hosts', 'w': 6, 'h': None, 'hidden': 'no'}]},
    {'panels': [{'id': 'hosts', 'w': 6}, {'id': 'hosts', 'w': 6}]},
    {'panels': [{'id': 'news', 'w': 6}]},
    {'panels': [{'id': 'hosts', 'w': 6, 'script': 'x'}]},
    {'panels': [{'id': 'hosts', 'w': True}]},
    {'dismissed': 'run-failed:r1'},
    {'dismissed': ['unknown:r1']},
    {'dismissed': ['run-failed:']},
    {'dismissed': ['run-failed:<script>']},
    {'dismissed': ['run-failed:a', 'run-failed:a']},
    {'dismissed': [f'run-failed:r{index}' for index in range(101)]},
])
def test_overview_preferences_reject_invalid_payloads(app, client, context, payload):
    assert client.put('/api/overview/preferences', json=payload).status_code == 400


def test_overview_preferences_require_login(client):
    assert client.put('/api/overview/preferences', json={'dismissed': []}).status_code in (302, 401)


class GreetingConnection:
    def __init__(self, *chunks, error=None):
        self.chunks, self.error, self.sent, self.closed = list(chunks), error, [], False

    def settimeout(self, value):
        pass

    def recv(self, size):
        if self.error:
            raise self.error
        return self.chunks.pop(0)[:size] if self.chunks else b''

    def send(self, data):  # pragma: no cover - must never be called
        self.sent.append(data)

    def close(self):
        self.closed = True


@pytest.mark.parametrize('chunks, platform', [
    ((b'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n',), 'debian'),
    ((b'SSH-2.0-OpenSSH_9.6p1 Ubu', b'ntu-3ubuntu13.5\r\n'), 'ubuntu'),
    ((b'Welcome\r\n', b'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n'), 'ubuntu'),
    ((b'SSH-2.0-OpenSSH_9.7\r\n',), None),
    ((b'HTTP/1.1 400 Bad Request\r\n',), None),
    ((b'x' * 400,), None),
])
def test_probe_reads_the_platform_from_the_ssh_greeting(monkeypatch, chunks, platform):
    from app import network_policy
    connection = GreetingConnection(*chunks)
    monkeypatch.setattr(network_policy, 'resolve_allowed_target', lambda *args, **kwargs: object())
    monkeypatch.setattr(network_policy, 'open_validated_socket', lambda target, timeout: connection)
    result = overview_routes._probe('host.example', 22)
    assert result['state'] == 'reachable'
    assert result.get('platform') == platform
    assert connection.closed and connection.sent == []


def test_a_silent_or_failing_greeting_still_counts_as_reachable(monkeypatch):
    from app import network_policy
    connection = GreetingConnection(error=TimeoutError('timed out'))
    monkeypatch.setattr(network_policy, 'resolve_allowed_target', lambda *args, **kwargs: object())
    monkeypatch.setattr(network_policy, 'open_validated_socket', lambda target, timeout: connection)
    result = overview_routes._probe('host.example', 22)
    assert result['state'] == 'reachable' and 'platform' not in result and connection.closed


def test_reachability_stores_greeting_hints_only_for_direct_hosts(app, client, context, monkeypatch):
    from app.jump_host_manager import add_jump_host, load_jump_hosts
    from app.profile_manager import add_profile, get_profile
    uid, _aid, _book, profile = context
    add_jump_host(uid, 'Bastion', 'bastion.example', 2222, 'ops', 'password')
    jump = load_jump_hosts(uid)[0]
    routed, _ = add_profile(uid, 'Routed', 'routed.example', 22, 'operator', 'password', None, jump['id'])
    monkeypatch.setattr(overview_routes, '_probe', lambda host, port: dict(state='reachable', latency_ms=3, platform='debian'))
    response = client.post('/api/overview/reachability', json={})
    assert response.status_code == 200
    assert response.json['platforms_updated'] is True
    assert 'platform' not in response.json['results'][profile['id']]
    with app.app_context():
        assert get_profile(uid, profile['id'])['greeting_platform'] == 'debian'
        # The probe reached the bastion; its greeting must not label the target.
        assert 'greeting_platform' not in get_profile(uid, routed['id'])


def test_greeting_hints_skip_hosts_edited_since_the_probe(app, context):
    from app.profile_manager import cache_greeting_platforms, get_profile
    uid, _aid, _book, profile = context
    with app.app_context():
        assert cache_greeting_platforms(uid, {profile['id']: (('other.example', 22), 'ubuntu')}) == 0
        assert 'greeting_platform' not in get_profile(uid, profile['id'])
        assert cache_greeting_platforms(uid, {profile['id']: (('server.example', 22), 'windows')}) == 0
