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
    assert overview_routes._probe('nowhere.invalid', 22) == {'state': 'unresolved'}


def test_probe_only_opens_and_closes_a_tcp_connection(monkeypatch):
    from app import network_policy
    events = []

    class Connection:
        def close(self):
            events.append('close')

        def send(self, *args):  # pragma: no cover - must never be called
            events.append('send')

    monkeypatch.setattr(network_policy, 'resolve_allowed_target', lambda *args, **kwargs: object())
    monkeypatch.setattr(network_policy, 'open_validated_socket', lambda target, timeout: (events.append(('open', timeout)), Connection())[1])
    result = overview_routes._probe('host.example', 22)
    assert result['state'] == 'reachable' and isinstance(result['latency_ms'], int)
    assert events == [('open', overview_routes.PROBE_TIMEOUT_SECONDS), 'close']

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
