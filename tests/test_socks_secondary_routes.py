"""SOCKS routes remain explicit in probes, automation, recovery, and exchange."""

from datetime import datetime, timezone
import io
import json
import zipfile

import pytest

from app.automation_store import AutomationError
from tests.test_automation_service import context  # noqa: F401
from tests.test_automation_schedules import scheduling, activate  # noqa: F401


@pytest.fixture(autouse=True)
def clear_overview_cache():
    from app.overview_routes import _CACHE

    _CACHE.clear()
    yield
    _CACHE.clear()


def _routed_profile(uid, *, auth_type='none'):
    from app.socks_proxy_manager import add_socks_proxy
    from app.profile_manager import add_profile

    proxy, error = add_socks_proxy(uid, 'Proxy', 'proxy.example', 1080,
        auth_type, 'proxy-user' if auth_type == 'password' else '')
    assert error is None
    profile, error = add_profile(uid, 'Routed', 'internal.example', 22,
        'deploy', 'password', socks_proxy_id=proxy['id'])
    assert error is None
    return profile, proxy


@pytest.mark.parametrize('proxy_auth, expected', [('none', 'ready'), ('password', 'password_required')])
def test_overview_describes_owned_socks_route_and_auth(app, client, context, proxy_auth, expected):
    uid = context[0]
    profile, proxy = _routed_profile(uid, auth_type=proxy_auth)
    response = client.get('/api/overview/status')
    assert response.status_code == 200
    row = next(item for item in response.json['hosts'] if item['id'] == profile['id'])
    assert row['route'] == 'socks'
    assert row['socks_proxy_id'] == proxy['id']
    assert row['via_socks'] is True
    assert row['socks_auth'] == expected


def test_missing_proxy_is_broken_in_overview_and_restore_check(app, client, context):
    from app.socks_proxy_manager import _get_file

    profile, proxy = _routed_profile(context[0])
    _get_file(context[0]).unlink()
    rows = client.get('/api/overview/status').json['hosts']
    row = next(item for item in rows if item['id'] == profile['id'])
    assert row['route'] == 'missing' and row['state'] == 'broken'
    assert row['socks_proxy_id'] == proxy['id']
    rows = client.get('/api/account/recovery-check').json['hosts']
    row = next(item for item in rows if item['id'] == profile['id'])
    assert row['route'] == 'missing_socks'


def test_overview_socks_auth_uses_the_proxy_credential_binding(app, client, context):
    uid = context[0]
    profile, proxy = _routed_profile(uid, auth_type='password')
    app.extensions['credentials'].create_assigned(uid, 'socks:' + proxy['id'],
        {'name': 'Proxy login', 'password': 'test-only-proxy-password'}, True)
    response = client.get('/api/overview/status')
    row = next(item for item in response.json['hosts'] if item['id'] == profile['id'])
    assert row['socks_auth'] == 'saved'
    assert row['auth'] == 'prompt'
    assert 'test-only-proxy-password' not in response.get_data(as_text=True)


def test_socks_reachability_only_probes_proxy_and_never_caches_its_platform(app, client, context, monkeypatch):
    from app import overview_routes
    from app.profile_manager import get_profile

    profile, _proxy = _routed_profile(context[0])
    calls = []

    def probe(host, port):
        calls.append((host, port))
        return {'state': 'reachable', 'latency_ms': 1, 'platform': 'ubuntu'}

    monkeypatch.setattr(overview_routes, '_probe', probe)
    response = client.post('/api/overview/reachability', json={'ids': [profile['id']]})
    assert response.status_code == 200
    assert calls == [('proxy.example', 1080)]
    assert response.json['results'][profile['id']] == {'state': 'reachable', 'latency_ms': 1, 'via_socks': True}
    assert 'greeting_platform' not in get_profile(context[0], profile['id'])


def test_missing_socks_reachability_never_falls_back_to_target(app, client, context, monkeypatch):
    from app import overview_routes
    from app.socks_proxy_manager import _get_file

    profile, _proxy = _routed_profile(context[0])
    _get_file(context[0]).unlink()

    def forbidden_probe(*_args):
        pytest.fail('Missing SOCKS route must not open a direct socket')

    monkeypatch.setattr(overview_routes, '_probe', forbidden_probe)
    response = client.post('/api/overview/reachability', json={'ids': [profile['id']]})
    assert response.status_code == 200
    assert response.json['results'][profile['id']] == {'state': 'unresolved', 'via_socks': True}


def test_probe_cache_signature_includes_proxy_identity(app, context):
    from app.overview_routes import _plans
    from app.profile_manager import upsert_profile
    from app.socks_proxy_manager import add_socks_proxy

    profile, _proxy = _routed_profile(context[0])
    _, before = _plans(context[0])
    other, error = add_socks_proxy(context[0], 'Other proxy', 'proxy.example', 1080)
    assert error is None
    updated, error = upsert_profile(context[0], {**profile, 'socks_proxy_id': other['id']})
    assert error is None and updated['socks_proxy_id'] == other['id']
    _, after = _plans(context[0])
    assert before != after


def test_discovery_recognizes_owned_proxy_endpoints(app, context):
    from app.discovery_routes import _known_endpoints

    _routed_profile(context[0])
    assert ('proxy.example', 1080) in _known_endpoints(context[0])
    assert ('proxy.example', 1080) not in _known_endpoints(context[0] + 1)


def test_automation_preview_and_schedule_reject_socks_targets(app, context):
    uid, aid, book, _direct = context
    profile, _proxy = _routed_profile(uid)
    payload = {'runbook_id': book['id'], 'profile_ids': [profile['id']]}
    with pytest.raises(AutomationError, match='unsupported_target'):
        app.extensions['automation'].prepare_run(uid, aid, payload)
    with pytest.raises(AutomationError, match='unsupported_target'):
        app.extensions['automation_schedules'].prepare(uid, aid,
            {**payload, 'cron': '* * * * *', 'timezone': 'UTC'})


def test_automation_readiness_explains_unsupported_socks_route(app, client, context, monkeypatch):
    import config

    profile, proxy = _routed_profile(context[0])
    monkeypatch.setattr(config, 'AUTOMATION_ALLOW_INSECURE_LOOPBACK', True)
    response = client.get('/api/automation/state')
    assert response.status_code == 200
    row = next(item for item in response.json['profiles'] if item['id'] == profile['id'])
    assert row['supported'] is False
    assert row['socks_proxy_id'] == proxy['id']
    assert row['unsupported_reason'] == 'SOCKS5 routes are not supported for automation yet'


@pytest.mark.parametrize('in_route', [False, True])
def test_automation_transport_defensively_rejects_socks_before_network(app, context, monkeypatch, in_route):
    from app import automation_transport

    profile, proxy = _routed_profile(context[0])

    def forbidden_target(*_args):
        pytest.fail('Unsupported SOCKS automation must not resolve or connect')

    monkeypatch.setattr(automation_transport, '_allowed_target', forbidden_target)
    kwargs = {}
    if in_route:
        profile = {key: value for key, value in profile.items() if key != 'socks_proxy_id'}
        kwargs['route'] = {**proxy, 'kind': 'socks'}
    with pytest.raises(AutomationError, match='unsupported_target'):
        with automation_transport.connect_profile(context[0], profile, None, lambda: False, **kwargs):
            pytest.fail('Unsupported connection yielded a transport')


def test_existing_schedule_requires_review_when_host_changes_to_socks(app, scheduling, monkeypatch):
    from app.profile_manager import upsert_profile

    service, uid, _aid, _book, direct = scheduling
    now = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
    activate(scheduling, now)
    _profile, proxy = _routed_profile(uid)
    assert upsert_profile(uid, {**direct, 'socks_proxy_id': proxy['id']})[1] is None
    dispatched = []
    monkeypatch.setattr(service.automation, 'start_scheduled', lambda grant: dispatched.append(grant))
    service.tick(now=now.replace(minute=1))
    assert dispatched == []
    assert service.list(uid)[0]['last_status'] == 'needs_review'


def test_socks_export_marks_route_loss_and_reimport_is_blocked(app, client, context):
    profile, proxy = _routed_profile(context[0])
    response = client.get('/api/profiles/exchange')
    assert response.status_code == 200
    assert response.headers['X-WebSSH-SOCKS-Routes-Omitted'] == '1'
    document = response.json
    row = next(item for item in document['hosts'] if item['name'] == profile['name'])
    assert row['socks_route_omitted'] is True
    assert row['warnings'] == ['SOCKS5 route not exported']
    assert proxy['id'] not in json.dumps(document)
    preview = client.post('/api/profiles/exchange/preview', json={'format': 'json', 'source': json.dumps(document)})
    assert preview.status_code == 200
    row = next(item for item in preview.json['records'] if item['name'] == profile['name'])
    assert row['blocked'] is True
    assert 'SOCKS5 route not exported' in row['warnings']
    index = next(index for index, item in enumerate(document['hosts']) if item['name'] == profile['name'])
    imported = client.post('/api/profiles/exchange', json={'format': 'json', 'source': json.dumps(document),
        'selections': [{'index': index}]})
    assert imported.status_code == 400


def test_batched_socks_export_preserves_per_host_warning_and_download_count(app, client, context, monkeypatch):
    import config
    from app.profile_manager import save_profiles
    from app.profile_exchange import preview_import

    profile, _proxy = _routed_profile(context[0])
    monkeypatch.setattr(config, 'PROFILE_MAX_RECORDS', 200)
    assert save_profiles(context[0], [
        {**profile, 'id': f'host-{index}', 'name': f'Host {index}'}
        for index in range(101)
    ])
    response = client.get('/api/profiles/exchange')
    assert response.status_code == 200
    assert response.mimetype == 'application/zip'
    assert response.headers['X-WebSSH-SOCKS-Routes-Omitted'] == '101'
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        documents = [json.loads(archive.read(name)) for name in archive.namelist()]
    assert [len(document['hosts']) for document in documents] == [100, 1]
    for document in documents:
        assert all(host['warnings'] == ['SOCKS5 route not exported'] for host in document['hosts'])
        assert all(host['blocked'] for host in preview_import(json.dumps(document), 'json')['records'])


@pytest.mark.parametrize('fields', [
    {'socks_proxy_id': 'proxy'}, {'socks_proxy': {'host': 'proxy.example'}},
    {'socks_route_omitted': 'false'}, {'warnings': ['user-controlled warning']},
    {'warnings': ['SOCKS5 route not exported']},
])
def test_json_import_rejects_unsupported_socks_or_warning_fields(fields):
    from app.profile_exchange import preview_import, ExchangeError

    with pytest.raises(ExchangeError):
        preview_import(json.dumps({'format': 'webssh-hosts', 'version': 1,
            'hosts': [{'name': 'Target', 'host': 'target.example', 'username': 'root', **fields}]}), 'json')


def test_proxycommand_socks_import_remains_blocked_without_evaluation():
    from app.profile_exchange import preview_import

    result = preview_import('Host routed\n HostName target.example\n User deploy\n'
        ' ProxyCommand nc -X 5 -x proxy.example:1080 %h %p', 'openssh')
    assert result['records'][0]['blocked'] is True
    assert result['warnings']
