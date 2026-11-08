"""Run history deletion and automation through a saved jump host."""
import threading
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from app.automation_service import AutomationService, connection_resources, password_resources
from app.automation_store import AutomationError, user_path, write_document
from tests.test_automation_routes import enabled  # noqa: F401 - fixture
from tests.test_automation_service import context  # noqa: F401 - fixture


def _run(run_id, status='succeeded'):
    step = dict(name='Identity', status=status, exit_code=0 if status == 'succeeded' else None, duration=.1)
    return dict(id=run_id, name='Check', created_at='2026-11-08T12:00:00+00:00',
                finished_at='2026-11-08T12:00:01+00:00', status=status,
                targets=[dict(id='p', name='Server', host='server.example', port=22, username='operator',
                              group=None, status=status, reason=None, steps=[step])])


def _seed(uid, *runs):
    write_document(user_path(uid, 'automation-runs.json'), dict(version=1, runs=list(runs)))


def _ids(service, uid):
    return [run['id'] for run in service.history(uid)]


def test_delete_single_and_all_finished_runs_keeps_active_work(app, context, monkeypatch):
    uid, _aid, _book, _profile = context
    service = AutomationService(app)
    events = []
    monkeypatch.setattr('app.automation_service.log_security_event', lambda name, **kw: events.append((name, kw)))
    _seed(uid, _run('active', 'running'), _run('done'), _run('failed', 'failed'), _run('old'))
    service._active[int(uid)] = dict(record=dict(id='active'))
    try:
        assert service.delete_runs(uid, ['done']) == 1
        assert _ids(service, uid) == ['active', 'failed', 'old']
        with pytest.raises(AutomationError, match='run_active'):
            service.delete_runs(uid, ['active'])
        with pytest.raises(AutomationError, match='not_found'):
            service.delete_runs(uid, ['done'])
        assert service.delete_runs(uid) == 2
        assert _ids(service, uid) == ['active']
        assert service.delete_runs(uid) == 0
    finally:
        service._active.clear()
    assert events == [('AUTOMATION_RUNS_DELETED', dict(user_id=uid, count=1)),
                      ('AUTOMATION_RUNS_DELETED', dict(user_id=uid, count=2))]


def test_interrupted_run_without_worker_can_be_deleted(app, context):
    uid, *_ = context
    service = AutomationService(app)
    _seed(uid, _run('stale', 'running'))
    assert service.history(uid)[0]['status'] == 'unknown'
    assert service.delete_runs(uid, ['stale']) == 1
    assert service.history(uid) == []


@pytest.mark.parametrize('run_ids', [[], 'done', [''], ['x' * 65], [1], ['a'] * 51])
def test_delete_rejects_malformed_identifiers(app, context, run_ids):
    uid, *_ = context
    with pytest.raises(AutomationError, match='invalid_request'):
        AutomationService(app).delete_runs(uid, run_ids)


def test_run_delete_routes_are_owned_and_csrf_protected(app, client, context, enabled):
    uid, *_ = context
    _seed(uid, _run('done'), _run('other'))
    app.config['WTF_CSRF_ENABLED'] = True
    assert client.delete('/api/automation/runs/done').status_code == 400
    assert client.post('/api/automation/runs/clear', json={}).status_code == 400
    app.config['WTF_CSRF_ENABLED'] = False
    assert client.delete('/api/automation/runs/missing').get_json()['code'] == 'not_found'
    response = client.delete('/api/automation/runs/done')
    assert response.status_code == 200 and response.get_json() == dict(deleted=1)
    response = client.post('/api/automation/runs/clear', json={})
    assert response.status_code == 200 and response.get_json() == dict(deleted=1)
    assert client.get('/api/automation/runs').get_json()['runs'] == []


def test_run_delete_cannot_reach_another_users_history(app, client, context, enabled):
    from app.auth import register_user
    other, error = register_user('other_run_owner', 'other-test-password')
    assert error is None
    _seed(other.id, _run('foreign'))
    assert client.delete('/api/automation/runs/foreign').status_code == 404
    assert client.post('/api/automation/runs/clear', json={}).get_json() == dict(deleted=0)
    assert [run['id'] for run in AutomationService(app).history(other.id)] == ['foreign']


@pytest.fixture
def jump_target(app, context):
    from app.jump_host_manager import add_jump_host
    from app.profile_manager import add_profile
    uid, aid, book, _profile = context
    route, error = add_jump_host(uid, 'Bastion', 'bastion.example', 22, 'gate', 'password')
    assert error is None
    profile, error = add_profile(uid, 'Behind', 'inner.example', 22, 'operator', 'password', jump_host_id=route['id'])
    assert error is None
    return uid, aid, book, profile, route


def _store_passwords(service, uid, aid, *resources):
    service.vault.setup(uid, aid, 'separate vault passphrase long enough')
    for resource, secret in resources:
        service.vault.put(uid, aid, resource, secret)


def test_jump_target_freezes_route_and_needs_both_passwords(app, jump_target):
    uid, aid, book, profile, route = jump_target
    service = AutomationService(app)
    current = service.current_targets(uid)[profile['id']]
    resource = service.credentials.resolve_resource(uid, 'jump:' + route['id'])
    _store_passwords(service, uid, aid, (current, 'target-secret'))
    with pytest.raises(AutomationError):
        service.prepare_run(uid, aid, dict(runbook_id=book['id'], profile_ids=[profile['id']]))
    service.vault.put(uid, aid, resource, 'jump-secret')
    preview = service.prepare_run(uid, aid, dict(runbook_id=book['id'], profile_ids=[profile['id']]))
    intent = service.intent(preview['intent'], uid, aid)
    frozen = intent['targets'][0]
    assert frozen['route']['id'] == 'jump:' + route['id'] and frozen['route']['host'] == 'bastion.example'
    assert {item['id'] for item in password_resources(intent['targets'])} == {profile['id'], 'jump:' + route['id']}
    assert 'jump-secret' not in str(preview) and 'target-secret' not in str(preview)
    service.validate_run(intent)


def test_changed_jump_host_invalidates_the_reviewed_run(app, jump_target):
    from app.jump_host_manager import add_jump_host
    uid, aid, book, profile, route = jump_target
    service = AutomationService(app)
    _store_passwords(service, uid, aid,
                     (service.current_targets(uid)[profile['id']], 'target-secret'),
                     (service.credentials.resolve_resource(uid, 'jump:' + route['id']), 'jump-secret'))
    preview = service.prepare_run(uid, aid, dict(runbook_id=book['id'], profile_ids=[profile['id']]))
    _updated, error = add_jump_host(uid, 'Bastion', 'other-bastion.example', 22, 'gate', 'password',
                                    jump_host_id=route['id'])
    assert error is None
    with pytest.raises(AutomationError, match='preview_changed'):
        service.validate_run(service.intent(preview['intent'], uid, aid))


def test_jump_host_key_must_be_trusted_before_review(app, jump_target, monkeypatch):
    from app.automation_store import AutomationHostKeyRequired
    from app.host_key_store import HostKeyStore
    uid, aid, book, profile, _route = jump_target
    monkeypatch.setattr(HostKeyStore, 'has_trusted_key', lambda self, hostname, port=22: hostname != 'bastion.example')
    service = AutomationService(app)
    with pytest.raises(AutomationHostKeyRequired) as raised:
        service.prepare_run(uid, aid, dict(runbook_id=book['id'], profile_ids=[profile['id']]))
    assert raised.value.hosts == ['Bastion']


def test_unsupported_jump_login_is_refused(app, jump_target, monkeypatch):
    uid, aid, book, profile, route = jump_target
    service = AutomationService(app)
    original = service.credentials.resources
    monkeypatch.setattr(service.credentials, 'resources', lambda user_id, **kw: [
        dict(item, auth_type='tailscale') if item['id'] == 'jump:' + route['id'] else item
        for item in original(user_id, **kw)])
    with pytest.raises(AutomationError, match='unsupported_target'):
        service.prepare_run(uid, aid, dict(runbook_id=book['id'], profile_ids=[profile['id']]))


def test_run_connects_through_route_and_redacts_both_secrets(app, jump_target, monkeypatch):
    import time
    import config
    monkeypatch.setattr(config, 'AUTOMATION_ENABLED', True)
    uid, aid, book, profile, route = jump_target
    service = AutomationService(app)
    _store_passwords(service, uid, aid,
                     (service.current_targets(uid)[profile['id']], 'target-secret'),
                     (service.credentials.resolve_resource(uid, 'jump:' + route['id']), 'jump-secret'))
    seen = {}

    @contextmanager
    def connect(_uid, target, password, _cancelled, _own, **kwargs):
        seen.update(password=password, route=kwargs['route']['host'], route_password=kwargs['route_password'])
        yield object()

    def execute(_transport, _step, _cancelled, secrets, _budget):
        seen['secrets'] = secrets
        return dict(status='succeeded', exit_code=0, duration=.1, reason=None, stdout='', stderr='',
                    output_truncated=False)

    monkeypatch.setattr('app.automation_service.connect_profile', connect)
    monkeypatch.setattr('app.automation_service.execute_step', execute)
    preview = service.prepare_run(uid, aid, dict(runbook_id=book['id'], profile_ids=[profile['id']]))
    service.start(preview['intent'], uid, aid, preview['confirmation'])
    deadline = time.monotonic() + 5
    while service._active and time.monotonic() < deadline:
        time.sleep(.02)
    assert seen == dict(password='target-secret', route='bastion.example', route_password='jump-secret',
                        secrets=('target-secret', 'jump-secret'))
    assert service.history(uid)[0]['status'] == 'succeeded'


def test_connection_resources_list_each_hop_once():
    route = dict(id='jump:r', auth_type='key')
    targets = [dict(id='a', auth_type='password', route=route), dict(id='b', auth_type='password', route=route)]
    assert [item['id'] for item in connection_resources(targets)] == ['jump:r', 'a', 'b']
    assert [item['id'] for item in password_resources(targets)] == ['a', 'b']


def test_state_reports_jump_targets_as_supported(app, client, jump_target, enabled):
    _uid, _aid, _book, profile, route = jump_target
    profiles = client.get('/api/automation/state').get_json()['profiles']
    entry = next(item for item in profiles if item['id'] == profile['id'])
    assert entry['supported'] is True and entry['via'] == 'Bastion'
    assert entry['route_id'] == 'jump:' + route['id'] and entry['route_credential_status'] in {'missing', 'disabled'}


class _Client:
    def __init__(self, log, name, channel=None):
        self.log, self.name, self.channel = log, name, channel

    def set_missing_host_key_policy(self, _policy):
        pass

    def connect(self, **kwargs):
        self.log.append(('connect', self.name, kwargs['hostname'], kwargs['port'], type(kwargs['sock']).__name__))
        source = next(kwargs['auth_strategy'].get_sources())
        source.authenticate(SimpleNamespace(
            auth_password=lambda user, secret, fallback: self.log.append(('auth', self.name, user, secret))))

    def get_transport(self):
        log, channel = self.log, self.channel
        return SimpleNamespace(open_channel=lambda kind, dest, src, timeout:
                               log.append(('channel', kind, dest)) or channel)

    def close(self):
        self.log.append(('close', self.name))


def _transport_lab(monkeypatch, resolved):
    log = []
    channel = SimpleNamespace(close=lambda: log.append(('close', 'channel')))
    clients = iter([_Client(log, 'bastion', channel), _Client(log, 'target')])
    store = SimpleNamespace(load_into=lambda _client: None, missing_key_policy=lambda: object())
    monkeypatch.setattr('app.automation_transport.HostKeyStore', lambda *_args: store)
    monkeypatch.setattr('app.automation_transport.paramiko.SSHClient', lambda: next(clients))

    def resolve(host, port, **_kwargs):
        if host not in resolved:
            raise ValueError('Connections to this address are not allowed')
        return SimpleNamespace(hostname=host, port=port, ip=resolved[host])

    monkeypatch.setattr('app.automation_transport.resolve_allowed_target', resolve)
    monkeypatch.setattr('app.automation_transport.open_validated_socket',
                        lambda target, _timeout: log.append(('socket', target.hostname))
                        or SimpleNamespace(close=lambda: log.append(('close', 'socket'))))
    return log


PROFILE = dict(id='p', host='inner.example', port=22, username='operator', auth_type='password')
ROUTE = dict(id='jump:r', host='bastion.example', port=2222, username='gate', auth_type='password')


def test_transport_reaches_target_through_validated_jump_host(monkeypatch):
    from app.automation_transport import connect_profile
    log = _transport_lab(monkeypatch, {'bastion.example': '203.0.113.5', 'inner.example': '198.51.100.7'})
    with connect_profile(1, PROFILE, 'target-secret', lambda: False, route=ROUTE, route_password='jump-secret'):
        pass
    assert log == [
        ('socket', 'bastion.example'),
        ('connect', 'bastion', 'bastion.example', 2222, 'SimpleNamespace'),
        ('auth', 'bastion', 'gate', 'jump-secret'),
        ('channel', 'direct-tcpip', ('198.51.100.7', 22)),
        ('connect', 'target', 'inner.example', 22, 'SimpleNamespace'),
        ('auth', 'target', 'operator', 'target-secret'),
        ('close', 'target'), ('close', 'channel'), ('close', 'bastion'), ('close', 'socket'),
    ]


@pytest.mark.parametrize('allowlist,allowed', [((), False), (('inner.example',), True)])
def test_target_only_resolvable_by_jump_host_follows_remote_dns_policy(monkeypatch, allowlist, allowed):
    import config
    from app.automation_transport import connect_profile
    monkeypatch.setattr(config, 'BLOCK_INTERNAL_SSH', True)
    monkeypatch.setattr(config, 'PROXY_JUMP_REMOTE_DNS_ALLOWLIST', allowlist)
    monkeypatch.setattr('app.automation_transport.proxy_jump_remote_dns_allowed',
                        lambda host, names: host in names)
    log = _transport_lab(monkeypatch, {'bastion.example': '203.0.113.5'})
    if allowed:
        with connect_profile(1, PROFILE, 'target-secret', lambda: False, route=ROUTE, route_password='jump-secret'):
            pass
        assert ('channel', 'direct-tcpip', ('inner.example', 22)) in log
    else:
        with pytest.raises(ValueError, match='not allowed'):
            with connect_profile(1, PROFILE, 'target-secret', lambda: False, route=ROUTE, route_password='jump-secret'):
                pytest.fail('blocked destination reached')
        assert log == []


def test_blocked_jump_host_opens_no_socket(monkeypatch):
    from app.automation_transport import connect_profile
    log = _transport_lab(monkeypatch, {'inner.example': '198.51.100.7'})
    with pytest.raises(ValueError, match='not allowed'):
        with connect_profile(1, PROFILE, 'target-secret', lambda: False, route=ROUTE, route_password='jump-secret'):
            pytest.fail('blocked jump host reached')
    assert not any(entry[0] == 'socket' for entry in log)


def test_cancellation_after_jump_login_closes_every_hop(monkeypatch):
    from app.automation_transport import connect_profile
    log = _transport_lab(monkeypatch, {'bastion.example': '203.0.113.5', 'inner.example': '198.51.100.7'})
    cancelled = threading.Event()
    original = _Client.connect

    def connect(self, **kwargs):
        original(self, **kwargs)
        if self.name == 'bastion':
            cancelled.set()

    monkeypatch.setattr(_Client, 'connect', connect)
    with pytest.raises(AutomationError, match='cancelled'):
        with connect_profile(1, PROFILE, 'target-secret', cancelled.is_set, route=ROUTE, route_password='jump-secret'):
            pytest.fail('cancelled run reached the target')
    assert ('connect', 'target', 'inner.example', 22, 'SimpleNamespace') not in log
    assert log[-2:] == [('close', 'bastion'), ('close', 'socket')]
