"""SOCKS credential bindings preserve route identity and legacy fingerprints."""
from types import SimpleNamespace

import pytest

from app.automation_store import AutomationError, profile_fingerprint
from app.credential_service import CredentialService
from tests.test_automation_service import context


LEGACY_PROFILE = dict(id='legacy-host', host='server.example', port=22,
                      username='operator', auth_type='password', key_id=None,
                      jump_host_id=None)


@pytest.mark.parametrize('extra', [{}, {'socks_proxy_id': None}, {'socks_proxy_id': ''}])
def test_legacy_fingerprint_stays_bit_identical(extra):
    assert profile_fingerprint(dict(LEGACY_PROFILE, **extra)) == (
        '959c1a1a2614870af3bd474f9bcaf0437c44a2f2d02fe38cd9eee2dc5a79f8ca'
    )


def test_socks_fingerprint_binds_route_and_dns_policy():
    assert profile_fingerprint(LEGACY_PROFILE) != profile_fingerprint(
        dict(LEGACY_PROFILE, socks_proxy_id='proxy-one'))
    proxy = dict(LEGACY_PROFILE, id='socks:proxy-one', kind='socks', port=1080)
    assert profile_fingerprint(proxy) == profile_fingerprint(dict(proxy, remote_dns=True))
    assert profile_fingerprint(proxy) != profile_fingerprint(dict(proxy, remote_dns=False))
    assert profile_fingerprint(proxy) != profile_fingerprint(dict(proxy, kind='jump'))


def test_socks_targets_keep_type_dns_and_default_port():
    target = CredentialService._normalize_target(dict(
        host='proxy.example', username='proxy-user', kind='socks', remote_dns=False))
    assert target['kind'] == 'socks'
    assert target['port'] == 1080
    assert target['remote_dns'] is False
    assert CredentialService._normalize_target(dict(target, remote_dns=True)) != target


def test_nested_socks_route_is_bound_to_saved_id():
    target = CredentialService._normalize_target(dict(
        LEGACY_PROFILE, socks_proxy={'socks_proxy_id': 'proxy-one'}))
    assert target['socks_proxy_id'] == 'proxy-one'


@pytest.mark.parametrize('changes', [
    {'socks_proxy': {'host': 'inline.example'}},
    {'socks_proxy': {'socks_proxy_id': ''}},
    {'socks_proxy': 'invalid'},
    {'socks_proxy': {}},
    {'socks_proxy': {'socks_proxy_id': 'one'}, 'socks_proxy_id': 'two'},
    {'socks_proxy_id': 'one', 'jump_host_id': 'jump-one'},
    {'socks_proxy_id': 'one', 'proxy_jump': {'jump_host_id': 'jump-one'}},
    {'socks_proxy_id': 'one', 'auth_type': 'tailscale'},
    {'socks_proxy_id': []},
    {'socks_proxy_id': False},
    {'socks_proxy_id': 0},
])
def test_malformed_or_conflicting_socks_targets_are_denied(changes):
    with pytest.raises(AutomationError, match='credential_target_changed'):
        CredentialService._normalize_target(dict(LEGACY_PROFILE, **changes))


def _proxy(uid, **changes):
    from app.socks_proxy_manager import add_socks_proxy
    payload = dict(
        name='Proxy', host='proxy.example', port=1080, username='proxy-user',
        auth_type='password', remote_dns=True)
    record, error = add_socks_proxy(uid, **dict(payload, **changes))
    assert error is None
    return record


def _routed_profile(uid, profile, proxy):
    from app.profile_manager import upsert_profile
    result, error = upsert_profile(uid, dict(profile, socks_proxy_id=proxy['id']))
    assert error is None
    return result


def test_named_proxy_password_uses_typed_owned_resource_and_exact_destination(app, context):
    uid, aid, _, profile = context
    service = app.extensions['credentials']
    proxy = _proxy(uid)
    resource_id = 'socks:' + proxy['id']
    resource = service.resolve_resource(uid, resource_id)
    assert resource['kind'] == 'socks'
    service.create_assigned(uid, resource_id, dict(name='Proxy login', password='proxy-secret'), True)
    assert service.connection_password(uid, aid, 'socks', resource_id, proxy) == 'proxy-secret'
    for change in ({'host': 'changed.example'}, {'remote_dns': False}, {'port': 1081},
                   {'username': 'changed'}, {'auth_type': 'none'}):
        with pytest.raises(AutomationError, match='credential_target_changed'):
            service.connection_password(uid, aid, 'socks', resource_id, dict(proxy, **change))
    with pytest.raises(AutomationError):
        service.connection_password(uid, aid, 'ssh', resource_id, proxy)
    with pytest.raises(AutomationError):
        service.connection_password(uid, aid, 'socks', 'socks:missing', proxy)


def test_host_password_and_context_bind_exact_socks_route(app, context):
    from app.host_context import ContextError, bind_profile
    uid, aid, _, profile = context
    service = app.extensions['credentials']
    proxy = _proxy(uid)
    routed = _routed_profile(uid, profile, proxy)
    service.create_assigned(uid, profile['id'], dict(name='Host login', password='host-secret'), True)
    assert service.connection_password(uid, aid, 'ssh', profile['id'], routed) == 'host-secret'
    assert bind_profile(uid, profile['id'], profile['host'], 22, profile['username'], None,
                        socks_proxy_id=proxy['id']) == profile['id']
    for route_id in (None, 'other-proxy'):
        with pytest.raises(AutomationError, match='credential_target_changed'):
            service.connection_password(uid, aid, 'ssh', profile['id'], dict(routed, socks_proxy_id=route_id))
        with pytest.raises(ContextError, match='invalid_profile'):
            bind_profile(uid, profile['id'], profile['host'], 22, profile['username'], None,
                         socks_proxy_id=route_id)
    assert bind_profile(uid, profile['id'], profile['host'], 22, profile['username'], None,
                        optional=True) is None


def test_socks_inline_creation_assigns_password_and_rolls_back_failure(app, context, monkeypatch):
    from app.socks_proxy_manager import load_socks_proxies
    uid, aid, _, _ = context
    service = app.extensions['credentials']
    payload = dict(resource_kind='socks', resource=dict(
        name='Proxy', host='proxy.example', port=1080, username='proxy-user',
        auth_type='password', remote_dns=False),
        name='Proxy login', password='proxy-secret', confirm_target=True)
    result = service.create_for_resource(uid, payload)
    resource = result['resource']
    assert service.connection_password(uid, aid, 'socks', 'socks:'+resource['id'], resource) == 'proxy-secret'
    before = load_socks_proxies(uid)
    def fail(*_args):
        raise OSError('storage failure')
    monkeypatch.setattr('app.credential_store.write_document', fail)
    with pytest.raises(OSError, match='storage failure'):
        service.create_for_resource(uid, payload)
    assert load_socks_proxies(uid) == before


def test_proxy_without_auth_cannot_receive_named_password(app, context):
    uid, _, _, _ = context
    service = app.extensions['credentials']
    proxy = _proxy(uid, auth_type='none', username='')
    credential = service.create_named(uid, dict(name='Unused', password='secret'))
    with pytest.raises(AutomationError, match='confirmation_required'):
        service.assign_named(uid, 'socks:'+proxy['id'], credential['id'], True)


def test_pending_socks_guard_rechecks_route_and_credential_changes(app, context, monkeypatch):
    from app.credential_connections import CredentialGuard, connection_password
    uid, aid, _, _ = context
    service = app.extensions['credentials']
    proxy = _proxy(uid, remote_dns=False)
    resource_id = 'socks:'+proxy['id']
    credential = service.create_assigned(uid, resource_id, dict(name='Proxy', password='secret'), True)
    monkeypatch.setattr('app.auth_assurance.current_authentication_session',
                        lambda: SimpleNamespace(id=aid, user_id=uid))
    # The ID on a live proxy payload identifies the proxy itself, not a nested route.
    payload = dict(proxy, socks_proxy_id=proxy['id'], credential_id=resource_id)
    with app.test_request_context(base_url='https://localhost'):
        guard = CredentialGuard(uid, 'socks', payload)
        assert connection_password(uid, 'socks', payload) == 'secret'
        guard.check()
        service.update_named(uid, credential['id'], dict(password='changed'))
        with pytest.raises(AutomationError, match='vault_locked'):
            guard.check()


def test_explicit_target_token_binds_socks_route_and_live_dns_policy(app, context):
    uid, aid, _, profile = context
    service = app.extensions['credentials']
    proxy = _proxy(uid)
    credential = service.create_named(uid, dict(name='Host', password='host-secret'))
    target = dict(profile, socks_proxy={'socks_proxy_id': proxy['id']})
    token = service.authorize_target(uid, aid, dict(credential_id=credential['id'], target=target,
                                                  confirm_target=True))['credential_target_token']
    assert service.target_password(uid, aid, credential['id'], target, token) == 'host-secret'
    _proxy(uid, socks_proxy_id=proxy['id'], remote_dns=False)
    with pytest.raises(AutomationError, match='credential_target_changed'):
        service.target_password(uid, aid, credential['id'], target, token)
    with pytest.raises(AutomationError):
        service.authorize_target(uid, aid, dict(credential_id=credential['id'],
            target=dict(profile, socks_proxy_id='missing'), confirm_target=True))


def test_host_guard_keeps_only_route_identity_and_detects_dns_change(app, context, monkeypatch):
    from app.credential_connections import CredentialGuard, connection_password
    uid, aid, _, profile = context
    service = app.extensions['credentials']
    proxy = _proxy(uid)
    routed = _routed_profile(uid, profile, proxy)
    service.create_assigned(uid, routed['id'], dict(name='Host', password='host-secret'), True)
    monkeypatch.setattr('app.auth_assurance.current_authentication_session',
                        lambda: SimpleNamespace(id=aid, user_id=uid))
    payload = dict(profile, credential_id=profile['id'], socks_proxy=dict(
        proxy, socks_proxy_id=proxy['id'], password='runtime-proxy-secret'))
    with app.test_request_context(base_url='https://localhost'):
        guard = CredentialGuard(uid, 'ssh', payload)
        assert connection_password(uid, 'ssh', payload) == 'host-secret'
        assert 'runtime-proxy-secret' not in repr(guard.args)
        _proxy(uid, socks_proxy_id=proxy['id'], remote_dns=False)
        with pytest.raises(AutomationError, match='vault_locked'):
            guard.check()


@pytest.mark.parametrize('kind', ['socks', 'jump'])
def test_inline_host_password_uses_same_route_fingerprint_as_resource_inventory(app, context, kind):
    from app.jump_host_manager import add_jump_host
    uid, aid, _, profile = context
    service = app.extensions['credentials']
    if kind == 'socks':
        route = _proxy(uid)
        route_fields = dict(socks_proxy_id=route['id'])
    else:
        route, error = add_jump_host(uid, 'Jump', 'jump.example', 22, 'operator', 'password')
        assert error is None
        route_fields = dict(jump_host_id=route['id'])
    payload = dict(name='New host', host='new.example', port=22, username='operator',
                   auth_type='password', **route_fields)
    result = service.create_for_resource(uid, dict(resource_kind='ssh', resource=payload,
        name='Host login', password='new-host-secret', confirm_target=True))
    resource = service.resolve_resource(uid, result['resource']['id'])
    expected_route = dict(route, id='socks:'+route['id'], kind='socks') if kind=='socks' else route
    assert resource['route_fingerprint'] == profile_fingerprint(expected_route)
    assert service.connection_password(uid, aid, 'ssh', resource['id'], payload) == 'new-host-secret'


def test_target_token_for_proxy_endpoint_preserves_kind_in_guard(app, context, monkeypatch):
    from app.credential_connections import CredentialGuard, connection_password
    uid, aid, _, _ = context
    service = app.extensions['credentials']
    proxy = _proxy(uid, remote_dns=False)
    credential = service.create_named(uid, dict(name='Proxy', password='explicit-secret'))
    target = dict(proxy, kind='socks')
    token = service.authorize_target(uid, aid, dict(credential_id=credential['id'], target=target,
                                                  confirm_target=True))['credential_target_token']
    monkeypatch.setattr('app.auth_assurance.current_authentication_session',
                        lambda: SimpleNamespace(id=aid, user_id=uid))
    payload = dict(proxy, socks_proxy_id=proxy['id'], credential_id=credential['id'],
                   credential_target_token=token)
    with app.test_request_context(base_url='https://localhost'):
        guard = CredentialGuard(uid, 'socks', payload)
        assert connection_password(uid, 'socks', payload) == 'explicit-secret'
        guard.check()
        with pytest.raises(AutomationError, match='credential_target_changed'):
            connection_password(uid, 'socks', dict(payload, remote_dns=True))


def test_foreign_and_deleted_socks_routes_never_release_host_password(app, context, monkeypatch):
    from app.auth import register_user
    uid, aid, _, profile = context
    service = app.extensions['credentials']
    proxy = _proxy(uid)
    other, error = register_user('other_proxy_owner', 'password123')
    assert error is None
    foreign = _proxy(other.id)
    credential = service.create_named(uid, dict(name='Host', password='host-secret'))
    with pytest.raises(AutomationError, match='invalid_targets'):
        service.authorize_target(uid, aid, dict(credential_id=credential['id'],
            target=dict(profile, socks_proxy_id=foreign['id']), confirm_target=True))
    routed = _routed_profile(uid, profile, proxy)
    service.assign_named(uid, profile['id'], credential['id'], True)
    monkeypatch.setattr('app.credential_service.load_socks_proxies', lambda _uid: [])
    with pytest.raises(AutomationError):
        service.connection_password(uid, aid, 'ssh', profile['id'], routed)


def test_duplicate_proxy_ids_are_not_resolved_by_list_order(app, context, monkeypatch):
    uid, _, _, _ = context
    service = app.extensions['credentials']
    proxy = _proxy(uid)
    monkeypatch.setattr('app.credential_service.load_socks_proxies',
                        lambda _uid: [proxy, dict(proxy, host='different.example')])
    with pytest.raises(AutomationError, match='invalid_targets'):
        service.resolve_resource(uid, 'socks:'+proxy['id'])


def test_incomplete_proxy_creation_fails_without_saving_credentials(app, context):
    uid, _, _, _ = context
    service = app.extensions['credentials']
    with pytest.raises(AutomationError, match='invalid_targets'):
        service.create_for_resource(uid, dict(resource_kind='socks', resource=dict(auth_type='password'),
            name='Invalid', password='secret', confirm_target=True))
    assert service.named.read(uid)['credentials'] == {}


def test_native_assignment_preview_rejects_proxy_dns_change(app, context):
    uid, aid, _, profile = context
    service = app.extensions['credentials']
    proxy = _proxy(uid)
    _routed_profile(uid, profile, proxy)
    credential = service.create_named(uid, dict(name='Host', password='secret'))
    mutation = dict(method='assign', resource_id=profile['id'], credential_id=credential['id'],
                    confirm_target=True)
    token = service.prepare_vault(uid, aid, dict(operation='native', mutation=mutation))['intent']
    _proxy(uid, socks_proxy_id=proxy['id'], remote_dns=False)
    with pytest.raises(AutomationError, match='preview_changed'):
        service.apply_native_assignment(uid, aid, token, mutation)
    assert profile['id'] not in service.named.read(uid)['assignments']


@pytest.mark.parametrize('kind', ['socks', 'jump'])
def test_top_level_route_reference_cannot_authorize_a_direct_connection(app, context, monkeypatch, kind):
    from app.credential_connections import CredentialGuard, connection_password
    from app.jump_host_manager import add_jump_host
    from app.profile_manager import upsert_profile
    uid, aid, _, profile = context
    service = app.extensions['credentials']
    if kind == 'socks':
        proxy = _proxy(uid)
        routed = _routed_profile(uid, profile, proxy)
    else:
        jump, error = add_jump_host(uid, 'Jump', 'jump.example', 22, 'operator', 'password')
        assert error is None
        routed, error = upsert_profile(uid, dict(profile, jump_host_id=jump['id']))
        assert error is None
    service.create_assigned(uid, profile['id'], dict(name='Host', password='secret'), True)
    monkeypatch.setattr('app.auth_assurance.current_authentication_session',
                        lambda: SimpleNamespace(id=aid, user_id=uid))
    # Transport selects nested proxy_jump/socks_proxy; an ID alone creates no route.
    data = dict(routed, credential_id=profile['id'])
    with app.test_request_context(base_url='https://localhost'):
        with pytest.raises(AutomationError, match='credential_target_changed'):
            CredentialGuard(uid, 'ssh', data)
        with pytest.raises(AutomationError, match='credential_target_changed'):
            connection_password(uid, 'ssh', data)
