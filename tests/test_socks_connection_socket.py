"""SOCKS routes stay user-bound at every interactive connection boundary."""

from types import SimpleNamespace

import pytest

from app import socket_events as events
from tests.test_socks_proxy_socket import call, user_socket

pytestmark = pytest.mark.usefixtures('direct_socket_authentication')


def saved_proxy(app, owner, **fields):
    from app import socks_proxy_manager
    with app.app_context():
        proxy, error = socks_proxy_manager.add_socks_proxy(
            owner, 'Proxy', 'live-proxy.example', 1080, **fields,
        )
        assert error is None
        return proxy


def connect_payload(**changes):
    result = dict(host='target.example', port=22, username='ops',
                  auth_type='password', password='target-secret')
    result.update(changes)
    return result


def capture_connections(app, monkeypatch):
    jobs, connections = [], []
    lifecycle = app.extensions['runtime_lifecycle']
    original = lifecycle.start_job

    def start(*args, **kwargs):
        handle = original(*args, **kwargs)
        jobs.append(handle)
        return handle

    monkeypatch.setattr(lifecycle, 'start_job', start)
    monkeypatch.setattr(events, '_validate_ssh_params',
                        lambda host, port, user, **kw: (host, int(port), user, None))
    monkeypatch.setattr(events.ssh_manager, 'create_ssh_connection',
                        lambda **kw: connections.append(kw) or (None, 'local stop'))
    return jobs, connections


def test_connect_resolves_owned_socks_metadata_live(app, monkeypatch):
    owner, sid = user_socket(app, 'socks_live')
    proxy = saved_proxy(app, owner, auth_type='password', username='live-user', remote_dns=False)
    jobs, connections = capture_connections(app, monkeypatch)
    _, emitted = call(app, monkeypatch, events.handle_ssh_connect, sid, connect_payload(socks_proxy={
        'socks_proxy_id': proxy['id'], 'host': 'attacker.example', 'port': 9999,
        'auth_type': 'none', 'username': 'attacker', 'remote_dns': True,
        'password': 'runtime-proxy-password',
    }))
    assert len(jobs) == 1, emitted
    assert jobs[0].join(3)
    route = connections[0]['socks_proxy']
    assert (route.proxy_id, route.host, route.port, route.auth_type, route.username, route.remote_dns) == (
        proxy['id'], 'live-proxy.example', 1080, 'password', 'live-user', False,
    )
    assert route.password == 'runtime-proxy-password'


@pytest.mark.parametrize('proxy_payload', [False, '', [], {}, {'host': 'inline.example'},
                                          {'socks_proxy_id': 'missing'}, {'socks_proxy_id': ['invalid']}])
def test_malformed_or_unknown_socks_route_never_uses_direct_path(app, monkeypatch, proxy_payload):
    _, sid = user_socket(app, 'socks_missing')
    jobs, connections = capture_connections(app, monkeypatch)
    _, emitted = call(app, monkeypatch, events.handle_ssh_connect, sid,
                      connect_payload(socks_proxy=proxy_payload))
    assert not jobs and not connections
    assert emitted[0][1]['error'] == 'SOCKS proxy reference not found'


def test_foreign_socks_proxy_is_not_found(app, monkeypatch):
    owner, _ = user_socket(app, 'socks_foreign_owner')
    _, sid = user_socket(app, 'socks_foreign_other')
    proxy = saved_proxy(app, owner)
    jobs, connections = capture_connections(app, monkeypatch)
    _, emitted = call(app, monkeypatch, events.handle_ssh_connect, sid,
                      connect_payload(socks_proxy={'socks_proxy_id': proxy['id']}))
    assert not jobs and not connections
    assert emitted[0][1]['error'] == 'SOCKS proxy reference not found'


@pytest.mark.parametrize('extra,message', [
    ({'proxy_jump': {'host': 'jump.example'}}, 'either a jump host or a SOCKS5 proxy'),
    ({'auth_type': 'tailscale'}, 'Tailscale SSH cannot be used with a SOCKS5 proxy'),
])
def test_socket_rejects_multiple_routes(app, monkeypatch, extra, message):
    owner, sid = user_socket(app, 'socks_conflict')
    proxy = saved_proxy(app, owner)
    jobs, _ = capture_connections(app, monkeypatch)
    _, emitted = call(app, monkeypatch, events.handle_ssh_connect, sid,
                      connect_payload(socks_proxy={'socks_proxy_id': proxy['id']}, **extra))
    assert not jobs
    assert message in emitted[0][1]['error']


@pytest.mark.parametrize('password', [None, '', 'x' * 256, '\ud800'])
def test_socks_login_requires_bounded_utf8_password(app, monkeypatch, password):
    owner, sid = user_socket(app, 'socks_password')
    proxy = saved_proxy(app, owner, auth_type='password', username='proxy-user')
    jobs, _ = capture_connections(app, monkeypatch)
    _, emitted = call(app, monkeypatch, events.handle_ssh_connect, sid,
                      connect_payload(socks_proxy={'socks_proxy_id': proxy['id'], 'password': password}))
    assert not jobs
    assert 'SOCKS5 proxy password' in emitted[0][1]['error']


@pytest.mark.parametrize('optional', [False, True])
def test_saved_socks_host_cannot_drop_route_even_for_optional_context(app, monkeypatch, optional):
    from app import profile_manager
    owner, sid = user_socket(app, 'socks_omitted')
    proxy = saved_proxy(app, owner)
    with app.app_context():
        profile, error = profile_manager.add_profile(
            owner, 'Saved target', 'target.example', 22, 'ops', 'password', socks_proxy_id=proxy['id'],
        )
        assert error is None
    jobs, _ = capture_connections(app, monkeypatch)
    _, emitted = call(app, monkeypatch, events.handle_ssh_connect, sid,
                      connect_payload(profile_id=profile['id'], profile_context_optional=optional))
    assert not jobs
    assert 'Saved host no longer matches' in emitted[0][1]['error']


@pytest.mark.parametrize('extra', [{'socks_proxy': {}}, {'socks_proxy_id': 'saved-proxy'}])
def test_quick_sftp_rejects_socks_before_any_connection(app, monkeypatch, extra):
    _, sid = user_socket(app, 'socks_quick')
    monkeypatch.setattr(events.connection_pool.temp_connection_pool, 'create_connection',
                        lambda **kw: pytest.fail('direct fallback'))
    _, emitted = call(app, monkeypatch, events.handle_quick_connect, sid, connect_payload(**extra))
    assert emitted[0][0] == 'quick_connect_error'
    assert 'SOCKS5' in emitted[0][1]['error']


def test_quick_sftp_cannot_omit_a_saved_profiles_socks_route(app, monkeypatch):
    from app import profile_manager
    owner, sid = user_socket(app, 'socks_quick_profile')
    proxy = saved_proxy(app, owner)
    with app.app_context():
        profile, error = profile_manager.add_profile(
            owner, 'Target', 'target.example', 22, 'ops', 'password', socks_proxy_id=proxy['id'],
        )
        assert error is None
    monkeypatch.setattr(events.connection_pool.temp_connection_pool, 'create_connection',
                        lambda **kw: pytest.fail('direct fallback'))
    _, emitted = call(app, monkeypatch, events.handle_quick_connect, sid,
                      connect_payload(profile_id=profile['id']))
    assert emitted[0][0] == 'quick_connect_error'
    assert 'SOCKS5' in emitted[0][1]['error']


@pytest.mark.parametrize('requested_route', ['direct', 'different_proxy'])
def test_persistent_tmux_reconnect_cannot_drop_or_replace_socks_route(app, monkeypatch, requested_route):
    from app.models import SSHSession, db
    owner, sid = user_socket(app, 'socks_tmux')
    original = saved_proxy(app, owner)
    with app.app_context():
        db.session.add(SSHSession(
            session_id='original-socks', user_id=owner, host='target.example', port=22,
            username='ops', connected=False, is_persistent=True, tmux_session_name='saved_tmux',
            socks_proxy_id=original['id'], via_socks=True,
        ))
        db.session.commit()
    monkeypatch.setattr(events, 'runtime_feature_enabled', lambda feature: feature == 'tmux_enabled')
    jobs, _ = capture_connections(app, monkeypatch)
    extra = {}
    if requested_route == 'different_proxy':
        extra['socks_proxy'] = {'socks_proxy_id': saved_proxy(app, owner)['id']}
    _, emitted = call(app, monkeypatch, events.handle_ssh_connect, sid,
                      connect_payload(use_tmux=True, reconnect_tmux_name='saved_tmux', **extra))
    assert not jobs
    assert emitted[0][1]['error'] == 'This persistent session uses a different SOCKS5 route. Close it and connect again.'


def test_combined_credential_check_bypasses_cached_poll_result():
    class Guard:
        def is_set(self):
            return False

        def check(self):
            raise events.AutomationError('vault_locked')

    clear = SimpleNamespace(is_set=lambda: False)
    cancellation = events._CombinedCancellation(clear, clear, credential_guards=[Guard()])
    with pytest.raises(events.AutomationError):
        cancellation.check()


def test_socks_runtime_password_and_saved_credential_are_mutually_exclusive(app, monkeypatch):
    owner, sid = user_socket(app, 'socks_ambiguous')
    proxy = saved_proxy(app, owner, auth_type='password', username='proxy-user')
    jobs, connections = capture_connections(app, monkeypatch)
    monkeypatch.setattr(events, 'CredentialGuard', lambda *args: SimpleNamespace())
    monkeypatch.setattr(events, 'connection_password', lambda *args: 'saved-secret')
    _, emitted = call(app, monkeypatch, events.handle_ssh_connect, sid, connect_payload(socks_proxy={
        'socks_proxy_id': proxy['id'], 'password': 'runtime-secret', 'credential_id': 'saved',
    }))
    assert not jobs and not connections
    assert emitted[0][1]['code'] == 'credential_unavailable'


def test_named_socks_credential_preserves_target_token_and_live_endpoint(app, monkeypatch):
    from flask import request
    import app.auth_assurance as assurance
    owner, sid = user_socket(app, 'socks_named')
    proxy = saved_proxy(app, owner, auth_type='password', username='proxy-user', remote_dns=False)
    jobs, connections = capture_connections(app, monkeypatch)
    monkeypatch.setattr(assurance, 'current_authentication_session',
                        lambda: SimpleNamespace(id=73, user_id=owner))
    generations, passwords = [], []
    app.extensions['credentials'] = SimpleNamespace(
        target_generation=lambda *args: generations.append(args) or 'generation',
        target_password=lambda *args: passwords.append(args) or 'saved-proxy-secret',
    )
    with app.test_request_context('/socket.io', base_url='https://localhost'):
        request.sid = sid
        events.handle_ssh_connect(connect_payload(socks_proxy={
            'socks_proxy_id': proxy['id'], 'credential_id': 'named-credential',
            'credential_target_token': 'bound-token', 'host': 'untrusted.example',
        }))
    assert len(jobs) == 1
    assert jobs[0].join(3)
    assert len(passwords) == 1
    for arguments in generations + passwords:
        assert arguments[:3] == (owner, 73, 'named-credential')
        target = arguments[3]
        assert target['kind'] == 'socks'
        assert target['host'] == 'live-proxy.example'
        assert target['remote_dns'] is False
        assert arguments[4] == 'bound-token'
        assert 'password' not in target
    assert connections[0]['socks_proxy'].password == 'saved-proxy-secret'
    assert set(connections[0]['saved_password_hops']) == {'socks'}
