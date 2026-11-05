"""Saved credentials never follow an untrusted connection destination."""
from types import SimpleNamespace

import pytest


def test_manual_connection_does_not_consult_vault(app):
    from app.credential_connections import connection_password
    with app.test_request_context('/socket.io'):
        assert connection_password(1, 'ssh', {'password': 'manual'}) == 'manual'


@pytest.mark.parametrize('secure,authenticated', [(False, True), (True, False)])
def test_saved_credentials_require_https_and_browser_identity(app, monkeypatch, secure, authenticated):
    from app.credential_connections import connection_password
    from app.automation_store import AutomationError
    import app.auth_assurance as assurance
    monkeypatch.setattr(assurance, 'current_authentication_session',
                        lambda: SimpleNamespace(id=7, user_id=1) if authenticated else None)
    with app.test_request_context('/socket.io', base_url='https://localhost' if secure else 'http://localhost'):
        with pytest.raises(AutomationError):
            connection_password(1, 'ssh', {'credential_id': 'host-1'})


def test_saved_credentials_use_current_authenticated_owner_and_full_target(app, monkeypatch):
    from app.credential_connections import connection_password
    import app.auth_assurance as assurance
    calls = []
    monkeypatch.setattr(assurance, 'current_authentication_session', lambda: SimpleNamespace(id=7, user_id=1))
    app.extensions['credentials'] = SimpleNamespace(connection_password=lambda *args: calls.append(args) or 'remote-secret')
    data = {'credential_id': 'host-1', 'host': 'target', 'port': 22,
            'username': 'user', 'auth_type': 'password', 'proxy_jump': {'jump_host_id': 'jump-1'}}
    with app.test_request_context('/socket.io', base_url='https://localhost'):
        assert connection_password(1, 'ssh', data) == 'remote-secret'
    assert calls[0][:4] == (1, 7, 'ssh', 'host-1')
    assert calls[0][4]['jump_host_id'] == 'jump-1'
    assert 'password' not in data


def test_saved_credentials_reject_other_session_owner_and_ambiguous_input(app, monkeypatch):
    from app.credential_connections import connection_password
    from app.automation_store import AutomationError
    import app.auth_assurance as assurance
    monkeypatch.setattr(assurance, 'current_authentication_session', lambda: SimpleNamespace(id=7, user_id=2))
    with app.test_request_context('/socket.io', base_url='https://localhost'):
        with pytest.raises(AutomationError):
            connection_password(1, 'ssh', {'credential_id': 'host-1'})
        with pytest.raises(AutomationError):
            connection_password(1, 'ssh', {'credential_id': 'host-1', 'password': 'manual'})


def test_saved_credentials_reject_inline_route_substitution(app, monkeypatch):
    from app.credential_connections import connection_password, CredentialGuard
    from app.automation_store import AutomationError
    import app.auth_assurance as assurance
    monkeypatch.setattr(assurance, 'current_authentication_session', lambda: SimpleNamespace(id=7, user_id=1))
    with app.test_request_context('/socket.io', base_url='https://localhost'):
        for route in ({'host': 'unexpected-jump'}, {'jump_host_id': ''}, 'invalid'):
            data = {'credential_id': 'host-1', 'proxy_jump': route}
            with pytest.raises(AutomationError, match='credential_target_changed'):
                connection_password(1, 'ssh', data)
            with pytest.raises(AutomationError, match='credential_target_changed'):
                CredentialGuard(1, 'ssh', data)


def test_pending_credential_guard_cancels_on_generation_change_and_never_revives(app, monkeypatch):
    from app.credential_connections import CredentialGuard
    import app.auth_assurance as assurance
    monkeypatch.setattr(assurance, 'current_authentication_session', lambda: SimpleNamespace(id=7, user_id=1))
    token = ['original']
    app.extensions['credentials'] = SimpleNamespace(connection_generation=lambda *args: token[0])
    with app.test_request_context('/socket.io', base_url='https://localhost'):
        guard = CredentialGuard(1, 'ssh', {'credential_id': 'p1', 'host': 'target', 'username': 'u'})
        assert not guard.is_set()
        token[0] = 'changed'
        assert guard.is_set()
        token[0] = 'original'
        assert guard.is_set()


def test_saved_password_is_checked_after_handshake_and_cleared():
    from app.credential_connections import SavedPasswordAuth
    from app.automation_store import AutomationError
    calls = []
    transport = SimpleNamespace(auth_password=lambda *args, **kwargs: calls.append((args, kwargs)))
    def reject():
        raise AutomationError('vault_locked')
    denied = SavedPasswordAuth('u', 'secret', SimpleNamespace(check=reject))
    with pytest.raises(AutomationError):
        denied.authenticate(transport)
    assert not calls
    assert denied.password is None
    allowed = SavedPasswordAuth('u', 'secret', SimpleNamespace(check=lambda: None))
    allowed.authenticate(transport)
    assert calls == [(('u', 'secret'), {'fallback': False})]
    assert allowed.password is None


@pytest.mark.usefixtures('direct_socket_authentication')
@pytest.mark.parametrize('handler,event,kind', [
    ('handle_ssh_connect', 'ssh_error', 'ssh'),
    ('handle_quick_connect', 'quick_connect_error', 'ssh'),
    ('handle_smb_quick_connect', 'smb_quick_connect_error', 'smb'),
])
def test_socket_paths_report_locked_vault_without_attempting_network(app, monkeypatch, handler, event, kind):
    import config
    import app.socket_events as sockets
    from app.automation_store import AutomationError
    from tests.test_command_set_socket_events import create_socket_user, call_socket_handler
    _, sid = create_socket_user(app, 'cred_' + handler)
    monkeypatch.setattr(config, 'SMB_ENABLED', True)
    monkeypatch.setattr(sockets, 'check_socket_rate_limit', lambda *args: False)
    seen = []
    def reject(user_id, actual_kind, data):
        seen.append((actual_kind, data['credential_id']))
        raise AutomationError('vault_locked')
    monkeypatch.setattr(sockets, 'CredentialGuard', reject)
    _, events = call_socket_handler(app, monkeypatch, getattr(sockets, handler), sid, {
        'host': 'host.example.test', 'port': 22 if kind == 'ssh' else 445,
        'username': 'u', 'auth_type': 'password', 'credential_id': 'saved',
        'client_request_id': 'request-1', 'request_id': 'request-1', 'share': 'data',
    })
    assert seen == [(kind, 'saved')]
    response = next(payload for name, payload in events if name == event)
    assert response['code'] == 'vault_locked'
    assert 'host.example.test' not in str(response)


@pytest.mark.usefixtures('direct_socket_authentication')
def test_saved_quick_sftp_rejects_jump_route_before_credential_lookup(app, monkeypatch):
    import app.socket_events as sockets
    from tests.test_command_set_socket_events import create_socket_user, call_socket_handler
    _, sid = create_socket_user(app, 'saved_quick_route')
    monkeypatch.setattr(sockets, 'check_socket_rate_limit', lambda *args: False)
    monkeypatch.setattr(sockets, 'CredentialGuard', lambda *args: pytest.fail('unsupported route released a credential'))
    _, events = call_socket_handler(app, monkeypatch, sockets.handle_quick_connect, sid, {
        'host': 'target', 'port': 22, 'username': 'u', 'credential_id': 'p1',
        'proxy_jump': {'jump_host_id': 'j1'}, 'client_request_id': 'request-1',
    })
    assert next(data for name, data in events if name == 'quick_connect_error')['code'] == 'credential_unavailable'


@pytest.mark.usefixtures('direct_socket_authentication')
def test_saved_gateway_quick_sftp_keeps_credential_guard(app, monkeypatch):
    import app.socket_events as sockets
    from tests.test_command_set_socket_events import create_socket_user, call_socket_handler
    _, sid = create_socket_user(app, 'saved_quick_gateway')
    monkeypatch.setattr(sockets, 'check_socket_rate_limit', lambda *args: False)
    monkeypatch.setattr('app.app_settings.is_ssh_gateway_enabled', lambda: True)
    sentinel = SimpleNamespace(is_set=lambda: False)
    monkeypatch.setattr(sockets, 'CredentialGuard', lambda *args: sentinel)
    monkeypatch.setattr(sockets, 'connection_password', lambda *args: 'fixture-secret')
    calls = []
    monkeypatch.setattr(sockets, '_start_gateway_quick_connect', lambda *args, **kwargs: calls.append(kwargs))
    call_socket_handler(app, monkeypatch, sockets.handle_quick_connect, sid, {
        'host': 'gateway.example.test', 'port': 22, 'username': 'u:target',
        'credential_id': 'p1', 'client_request_id': 'request-1', 'gateway_interaction': 1,
    })
    assert calls == [{'credential_guard': sentinel}]
