import paramiko
import pytest
from app.ssh_gateway_auth import GatewayAuthStrategy


class Transport:
    def __init__(self):
        self.authenticated = False
        self.calls = []
        self.none_requests = 0
    def close(self):
        self.authenticated = False
    def is_authenticated(self):
        return self.authenticated
    def auth_none(self, username):
        self.none_requests += 1
        raise paramiko.BadAuthenticationType('Methods available', ['password'])
    def auth_password(self, username, password, fallback=True):
        self.calls.append(("password", password, fallback))
        raise paramiko.BadAuthenticationType("More factors", ["keyboard-interactive"])
    def auth_interactive(self, username, handler):
        self.calls.append(("interactive",))
        assert handler("OTP", "Enter code", [("Code", True)]) == ["123456"]
        self.authenticated = True
        return []


def test_password_never_replayed_into_otp():
    transport = Transport()
    strategy = GatewayAuthStrategy("u:t", password="initial-secret", interact=lambda *args: ["123456"])
    strategy.authenticate(transport)
    assert transport.calls == [("password", "initial-secret", False), ("interactive",)]
    assert transport.none_requests == 0


def test_empty_password_starts_interactive():
    transport = Transport()
    GatewayAuthStrategy("u:t", interact=lambda *args: ["123456"]).authenticate(transport)
    assert transport.calls == [("interactive",)]


def test_no_success_without_authenticated_transport():
    transport = Transport()
    transport.auth_interactive = lambda *args: []
    with pytest.raises(paramiko.AuthenticationException):
        GatewayAuthStrategy("u:t", interact=lambda *args: []).authenticate(transport)


def test_generic_auth_failure_does_not_guess_next_method():
    transport = Transport()
    def reject(*args, **kwargs):
        raise paramiko.AuthenticationException("Denied")
    transport.auth_password = reject
    with pytest.raises(paramiko.AuthenticationException):
        GatewayAuthStrategy("u:t", password="wrong", interact=lambda *args: pytest.fail()).authenticate(transport)
    assert transport.calls == []

def test_service_request_wait_is_bounded_and_disconnect_aware(monkeypatch):
    from app.ssh_gateway_auth import GatewayTransport
    from paramiko import SSHException
    transport = object.__new__(GatewayTransport)
    transport.active = False
    transport.initial_kex_done = True
    transport._service_userauth_accepted = False
    with pytest.raises(SSHException):
        transport.ensure_session()


def test_service_request_is_sent_only_once(monkeypatch):
    from app.ssh_gateway_auth import GatewayTransport
    transport = object.__new__(GatewayTransport)
    transport.active = True
    transport.initial_kex_done = True
    transport._service_userauth_accepted = True
    transport._send_message = lambda message: pytest.fail("duplicate SSH service request")
    transport.ensure_session()

def test_key_with_password_and_otp_supplies_password_before_interactive():
    transport = Transport()
    transport.auth_publickey = lambda *args: ["password", "keyboard-interactive"]
    strategy = GatewayAuthStrategy("u:t", pkey=object(),
        interact=lambda title, instructions, prompts: ["initial-secret" if prompts[0][0] == "Password" else "123456"])
    strategy.authenticate(transport)
    assert transport.calls == [("password", "initial-secret", False), ("interactive",)]


def test_authentication_methods_share_remaining_deadline(monkeypatch):
    import app.ssh_gateway_auth as auth
    now = [100.0]
    monkeypatch.setattr(auth.time, "monotonic", lambda: now[0])
    transport = Transport()
    transport.close = lambda: None
    def key(*args):
        now[0] += 110
        return ["password"]
    def answer(*args):
        now[0] += 20
        return ["secret"]
    def password(*args, **kwargs):
        assert 0 < transport.auth_timeout <= 50
        transport.authenticated = True
        return []
    transport.auth_publickey = key
    transport.auth_password = password
    GatewayAuthStrategy("u:t", pkey=object(), interact=answer).authenticate(transport)


def test_shared_deadline_closes_a_blocked_authentication(monkeypatch):
    import app.ssh_gateway_auth as auth
    timers = []
    class Timer:
        def __init__(self, seconds, callback):
            assert seconds == 180
            self.callback = callback
            self.cancelled = False
            timers.append(self)
        def start(self): pass
        def cancel(self): self.cancelled = True
    monkeypatch.setattr(auth.threading, "Timer", Timer)
    transport = Transport()
    closed = []
    transport.close = lambda: closed.append(True)
    def blocked(*args):
        timers[0].callback()
        assert closed == [True]
        raise paramiko.AuthenticationException("closed")
    transport.auth_interactive = blocked
    with pytest.raises(paramiko.AuthenticationException):
        GatewayAuthStrategy("u:t", interact=lambda *args: []).authenticate(transport)
    assert timers[0].cancelled

@pytest.mark.parametrize("username", ["alice", "root", "user@example.test"])
def test_ordinary_ssh_password_then_otp(username):
    transport = Transport()
    GatewayAuthStrategy(username, password="initial-secret", interact=lambda *args: ["123456"]).authenticate(transport)
    assert transport.is_authenticated()
    assert transport.calls == [("password", "initial-secret", False), ("interactive",)]


def test_ordinary_key_partial_success_then_otp():
    transport = Transport()
    transport.auth_publickey = lambda *args: ["keyboard-interactive"]
    GatewayAuthStrategy("alice", pkey=object(), interact=lambda *args: ["123456"]).authenticate(transport)
    assert transport.is_authenticated()
    assert transport.calls == [("interactive",)]

@pytest.mark.parametrize('response', ['success', 'partial'])
def test_immediate_auth_reply_is_not_lost(response):
    import threading
    from paramiko import Message
    from paramiko.auth_handler import PartialAuthentication
    from app.ssh_gateway_auth import GatewayTransport
    class ImmediateTransport:
        lock = threading.Lock()
        auth_timeout = .1
        def _log(self, *args): pass
        def _auth_trigger(self): pass
        def is_active(self): return True
        def get_exception(self):
            return PartialAuthentication(['keyboard-interactive']) if response == 'partial' else None
        def _send_message(self, message):
            if response == 'success':
                handler._parse_userauth_success(Message())
            elif handler.auth_event is not None:
                handler.auth_event.set()
    transport = ImmediateTransport()
    handler = GatewayTransport.get_auth_handler(transport)
    assert handler.auth_password('alice', 'secret') == ([] if response == 'success' else ['keyboard-interactive'])


def test_ordinary_password_prefers_advertised_interactive_without_password_replay():
    transport = Transport()
    def discover(username):
        raise paramiko.BadAuthenticationType('Methods available', ['password', 'keyboard-interactive'])
    transport.auth_none = discover
    GatewayAuthStrategy('alice', password='initial-secret', interact=lambda *args: ['123456']).authenticate(transport)
    assert transport.calls == [('interactive',)]


@pytest.mark.parametrize('failure', ['generic', 'unsupported'])
def test_ordinary_method_discovery_fails_closed(failure):
    transport = Transport()
    def discover(username):
        if failure == 'generic':
            raise paramiko.AuthenticationException('Discovery rejected')
        raise paramiko.BadAuthenticationType('Methods available', ['publickey'])
    transport.auth_none = discover
    strategy = GatewayAuthStrategy('alice', password='secret', interact=lambda *args: pytest.fail('unexpected prompt'))
    with pytest.raises(paramiko.AuthenticationException):
        strategy.authenticate(transport)
    assert transport.calls == []
    assert strategy.password is None and strategy.pkey is None


def test_none_authentication_success_needs_no_credential_request():
    transport = Transport()
    def discover(username):
        transport.authenticated = True
        return []
    transport.auth_none = discover
    GatewayAuthStrategy('alice', password='secret', interact=lambda *args: pytest.fail('unexpected prompt')).authenticate(transport)
    assert transport.calls == []


def test_ordinary_wrong_password_does_not_trigger_fallback_prompt():
    transport = Transport()
    def reject(*args, **kwargs):
        raise paramiko.AuthenticationException('Wrong password')
    transport.auth_password = reject
    with pytest.raises(paramiko.AuthenticationException, match='Wrong password'):
        GatewayAuthStrategy('alice', password='wrong', interact=lambda *args: pytest.fail('unexpected fallback')).authenticate(transport)
    assert transport.none_requests == 1


def test_method_discovery_uses_shared_authentication_deadline(monkeypatch):
    import app.ssh_gateway_auth as auth
    now = [100.0]
    monkeypatch.setattr(auth.time, 'monotonic', lambda: now[0])
    transport = Transport()
    def discover(username):
        now[0] += 150
        raise paramiko.BadAuthenticationType('Methods available', ['password'])
    def password(*args, **kwargs):
        assert 0 < transport.auth_timeout <= 30
        transport.authenticated = True
        return []
    transport.auth_none = discover
    transport.auth_password = password
    GatewayAuthStrategy('alice', password='secret', interact=lambda *args: pytest.fail('unexpected prompt')).authenticate(transport)
