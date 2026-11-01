import pytest
from app.socket_events import _validate_ssh_params


@pytest.fixture(autouse=True)
def gateway_enabled(monkeypatch):
    from app import app_settings
    monkeypatch.setattr(app_settings, 'is_ssh_gateway_enabled', lambda: True)

def test_gateway_validation_is_explicitly_opt_in():
    assert _validate_ssh_params("host",22,"u:t")[3]
    assert _validate_ssh_params("host",22,"u:t",allow_gateway=True) == ("host",22,"u:t",None)

@pytest.mark.parametrize("value", [" u:t", "u:t ", "u: t", "ticket-user:t", "u#x:t"])
def test_gateway_validation_does_not_trim_or_reinterpret(value):
    assert _validate_ssh_params("host",22,value,allow_gateway=True)[3]

def test_ordinary_validation_keeps_trimming():
    assert _validate_ssh_params("host",22," user ") == ("host",22,"user",None)

def test_profile_storage_keeps_legacy_schema_with_gateway(app):
    from app import profile_manager
    from tests.test_command_set_socket_events import create_socket_user
    user_id, _sid = create_socket_user(app, "gateway_profile")
    with app.app_context():
        profile, error = profile_manager.add_profile(user_id, "Gateway", "host", 22, "u:t", "password")
        assert error is None
        assert profile["auth_type"] == "password"
        assert profile_manager._valid_profile(profile)


@pytest.mark.usefixtures("direct_socket_authentication")
def test_socket_gateway_admission_and_cancel(app, monkeypatch):
    import threading
    from flask import request
    from app import socket_events, ssh_manager
    from tests.test_command_set_socket_events import create_socket_user
    user_id, sid = create_socket_user(app, "gateway_cancel")
    entered, finished = threading.Event(), threading.Event()
    received = []
    monkeypatch.setattr(socket_events, "emit", lambda *args, **kwargs: received.append(args))
    def connect(**kwargs):
        attempt = kwargs["gateway_attempt"]
        assert kwargs["password"] is None
        entered.set()
        try:
            attempt.challenge("", "", [("OTP", False)])
        except ValueError:
            pass
        finally: finished.set()
        return None, "cancelled"
    monkeypatch.setattr(ssh_manager, "create_ssh_connection", connect)
    with app.test_request_context("/socket.io"):
        request.sid = sid
        socket_events.handle_ssh_connect({
            "host":"host", "username":"u:t", "auth_type":"password",
            "client_request_id":"gateway-request", "gateway_interaction":1,
        })
    assert entered.wait(2), received
    with app.test_request_context("/socket.io"):
        request.sid = sid
        assert socket_events.handle_ssh_connect_cancel({"client_request_id":"gateway-request"})["success"]
    assert finished.wait(2)


@pytest.mark.usefixtures("direct_socket_authentication")
def test_gateway_requires_client_capability(app, monkeypatch):
    from app import socket_events, ssh_manager
    from tests.test_command_set_socket_events import create_socket_user, call_socket_handler
    _, sid = create_socket_user(app, "gateway_old_client")
    monkeypatch.setattr(ssh_manager, "create_ssh_connection", lambda **kwargs: pytest.fail("connected"))
    _, events = call_socket_handler(app, monkeypatch, socket_events.handle_ssh_connect, sid,
        {"host":"host", "username":"u:t", "client_request_id":"legacy"})
    assert any("updated interactive client" in payload.get("error","") for event,payload in events)


@pytest.mark.usefixtures("direct_socket_authentication")
@pytest.mark.parametrize("failure", ["host", "key", "rate"])
def test_gateway_quick_validation_errors_are_correlated(app, monkeypatch, failure):
    from app import socket_events
    from tests.test_command_set_socket_events import create_socket_user, call_socket_handler
    _, sid = create_socket_user(app, "gateway_validation_" + failure)
    data = {"host": "host", "username": "u:t", "client_request_id": "quick-req", "gateway_interaction": 1}
    monkeypatch.setattr(socket_events, "check_socket_rate_limit", lambda *args: failure == "rate")
    if failure == "host": data["host"] = ""
    if failure == "key":
        data["key_id"] = "missing"
        monkeypatch.setattr(socket_events.key_manager, "read_key_content", lambda *args: (None, "not found"))
    _, events = call_socket_handler(app, monkeypatch, socket_events.handle_quick_connect, sid, data)
    errors = [payload for name, payload in events if name == "quick_connect_error"]
    assert len(errors) == 1
    assert errors[0].get("client_request_id") == "quick-req"


@pytest.mark.usefixtures("direct_socket_authentication")
@pytest.mark.parametrize("reason", ["failed", "timeout"])
def test_gateway_quick_internal_cancellation_emits_terminal_error(app, monkeypatch, reason):
    import threading
    from app import socket_events
    from tests.test_command_set_socket_events import create_socket_user, call_socket_handler
    _, sid = create_socket_user(app, "gateway_internal_" + reason)
    done = threading.Event()
    events = []
    registry = app.extensions["ssh_attempt_registry"]
    original_finish = registry.finish
    def finish(attempt):
        original_finish(attempt)
        done.set()
    monkeypatch.setattr(registry, "finish", finish)
    monkeypatch.setattr(socket_events.socketio, "emit", lambda event, data, **kwargs: events.append((event, data)))
    def connect(*args, **kwargs):
        attempt = kwargs["gateway_attempt"]
        attempt.cancel(reason=reason)
        return None, "failed"
    monkeypatch.setattr(socket_events.connection_pool.temp_connection_pool, "create_connection", connect)
    call_socket_handler(app, monkeypatch, socket_events.handle_quick_connect, sid,
        {"host": "host", "username": "u:t", "client_request_id": "quick-req", "gateway_interaction": 1})
    assert done.wait(3)
    errors = [payload for name, payload in events if name == "quick_connect_error"]
    assert len(errors) == 1
    assert errors[0]["client_request_id"] == "quick-req"
    assert not registry.attempts


@pytest.mark.usefixtures("direct_socket_authentication")
def test_terminal_gateway_timeout_emits_one_correlated_error(app, monkeypatch):
    import threading
    from app import socket_events, ssh_manager
    from tests.test_command_set_socket_events import create_socket_user, call_socket_handler
    _, sid = create_socket_user(app, "gateway_terminal_timeout")
    done = threading.Event()
    events = []
    registry = app.extensions["ssh_attempt_registry"]
    original_finish = registry.finish
    def finish(attempt):
        original_finish(attempt)
        done.set()
    monkeypatch.setattr(registry, "finish", finish)
    def connect(**kwargs):
        kwargs["gateway_attempt"].cancel(reason="timeout")
        assert not kwargs["cancel_event"].commit_if_active()
        return None, "Connection cancelled"
    monkeypatch.setattr(ssh_manager, "create_ssh_connection", connect)
    _, events = call_socket_handler(app, monkeypatch, socket_events.handle_ssh_connect, sid,
        {"host": "host", "username": "u:t", "client_request_id": "terminal-timeout", "gateway_interaction": 1})
    assert done.wait(3)
    errors = [payload for name, payload in events if name == "ssh_error"]
    assert len(errors) == 1
    assert errors[0]["client_request_id"] == "terminal-timeout"
    assert not any(name == "ssh_connected" for name, _ in events)
    assert not registry.attempts

@pytest.mark.usefixtures('direct_socket_authentication')
@pytest.mark.parametrize('gateway', [False, True])
def test_rejected_connect_job_releases_attempt_and_admission(app, monkeypatch, gateway):
    from app import socket_events, ssh_manager
    from app import ssh_connection_attempt
    from app.quota_manager import QuotaKind, QuotaManager
    from tests.test_command_set_socket_events import create_socket_user, call_socket_handler
    user_id, sid = create_socket_user(app, 'job_rejected_' + str(gateway))
    registry = app.extensions['ssh_attempt_registry']
    quotas = QuotaManager({kind: {'global': 2, 'per_user': 1} for kind in QuotaKind})
    monkeypatch.setattr(ssh_connection_attempt, 'quota_manager', quotas)

    def reject(*args, **kwargs):
        raise RuntimeError('runtime stopped')

    monkeypatch.setattr(app.extensions['runtime_lifecycle'], 'start_job', reject)
    monkeypatch.setattr(ssh_manager, 'create_ssh_connection',
                        lambda **kwargs: pytest.fail('network work after rejection'))
    _, events = call_socket_handler(app, monkeypatch, socket_events.handle_ssh_connect, sid, {
        'host': 'host', 'username': 'u:t' if gateway else 'u', 'password': 'synthetic',
        'client_request_id': 'rejected', 'gateway_interaction': 1,
    })
    assert registry.get(user_id, sid, 'rejected') is None
    # The same user's only slot must be available again after job rejection.
    reservation = quotas.reserve(QuotaKind.BACKGROUND_JOB, user_id)
    reservation.release()
    errors = [data for name, data in events if name == 'ssh_error']
    assert len(errors) == 1
    assert errors[0]['client_request_id'] == 'rejected'


@pytest.mark.usefixtures('direct_socket_authentication')
def test_gateway_events_cannot_mutate_an_ordinary_ssh_attempt(app, monkeypatch):
    from app import socket_events
    from tests.test_command_set_socket_events import create_socket_user, call_socket_handler
    user_id, sid = create_socket_user(app, 'ordinary_gateway_events')
    registry = app.extensions['ssh_attempt_registry']
    attempt = registry.create(user_id, sid, 'ordinary')
    try:
        for handler in (socket_events.handle_gateway_answer, socket_events.handle_gateway_input,
                        socket_events.handle_gateway_quick_cancel):
            response, _ = call_socket_handler(app, monkeypatch, handler, sid, {
                'client_request_id': 'ordinary', 'challenge_id': 'x', 'answers': ['x'], 'data': 'x',
            })
            assert response['success'] is False
        call_socket_handler(app, monkeypatch, socket_events.handle_gateway_ack, sid,
                            {'client_request_id': 'ordinary', 'sequence': 1})
        assert not attempt.is_set()
        assert attempt.commit_if_active()
    finally:
        registry.finish(attempt)


@pytest.mark.usefixtures('direct_socket_authentication')
def test_ordinary_connect_does_not_depend_on_gateway_admission(app, monkeypatch):
    import threading
    from app import socket_events, ssh_manager
    from tests.test_command_set_socket_events import create_socket_user, call_socket_handler
    _, sid = create_socket_user(app, 'ordinary_independent')
    connected = threading.Event()
    app.extensions['ssh_attempt_registry'].shutdown()
    def connect(**kwargs):
        assert 'gateway_attempt' not in kwargs
        assert kwargs['password'] == 'secret'
        connected.set()
        return None, 'Expected test stop'
    monkeypatch.setattr(ssh_manager, 'create_ssh_connection', connect)
    call_socket_handler(app, monkeypatch, socket_events.handle_ssh_connect, sid, {
        'host': 'host', 'username': 'deploy', 'password': 'secret',
        'client_request_id': 'ordinary-request',
    })
    assert connected.wait(2)


@pytest.mark.usefixtures('direct_socket_authentication')
@pytest.mark.parametrize('first,second', [
    ('ordinary', 'gateway'), ('gateway', 'ordinary'),
    ('ordinary', 'quick'), ('quick', 'ordinary'),
])
def test_request_id_cannot_cross_ordinary_and_gateway_attempts(app, monkeypatch, first, second):
    import threading
    from app import socket_events, ssh_manager
    from tests.test_command_set_socket_events import create_socket_user, call_socket_handler
    _, sid = create_socket_user(app, 'request_collision')
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    calls = []

    def connect(*args, **kwargs):
        calls.append(kwargs)
        entered.set()
        try:
            assert release.wait(3)
            return None, 'Expected test stop'
        finally:
            finished.set()

    monkeypatch.setattr(ssh_manager, 'create_ssh_connection', connect)
    monkeypatch.setattr(socket_events.connection_pool.temp_connection_pool, 'create_connection', connect)

    def start(kind):
        handler = (socket_events.handle_quick_connect if kind == 'quick'
                   else socket_events.handle_ssh_connect)
        return call_socket_handler(app, monkeypatch, handler, sid, {
            'host': 'host', 'username': 'deploy' if kind == 'ordinary' else 'u:t',
            'password': 'secret', 'client_request_id': 'same-request',
            'gateway_interaction': 1,
        })

    try:
        start(first)
        assert entered.wait(2)
        _, events = start(second)
        assert len(calls) == 1
        assert any(name in ('ssh_error', 'quick_connect_error') for name, _ in events)
    finally:
        release.set()
        assert finished.wait(2)

@pytest.mark.usefixtures("direct_socket_authentication")
def test_ordinary_socket_mfa_admission_and_cancel_with_gateway_disabled(app, monkeypatch):
    import threading
    from flask import request
    from app import app_settings, socket_events, ssh_manager
    from tests.test_command_set_socket_events import create_socket_user
    monkeypatch.setattr(app_settings, 'is_ssh_gateway_enabled', lambda: False)
    _, sid = create_socket_user(app, "pam_cancel")
    entered, finished = threading.Event(), threading.Event()
    def connect(**kwargs):
        attempt = kwargs.get("gateway_attempt")
        if attempt is None:
            finished.set()
            return None, "missing interaction"
        attempt.check()
        entered.set()
        try:
            attempt.challenge("PAM", "", [("Verification code:", False)])
        except ValueError:
            pass
        finally:
            finished.set()
        return None, "cancelled"
    monkeypatch.setattr(ssh_manager, "create_ssh_connection", connect)
    with app.test_request_context("/socket.io"):
        request.sid = sid
        socket_events.handle_ssh_connect({
            "host": "host", "username": "alice", "password": "secret",
            "client_request_id": "pam-request", "ssh_interaction": 1,
        })
    try:
        assert entered.wait(2)
        with app.test_request_context("/socket.io"):
            request.sid = sid
            assert socket_events.handle_ssh_connect_cancel({"client_request_id": "pam-request"})["success"]
        assert finished.wait(2)
    finally:
        app.extensions['ssh_attempt_registry'].cancel_socket(sid)
