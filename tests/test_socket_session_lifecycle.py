import importlib
import os
import tempfile
import time

import pytest

from app import socketio, ssh_manager
from app.auth import register_user


@pytest.fixture(scope='module')
def app():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        os.environ['DATA_DIR'] = tmpdir
        import config
        importlib.reload(config)
        config.RATELIMIT_ENABLED = False

        from app import create_app
        from app.models import db

        test_app = create_app()
        # Re-register handlers on the Socket.IO server created for this app.
        from app import socket_events
        importlib.reload(socket_events)
        test_app.config['TESTING'] = True
        test_app.config['WTF_CSRF_ENABLED'] = False
        with test_app.app_context():
            db.create_all()
        yield test_app
        with test_app.app_context():
            db.session.remove()
            db.engine.dispose()


def _authenticated_socket(app):
    username = 'session_race_user'
    password = 'socket-password-123'
    with app.app_context():
        user, error = register_user(username, password)
        assert error is None
        user_id = user.id

    http_client = app.test_client()
    response = http_client.post('/login', data={
        'username': username,
        'password': password,
    })
    assert response.status_code == 302

    socket_client = socketio.test_client(
        app, flask_test_client=http_client)
    assert socket_client.is_connected()
    socket_client.get_received()
    return socket_client, user_id


def _collect_until(socket_client, event_name, timeout=5):
    deadline = time.monotonic() + timeout
    events = []
    while time.monotonic() < deadline:
        events.extend(socket_client.get_received())
        if any(event['name'] == event_name for event in events):
            break
        time.sleep(0.02)
    return events


def test_connect_fails_closed_if_created_session_disappears(app, monkeypatch):
    from app.models import SSHSession

    socket_client, _user_id = _authenticated_socket(app)
    monkeypatch.setattr(
        ssh_manager,
        'create_ssh_connection',
        lambda **_kwargs: ('vanished-session', None),
    )
    monkeypatch.setattr(ssh_manager, 'get_session', lambda _session_id: None)

    try:
        socket_client.emit('ssh_connect', {
            'host': 'example.com',
            'port': 22,
            'username': 'alice',
            'password': 'secret',
            'use_tmux': True,
            'client_request_id': 'race-request',
        })
        events = _collect_until(socket_client, 'ssh_error')

        errors = [event for event in events if event['name'] == 'ssh_error']
        assert errors
        assert errors[0]['args'][0]['error'] == 'Connection failed'
        assert not any(event['name'] == 'ssh_connected' for event in events)
        with app.app_context():
            assert SSHSession.query.filter_by(
                session_id='vanished-session').first() is None
    finally:
        if socket_client.is_connected():
            socket_client.disconnect()
