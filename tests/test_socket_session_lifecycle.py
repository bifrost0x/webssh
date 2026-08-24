import importlib
import os
import tempfile
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app import socketio, ssh_manager
from app.auth import register_user
from app.file_sources import SourceHoldSet


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
        runtime_lifecycle = test_app.extensions['runtime_lifecycle']
        # Re-register handlers on the Socket.IO server created for this app.
        from app import socket_events
        importlib.reload(socket_events)
        test_app.config['TESTING'] = True
        test_app.config['WTF_CSRF_ENABLED'] = False
        with test_app.app_context():
            db.create_all()
        yield test_app
        with test_app.app_context():
            runtime_lifecycle.begin_shutdown(
                config.RUNTIME_SHUTDOWN_GRACE_SECONDS
            )
            db.session.remove()
            db.engine.dispose()


def _authenticated_socket(app, username='session_race_user'):
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


def _logged_in_http_client(app, username):
    http_client = app.test_client()
    response = http_client.post('/login', data={
        'username': username,
        'password': 'socket-password-123',
    })
    assert response.status_code == 302
    return http_client


def _collect_until(socket_client, event_name, timeout=5):
    deadline = time.monotonic() + timeout
    events = []
    while time.monotonic() < deadline:
        events.extend(socket_client.get_received())
        if any(event['name'] == event_name for event in events):
            break
        time.sleep(0.02)
    return events


def test_socket_capacity_preserves_per_user_and_global_reserve(app, monkeypatch):
    import config

    monkeypatch.setattr(config, 'MAX_SOCKET_CONNECTIONS', 2, raising=False)
    monkeypatch.setattr(
        config,
        'MAX_SOCKET_CONNECTIONS_PER_USER',
        1,
        raising=False,
    )
    first_socket, _user_id = _authenticated_socket(app, 'capacity_first')
    second_same_user = socketio.test_client(
        app,
        flask_test_client=_logged_in_http_client(app, 'capacity_first'),
    )
    other_socket, _other_id = _authenticated_socket(app, 'capacity_other')

    with app.app_context():
        user, error = register_user('capacity_third', 'socket-password-123')
        assert error is None
        assert user is not None
    over_global_limit = socketio.test_client(
        app,
        flask_test_client=_logged_in_http_client(app, 'capacity_third'),
    )

    try:
        assert not second_same_user.is_connected()
        assert other_socket.is_connected()
        assert not over_global_limit.is_connected()
    finally:
        for client in (
            first_socket,
            second_same_user,
            other_socket,
            over_global_limit,
        ):
            if client.is_connected():
                client.disconnect()


def test_socket_connect_is_rejected_while_runtime_is_shutting_down(
        app, monkeypatch):
    from app.models import SocketSession
    from app.socket_capacity import socket_capacity

    username = 'shutdown_connect_user'
    with app.app_context():
        user, error = register_user(username, 'socket-password-123')
        assert error is None
        user_id = user.id

    http_client = _logged_in_http_client(app, username)
    lifecycle = app.extensions['runtime_lifecycle']
    monkeypatch.setattr(lifecycle, 'accepting_work', lambda: False)
    monkeypatch.setattr(
        socket_capacity,
        'reserve',
        lambda *_args, **_kwargs: pytest.fail(
            'shutdown socket reached capacity reservation'
        ),
    )

    socket_client = socketio.test_client(
        app,
        flask_test_client=http_client,
    )

    assert not socket_client.is_connected()
    with app.app_context():
        assert SocketSession.query.filter_by(user_id=user_id).count() == 0


def test_locked_user_disconnect_still_cancels_owned_transfers(app, monkeypatch):
    from app import socket_events
    from app.models import User, db
    from app.transfer_manager import TransferManager

    socket_client, user_id = _authenticated_socket(app, 'locked_transfer_user')
    manager = TransferManager()
    record = manager.create(
        user_id,
        'locked-session',
        'download',
        {},
    )
    monkeypatch.setattr(socket_events, 'transfer_manager', manager)
    with app.app_context():
        user = db.session.get(User, user_id)
        user.is_locked = True
        db.session.commit()

    socket_client.disconnect()

    assert record.cancel_event.is_set()
    assert manager._records == {}


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


@pytest.mark.parametrize('auth_session_state', ('expired', 'deleted'))
def test_socket_event_revalidates_server_authentication_session(
        app, monkeypatch, auth_session_state):
    from app import socket_events
    from app.models import AuthenticationSession, SocketSession, db

    socket_client, user_id = _authenticated_socket(
        app,
        f'auth_session_{auth_session_state}',
    )
    profile_loads = []
    monkeypatch.setattr(
        socket_events.profile_manager,
        'load_profiles',
        lambda loaded_user_id: profile_loads.append(loaded_user_id) or [],
    )

    with app.app_context():
        auth_session = AuthenticationSession.query.filter_by(
            user_id=user_id,
        ).one()
        if auth_session_state == 'expired':
            auth_session.expires_at = (
                datetime.now(timezone.utc) - timedelta(seconds=1)
            )
        else:
            db.session.delete(auth_session)
        db.session.commit()

    socket_client.emit('list_profiles')

    assert not socket_client.is_connected()
    assert profile_loads == []
    with app.app_context():
        assert SocketSession.query.filter_by(user_id=user_id).count() == 0


def test_last_socket_disconnect_cancels_user_transfers(app, monkeypatch):
    from app import socket_events
    from app.transfer_manager import TransferManager

    username = 'transfer_disconnect_user'
    first_socket, user_id = _authenticated_socket(app, username)
    second_http = app.test_client()
    response = second_http.post('/login', data={
        'username': username,
        'password': 'socket-password-123',
    })
    assert response.status_code == 302
    second_socket = socketio.test_client(app, flask_test_client=second_http)
    assert second_socket.is_connected()
    second_socket.get_received()

    manager = TransferManager()
    first_record = manager.create(user_id, 'session-a', 'upload', {})
    monkeypatch.setattr(socket_events, 'transfer_manager', manager)

    first_socket.disconnect()
    assert first_record.transfer_id in manager._records
    assert not first_record.cancel_event.is_set()

    second_record = manager.create(user_id, 'session-b', 'download', {})
    second_socket.disconnect()

    assert first_record.cancel_event.is_set()
    assert second_record.cancel_event.is_set()
    assert manager._records == {}


def test_disconnect_cancels_only_transfers_prepared_by_that_socket(app, monkeypatch):
    from app import socket_events, transfer_routes
    from app.transfer_manager import TransferManager

    username = 'transfer_socket_owner_user'
    first_socket, user_id = _authenticated_socket(app, username)
    second_http = app.test_client()
    response = second_http.post('/login', data={
        'username': username,
        'password': 'socket-password-123',
    })
    assert response.status_code == 302
    second_socket = socketio.test_client(app, flask_test_client=second_http)
    assert second_socket.is_connected()
    second_socket.get_received()

    manager = TransferManager()
    monkeypatch.setattr(socket_events, 'transfer_manager', manager)
    monkeypatch.setattr(transfer_routes, 'transfer_manager', manager)
    monkeypatch.setattr(
        transfer_routes.file_service,
        'resolve',
        lambda *_args, **_kwargs: SimpleNamespace(handle_id='owned-session'),
    )
    monkeypatch.setattr(
        transfer_routes.file_source_resolver,
        'acquire_transfer_holds',
        lambda _user_id, source_ids: SourceHoldSet(tuple(source_ids)),
    )

    first_result = first_socket.emit('prepare_transfer', {
        'direction': 'upload',
        'source_id': 'sftp-session:owned-session',
        'request_id': 'prepare-first-transfer',
        'remote_path': '/remote/first.bin',
    }, callback=True)
    second_result = second_socket.emit('prepare_transfer', {
        'direction': 'download',
        'source_id': 'sftp-session:owned-session',
        'request_id': 'prepare-second-transfer',
        'remote_path': '/remote/second.bin',
    }, callback=True)
    first_record = manager._records[first_result['transfer_id']]
    second_record = manager._records[second_result['transfer_id']]

    first_socket.disconnect()

    assert first_record.cancel_event.is_set()
    assert first_record.transfer_id not in manager._records
    assert not second_record.cancel_event.is_set()
    assert second_record.transfer_id in manager._records
    assert str(second_record.user_id) == str(user_id)

    second_socket.disconnect()
