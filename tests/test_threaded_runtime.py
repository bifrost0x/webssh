"""Runtime contracts for the native-threading Socket.IO canary."""

import importlib
import json
import os
import socket
import subprocess
import sys
import time
import threading
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENGINEIO_BASE_URL = 'http://localhost:5000'


def _free_loopback_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def _config_probe(gunicorn_threads):
    """Load production configuration in an isolated interpreter."""
    environment = os.environ.copy()
    environment.update({
        'DEBUG': 'True',
        'SECRET_KEY': 'threading-runtime-test-secret',
        'GUNICORN_THREADS': gunicorn_threads,
    })
    return subprocess.run(
        [
            sys.executable,
            '-c',
            'import config; print(config.GUNICORN_THREADS)',
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def _logged_in_http_client(app, username):
    from app.auth import register_user
    from flask import g

    with app.app_context():
        user, error = register_user(username, 'socket-password-123')
        assert error is None
        user_id = user.id
    # conftest intentionally keeps one outer app context around the test;
    # Flask-Login otherwise caches the previous request's user on that g.
    g.pop('_login_user', None)
    client = app.test_client()
    response = client.post('/login', data={
        'username': username,
        'password': 'socket-password-123',
    })
    assert response.status_code == 302
    return client, user_id


def _create_bootstrap_user(app, username):
    from app.auth import register_user

    with app.app_context():
        user, error = register_user(username, 'socket-password-123')
        assert error is None
        assert user.is_admin is True


def _mark_user_ldap_managed(app, user_id, username):
    from app.models import LDAPIdentity, db

    with app.app_context():
        db.session.add(LDAPIdentity(
            user_id=user_id,
            provider='default',
            subject=f'stable-{username}-id',
            directory_username=username,
            distinguished_name=f'uid={username},dc=example,dc=com',
        ))
        db.session.commit()


def _engineio_handshake(client, suffix):
    from flask import g

    g.pop('_login_user', None)
    return client.get(
        f'/socket.io/?EIO=4&transport=polling&t={suffix}',
        base_url=ENGINEIO_BASE_URL,
        headers={'Origin': ENGINEIO_BASE_URL},
    )


def _engineio_sid(response):
    assert response.data.startswith(b'0{')
    return json.loads(response.data[1:])['sid']


def _close_engineio_socket(engineio_sid):
    from app import socketio

    engineio_socket = socketio.server.eio.sockets[engineio_sid]
    engineio_socket.close(wait=False, abort=True)
    socketio.server.eio.sockets.pop(engineio_sid, None)


def test_app_uses_native_threading_socketio_runtime(app):
    """An Eventlet fallback would change Socket.IO scheduling semantics."""
    from app import socketio

    assert app.config['SOCKETIO_ASYNC_MODE'] == 'threading'
    assert socketio.async_mode == 'threading'


def test_socketio_handlers_use_the_bounded_gthread_request_context(app):
    """Per-event daemon threads would bypass the configured gthread limit."""
    from app import socketio

    assert app.config['SOCKETIO_ASYNC_HANDLERS'] is False
    assert socketio.server.async_handlers is False


def test_engineio_rejects_unauthenticated_transport_before_retention(app):
    from app import socketio

    capacity = app.extensions['engineio_socket_capacity']
    response = _engineio_handshake(app.test_client(), 'unauthenticated')

    assert response.status_code == 401
    assert response.headers['Access-Control-Allow-Origin'] == ENGINEIO_BASE_URL
    assert response.data == b'"Unauthorized"'
    assert socketio.server.eio.sockets == {}
    assert capacity.count() == 0


def test_engineio_admission_exception_fails_closed_without_retention(
    app,
    monkeypatch,
):
    import app as app_package
    from app import socketio

    capacity = app.extensions['engineio_socket_capacity']
    logged_errors = []

    def fail_admission(_app, _environ):
        raise RuntimeError('simulated admission failure')

    monkeypatch.setattr(
        app_package,
        '_engineio_admission_user',
        fail_admission,
    )
    monkeypatch.setattr(
        app_package,
        'log_error',
        lambda message, **details: logged_errors.append((message, details)),
    )

    response = _engineio_handshake(app.test_client(), 'admission-error')

    assert response.status_code == 401
    assert response.data == b'"Unauthorized"'
    assert socketio.server.eio.sockets == {}
    assert capacity.count() == 0
    assert len(logged_errors) == 1
    message, details = logged_errors[0]
    assert message == 'Engine.IO transport admission failed closed'
    assert details['error_type'] == 'RuntimeError'
    assert isinstance(details['sid'], str)
    assert details['sid']


def test_engineio_rejects_browser_session_after_epoch_rotation(app):
    from app import socketio
    from app.session_epoch import rotate_epoch

    client, _user_id = _logged_in_http_client(app, 'engineio_epoch')
    rotate_epoch()

    response = _engineio_handshake(client, 'rotated-epoch')

    assert response.status_code == 401
    assert response.data == b'"Unauthorized"'
    assert socketio.server.eio.sockets == {}
    assert app.extensions['engineio_socket_capacity'].count() == 0


def test_engineio_final_admission_recheck_closes_revocation_race(
    app,
    monkeypatch,
):
    import app as app_package
    from app import socketio
    from app.models import User, db
    from app.user_lifecycle import revoke_user_access

    client, user_id = _logged_in_http_client(
        app,
        'engineio_admission_revoke_race',
    )
    original_admission = app_package._engineio_admission_user
    validated = threading.Event()
    resume = threading.Event()

    def pause_after_validation(flask_app, environ):
        admitted_user = original_admission(flask_app, environ)
        validated.set()
        assert resume.wait(2)
        return admitted_user

    monkeypatch.setattr(
        app_package,
        '_engineio_admission_user',
        pause_after_validation,
    )
    responses = []
    failures = []

    def perform_handshake():
        try:
            with app.app_context():
                responses.append(_engineio_handshake(client, 'revoke-race'))
        except BaseException as error:
            failures.append(error)

    worker = threading.Thread(target=perform_handshake)
    worker.start()
    assert validated.wait(1)
    with app.app_context():
        user = db.session.get(User, user_id)
        user.is_locked = True
        db.session.commit()
        result = revoke_user_access(user_id, socketio)
    assert result['sockets'] == 0
    resume.set()
    worker.join(3)

    assert not worker.is_alive()
    assert failures == []
    assert len(responses) == 1
    assert responses[0].status_code == 401
    assert socketio.server.eio.sockets == {}
    assert app.extensions['engineio_socket_capacity'].count() == 0


@pytest.mark.parametrize('scheduler_failure', (False, True))
def test_engineio_cleanup_waits_for_library_owned_handshake_frame(
    app,
    monkeypatch,
    scheduler_failure,
):
    import app as app_package
    from app import socketio
    from app.models import User, db
    from app.user_lifecycle import revoke_user_access

    client, user_id = _logged_in_http_client(
        app,
        'engineio_admission_cleanup_race',
    )
    original_final_admission = app_package._engineio_admission_is_current
    validated = threading.Event()
    resume = threading.Event()

    def pause_after_final_validation(flask_app, environ, expected_user_id):
        admitted = original_final_admission(
            flask_app,
            environ,
            expected_user_id,
        )
        assert admitted is True
        validated.set()
        assert resume.wait(2)
        return admitted

    monkeypatch.setattr(
        app_package,
        '_engineio_admission_is_current',
        pause_after_final_validation,
    )
    responses = []
    failures = []

    def perform_handshake():
        try:
            with app.app_context():
                responses.append(_engineio_handshake(client, 'cleanup-race'))
        except BaseException as error:
            failures.append(error)

    worker = threading.Thread(target=perform_handshake)
    worker.start()
    assert validated.wait(1)
    if scheduler_failure:
        monkeypatch.setattr(
            socketio.server.eio,
            'start_background_task',
            lambda _target: (_ for _ in ()).throw(
                RuntimeError('simulated scheduler failure')
            ),
        )
    with app.app_context():
        user = db.session.get(User, user_id)
        user.is_locked = True
        db.session.commit()
        revoke_user_access(user_id, socketio)

    capacity = app.extensions['engineio_socket_capacity']
    assert capacity.count() == 1
    engineio_sid = capacity.sids_for_user(user_id)[0]
    assert capacity.is_terminal(engineio_sid) is True
    assert engineio_sid in socketio.server.eio.sockets

    resume.set()
    worker.join(3)

    assert not worker.is_alive()
    assert failures == []
    assert len(responses) == 1
    assert responses[0].status_code == 401
    assert socketio.server.eio.sockets == {}
    assert capacity.count() == 0


def test_engineio_final_admission_recheck_closes_restore_race(
    app,
    monkeypatch,
):
    import app as app_package
    from app import socketio
    from app.restore_service import _disconnect_sockets

    client, _user_id = _logged_in_http_client(
        app,
        'engineio_admission_restore_race',
    )
    lifecycle = app.extensions['runtime_lifecycle']
    original_accepting_work = lifecycle.accepting_work
    accepting_work = True
    monkeypatch.setattr(
        lifecycle,
        'accepting_work',
        lambda: accepting_work and original_accepting_work(),
    )
    original_admission = app_package._engineio_admission_user
    validated = threading.Event()
    resume = threading.Event()

    def pause_after_validation(flask_app, environ):
        admitted_user = original_admission(flask_app, environ)
        validated.set()
        assert resume.wait(2)
        return admitted_user

    monkeypatch.setattr(
        app_package,
        '_engineio_admission_user',
        pause_after_validation,
    )
    responses = []
    failures = []

    def perform_handshake():
        try:
            with app.app_context():
                responses.append(_engineio_handshake(client, 'restore-race'))
        except BaseException as error:
            failures.append(error)

    worker = threading.Thread(target=perform_handshake)
    worker.start()
    assert validated.wait(1)
    accepting_work = False
    _disconnect_sockets(socketio)
    resume.set()
    worker.join(3)

    assert not worker.is_alive()
    assert failures == []
    assert len(responses) == 1
    assert responses[0].status_code == 401
    assert socketio.server.eio.sockets == {}
    assert app.extensions['engineio_socket_capacity'].count() == 0


def test_engineio_final_recheck_closes_background_ldap_revocation_race(
    app,
    monkeypatch,
):
    import config
    import app as app_package
    import app.ldap_session as ldap_session
    from app import socketio
    from app.ldap_service import LDAPLookupRejected
    from app.models import AuthenticationSession, LDAPIdentity, db

    client, user_id = _logged_in_http_client(
        app,
        'engineio_admission_ldap_race',
    )
    with app.app_context():
        db.session.add(LDAPIdentity(
            user_id=user_id,
            provider='default',
            subject='stable-engineio-admission-id',
            directory_username='engineio_admission_ldap_race',
            distinguished_name=(
                'uid=engineio_admission_ldap_race,dc=example,dc=com'
            ),
        ))
        db.session.commit()
    with client.session_transaction() as browser_session:
        browser_session['_ldap_verified_at'] = int(time.time())

    monkeypatch.setattr(config, 'LDAP_ENABLED', True)
    monkeypatch.setattr(
        ldap_session,
        'revalidate_user',
        lambda _user: (_ for _ in ()).throw(
            LDAPLookupRejected('simulated directory removal')
        ),
    )
    original_admission = app_package._engineio_admission_user
    validated = threading.Event()
    resume = threading.Event()

    def pause_after_validation(flask_app, environ):
        admitted_user = original_admission(flask_app, environ)
        validated.set()
        assert resume.wait(2)
        return admitted_user

    monkeypatch.setattr(
        app_package,
        '_engineio_admission_user',
        pause_after_validation,
    )
    responses = []
    failures = []

    def perform_handshake():
        try:
            with app.app_context():
                responses.append(_engineio_handshake(client, 'ldap-race'))
        except BaseException as error:
            failures.append(error)

    worker = threading.Thread(target=perform_handshake)
    worker.start()
    assert validated.wait(1)
    ldap_session.revalidate_all_linked_users(app, socketio)
    with app.app_context():
        assert AuthenticationSession.query.filter_by(
            user_id=user_id,
        ).count() == 0
    resume.set()
    worker.join(3)

    assert not worker.is_alive()
    assert failures == []
    assert len(responses) == 1
    assert responses[0].status_code == 401
    assert socketio.server.eio.sockets == {}
    assert app.extensions['engineio_socket_capacity'].count() == 0


def test_failed_ldap_invalidation_fences_http_and_engineio_until_commit(
    app,
    monkeypatch,
):
    import config
    import app.ldap_session as ldap_session
    from app import socketio
    from app.ldap_service import LDAPLookupRejected
    from app.models import AuthenticationSession, User, db
    from flask import g

    _create_bootstrap_user(app, 'ldap_commit_admin')
    client, user_id = _logged_in_http_client(app, 'ldap_commit_fence')
    _mark_user_ldap_managed(app, user_id, 'ldap_commit_fence')
    with client.session_transaction() as browser_session:
        browser_session['_ldap_verified_at'] = int(time.time())
    replay_client = app.test_client()
    session_cookie_name = app.config['SESSION_COOKIE_NAME']
    replay_client.set_cookie(
        session_cookie_name,
        client.get_cookie(session_cookie_name).value,
    )

    monkeypatch.setattr(config, 'LDAP_ENABLED', True)
    monkeypatch.setattr(
        ldap_session,
        'revalidate_user',
        lambda _user: (_ for _ in ()).throw(
            LDAPLookupRejected('simulated directory removal')
        ),
    )
    revoked = []
    monkeypatch.setattr(
        ldap_session.user_lifecycle,
        'revoke_user_access',
        lambda owner_id, socketio_instance=None: revoked.append(owner_id),
    )

    real_commit = db.session.commit
    commit_attempts = 0

    def fail_first_two_invalidation_commits():
        nonlocal commit_attempts
        commit_attempts += 1
        if commit_attempts <= 2:
            raise RuntimeError('transient database failure')
        return real_commit()

    monkeypatch.setattr(
        db.session,
        'commit',
        fail_first_two_invalidation_commits,
    )

    ldap_session.revalidate_all_linked_users(app, socketio)

    with app.app_context():
        assert AuthenticationSession.query.filter_by(
            user_id=user_id,
        ).count() == 1
        assert db.session.get(User, user_id).auth_generation == 0
        assert ldap_session.ldap_revocation_pending(app, user_id) is True

    # Simulate a complete process restart: no in-memory pending set survives,
    # but the replacement app instance must discover the durable marker before
    # accepting the still-valid signed cookie.
    marker_directory = (
        app.extensions['ldap_revocation_fence']._marker_directory
    )
    app.extensions['ldap_revocation_fence'] = (
        ldap_session.LDAPRevocationFence(marker_directory)
    )
    assert ldap_session.ldap_revocation_pending(app, user_id) is True

    engineio_response = _engineio_handshake(client, 'ldap-commit-fence')

    assert engineio_response.status_code == 401
    assert socketio.server.eio.sockets == {}
    assert app.extensions['engineio_socket_capacity'].count() == 0
    assert ldap_session.ldap_revocation_pending(app, user_id) is True

    g.pop('_login_user', None)
    http_response = replay_client.get('/')

    assert http_response.status_code == 302
    assert '/login' in http_response.headers['Location']
    assert commit_attempts == 3
    assert revoked == [user_id, user_id, user_id]
    with app.app_context():
        assert AuthenticationSession.query.filter_by(
            user_id=user_id,
        ).count() == 0
        assert db.session.get(User, user_id).auth_generation == 1
        assert ldap_session.ldap_revocation_pending(app, user_id) is False
    assert ldap_session.LDAPRevocationFence(
        marker_directory,
    ).contains(user_id) is False


def test_engineio_safe_get_preprocessing_remains_compatible_with_csrf(app):
    from app import socketio

    client, user_id = _logged_in_http_client(app, 'engineio_csrf')
    app.config['WTF_CSRF_ENABLED'] = True

    response = _engineio_handshake(client, 'csrf-safe-get')
    engineio_sid = _engineio_sid(response)

    try:
        assert response.status_code == 200
        assert (
            app.extensions['engineio_socket_capacity'].owner(engineio_sid)
            == user_id
        )
        assert engineio_sid in socketio.server.eio.sockets
    finally:
        _close_engineio_socket(engineio_sid)

    assert app.extensions['engineio_socket_capacity'].count() == 0


def test_engineio_rejects_ldap_managed_session_when_ldap_is_disabled(app):
    from app import socketio

    _create_bootstrap_user(app, 'engineio_ldap_bootstrap')
    username = 'engineio_ldap_disabled'
    client, user_id = _logged_in_http_client(app, username)
    _mark_user_ldap_managed(app, user_id, username)

    response = _engineio_handshake(client, 'ldap-disabled')

    assert response.status_code == 401
    assert response.data == b'"Unauthorized"'
    assert socketio.server.eio.sockets == {}
    assert app.extensions['engineio_socket_capacity'].count() == 0


def test_engineio_rejects_failed_due_ldap_revalidation(
    app,
    monkeypatch,
):
    import config
    import app.ldap_session as ldap_session
    from app import socketio
    from app.ldap_service import LDAPUnavailable

    _create_bootstrap_user(app, 'engineio_ldap_failure_bootstrap')
    username = 'engineio_ldap_failure'
    client, user_id = _logged_in_http_client(app, username)
    _mark_user_ldap_managed(app, user_id, username)
    revalidated_users = []

    def fail_revalidation(user):
        revalidated_users.append(user.id)
        raise LDAPUnavailable('simulated directory outage')

    monkeypatch.setattr(config, 'LDAP_ENABLED', True)
    monkeypatch.setattr(ldap_session, 'revalidate_user', fail_revalidation)

    response = _engineio_handshake(client, 'ldap-revalidation-failure')

    assert response.status_code == 401
    assert response.data == b'"Unauthorized"'
    assert revalidated_users == [user_id]
    assert socketio.server.eio.sockets == {}
    assert app.extensions['engineio_socket_capacity'].count() == 0


def test_engineio_accepts_successfully_revalidated_ldap_session(
    app,
    monkeypatch,
):
    import config
    import app.ldap_session as ldap_session
    from app import socketio

    _create_bootstrap_user(app, 'engineio_ldap_success_bootstrap')
    username = 'engineio_ldap_success'
    client, user_id = _logged_in_http_client(app, username)
    _mark_user_ldap_managed(app, user_id, username)
    revalidated_users = []
    monkeypatch.setattr(config, 'LDAP_ENABLED', True)
    monkeypatch.setattr(
        ldap_session,
        'revalidate_user',
        lambda user: revalidated_users.append(user.id),
    )

    response = _engineio_handshake(client, 'ldap-revalidation-success')
    engineio_sid = _engineio_sid(response)

    try:
        assert response.status_code == 200
        assert revalidated_users == [user_id]
        assert (
            app.extensions['engineio_socket_capacity'].owner(engineio_sid)
            == user_id
        )
        assert engineio_sid in socketio.server.eio.sockets
    finally:
        _close_engineio_socket(engineio_sid)

    assert app.extensions['engineio_socket_capacity'].count() == 0


@pytest.mark.parametrize('state', ('expired', 'locked', 'recovery'))
def test_engineio_rejects_stale_or_restricted_browser_session(
    app,
    state,
    monkeypatch,
):
    import app as app_package
    from app import socketio
    from app.models import AuthenticationSession, User, db

    admission_errors = []
    monkeypatch.setattr(
        app_package,
        'log_error',
        lambda message, **details: admission_errors.append(
            (message, details)
        ),
    )
    client, user_id = _logged_in_http_client(app, f'engineio_{state}')
    with app.app_context():
        if state == 'locked':
            user = db.session.get(User, user_id)
            user.is_locked = True
        else:
            auth_session = AuthenticationSession.query.filter_by(
                user_id=user_id,
            ).one()
            if state == 'expired':
                auth_session.expires_at = datetime.now(timezone.utc) - timedelta(
                    seconds=1
                )
            else:
                auth_session.methods_json = json.dumps([
                    'password',
                    'recovery_code',
                ])
        db.session.commit()

    response = _engineio_handshake(client, state)

    assert response.status_code == 401
    assert socketio.server.eio.sockets == {}
    assert app.extensions['engineio_socket_capacity'].count() == 0
    assert admission_errors == []


def test_engineio_transport_and_socketio_namespace_keep_separate_lifecycles(app):
    from app import socket_events, socketio
    from app.models import SocketSession
    from app.socket_capacity import socket_capacity
    from app.socket_protocol import SOCKET_WIRE_REVISION

    # The session-scoped database template creates an earlier Socket.IO server.
    # Rebind decorators to this test app before exercising the real wire path.
    importlib.reload(socket_events)

    client, user_id = _logged_in_http_client(app, 'engineio_namespace')
    capacity = app.extensions['engineio_socket_capacity']
    response = _engineio_handshake(client, 'namespace')
    engineio_sid = _engineio_sid(response)

    try:
        assert response.status_code == 200
        assert capacity.owner(engineio_sid) == user_id
        assert socket_capacity.count_for_user(user_id) == 0

        namespace_response = client.post(
            f'/socket.io/?EIO=4&transport=polling&sid={engineio_sid}',
            base_url=ENGINEIO_BASE_URL,
            headers={
                'Content-Type': 'text/plain;charset=UTF-8',
                'Origin': ENGINEIO_BASE_URL,
            },
            data='40' + json.dumps(
                {'wire_revision': SOCKET_WIRE_REVISION},
                separators=(',', ':'),
            ),
        )

        assert namespace_response.status_code == 200
        assert namespace_response.data == b'OK'
        assert socket_capacity.count_for_user(user_id) == 1
        with app.app_context():
            socket_session = SocketSession.query.filter_by(
                user_id=user_id,
            ).one()
            assert socket_session.socket_sid != engineio_sid
    finally:
        _close_engineio_socket(engineio_sid)

    assert capacity.count() == 0
    assert socket_capacity.count_for_user(user_id) == 0
    with app.app_context():
        assert SocketSession.query.filter_by(user_id=user_id).count() == 0


def test_socketio_namespace_setup_is_linearized_before_user_revocation(
    app,
    monkeypatch,
):
    from app import socket_events, socketio
    from app.models import SocketSession, User, db
    from app.socket_capacity import socket_capacity
    from app.socket_protocol import SOCKET_WIRE_REVISION
    from app.user_lifecycle import revoke_user_access

    importlib.reload(socket_events)
    client, user_id = _logged_in_http_client(
        app,
        'engineio_namespace_revoke_race',
    )
    capacity = app.extensions['engineio_socket_capacity']
    response = _engineio_handshake(client, 'namespace-revoke-race')
    engineio_sid = _engineio_sid(response)
    original_admitted = socket_events._engineio_transport_is_admitted
    admitted = threading.Event()
    resume = threading.Event()
    terminalizing_transport = threading.Event()

    def pause_after_admission(user):
        result = original_admitted(user)
        assert result is True
        admitted.set()
        assert resume.wait(2)
        return result

    monkeypatch.setattr(
        socket_events,
        '_engineio_transport_is_admitted',
        pause_after_admission,
    )
    original_mark_terminal = capacity.mark_terminal

    def tracked_mark_terminal(transport_sid):
        terminalizing_transport.set()
        return original_mark_terminal(transport_sid)

    monkeypatch.setattr(capacity, 'mark_terminal', tracked_mark_terminal)
    namespace_responses = []
    namespace_failures = []

    def connect_namespace():
        try:
            namespace_responses.append(client.post(
                f'/socket.io/?EIO=4&transport=polling&sid={engineio_sid}',
                base_url=ENGINEIO_BASE_URL,
                headers={
                    'Content-Type': 'text/plain;charset=UTF-8',
                    'Origin': ENGINEIO_BASE_URL,
                },
                data='40' + json.dumps(
                    {'wire_revision': SOCKET_WIRE_REVISION},
                    separators=(',', ':'),
                ),
            ))
        except BaseException as error:
            namespace_failures.append(error)

    namespace_worker = threading.Thread(target=connect_namespace)
    namespace_worker.start()
    assert admitted.wait(1)

    with app.app_context():
        user = db.session.get(User, user_id)
        user.is_locked = True
        db.session.commit()

    revocation_results = []
    revocation_failures = []

    def revoke_user():
        try:
            with app.app_context():
                revocation_results.append(
                    revoke_user_access(user_id, socketio)
                )
        except BaseException as error:
            revocation_failures.append(error)

    revocation_worker = threading.Thread(target=revoke_user)
    revocation_worker.start()
    assert terminalizing_transport.wait(1)
    assert revocation_worker.is_alive()

    resume.set()
    namespace_worker.join(3)
    revocation_worker.join(3)

    assert not namespace_worker.is_alive()
    assert not revocation_worker.is_alive()
    assert namespace_failures == []
    assert revocation_failures == []
    assert len(namespace_responses) == 1
    assert namespace_responses[0].status_code == 200
    assert len(revocation_results) == 1
    assert engineio_sid not in socketio.server.eio.sockets
    assert capacity.count() == 0
    assert socket_capacity.count_for_user(user_id) == 0
    with app.app_context():
        assert SocketSession.query.filter_by(user_id=user_id).count() == 0


def test_rejected_namespace_drains_error_then_releases_engineio(app):
    from app import socket_events, socketio
    from app.models import SocketSession
    from app.socket_capacity import socket_capacity
    from app.socket_protocol import SOCKET_WIRE_REVISION

    importlib.reload(socket_events)
    client, user_id = _logged_in_http_client(
        app,
        'engineio_rejected_namespace',
    )
    capacity = app.extensions['engineio_socket_capacity']
    response = _engineio_handshake(client, 'rejected-namespace')
    engineio_sid = _engineio_sid(response)

    try:
        rejected = client.post(
            f'/socket.io/?EIO=4&transport=polling&sid={engineio_sid}',
            base_url=ENGINEIO_BASE_URL,
            headers={
                'Content-Type': 'text/plain;charset=UTF-8',
                'Origin': ENGINEIO_BASE_URL,
            },
            data='40' + json.dumps(
                {'wire_revision': SOCKET_WIRE_REVISION - 1},
                separators=(',', ':'),
            ),
        )

        assert rejected.status_code == 200
        assert rejected.data == b'OK'
        assert capacity.is_terminal(engineio_sid) is True

        # A racing retry on the same admitted transport must not bind after
        # it was terminalized by the first rejected namespace.
        retried = client.post(
            f'/socket.io/?EIO=4&transport=polling&sid={engineio_sid}',
            base_url=ENGINEIO_BASE_URL,
            headers={
                'Content-Type': 'text/plain;charset=UTF-8',
                'Origin': ENGINEIO_BASE_URL,
            },
            data='40' + json.dumps(
                {'wire_revision': SOCKET_WIRE_REVISION},
                separators=(',', ':'),
            ),
        )
        assert retried.status_code == 200
        assert retried.data == b'OK'
        assert socket_capacity.count_for_user(user_id) == 0

        error_response = client.get(
            f'/socket.io/?EIO=4&transport=polling&sid={engineio_sid}',
            base_url=ENGINEIO_BASE_URL,
            headers={'Origin': ENGINEIO_BASE_URL},
        )
        assert error_response.status_code == 200
        assert b'socket_protocol_mismatch' in error_response.data

        deadline = time.monotonic() + 2
        while (
            engineio_sid in socketio.server.eio.sockets
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)

        assert engineio_sid not in socketio.server.eio.sockets
        assert capacity.count() == 0
        assert capacity.is_terminal(engineio_sid) is False
        rejected_pong = client.post(
            f'/socket.io/?EIO=4&transport=polling&sid={engineio_sid}',
            base_url=ENGINEIO_BASE_URL,
            headers={
                'Content-Type': 'text/plain;charset=UTF-8',
                'Origin': ENGINEIO_BASE_URL,
            },
            data='3',
        )
        assert rejected_pong.status_code == 400
    finally:
        if engineio_sid in socketio.server.eio.sockets:
            _close_engineio_socket(engineio_sid)

    with app.app_context():
        assert SocketSession.query.filter_by(user_id=user_id).count() == 0


def test_rejected_namespace_cleanup_survives_namespace_disconnect(
    app,
    monkeypatch,
):
    from app import socket_events, socketio
    from app.socket_protocol import SOCKET_WIRE_REVISION

    importlib.reload(socket_events)
    client, _user_id = _logged_in_http_client(
        app,
        'engineio_namespace_auth_race',
    )
    capacity = app.extensions['engineio_socket_capacity']
    response = _engineio_handshake(client, 'namespace-auth-race')
    engineio_sid = _engineio_sid(response)
    monkeypatch.setattr(socket_events, 'load_user', lambda _user_id: None)

    try:
        rejected = client.post(
            f'/socket.io/?EIO=4&transport=polling&sid={engineio_sid}',
            base_url=ENGINEIO_BASE_URL,
            headers={
                'Content-Type': 'text/plain;charset=UTF-8',
                'Origin': ENGINEIO_BASE_URL,
            },
            data='40' + json.dumps(
                {'wire_revision': SOCKET_WIRE_REVISION},
                separators=(',', ':'),
            ),
        )

        assert rejected.status_code == 200
        assert rejected.data == b'OK'
        assert socketio.server.manager.sid_from_eio_sid(
            engineio_sid,
            '/',
        ) is None
        assert capacity.is_terminal(engineio_sid) is True

        deadline = time.monotonic() + 2
        while (
            engineio_sid in socketio.server.eio.sockets
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)

        assert engineio_sid not in socketio.server.eio.sockets
        assert capacity.count() == 0
        rejected_pong = client.post(
            f'/socket.io/?EIO=4&transport=polling&sid={engineio_sid}',
            base_url=ENGINEIO_BASE_URL,
            headers={
                'Content-Type': 'text/plain;charset=UTF-8',
                'Origin': ENGINEIO_BASE_URL,
            },
            data='3',
        )
        assert rejected_pong.status_code == 400
    finally:
        if engineio_sid in socketio.server.eio.sockets:
            _close_engineio_socket(engineio_sid)


def test_server_disconnect_retires_the_exact_engineio_transport(app):
    from app import socket_events, socketio
    from app.models import SocketSession
    from app.socket_capacity import socket_capacity
    from app.socket_protocol import SOCKET_WIRE_REVISION

    importlib.reload(socket_events)
    client, user_id = _logged_in_http_client(
        app,
        'engineio_forced_disconnect',
    )
    capacity = app.extensions['engineio_socket_capacity']
    response = _engineio_handshake(client, 'forced-disconnect')
    engineio_sid = _engineio_sid(response)

    try:
        connected = client.post(
            f'/socket.io/?EIO=4&transport=polling&sid={engineio_sid}',
            base_url=ENGINEIO_BASE_URL,
            headers={
                'Content-Type': 'text/plain;charset=UTF-8',
                'Origin': ENGINEIO_BASE_URL,
            },
            data='40' + json.dumps(
                {'wire_revision': SOCKET_WIRE_REVISION},
                separators=(',', ':'),
            ),
        )
        assert connected.status_code == 200

        namespace_sid = socketio.server.manager.sid_from_eio_sid(
            engineio_sid,
            '/',
        )
        assert namespace_sid is not None
        assert socket_capacity.count_for_user(user_id) == 1

        assert socket_events.disconnect_socket_transport(
            socketio.server,
            namespace_sid,
        ) is True
        assert capacity.is_terminal(engineio_sid) is True

        drained = client.get(
            f'/socket.io/?EIO=4&transport=polling&sid={engineio_sid}',
            base_url=ENGINEIO_BASE_URL,
            headers={'Origin': ENGINEIO_BASE_URL},
        )
        assert drained.status_code == 200
        assert b'41' in drained.data

        deadline = time.monotonic() + 2
        while (
            engineio_sid in socketio.server.eio.sockets
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)

        assert engineio_sid not in socketio.server.eio.sockets
        assert capacity.count() == 0
        assert socket_capacity.count_for_user(user_id) == 0
        rejected_pong = client.post(
            f'/socket.io/?EIO=4&transport=polling&sid={engineio_sid}',
            base_url=ENGINEIO_BASE_URL,
            headers={
                'Content-Type': 'text/plain;charset=UTF-8',
                'Origin': ENGINEIO_BASE_URL,
            },
            data='3',
        )
        assert rejected_pong.status_code == 400
    finally:
        if engineio_sid in socketio.server.eio.sockets:
            _close_engineio_socket(engineio_sid)

    with app.app_context():
        assert SocketSession.query.filter_by(user_id=user_id).count() == 0


def test_stale_socket_auth_drains_error_and_retires_transport(app):
    from app import socket_events, socketio
    from app.models import AuthenticationSession, SocketSession, db
    from app.socket_capacity import socket_capacity
    from app.socket_protocol import SOCKET_WIRE_REVISION

    importlib.reload(socket_events)
    client, user_id = _logged_in_http_client(app, 'engineio_stale_auth')
    capacity = app.extensions['engineio_socket_capacity']
    response = _engineio_handshake(client, 'stale-auth')
    engineio_sid = _engineio_sid(response)

    try:
        connected = client.post(
            f'/socket.io/?EIO=4&transport=polling&sid={engineio_sid}',
            base_url=ENGINEIO_BASE_URL,
            headers={
                'Content-Type': 'text/plain;charset=UTF-8',
                'Origin': ENGINEIO_BASE_URL,
            },
            data='40' + json.dumps(
                {'wire_revision': SOCKET_WIRE_REVISION},
                separators=(',', ':'),
            ),
        )
        assert connected.status_code == 200

        initial_events = client.get(
            f'/socket.io/?EIO=4&transport=polling&sid={engineio_sid}',
            base_url=ENGINEIO_BASE_URL,
            headers={'Origin': ENGINEIO_BASE_URL},
        )
        assert initial_events.status_code == 200
        assert b'connected' in initial_events.data

        with app.app_context():
            AuthenticationSession.query.filter_by(user_id=user_id).delete()
            db.session.commit()

        rejected = client.post(
            f'/socket.io/?EIO=4&transport=polling&sid={engineio_sid}',
            base_url=ENGINEIO_BASE_URL,
            headers={
                'Content-Type': 'text/plain;charset=UTF-8',
                'Origin': ENGINEIO_BASE_URL,
            },
            data='42' + json.dumps(
                ['cancel_directory_listing', {}],
                separators=(',', ':'),
            ),
        )
        assert rejected.status_code == 200

        drained = client.get(
            f'/socket.io/?EIO=4&transport=polling&sid={engineio_sid}',
            base_url=ENGINEIO_BASE_URL,
            headers={'Origin': ENGINEIO_BASE_URL},
        )
        assert drained.status_code == 200
        assert b'authentication_required' in drained.data
        assert b'41' in drained.data

        deadline = time.monotonic() + 2
        while (
            engineio_sid in socketio.server.eio.sockets
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)

        assert engineio_sid not in socketio.server.eio.sockets
        assert capacity.count() == 0
        assert socket_capacity.count_for_user(user_id) == 0
        rejected_pong = client.post(
            f'/socket.io/?EIO=4&transport=polling&sid={engineio_sid}',
            base_url=ENGINEIO_BASE_URL,
            headers={
                'Content-Type': 'text/plain;charset=UTF-8',
                'Origin': ENGINEIO_BASE_URL,
            },
            data='3',
        )
        assert rejected_pong.status_code == 400
    finally:
        if engineio_sid in socketio.server.eio.sockets:
            _close_engineio_socket(engineio_sid)

    with app.app_context():
        assert SocketSession.query.filter_by(user_id=user_id).count() == 0


def test_engineio_cleanup_scheduling_failure_releases_exact_capacity_slot():
    from types import SimpleNamespace

    from app import socket_events
    from app.socket_capacity import SocketCapacityRegistry

    capacity = SocketCapacityRegistry()
    assert capacity.reserve(7, 'engineio-exact', 10, 10) is True
    assert capacity.mark_terminal('engineio-exact') == 7

    closed = []
    engineio_socket = SimpleNamespace(
        close=lambda **kwargs: closed.append(kwargs),
    )

    class FailingEngineIOServer:
        sockets = {'engineio-exact': engineio_socket}
        reason = SimpleNamespace(SERVER_DISCONNECT='server disconnect')

        @staticmethod
        def start_background_task(_target):
            raise RuntimeError('simulated scheduler failure')

    engineio_server = FailingEngineIOServer()
    cleanup_context = (
        object(),
        object(),
        engineio_server,
        'engineio-exact',
        engineio_socket,
        capacity,
        7,
    )

    socket_events._schedule_engineio_cleanup(cleanup_context)

    assert closed == [{
        'wait': False,
        'abort': True,
        'reason': 'server disconnect',
    }]
    assert engineio_server.sockets == {}
    assert capacity.count() == 0


def test_engineio_handshake_exception_releases_exact_socket_and_capacity(
    app,
    monkeypatch,
):
    from app import socketio

    warm_client, _warm_user_id = _logged_in_http_client(
        app,
        'engineio_exception_warmup',
    )
    warm_response = _engineio_handshake(warm_client, 'exception-warmup')
    warm_sid = _engineio_sid(warm_response)
    _close_engineio_socket(warm_sid)

    client, user_id = _logged_in_http_client(
        app,
        'engineio_handshake_exception',
    )
    monkeypatch.setattr(
        socketio.server.eio,
        'start_background_task',
        lambda _target: (_ for _ in ()).throw(
            RuntimeError('simulated ping scheduler failure')
        ),
    )

    with pytest.raises(RuntimeError, match='ping scheduler failure'):
        _engineio_handshake(client, 'handshake-exception')

    capacity = app.extensions['engineio_socket_capacity']
    assert socketio.server.eio.sockets == {}
    assert capacity.count() == 0
    assert capacity.count_for_user(user_id) == 0


def test_engineio_cleanup_is_safe_after_a_natural_close_race():
    from types import SimpleNamespace

    from app import socket_events
    from app.socket_capacity import SocketCapacityRegistry

    capacity = SocketCapacityRegistry()
    assert capacity.reserve(8, 'engineio-race', 10, 10) is True
    assert capacity.mark_terminal('engineio-race') == 8
    engineio_socket = SimpleNamespace(
        close=lambda **_kwargs: pytest.fail('already-closed socket reused'),
    )

    class RacingEngineIOServer:
        sockets = {'engineio-race': engineio_socket}
        reason = SimpleNamespace(SERVER_DISCONNECT='server disconnect')

        def start_background_task(self, target):
            self.sockets.pop('engineio-race')
            capacity.release('engineio-race')
            target()

    engineio_server = RacingEngineIOServer()
    cleanup_context = (
        object(),
        object(),
        engineio_server,
        'engineio-race',
        engineio_socket,
        capacity,
        8,
    )

    socket_events._schedule_engineio_cleanup(cleanup_context, drain=False)

    assert engineio_server.sockets == {}
    assert capacity.count() == 0


def test_user_revocation_retires_pre_namespace_engineio_transport(app):
    from app import socketio
    from app.models import AuthenticationSession
    from app.socket_protocol import SOCKET_WIRE_REVISION
    from app.user_lifecycle import revoke_user_access

    client, user_id = _logged_in_http_client(
        app,
        'engineio_pre_namespace_revoke',
    )
    capacity = app.extensions['engineio_socket_capacity']
    response = _engineio_handshake(client, 'pre-namespace-revoke')
    engineio_sid = _engineio_sid(response)

    try:
        assert capacity.owner(engineio_sid) == user_id
        assert socketio.server.manager.sid_from_eio_sid(
            engineio_sid,
            '/',
        ) is None

        with app.app_context():
            # Background LDAP rejection retains the browser assurance row;
            # revocation itself must still invalidate an already-admitted EIO
            # transport before it can establish a Socket.IO namespace.
            assert AuthenticationSession.query.filter_by(
                user_id=user_id,
            ).count() == 1
            revoke_user_access(user_id, socketio)

        deadline = time.monotonic() + 2
        while (
            engineio_sid in socketio.server.eio.sockets
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)

        assert engineio_sid not in socketio.server.eio.sockets
        assert capacity.count() == 0
        rejected_namespace = client.post(
            f'/socket.io/?EIO=4&transport=polling&sid={engineio_sid}',
            base_url=ENGINEIO_BASE_URL,
            headers={
                'Content-Type': 'text/plain;charset=UTF-8',
                'Origin': ENGINEIO_BASE_URL,
            },
            data='40' + json.dumps(
                {'wire_revision': SOCKET_WIRE_REVISION},
                separators=(',', ':'),
            ),
        )
        assert rejected_namespace.status_code == 400
    finally:
        if engineio_sid in socketio.server.eio.sockets:
            _close_engineio_socket(engineio_sid)


def test_restore_disconnect_retires_pre_namespace_engineio_transport(app):
    from app import socketio
    from app.restore_service import _disconnect_sockets

    client, user_id = _logged_in_http_client(
        app,
        'engineio_pre_namespace_restore',
    )
    capacity = app.extensions['engineio_socket_capacity']
    response = _engineio_handshake(client, 'pre-namespace-restore')
    engineio_sid = _engineio_sid(response)

    try:
        assert capacity.owner(engineio_sid) == user_id
        assert socketio.server.manager.sid_from_eio_sid(
            engineio_sid,
            '/',
        ) is None

        _disconnect_sockets(socketio)

        deadline = time.monotonic() + 2
        while (
            engineio_sid in socketio.server.eio.sockets
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)

        assert engineio_sid not in socketio.server.eio.sockets
        assert capacity.count() == 0
        rejected_pong = client.post(
            f'/socket.io/?EIO=4&transport=polling&sid={engineio_sid}',
            base_url=ENGINEIO_BASE_URL,
            headers={
                'Content-Type': 'text/plain;charset=UTF-8',
                'Origin': ENGINEIO_BASE_URL,
            },
            data='3',
        )
        assert rejected_pong.status_code == 400
    finally:
        if engineio_sid in socketio.server.eio.sockets:
            _close_engineio_socket(engineio_sid)


def test_engineio_capacity_snapshots_exact_owned_transport_ids():
    from app.socket_capacity import SocketCapacityRegistry

    capacity = SocketCapacityRegistry()
    assert capacity.reserve(7, 'first', 10, 10) is True
    assert capacity.reserve(7, 'second', 10, 10) is True
    assert capacity.reserve(8, 'other', 10, 10) is True

    assert set(capacity.sids_for_user(7)) == {'first', 'second'}
    assert set(capacity.sids()) == {'first', 'second', 'other'}

    capacity.release('first')

    assert capacity.sids_for_user(7) == ('second',)
    assert set(capacity.sids()) == {'second', 'other'}


def test_engineio_admission_guard_only_blocks_the_same_transport():
    from app.socket_capacity import SocketCapacityRegistry

    capacity = SocketCapacityRegistry()
    assert capacity.reserve(7, 'guarded', 10, 10) is True
    assert capacity.reserve(8, 'independent', 10, 10) is True

    guard_entered = threading.Event()
    release_guard = threading.Event()

    def hold_guard():
        with capacity.admission_guard('guarded', 7) as admitted:
            assert admitted is True
            guard_entered.set()
            assert release_guard.wait(timeout=2)

    guard_thread = threading.Thread(target=hold_guard)
    guard_thread.start()
    assert guard_entered.wait(timeout=2)

    independent_result = []
    independent_done = threading.Event()

    def terminalize_independent():
        independent_result.append(capacity.mark_terminal('independent'))
        independent_done.set()

    independent_thread = threading.Thread(target=terminalize_independent)
    independent_thread.start()
    assert independent_done.wait(timeout=2)
    assert independent_result == [8]

    guarded_result = []
    guarded_done = threading.Event()

    def terminalize_guarded():
        guarded_result.append(capacity.mark_terminal('guarded'))
        guarded_done.set()

    guarded_thread = threading.Thread(target=terminalize_guarded)
    guarded_thread.start()
    assert guarded_done.wait(timeout=0.05) is False

    release_guard.set()
    guard_thread.join(timeout=2)
    guarded_thread.join(timeout=2)
    independent_thread.join(timeout=2)

    assert guard_thread.is_alive() is False
    assert guarded_thread.is_alive() is False
    assert independent_thread.is_alive() is False
    assert guarded_result == [7]


def test_engineio_capacity_applies_before_socketio_namespace_connect(
    app,
    monkeypatch,
):
    import config
    from app import socketio
    from app.socket_capacity import socket_capacity

    monkeypatch.setattr(config, 'MAX_SOCKET_CONNECTIONS', 2, raising=False)
    monkeypatch.setattr(
        config,
        'MAX_SOCKET_CONNECTIONS_PER_USER',
        1,
        raising=False,
    )
    first_client, first_user_id = _logged_in_http_client(
        app,
        'engineio_capacity_first',
    )
    second_client, second_user_id = _logged_in_http_client(
        app,
        'engineio_capacity_second',
    )
    third_client, _third_user_id = _logged_in_http_client(
        app,
        'engineio_capacity_third',
    )

    first_response = _engineio_handshake(first_client, 'capacity-first')
    first_sid = _engineio_sid(first_response)
    second_sid = None
    try:
        same_user_response = _engineio_handshake(
            first_client,
            'capacity-same-user',
        )
        second_response = _engineio_handshake(second_client, 'capacity-second')
        second_sid = _engineio_sid(second_response)
        over_global_response = _engineio_handshake(
            third_client,
            'capacity-global',
        )

        capacity = app.extensions['engineio_socket_capacity']
        assert first_response.status_code == 200
        assert same_user_response.status_code == 401
        assert second_response.status_code == 200
        assert over_global_response.status_code == 401
        assert capacity.count() == 2
        assert capacity.count_for_user(first_user_id) == 1
        assert capacity.count_for_user(second_user_id) == 1
        assert len(socketio.server.eio.sockets) == 2
        assert socket_capacity.count() == 0
    finally:
        _close_engineio_socket(first_sid)
        if second_sid is not None:
            _close_engineio_socket(second_sid)

    assert app.extensions['engineio_socket_capacity'].count() == 0


def test_missing_engineio_transport_is_only_allowed_for_testing_adapter(
    app,
    monkeypatch,
):
    from flask import request

    from app import socket_events, socketio

    missing_sid = 'missing-engineio-transport'
    assert missing_sid not in socketio.server.eio.sockets
    monkeypatch.setattr(
        socketio.server.manager,
        'eio_sid_from_sid',
        lambda _sid, _namespace: missing_sid,
    )
    user = type('User', (), {'id': 1})()

    with app.test_request_context('/socket.io'):
        request.sid = 'test-namespace-sid'
        app.config['TESTING'] = False
        assert socket_events._engineio_transport_is_admitted(user) is False

        app.config['TESTING'] = True
        assert socket_events._engineio_transport_is_admitted(user) is True


def test_synchronous_socketio_handler_never_queues_an_unbounded_task():
    """A saturated caller waits in its worker instead of creating another thread."""
    import socketio as python_socketio

    server = python_socketio.Server(
        async_mode='threading',
        async_handlers=False,
    )
    eio_sid = 'bounded-eio-sid'
    server.manager.connect(eio_sid, '/')
    observed_threads = []
    server.on('bounded_event', lambda _sid: observed_threads.append(
        threading.get_ident()
    ))
    server.start_background_task = lambda *_args, **_kwargs: pytest.fail(
        'async handler queue attempted to create a background task'
    )

    caller_thread = threading.get_ident()
    server._handle_event(eio_sid, '/', None, ['bounded_event'])

    assert observed_threads == [caller_thread]


@pytest.mark.parametrize('thread_count', ['0', '1', '7', '257', 'invalid'])
def test_gunicorn_threads_rejects_values_outside_the_safe_range(thread_count):
    """An unbounded gthread worker could exhaust process memory under load."""
    result = _config_probe(thread_count)

    assert result.returncode != 0
    assert 'CONFIGURATION ERROR: GUNICORN_THREADS must be between 8 and 256' in (
        result.stderr
    )


def test_gunicorn_threads_preserves_an_http_reserve_by_default():
    """Held WebSockets must leave request threads for login and transfers."""
    environment = os.environ.copy()
    environment.update({
        'DEBUG': 'True',
        'SECRET_KEY': 'threading-runtime-test-secret',
    })
    environment.pop('GUNICORN_THREADS', None)
    result = subprocess.run(
        [
            sys.executable,
            '-c',
            'import config; print(config.GUNICORN_THREADS)',
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[-1] == '64'


def test_socket_capacity_rejects_configuration_without_http_reserve():
    environment = os.environ.copy()
    environment.update({
        'DEBUG': 'True',
        'SECRET_KEY': 'threading-runtime-test-secret',
        'GUNICORN_THREADS': '16',
        'MAX_SOCKET_CONNECTIONS': '13',
    })

    result = subprocess.run(
        [sys.executable, '-c', 'import config'],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert 'at least 4 Gunicorn threads available for HTTP' in result.stderr


def test_playwright_uses_the_configured_e2e_port():
    """A shared workstation must not force browser tests onto port 4173."""
    environment = os.environ.copy()
    port = str(_free_loopback_port())
    environment['WEBSSH_E2E_PORT'] = port
    result = subprocess.run(
        [
            'node',
            '-e',
            "console.log(require('./playwright.config').use.baseURL)",
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f'http://127.0.0.1:{port}'


def test_e2e_runner_listens_on_the_configured_port():
    """The browser server and its base URL must select the same free port."""
    environment = os.environ.copy()
    port = _free_loopback_port()
    environment['WEBSSH_E2E_PORT'] = str(port)
    process = subprocess.Popen(
        [sys.executable, 'tests/e2e/run_app.py'],
        cwd=PROJECT_ROOT,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 15
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            try:
                with urllib.request.urlopen(
            f'http://127.0.0.1:{port}/login', timeout=1) as response:
                    assert response.status == 200
                    return
            except OSError:
                time.sleep(0.1)
        raise AssertionError('E2E runner did not listen on WEBSSH_E2E_PORT')
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)


def test_e2e_runner_rejects_unauthenticated_engineio_on_configured_origin():
    """CORS remains correct when transport admission rejects the browser."""
    environment = os.environ.copy()
    port = _free_loopback_port()
    environment['WEBSSH_E2E_PORT'] = str(port)
    base_url = f'http://127.0.0.1:{port}'
    process = subprocess.Popen(
        [sys.executable, 'tests/e2e/run_app.py'],
        cwd=PROJECT_ROOT,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 15
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            try:
                with urllib.request.urlopen(
                        f'{base_url}/login', timeout=1) as response:
                    if response.status == 200:
                        break
            except OSError:
                time.sleep(0.1)
        else:
            raise AssertionError('E2E runner did not start for Socket.IO test')

        handshake_url = (
            f'{base_url}/socket.io/?EIO=4&transport=polling&t=threading-test'
        )
        with pytest.raises(urllib.error.HTTPError) as rejected:
            urllib.request.urlopen(urllib.request.Request(
                handshake_url,
                headers={'Origin': base_url},
            ), timeout=5)
        assert rejected.value.code == 401
        assert (
            rejected.value.headers['Access-Control-Allow-Origin']
            == base_url
        )
        assert rejected.value.read() == b'"Unauthorized"'
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
