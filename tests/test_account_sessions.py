"""Personal login inventory and exact browser revocation boundaries."""
from datetime import datetime, timedelta, timezone
import pytest


@pytest.fixture(autouse=True)
def separate_browser_contexts(app, monkeypatch):
    from flask.testing import FlaskClient

    class BrowserClient(FlaskClient):
        def open(self, *args, **kwargs):
            with app.app_context():
                return super().open(*args, **kwargs)

    monkeypatch.setattr(app, 'test_client_class', BrowserClient)


def _login(app, username='session_owner', *, create=False, remember=False):
    from app.auth import register_user
    if create:
        with app.app_context():
            user, error = register_user(username, 'password123')
            assert error is None
    client = app.test_client()
    assert client.post('/login', data={
        'username': username, 'password': 'password123', 'remember': 'on' if remember else '',
    }).status_code == 302
    return client


def test_inventory_is_owned_active_and_does_not_expose_auth_identifiers(app):
    from app.models import AuthenticationSession, db
    current = _login(app, create=True)
    _login(app)
    _login(app, 'another_owner', create=True)
    _login(app)
    with app.app_context():
        expired = AuthenticationSession.query.order_by(AuthenticationSession.id.desc()).first()
        expired.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=1)
        db.session.commit()
        secrets = [row.session_hash for row in AuthenticationSession.query.all()]
    response = current.get('/api/account/sessions')
    assert response.status_code == 200
    rows = response.json['sessions']
    assert len(rows) == 2
    assert sum(row['current'] for row in rows) == 1
    assert all(row['methods'] == ['password'] for row in rows)
    assert all(set(row) == {'handle', 'current', 'methods', 'started_at', 'expires_at'} for row in rows)
    assert all(secret not in response.text for secret in secrets)
    assert response.headers['Cache-Control'] == 'no-store'


def test_revoke_selected_blocks_remember_cookie_but_preserves_current_and_others(app):
    current = _login(app, create=True)
    selected = _login(app, remember=True)
    untouched = _login(app)
    outsider = _login(app, 'another_owner', create=True)
    handle = next(row['handle'] for row in selected.get('/api/account/sessions').json['sessions'] if row['current'])
    assert outsider.post('/api/account/sessions/revoke', json={'session': handle}).status_code == 404
    assert current.post('/api/account/sessions/revoke', json={'session': handle}).status_code == 200
    assert selected.get_cookie('remember_token') is not None
    selected.delete_cookie('session', domain='localhost')
    assert selected.get('/api/account/sessions').status_code in (302, 401)
    assert current.get('/api/account/sessions').status_code == 200
    assert untouched.get('/api/account/sessions').status_code == 200
    assert outsider.get('/api/account/sessions').status_code == 200


def test_revoke_others_keeps_current_and_requires_csrf(app):
    current = _login(app, create=True)
    other = _login(app)
    handle = next(row['handle'] for row in current.get('/api/account/sessions').json['sessions'] if row['current'])
    assert current.post('/api/account/sessions/revoke', json={'session': handle}).status_code == 409
    app.config['WTF_CSRF_ENABLED'] = True
    assert current.post('/api/account/sessions/revoke', json={'others': True}).status_code == 400
    app.config['WTF_CSRF_ENABLED'] = False
    assert other.get('/api/account/sessions').status_code == 200
    assert current.post('/api/account/sessions/revoke', json={'others': True}).json['revoked'] == 1
    assert other.get('/api/account/sessions').status_code in (302, 401)
    assert current.get('/api/account/sessions').status_code == 200


def test_recovery_session_cannot_read_or_revoke_logins(app):
    from app.models import AuthenticationSession, db
    current = _login(app, create=True)
    with app.app_context():
        row = AuthenticationSession.query.first()
        row.methods_json = '["password","recovery_code"]'
        db.session.commit()
    assert current.get('/api/account/sessions').status_code == 403
    assert current.post('/api/account/sessions/revoke', json={'others': True}).status_code == 403


def test_revocation_disconnects_only_selected_socket_and_cancels_stream(app, monkeypatch):
    import importlib
    from app import socketio, socket_events, ssh_manager
    from app.models import SocketSession
    from app.socket_protocol import SOCKET_WIRE_REVISION
    from app.transfer_routes import transfer_manager
    from app.file_sources import SourceHoldSet
    importlib.reload(socket_events)
    current = _login(app, create=True)
    selected = _login(app)
    untouched = _login(app, 'another_owner', create=True)
    sockets = []
    record = None
    try:
        for client in (current, selected, untouched):
            with app.app_context():
                socket = socketio.test_client(app, flask_test_client=client, auth={'wire_revision':SOCKET_WIRE_REVISION})
                assert socket.is_connected()
                sockets.append(socket)
        with app.app_context():
            bindings = SocketSession.query.order_by(SocketSession.id).all()
            assert all(row.authentication_session_id for row in bindings)
            selected_sid = bindings[1].socket_sid
            selected_user = bindings[1].user_id
        record = transfer_manager.create(user_id=selected_user, source_id='ssh:synthetic', direction='download',
            owner_sid=selected_sid, source_holds=SourceHoldSet(('ssh:synthetic',)), metadata={})
        transfer_manager.consume_token(record.token, user_id=selected_user)
        handle = next(row['handle'] for row in selected.get('/api/account/sessions').json['sessions'] if row['current'])
        closed = []
        monkeypatch.setattr(ssh_manager, 'close_session', lambda *args, **kwargs: closed.append(args))
        assert current.post('/api/account/sessions/revoke', json={'session':handle}).status_code == 200
        assert record.cancel_event.is_set()
        assert sockets[0].is_connected()
        assert not sockets[1].is_connected()
        assert sockets[2].is_connected()
        assert closed == []
        with app.app_context():
            assert not socketio.test_client(app, flask_test_client=selected,
                auth={'wire_revision':SOCKET_WIRE_REVISION}).is_connected()
    finally:
        if record is not None:
            transfer_manager.finish_cancelled(record.transfer_id, record.user_id)
            record.release_source_holds()
            record.request_done_event.set()
        for socket in sockets:
            if socket.is_connected():
                with app.app_context():
                    socket.disconnect()


def test_ongoing_http_operation_cancellation_observes_revoked_login(app):
    from app.models import AuthenticationSession
    from app.account_sessions import login_cancellation_check
    current = _login(app, create=True)
    selected = _login(app)
    with app.app_context():
        auth = AuthenticationSession.query.order_by(AuthenticationSession.id.desc()).first()
        cancelled = login_cancellation_check(auth)
        assert cancelled() is False
    assert current.post('/api/account/sessions/revoke', json={'others':True}).status_code == 200
    with app.app_context():
        assert cancelled() is True


def test_non_ascii_session_handle_is_rejected(app):
    current = _login(app, create=True)
    assert current.post('/api/account/sessions/revoke', json={'session':'ä' * 64}).status_code == 400


def test_transfer_creation_cannot_resume_after_its_login_is_revoked(app):
    from flask import session
    from app.transfer_manager import TransferManager
    from app.file_sources import SourceHoldSet
    current = _login(app, create=True)
    selected = _login(app)
    with selected.session_transaction() as stored:
        captured = dict(stored)
    assert current.post('/api/account/sessions/revoke', json={'others':True}).status_code == 200
    with app.test_request_context():
        session.update(captured)
        with pytest.raises(ValueError, match='authentication'):
            TransferManager().create(user_id='1', source_id='ssh:synthetic', direction='download',
                owner_sid='revoked-socket', source_holds=SourceHoldSet(('ssh:synthetic',)), metadata={})


def test_resource_cleanup_failure_reports_revocation_and_continues(app, monkeypatch):
    from app.models import AuthenticationSession, SocketSession, db
    from app import socket_events
    from app.transfer_routes import transfer_manager
    current = _login(app, create=True)
    selected = _login(app)
    with app.app_context():
        auth = AuthenticationSession.query.order_by(AuthenticationSession.id.desc()).first()
        db.session.add(SocketSession(user_id=auth.user_id, socket_sid='selected-socket', authentication_session_id=auth.id))
        db.session.commit()
    def fail(*_args):
        raise RuntimeError('synthetic failure')
    disconnected = []
    monkeypatch.setattr(transfer_manager, 'cancel_all_for_socket', fail)
    monkeypatch.setattr(socket_events, 'disconnect_socket_transport', lambda _server, sid, **kwargs: disconnected.append(sid))
    response = current.post('/api/account/sessions/revoke', json={'others':True})
    assert response.status_code == 200
    assert response.json == {'revoked':1, 'cleanup_incomplete':True}
    assert disconnected == ['selected-socket']
    assert selected.get('/api/account/sessions').status_code == 302


def test_existing_socket_table_is_migrated_without_assigning_a_login(app):
    from sqlalchemy import text, inspect
    from app.models import db, ensure_security_columns
    _login(app, create=True)
    with app.app_context():
        db.session.execute(text('ALTER TABLE socket_sessions DROP COLUMN authentication_session_id'))
        db.session.execute(text("INSERT INTO socket_sessions (user_id, socket_sid) VALUES (1, 'legacy-socket')"))
        db.session.commit()
        ensure_security_columns()
        assert 'authentication_session_id' in {column['name'] for column in inspect(db.engine).get_columns('socket_sessions')}
        assert db.session.execute(text("SELECT authentication_session_id FROM socket_sessions WHERE socket_sid='legacy-socket'")).scalar() is None


def test_revocation_waits_for_admitted_socket_and_disconnects_it(app, monkeypatch):
    import importlib
    import threading
    from app import socket_events, socketio
    from app.socket_protocol import SOCKET_WIRE_REVISION
    importlib.reload(socket_events)
    current = _login(app, create=True)
    selected = _login(app)
    admitted, release, revoked = threading.Event(), threading.Event(), threading.Event()
    registered = socket_events.register_socket_session
    result = {}
    def pause_registration(*args, **kwargs):
        row = registered(*args, **kwargs)
        admitted.set()
        assert release.wait(5)
        return row
    monkeypatch.setattr(socket_events, 'register_socket_session', pause_registration)
    def connect():
        with app.app_context():
            result['socket'] = socketio.test_client(app, flask_test_client=selected, auth={'wire_revision':SOCKET_WIRE_REVISION})
    def revoke():
        result['response'] = current.post('/api/account/sessions/revoke', json={'others':True})
        revoked.set()
    connector = threading.Thread(target=connect)
    revoker = threading.Thread(target=revoke)
    try:
        connector.start()
        assert admitted.wait(5)
        revoker.start()
        assert not revoked.wait(.1)
        release.set()
        connector.join(5)
        revoker.join(5)
        assert revoked.is_set()
        assert result['response'].status_code == 200
        assert not result['socket'].is_connected()
    finally:
        release.set()
        connector.join(5)
        if revoker.ident is not None:
            revoker.join(5)


def test_discovery_revocation_is_bound_to_selected_login(app, monkeypatch):
    from app import discovery_routes
    from app.models import AuthenticationSession
    current = _login(app, create=True)
    _login(app)
    with app.app_context():
        auths = AuthenticationSession.query.order_by(AuthenticationSession.id).all()
        scans = [discovery_routes.Scan(row.user_id, '192.0.2.0/30', [], [22], set(), row.id, row.session_hash) for row in auths]
    monkeypatch.setattr(discovery_routes, '_SCANS', {scan.id:scan for scan in scans})
    assert current.post('/api/account/sessions/revoke', json={'others':True}).status_code == 200
    assert not scans[0].cancel_event.is_set()
    assert scans[1].cancel_event.is_set()
    assert scans[1].revoked


def test_discovery_cancellation_does_not_cross_reused_authentication_ids(app, monkeypatch):
    from app import discovery_routes
    scans = [discovery_routes.Scan(user, '192.0.2.0/30', [], [22], set(), 7, digest)
        for user, digest in ((1, 'old'), (2, 'other'), (1, 'new'))]
    monkeypatch.setattr(discovery_routes, '_SCANS', {scan.id:scan for scan in scans})
    discovery_routes.cancel_for_authentication_sessions([(1, 7, 'new')])
    assert [scan.revoked for scan in scans] == [False, False, True]


def test_new_login_waits_until_old_login_resource_cleanup_finishes(app, monkeypatch):
    import threading
    current = _login(app, create=True)
    _login(app)
    cleaning, release, finished = threading.Event(), threading.Event(), threading.Event()
    original = app.extensions['credentials'].revoke_session
    results = {}
    def pause_cleanup(auth_id):
        cleaning.set()
        assert release.wait(5)
        return original(auth_id)
    monkeypatch.setattr(app.extensions['credentials'], 'revoke_session', pause_cleanup)
    def revoke():
        results['revoke'] = current.post('/api/account/sessions/revoke', json={'others':True})
    def login():
        results['login'] = _login(app)
        finished.set()
    revoker, logger = threading.Thread(target=revoke), threading.Thread(target=login)
    try:
        revoker.start()
        assert cleaning.wait(5)
        logger.start()
        assert not finished.wait(.1)
        release.set()
        revoker.join(5)
        logger.join(5)
        assert finished.is_set()
        assert results['revoke'].status_code == 200
        assert results['login'].get('/api/account/sessions').status_code == 200
    finally:
        release.set()
        revoker.join(5)
        if logger.ident is not None:
            logger.join(5)


def test_discovery_cannot_register_after_login_revoked_during_validation(app, monkeypatch):
    import config
    from app import discovery_routes
    current = _login(app, create=True)
    selected = _login(app)
    monkeypatch.setattr(config, 'HOST_DISCOVERY_ENABLED', True)
    monkeypatch.setattr(discovery_routes, '_SCANS', {})
    original = discovery_routes.Scan.__init__
    def revoke_during_construction(scan, *args, **kwargs):
        original(scan, *args, **kwargs)
        assert current.post('/api/account/sessions/revoke', json={'others':True}).status_code == 200
    monkeypatch.setattr(discovery_routes.Scan, '__init__', revoke_during_construction)
    response = selected.post('/api/discovery/scans', json={'network':'192.0.2.0/30'})
    assert response.status_code == 401
    assert discovery_routes._SCANS == {}
