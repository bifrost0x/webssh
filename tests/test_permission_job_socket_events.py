"""Exercise permission jobs through authenticated Socket.IO and real DB assurance."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import pytest
from app import socketio, socket_events, socket_file_control
from app.auth import register_user
from app.file_sources import FileCapability, FileSourceUnavailable
from app.models import db, User, AuthenticationSession, SocketSession
from app.socket_protocol import SOCKET_WIRE_REVISION
from tests.test_permission_jobs import Remote, Runtime

@pytest.fixture
def socket_lab(app, monkeypatch):
    import config
    monkeypatch.setattr(config, 'SFTP_CHMOD_ENABLED', True)
    monkeypatch.setattr(config, 'RATELIMIT_ENABLED', False)
    socket_file_control._file_control_budgets.clear()
    user, error = register_user('permissions_operator', 'socket-password-123')
    assert error is None
    user_id = user.id
    http = app.test_client()
    assert http.post('/login', data={'username': 'permissions_operator', 'password': 'socket-password-123'}).status_code == 302
    client = socketio.test_client(app, flask_test_client=http, auth={'wire_revision': SOCKET_WIRE_REVISION})
    assert client.is_connected()
    client.get_received()
    sid = SocketSession.query.filter_by(user_id=user_id).first().socket_sid
    runtime = Runtime()
    monkeypatch.setitem(app.extensions, 'runtime_lifecycle', runtime)
    remote = Remote()

    @contextmanager
    def session(source, **kwargs):
        yield remote
    source = SimpleNamespace(source_id='sftp-session:owned', handle_id='bound', descriptor=SimpleNamespace(capabilities=[FileCapability.CHMOD]), backend=SimpleNamespace(permission_job_session=session))

    def resolve(source_id, owner):
        if source_id != source.source_id or str(owner) != str(user_id):
            raise FileSourceUnavailable()
        return source
    monkeypatch.setattr(socket_events.file_service.resolver, 'resolve', resolve)
    monkeypatch.setattr(socket_events, '_audit_file_source_operation', lambda *args, **kwargs: None)

    def prepare():
        client.emit('prepare_file_permissions', {'source_id': source.source_id, 'request_id': 'preview', 'paths': ['/tree'], 'recursive': True, 'file_mode': '644', 'directory_mode': '750'})
        messages = client.get_received()
        event = next((m for m in messages if m['name'] == 'file_permissions_job'), None)
        assert event is not None, messages
        return event['args'][0]['job_id']
    yield (app, client, runtime, remote, source, user_id, sid, prepare, http)
    if client.is_connected():
        client.disconnect()
    socket_file_control._file_control_budgets.clear()

@pytest.mark.parametrize('revocation', ['lock', 'auth_deleted', 'generation', 'expiry', 'ldap', 'maintenance', 'disconnect', 'source'])
def test_database_revocation_after_preview_admission_prevents_remote_writes(socket_lab, monkeypatch, revocation):
    app, client, runtime, remote, source, user_id, sid, prepare, http = socket_lab
    job = prepare()
    runtime.run()
    assert app.extensions['permission_jobs'].get(user_id, sid, source.source_id, job)['state'] == 'ready'
    client.emit('apply_file_permissions_job', {'source_id': source.source_id, 'request_id': 'apply', 'job_id': job})
    assert len(runtime.pending) == 1
    if revocation == 'lock':
        db.session.get(User, user_id).is_locked = True
    elif revocation == 'auth_deleted':
        AuthenticationSession.query.filter_by(user_id=user_id).delete()
    elif revocation == 'generation':
        db.session.get(User, user_id).auth_generation += 1
    elif revocation == 'expiry':
        AuthenticationSession.query.filter_by(user_id=user_id).first().expires_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=1)
    elif revocation == 'ldap':
        monkeypatch.setattr(User, 'is_ldap_managed', property(lambda self: True))
        from app import ldap_session
        monkeypatch.setattr(ldap_session, 'ldap_revocation_pending', lambda *_: True)
    elif revocation == 'maintenance':
        from app import maintenance_mode
        monkeypatch.setattr(maintenance_mode, 'is_active', lambda: True)
    elif revocation == 'disconnect':
        client.disconnect()
    elif revocation == 'source':
        source.handle_id = 'replacement'
    db.session.commit()
    runtime.run()
    status = app.extensions['permission_jobs'].get(user_id, sid, source.source_id, job)
    assert status['state'] in {'failed', 'cancelled'} and (not remote.writes)

def test_socket_job_roundtrip_and_immutable_apply_payload(socket_lab):
    app, client, runtime, remote, source, user_id, sid, prepare, http = socket_lab
    job = prepare()
    runtime.run()
    client.emit('apply_file_permissions_job', {'source_id': source.source_id, 'request_id': 'bad', 'job_id': job, 'file_mode': '777'})
    assert next((m for m in client.get_received() if m['name'] == 'error'))['args'][0]['code'] == 'INVALID_REQUEST'
    assert not runtime.pending and (not remote.writes)
    client.emit('get_file_permissions_job', {'source_id': source.source_id, 'request_id': 'get', 'job_id': job})
    status = next((m for m in client.get_received() if m['name'] == 'file_permissions_job'))['args'][0]
    assert status['state'] == 'ready' and status['request_id'] == 'get'
    client.emit('apply_file_permissions_job', {'source_id': source.source_id, 'request_id': 'apply', 'job_id': job})
    runtime.run()
    assert len(remote.writes) == 4
    client.emit('apply_file_permissions_job', {'source_id': source.source_id, 'request_id': 'repeat', 'job_id': job})
    assert next((m for m in client.get_received() if m['name'] == 'error'))['args'][0]['code'] == 'CONFLICT'

@pytest.mark.parametrize('event', ['get_file_permissions_job', 'apply_file_permissions_job', 'cancel_file_permissions_job'])
def test_other_authenticated_socket_cannot_access_job(socket_lab, event):
    app, client, runtime, remote, source, user_id, sid, prepare, http = socket_lab
    job = prepare()
    runtime.run()
    other = socketio.test_client(app, flask_test_client=http, auth={'wire_revision': SOCKET_WIRE_REVISION})
    assert other.is_connected()
    other.get_received()
    try:
        other.emit(event, {'source_id': source.source_id, 'request_id': 'foreign', 'job_id': job})
        assert next((m for m in other.get_received() if m['name'] == 'error'))['args'][0]['code'] == 'NOT_FOUND'
        assert not remote.writes and (not runtime.pending)
    finally:
        other.disconnect()

def test_disabled_feature_rejects_job_even_with_backend_capability(socket_lab, monkeypatch):
    import config
    app, client, runtime, remote, source, user_id, sid, prepare, http = socket_lab
    monkeypatch.setattr(config, 'SFTP_CHMOD_ENABLED', False)
    client.emit('prepare_file_permissions', {'source_id': source.source_id, 'request_id': 'disabled', 'paths': ['/tree'], 'recursive': True, 'file_mode': '644', 'directory_mode': '755'})
    assert next((m for m in client.get_received() if m['name'] == 'error'))['args'][0]['code'] == 'UNSUPPORTED_OPERATION'
    assert not runtime.pending and (not remote.writes)

def test_authenticated_job_runs_in_a_real_worker_request_context(socket_lab,monkeypatch):
    import time
    from app.runtime_lifecycle import RuntimeLifecycle
    app,client,_,remote,source,user_id,sid,prepare,http=socket_lab
    runtime=RuntimeLifecycle(1)
    monkeypatch.setitem(app.extensions,'runtime_lifecycle',runtime)
    try:
        job=prepare()
        manager=app.extensions['permission_jobs']
        assert manager._jobs[job].handle.join(5)
        assert manager.get(user_id,sid,source.source_id,job)['state']=='ready'
        client.emit('apply_file_permissions_job',{'source_id':source.source_id,'request_id':'thread-apply','job_id':job})
        assert manager._jobs[job].handle.join(5)
        status=manager.get(user_id,sid,source.source_id,job)
        assert status['state']=='completed' and status['changed']==4
    finally:
        runtime.begin_shutdown(3)
