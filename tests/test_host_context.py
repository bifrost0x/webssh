"""Private profile context has stable identity and optimistic concurrency."""

import pytest

from app.host_context import ContextError, read_context, write_context


def test_connection_binding_requires_owned_exact_profile_identity(app):
    from app.host_context import bind_profile
    owner, profile = _profile(app)
    other, _ = _profile(app, 'binding-other')
    with app.app_context():
        assert bind_profile(owner, None, 'example.com', 22, 'deploy', None) is None
        assert bind_profile(owner, profile, 'example.com', 22, 'deploy', None) == profile
        for args in [(other, profile, 'example.com', 22, 'deploy', None),
                     (owner, profile, 'other.example.com', 22, 'deploy', None),
                     (owner, profile, 'example.com', 2222, 'deploy', None),
                     (owner, profile, 'example.com', 22, 'root', None),
                     (owner, profile, 'example.com', 22, 'deploy', 'jump')]:
            with pytest.raises(ContextError):
                bind_profile(*args)


def test_optional_reconnect_context_detaches_deleted_or_changed_profile(app):
    from app.host_context import bind_profile
    from app.profile_manager import delete_profile
    owner, profile = _profile(app)
    with app.app_context():
        assert bind_profile(owner, profile, 'example.com', 22, 'deploy', None, optional=True) == profile
        assert bind_profile(owner, profile, 'changed.example.com', 22, 'deploy', None, optional=True) is None
        assert delete_profile(owner, profile)[0]
        assert bind_profile(owner, profile, 'example.com', 22, 'deploy', None, optional=True) is None
        with pytest.raises(ContextError):
            bind_profile(owner, profile, 'example.com', 22, 'deploy', None)


def test_ssh_profile_migration_preserves_legacy_rows(app):
    from app.models import db, ensure_ssh_session_columns
    from sqlalchemy import text, inspect
    with app.app_context():
        db.session.execute(text('DROP TABLE ssh_sessions'))
        db.session.execute(text('CREATE TABLE ssh_sessions (id INTEGER PRIMARY KEY, session_id VARCHAR(36))'))
        db.session.execute(text("INSERT INTO ssh_sessions (session_id) VALUES ('legacy')"))
        db.session.commit()
        ensure_ssh_session_columns()
        ensure_ssh_session_columns()
        assert 'profile_id' in {column['name'] for column in inspect(db.engine).get_columns('ssh_sessions')}
        assert db.session.execute(text('SELECT session_id, profile_id FROM ssh_sessions')).one() == ('legacy', None)


def _profile(app, username='context-owner'):
    from app.models import User, db
    from app.profile_manager import upsert_profile
    with app.app_context():
        user = User(username=username, password_hash='unused')
        db.session.add(user)
        db.session.commit()
        profile, error = upsert_profile(user.id, {
            'name': 'Host', 'host': 'example.com', 'username': 'deploy', 'auth_type': 'password',
        })
        assert error is None
        return user.id, profile['id']


def _payload(**updates):
    return {'notes': 'Private notes', 'directories': ['/var/log'], 'command_sets': [], **updates}


def test_context_revision_and_profile_isolation(app):
    from app.profile_manager import upsert_profile
    owner, profile = _profile(app)
    with app.app_context():
        second, error = upsert_profile(owner, {
            'name': 'Other', 'host': 'example.com', 'username': 'deploy', 'auth_type': 'password',
        })
        assert error is None
        original = read_context(owner, profile)
        saved = write_context(owner, profile, _payload(), original['revision'])
        assert saved['notes'] == 'Private notes'
        assert read_context(owner, second['id'])['notes'] == ''
        with pytest.raises(ContextError) as conflict:
            write_context(owner, profile, _payload(notes='stale'), original['revision'])
        assert conflict.value.code == 'conflict'
        assert read_context(owner, profile) == saved


def test_other_user_and_deleted_profiles_are_inaccessible(app):
    from app.profile_manager import delete_profile
    owner, profile = _profile(app)
    other, _ = _profile(app, 'other-context-owner')
    with app.app_context():
        with pytest.raises(ContextError) as missing:
            read_context(other, profile)
        assert missing.value.code == 'not_found'
        write_context(owner, profile, _payload(), 0)
        assert delete_profile(owner, profile)[0]
        with pytest.raises(ContextError):
            read_context(owner, profile)


@pytest.mark.parametrize('patch', [
    {'notes': 'x' * 100001}, {'directories': ['relative']},
    {'directories': ['/tmp\nwhoami']}, {'directories': ['/x'] * 21},
    {'command_sets': ['not-owned']}, {'notes': {'nested': 'no'}},
])
def test_limits_and_owned_command_set_references(app, patch):
    owner, profile = _profile(app)
    with app.app_context():
        with pytest.raises(ContextError):
            write_context(owner, profile, _payload(**patch), 0)
        assert read_context(owner, profile)['revision'] == 0


def test_context_route_ownership_and_conflicts(app, client):
    from app.auth import register_user
    from app.profile_manager import upsert_profile
    with app.app_context():
        user, error = register_user('context_http', 'password123')
        assert error is None
        profile, error = upsert_profile(user.id, {
            'name': 'HTTP', 'host': 'example.com', 'username': 'deploy', 'auth_type': 'password',
        })
        assert error is None
    _, other_profile = _profile(app, 'context-other-http')
    url = f"/api/profiles/{profile['id']}/context"
    assert client.get(url).status_code in (302, 401)
    client.post('/login', data={'username': 'context_http', 'password': 'password123'})
    assert client.get(f'/api/profiles/{other_profile}/context').status_code == 404
    assert client.get(url).json['revision'] == 0
    assert client.put(url, json={'revision': 0, **_payload()}).status_code == 200
    assert client.put(url, json={'revision': 0, **_payload(notes='stale')}).status_code == 409
    assert client.get(url).json['notes'] == 'Private notes'


def test_context_store_quota_preserves_previous_revision(app, monkeypatch):
    import app.host_context as context
    owner, profile = _profile(app)
    with app.app_context():
        saved = write_context(owner, profile, _payload(), 0)
        monkeypatch.setattr(context, 'MAX_STORE_BYTES', 500)
        with pytest.raises(ContextError) as error:
            write_context(owner, profile, _payload(notes='a' * 600), 1)
        assert error.value.code == 'quota'
        assert read_context(owner, profile) == saved


def test_context_501st_profile_remains_readable(app, monkeypatch):
    import json
    import app.host_context as context
    from app.models import User, db
    owner, profile = _profile(app)
    with app.app_context():
        path = db.session.get(User, owner).get_data_dir() / 'host_context.json'
        hosts = {f'profile-{index}': {**_payload(), 'revision': 1} for index in range(500)}
        path.write_text(json.dumps({'version': 1, 'hosts': hosts}), encoding='utf-8')
        monkeypatch.setattr(context, '_owned_profiles', lambda *_args: set(hosts) | {profile})
        saved = write_context(owner, profile, _payload(), 0)
        assert read_context(owner, profile) == saved
        assert len(json.loads(path.read_text(encoding='utf-8'))['hosts']) == 501


@pytest.mark.usefixtures('direct_socket_authentication')
def test_socket_connect_rejects_mismatched_profile_before_transport(app, monkeypatch):
    from flask import request
    from app import socket_events
    from app.auth import register_socket_session
    from app.models import db
    owner, profile = _profile(app)
    with app.app_context():
        register_socket_session(owner, 'context-binding-socket')
        db.session.commit()
    emitted = []
    monkeypatch.setattr(socket_events, 'emit', lambda event, data=None, **kwargs: emitted.append((event, data)))
    monkeypatch.setattr(socket_events.ssh_manager, 'create_ssh_connection', lambda **kwargs: pytest.fail('transport must not start'))
    with app.test_request_context('/socket.io'):
        request.sid = 'context-binding-socket'
        socket_events.handle_ssh_connect({'host': 'different.example.com', 'port': 22,
            'username': 'deploy', 'password': 'test-only', 'profile_id': profile})
    assert any(event == 'ssh_error' and 'Saved host no longer matches' in value['error'] for event, value in emitted)


def test_live_and_offline_restore_keep_explicit_profile_identity(app, monkeypatch):
    from app import socket_events
    from app.models import SSHSession, db
    import config
    owner, profile = _profile(app)
    with app.app_context():
        for session_id, connected in [('context-live', True), ('context-offline', False)]:
            db.session.add(SSHSession(session_id=session_id, user_id=owner,
                host='example.com', port=22, username='deploy', connected=connected,
                is_persistent=True, tmux_session_name=session_id, profile_id=profile))
        db.session.commit()
    runtime = {'connected': True, 'profile_id': profile}
    monkeypatch.setattr(config, 'TMUX_ENABLED', True)
    monkeypatch.setattr(socket_events.ssh_manager, 'get_session', lambda session_id: runtime if session_id == 'context-live' else None)
    monkeypatch.setattr(socket_events.ssh_manager, 'get_output_snapshot', lambda _id: ('', 0))
    monkeypatch.setattr(socket_events, '_public_file_source', lambda *_args: None)
    emitted = []
    monkeypatch.setattr(socket_events, 'emit', lambda event, data=None, **kwargs: emitted.append((event, data)))
    with app.test_request_context('/socket.io'):
        socket_events.restore_user_sessions(owner, 'restoring-socket')
    identities = {value['session_id']: value.get('profile_id') for _event, value in emitted}
    assert identities == {'context-live': profile, 'context-offline': profile}


def test_context_file_is_covered_by_backup_snapshot(app, tmp_path):
    from app.backup_manager import _stage_source
    from app.models import User, db
    owner, profile = _profile(app)
    with app.app_context():
        write_context(owner, profile, _payload(), 0)
        data_dir = db.session.get(User, owner).get_data_dir()
        manifest = _stage_source(data_dir, tmp_path)
        assert any(item.path == 'host_context.json' for item in manifest.files)
        assert (tmp_path / 'host_context.json').read_bytes() == (data_dir / 'host_context.json').read_bytes()
