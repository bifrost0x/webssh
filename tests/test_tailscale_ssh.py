from types import SimpleNamespace

from sqlalchemy import inspect, text


def _set_policy(monkeypatch, *, enabled=True, users=(), targets=(), remote_users=()):
    import config

    monkeypatch.setattr(config, 'TAILSCALE_SSH_ENABLED', enabled)
    monkeypatch.setattr(config, 'TAILSCALE_SSH_ALLOWED_WEBSSH_USERS', frozenset(users))
    monkeypatch.setattr(config, 'TAILSCALE_SSH_ALLOWED_TARGETS', frozenset(targets))
    monkeypatch.setattr(config, 'TAILSCALE_SSH_ALLOWED_REMOTE_USERS', frozenset(remote_users))


def test_tailscale_ssh_disabled_by_default(monkeypatch):
    from app.tailscale_ssh import validate_tailscale_ssh_access

    _set_policy(monkeypatch, enabled=False)
    user = SimpleNamespace(username='admin', is_admin=True)

    assert validate_tailscale_ssh_access(user, 'tiny-server', 'root') == (
        'Tailscale SSH is not enabled for this account'
    )


def test_tailscale_ssh_allows_admin_when_enabled(monkeypatch):
    from app.tailscale_ssh import validate_tailscale_ssh_access

    _set_policy(monkeypatch)
    user = SimpleNamespace(username='admin', is_admin=True)

    assert validate_tailscale_ssh_access(user, 'tiny-server', 'root') is None


def test_tailscale_ssh_allows_explicit_webssh_user(monkeypatch):
    from app.tailscale_ssh import validate_tailscale_ssh_access

    _set_policy(monkeypatch, users={'operator'})
    user = SimpleNamespace(username='operator', is_admin=False)

    assert validate_tailscale_ssh_access(user, 'tiny-server', 'root') is None


def test_tailscale_ssh_rejects_unlisted_webssh_user(monkeypatch):
    from app.tailscale_ssh import validate_tailscale_ssh_access

    _set_policy(monkeypatch, users={'operator'})
    user = SimpleNamespace(username='viewer', is_admin=False)

    assert validate_tailscale_ssh_access(user, 'tiny-server', 'root') == (
        'Tailscale SSH is not enabled for this account'
    )


def test_tailscale_ssh_enforces_target_and_remote_user_allowlists(monkeypatch):
    from app.tailscale_ssh import validate_tailscale_ssh_access

    _set_policy(monkeypatch, targets={'tiny-server'}, remote_users={'root'})
    user = SimpleNamespace(username='admin', is_admin=True)

    assert validate_tailscale_ssh_access(user, 'TINY-SERVER', 'root') is None
    assert validate_tailscale_ssh_access(user, 'other-server', 'root') == (
        'Tailscale SSH target is not allowed'
    )
    assert validate_tailscale_ssh_access(user, 'tiny-server', 'ubuntu') == (
        'Tailscale SSH remote username is not allowed'
    )


def test_backend_rejects_unauthorized_tailscale_connection(app, monkeypatch):
    from flask import request
    from app import ssh_manager
    from app.auth import register_socket_session, register_user
    from app.models import db
    import app.socket_events as socket_events

    _set_policy(monkeypatch)
    with app.app_context():
        admin, error = register_user('policyadmin', 'password-123')
        assert error is None and admin.is_admin
        viewer, error = register_user('policyviewer', 'password-123')
        assert error is None and not viewer.is_admin
        register_socket_session(viewer.id, 'unauthorized-socket')
        db.session.commit()

    def fail_create_ssh_connection(**kwargs):
        raise AssertionError('SSH manager must not be called')

    monkeypatch.setattr(ssh_manager, 'create_ssh_connection', fail_create_ssh_connection)
    emitted = []
    audits = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, payload=None, **kwargs: emitted.append((event, payload)),
    )
    monkeypatch.setattr(
        socket_events,
        'log_tailscale_ssh_usage',
        lambda *args, **kwargs: audits.append((args, kwargs)),
    )

    with app.test_request_context('/socket.io', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        request.sid = 'unauthorized-socket'
        socket_events.handle_ssh_connect({
            'host': 'tiny-server',
            'port': 22,
            'username': 'root',
            'auth_type': 'tailscale',
        })

    assert emitted == [(
        'ssh_error',
        {'error': 'Tailscale SSH is not enabled for this account', 'client_request_id': None},
    )]
    assert audits[0][1] == {
        'allowed': False,
        'error': 'Tailscale SSH is not enabled for this account',
    }


def test_tailscale_option_is_visible_only_to_authorized_users(app, client, monkeypatch):
    from app.auth import register_user

    with app.app_context():
        user, error = register_user('visibleadmin', 'password-123')
        assert error is None and user.is_admin

    response = client.post('/login', data={
        'username': 'visibleadmin',
        'password': 'password-123',
    })
    assert response.status_code == 302

    _set_policy(monkeypatch, enabled=False)
    assert b'<option value="tailscale"' not in client.get('/').data

    _set_policy(monkeypatch, enabled=True)
    assert b'<option value="tailscale"' in client.get('/').data


def test_auth_type_migration_backfills_persistent_key_sessions(app):
    from app.models import db, ensure_ssh_session_columns

    with app.app_context():
        db.session.execute(text('DROP TABLE ssh_sessions'))
        db.session.execute(text(
            'CREATE TABLE ssh_sessions ('
            'id INTEGER PRIMARY KEY, session_id VARCHAR(36) NOT NULL, '
            'user_id INTEGER NOT NULL, host VARCHAR(256) NOT NULL, '
            'port INTEGER NOT NULL, username VARCHAR(128) NOT NULL, '
            'connected BOOLEAN DEFAULT 1, created_at DATETIME, last_activity DATETIME, '
            'is_persistent BOOLEAN NOT NULL DEFAULT 0, key_id VARCHAR(64), '
            'tmux_session_name VARCHAR(256), display_name VARCHAR(128))'
        ))
        db.session.execute(text(
            "INSERT INTO ssh_sessions "
            "(id, session_id, user_id, host, port, username, is_persistent, key_id) "
            "VALUES (1, 'password-session', 1, 'one', 22, 'root', 1, NULL), "
            "(2, 'key-session', 1, 'two', 22, 'root', 1, 'key-1')"
        ))
        db.session.commit()

        ensure_ssh_session_columns()

        columns = {column['name'] for column in inspect(db.engine).get_columns('ssh_sessions')}
        rows = db.session.execute(text(
            'SELECT session_id, auth_type FROM ssh_sessions ORDER BY id'
        )).all()

        assert 'auth_type' in columns
        assert rows == [('password-session', 'password'), ('key-session', 'key')]


def test_tailscale_tmux_reconnect_survives_webssh_restart(app, monkeypatch):
    import config
    from flask import request
    from app import ssh_manager
    from app.auth import register_socket_session, register_user
    from app.models import db, SSHSession
    import app.socket_events as socket_events

    _set_policy(monkeypatch)

    with app.app_context():
        user, error = register_user('tailscaleadmin', 'socket-password-123')
        assert error is None
        user_id = user.id
        db.session.add(SSHSession(
            session_id='old-tailscale-session',
            user_id=user_id,
            host='tiny-server',
            port=22,
            username='root',
            connected=False,
            is_persistent=True,
            auth_type='tailscale',
            tmux_session_name='webssh_tiny_root',
            display_name='Tiny root',
        ))
        register_socket_session(user_id, 'restart-socket')
        db.session.commit()

    calls = []

    def fake_create_ssh_connection(**kwargs):
        calls.append(kwargs)
        return 'new-tailscale-session', None

    def fake_get_session(session_id):
        assert session_id == 'new-tailscale-session'
        return {
            'connected': True,
            'auth_type': 'tailscale',
            'tmux_session_name': 'webssh_tiny_root',
        }

    monkeypatch.setattr(ssh_manager, 'create_ssh_connection', fake_create_ssh_connection)
    monkeypatch.setattr(ssh_manager, 'get_session', fake_get_session)
    monkeypatch.setattr(config, 'TMUX_ENABLED', True)
    emitted = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, payload=None, **kwargs: emitted.append((event, payload)),
    )

    with app.test_request_context('/socket.io', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        request.sid = 'restart-socket'
        socket_events.restore_user_sessions(user_id)
        persistent = next(
            payload for event, payload in emitted
            if event == 'persistent_session_available'
        )
        assert persistent['auth_type'] == 'tailscale'

        emitted.clear()
        socket_events.handle_ssh_connect({
            'host': persistent['host'],
            'port': persistent['port'],
            'username': persistent['username'],
            'auth_type': persistent['auth_type'],
            'use_tmux': True,
            'reconnect_tmux_name': persistent['tmux_session_name'],
            'display_name': persistent['display_name'],
        })

    connected = next(
        payload for event, payload in emitted
        if event == 'ssh_connected'
    )
    assert connected['auth_type'] == 'tailscale'
    assert calls[0]['auth_type'] == 'tailscale'
    assert calls[0]['reconnect_tmux_name'] == 'webssh_tiny_root'

    with app.app_context():
        restored = SSHSession.query.filter_by(session_id='new-tailscale-session').one()
        assert restored.auth_type == 'tailscale'
        assert SSHSession.query.filter_by(session_id='old-tailscale-session').first() is None


def test_socket_rejects_invalid_startup_commands_before_connect(app, monkeypatch):
    from flask import request
    from app import ssh_manager
    from app.auth import register_socket_session, register_user
    from app.models import db
    import app.socket_events as socket_events

    with app.app_context():
        user, error = register_user('startupinvalid', 'socket-password-123')
        assert error is None
        register_socket_session(user.id, 'startup-invalid-socket')
        db.session.commit()

    def fail_create_ssh_connection(**_kwargs):
        raise AssertionError('SSH manager must not be called')

    monkeypatch.setattr(ssh_manager, 'create_ssh_connection', fail_create_ssh_connection)
    emitted = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, payload=None, **kwargs: emitted.append((event, payload)),
    )

    with app.test_request_context('/socket.io', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        request.sid = 'startup-invalid-socket'
        socket_events.handle_ssh_connect({
            'host': 'tiny-server',
            'port': 22,
            'username': 'root',
            'password': 'secret',
            'startup_commands': ['echo unsafe'],
        })

    assert emitted == [(
        'ssh_error',
        {'error': 'Startup commands must be text', 'client_request_id': None},
    )]


def test_tmux_reconnect_does_not_pass_startup_commands_to_ssh_manager(app, monkeypatch):
    import config
    from flask import request
    from app import ssh_manager
    from app.auth import register_socket_session, register_user
    from app.models import db, SSHSession
    import app.socket_events as socket_events

    with app.app_context():
        user, error = register_user('startupreconnect', 'socket-password-123')
        assert error is None
        db.session.add(SSHSession(
            session_id='existing-startup-session',
            user_id=user.id,
            host='tiny-server',
            port=22,
            username='root',
            connected=False,
            is_persistent=True,
            tmux_session_name='webssh_tiny_root',
        ))
        register_socket_session(user.id, 'startup-reconnect-socket')
        db.session.commit()

    calls = []
    monkeypatch.setattr(
        ssh_manager,
        'create_ssh_connection',
        lambda **kwargs: (calls.append(kwargs) or ('new-startup-session', None)),
    )
    monkeypatch.setattr(
        ssh_manager,
        'get_session',
        lambda _session_id: {'tmux_session_name': 'webssh_tiny_root'},
    )
    monkeypatch.setattr(config, 'TMUX_ENABLED', True)
    monkeypatch.setattr(socket_events, 'emit', lambda *_args, **_kwargs: None)

    with app.test_request_context('/socket.io', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        request.sid = 'startup-reconnect-socket'
        socket_events.handle_ssh_connect({
            'host': 'tiny-server',
            'port': 22,
            'username': 'root',
            'password': 'secret',
            'use_tmux': True,
            'reconnect_tmux_name': 'webssh_tiny_root',
            'startup_commands': 'echo should-not-run',
        })

    assert calls[0]['startup_commands'] == ''


def test_socket_rejects_invalid_startup_commands_without_dns_lookup(app, monkeypatch):
    import config
    from flask import request
    from app.auth import register_socket_session, register_user
    from app.models import db
    import app.socket_events as socket_events

    with app.app_context():
        user, error = register_user('startupnodns', 'socket-password-123')
        assert error is None
        register_socket_session(user.id, 'startup-no-dns-socket')
        db.session.commit()

    emitted = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, payload=None, **kwargs: emitted.append((event, payload)),
    )
    monkeypatch.setattr(config, 'BLOCK_INTERNAL_SSH', True)
    monkeypatch.setattr(
        socket_events.socket,
        'getaddrinfo',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError('DNS must not be queried')
        ),
    )

    with app.test_request_context('/socket.io', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        request.sid = 'startup-no-dns-socket'
        socket_events.handle_ssh_connect({
            'host': 'tiny-server',
            'port': 22,
            'username': 'root',
            'password': 'secret',
            'startup_commands': ['echo unsafe'],
        })

    assert emitted == [(
        'ssh_error',
        {'error': 'Startup commands must be text', 'client_request_id': None},
    )]


def test_socket_save_profile_stores_normalized_startup_commands(app, monkeypatch):
    from flask import request
    from app.auth import register_socket_session, register_user
    from app.models import db
    import app.socket_events as socket_events

    with app.app_context():
        user, error = register_user('startupprofile', 'socket-password-123')
        assert error is None
        register_socket_session(user.id, 'startup-profile-socket')
        db.session.commit()

    emitted = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, payload=None, **kwargs: emitted.append((event, payload)),
    )

    with app.test_request_context('/socket.io'):
        request.sid = 'startup-profile-socket'
        socket_events.handle_save_profile({
            'name': 'Production',
            'host': 'example.com',
            'port': 22,
            'username': 'deploy',
            'auth_type': 'password',
            'startup_commands': 'echo connected\r\nwhoami',
        })

    saved_profile = next(payload['profile'] for event, payload in emitted if event == 'profile_saved')
    assert saved_profile['startup_commands'] == 'echo connected\nwhoami'


def test_socket_save_profile_rejects_invalid_startup_commands(app, monkeypatch):
    from flask import request
    from app import profile_manager
    from app.auth import register_socket_session, register_user
    from app.models import db
    import app.socket_events as socket_events

    with app.app_context():
        user, error = register_user('startupprofilebad', 'socket-password-123')
        assert error is None
        user_id = user.id
        register_socket_session(user_id, 'startup-profile-invalid-socket')
        db.session.commit()

    emitted = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, payload=None, **kwargs: emitted.append((event, payload)),
    )

    with app.test_request_context('/socket.io'):
        request.sid = 'startup-profile-invalid-socket'
        socket_events.handle_save_profile({
            'name': 'Production',
            'host': 'example.com',
            'port': 22,
            'username': 'deploy',
            'auth_type': 'password',
            'startup_commands': ['echo unsafe'],
        })

    assert emitted == [('error', {'error': 'Startup commands must be text'})]
    with app.app_context():
        assert profile_manager.load_profiles(user_id) == []
