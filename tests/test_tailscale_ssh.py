from types import SimpleNamespace
import ipaddress
import socket
import struct
import threading

import pytest
from sqlalchemy import inspect, text


pytestmark = pytest.mark.usefixtures('direct_socket_authentication')


def _set_policy(
    monkeypatch,
    *,
    enabled=True,
    users=(),
    targets=('tiny-server',),
    remote_users=(),
    interface='tailscale0',
):
    import config
    from app import tailscale_ssh
    from app.network_policy import ResolvedTarget

    monkeypatch.setattr(config, 'TAILSCALE_SSH_ENABLED', enabled)
    monkeypatch.setattr(config, 'TAILSCALE_SSH_ALLOWED_WEBSSH_USERS', frozenset(users))
    monkeypatch.setattr(config, 'TAILSCALE_SSH_ALLOWED_TARGETS', frozenset(targets))
    monkeypatch.setattr(config, 'TAILSCALE_SSH_ALLOWED_REMOTE_USERS', frozenset(remote_users))
    monkeypatch.setattr(config, 'TAILSCALE_SSH_INTERFACE', interface)
    monkeypatch.setattr(
        tailscale_ssh,
        'target_uses_tailscale_route',
        lambda _address: True,
    )

    def resolve(host, port, allow_internal=False, *, target_validator=None):
        target = ResolvedTarget(host, port, '100.64.0.10', 2)
        if target_validator is not None and not target_validator(target):
            raise ValueError('target rejected')
        return target

    monkeypatch.setattr(tailscale_ssh, 'resolve_allowed_target', resolve)


def test_tailscale_ssh_disabled_by_default(monkeypatch):
    from app.tailscale_ssh import validate_tailscale_ssh_access

    _set_policy(monkeypatch, enabled=False)
    user = SimpleNamespace(username='admin', is_admin=True)

    assert validate_tailscale_ssh_access(user, 'tiny-server', 'root') == (
        'Tailscale SSH is not enabled for this account'
    )


@pytest.mark.parametrize(
    ('raw_target', 'expected'),
    (
        ('Tiny-Server.', ('tiny-server', 22)),
        ('tiny-server:2200', ('tiny-server', 2200)),
        ('100.64.0.10', ('100.64.0.10', 22)),
        ('100.64.0.10:2200', ('100.64.0.10', 2200)),
        ('fd7a:115c:a1e0::10', ('fd7a:115c:a1e0::10', 22)),
        ('[fd7a:115c:a1e0::10]:2200', ('fd7a:115c:a1e0::10', 2200)),
    ),
)
def test_tailscale_target_parser_canonicalizes_supported_forms(
    raw_target,
    expected,
):
    import config

    assert config.parse_tailscale_ssh_target(raw_target) == expected


@pytest.mark.parametrize(
    'raw_target',
    (
        '',
        'bad target',
        '*',
        'tiny-server:0',
        'tiny-server:65536',
        'tiny-server:not-a-port',
        '[fd7a:115c:a1e0::10',
        '[fd7a:115c:a1e0::10]extra',
        '[100.64.0.10]:22',
        'fe80::1%tailscale0',
    ),
)
def test_tailscale_target_parser_rejects_malformed_entries(raw_target):
    import config

    with pytest.raises(ValueError):
        config.parse_tailscale_ssh_target(raw_target)


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


def test_tailscale_ssh_requires_an_explicit_exact_host_and_port(monkeypatch):
    from app.tailscale_ssh import validate_tailscale_ssh_access

    user = SimpleNamespace(username='admin', is_admin=True)
    _set_policy(monkeypatch, targets=())
    assert validate_tailscale_ssh_access(user, 'tiny-server', 'root') == (
        'Tailscale SSH target is not allowed'
    )

    _set_policy(monkeypatch, targets={'tiny-server:2200'})
    assert validate_tailscale_ssh_access(
        user, 'tiny-server', 'root', port=2200
    ) is None
    assert validate_tailscale_ssh_access(
        user, 'tiny-server', 'root', port=22
    ) == 'Tailscale SSH target is not allowed'


def test_linux_route_lookup_uses_policy_routing_result(monkeypatch):
    from app import tailscale_ssh

    destination = ipaddress.ip_address('100.64.1.2')
    sent = []
    route_attributes = tailscale_ssh._netlink_attribute(
        tailscale_ssh._RTA_OIF,
        struct.pack('=I', 52),
    )
    # A table-52 result models standard Tailscale policy routing; the output
    # interface, not the main routing table, is the authorization boundary.
    route_payload = tailscale_ssh._RTMSG.pack(
        socket.AF_INET, 32, 0, 0, 52, 0, 0, 0, 0
    ) + route_attributes
    response = tailscale_ssh._NLMSG_HEADER.pack(
        tailscale_ssh._NLMSG_HEADER.size + len(route_payload),
        tailscale_ssh._RTM_NEWROUTE,
        0,
        1,
        0,
    ) + route_payload

    class FakeRouteSocket:
        def settimeout(self, value):
            assert value == 1.0

        def bind(self, address):
            assert address == (0, 0)

        def sendto(self, message, address):
            sent.append(message)
            assert address == (0, 0)

        def recv(self, _size):
            return response

        def close(self):
            pass

    monkeypatch.setattr(
        tailscale_ssh.socket,
        'if_indextoname',
        lambda index: 'tailscale0' if index == 52 else 'eth0',
    )

    assert tailscale_ssh._route_interface_for_ip(
        destination.compressed,
        socket_factory=lambda *_args: FakeRouteSocket(),
    ) == 'tailscale0'
    assert destination.packed in sent[0]


def test_tailscale_ssh_fails_closed_for_invalid_configured_target(monkeypatch):
    from app.tailscale_ssh import validate_tailscale_ssh_access

    _set_policy(monkeypatch, targets={'bad target'})
    user = SimpleNamespace(id=7, username='admin', is_admin=True)

    assert validate_tailscale_ssh_access(user, 'tiny-server', 'root') == (
        'Tailscale SSH target is not allowed'
    )


def test_tailscale_ssh_ignores_malformed_target_beside_valid_sibling(
    monkeypatch,
):
    from app.tailscale_ssh import validate_tailscale_ssh_access

    _set_policy(
        monkeypatch,
        targets={'bad target', 'tiny-server:2200'},
    )
    user = SimpleNamespace(id=7, username='admin', is_admin=True)

    assert validate_tailscale_ssh_access(
        user,
        'tiny-server',
        'root',
        port=2200,
    ) is None
    assert validate_tailscale_ssh_access(
        user,
        'tiny-server',
        'root',
        port=22,
    ) == 'Tailscale SSH target is not allowed'


def test_tailscale_ssh_fails_closed_when_interface_is_empty(monkeypatch):
    from app.tailscale_ssh import validate_tailscale_ssh_access

    _set_policy(monkeypatch, interface='')
    user = SimpleNamespace(id=7, username='admin', is_admin=True)

    assert validate_tailscale_ssh_access(user, 'tiny-server', 'root') == (
        'Tailscale SSH target is not allowed'
    )


def test_tailscale_authorization_is_bound_to_exact_user_target_and_remote_user(
    monkeypatch,
):
    from app.tailscale_ssh import authorize_tailscale_ssh_access

    _set_policy(monkeypatch, targets={'tiny-server'}, remote_users={'root'})
    user = SimpleNamespace(id=7, username='admin', is_admin=True)

    authorization, error = authorize_tailscale_ssh_access(
        user,
        'TINY-SERVER.',
        'root',
    )

    assert error is None
    assert authorization.matches(7, 'tiny-server', 22, 'root')
    assert not authorization.matches(8, 'tiny-server', 22, 'root')
    assert not authorization.matches(7, 'other-server', 22, 'root')
    assert not authorization.matches(7, 'tiny-server', 2200, 'root')
    assert not authorization.matches(7, 'tiny-server', 22, 'ubuntu')


def test_profile_launch_authorization_tracks_target_policy(monkeypatch):
    from app.tailscale_ssh import profile_is_authorized_for_launch

    _set_policy(
        monkeypatch,
        enabled=True,
        targets=('tiny-server',),
        remote_users=('root',),
    )
    user = SimpleNamespace(is_admin=True, username='admin')

    assert profile_is_authorized_for_launch(user, {
        'auth_type': 'tailscale',
        'host': 'tiny-server',
        'username': 'root',
    }) is True
    assert profile_is_authorized_for_launch(user, {
        'auth_type': 'tailscale',
        'host': 'other-server',
        'username': 'root',
    }) is False
    assert profile_is_authorized_for_launch(user, {
        'auth_type': 'key',
        'host': 'other-server',
        'username': 'root',
    }) is True


def test_profile_list_includes_transient_tailscale_authorization(
        monkeypatch):
    import app.socket_events as socket_events

    _set_policy(
        monkeypatch,
        enabled=True,
        targets=('tiny-server',),
        remote_users=('root',),
    )
    user = SimpleNamespace(id=7, is_admin=True, username='admin')
    stored_profiles = [
        {
            'id': 'allowed',
            'auth_type': 'tailscale',
            'host': 'tiny-server',
            'username': 'root',
            'tailscale_authorized': False,
        },
        {
            'id': 'denied',
            'auth_type': 'tailscale',
            'host': 'other-server',
            'username': 'root',
            'tailscale_authorized': True,
        },
        {
            'id': 'key',
            'auth_type': 'key',
            'host': 'server.example',
            'username': 'root',
            'tailscale_authorized': True,
        },
    ]
    monkeypatch.setattr(
        socket_events.profile_manager,
        'load_profiles',
        lambda _user_id: stored_profiles,
    )
    emitted = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, payload: emitted.append((event, payload)),
    )

    socket_events.handle_list_profiles.__wrapped__(current_user=user)

    profiles = emitted[0][1]['profiles']
    assert profiles[0]['tailscale_authorized'] is True
    assert profiles[1]['tailscale_authorized'] is False
    assert 'tailscale_authorized' not in profiles[2]
    assert stored_profiles[0]['tailscale_authorized'] is False
    assert stored_profiles[1]['tailscale_authorized'] is True
    assert stored_profiles[2]['tailscale_authorized'] is True


def test_backend_rejects_unauthorized_tailscale_connection(app, monkeypatch):
    from flask import request
    from app import ssh_manager
    from app.auth import register_socket_session, register_user
    from app.models import db
    import app.socket_events as socket_events

    _set_policy(monkeypatch)
    with app.app_context():
        admin, error = register_user('policyadmin', 'password-123')
        assert error is None
        admin.is_admin = True
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
        assert error is None
        user.is_admin = True
        from app.models import db
        db.session.commit()

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
        user.is_admin = True
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
            'use_tmux': True,
            'tmux_session_name': 'webssh_tiny_root',
            'tmux_reconnect': True,
        }

    monkeypatch.setattr(ssh_manager, 'create_ssh_connection', fake_create_ssh_connection)
    monkeypatch.setattr(ssh_manager, 'get_session', fake_get_session)
    monkeypatch.setattr(config, 'TMUX_ENABLED', True)
    emitted = []
    emit_targets = []
    connected_event = threading.Event()

    def record_emit(event, payload=None, **kwargs):
        emitted.append((event, payload))
        emit_targets.append((event, kwargs))
        if event == 'ssh_connected':
            connected_event.set()

    monkeypatch.setattr(
        socket_events,
        'emit',
        record_emit,
    )

    with app.test_request_context('/socket.io', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        request.sid = 'restart-socket'
        socket_events.restore_user_sessions(user_id, request.sid)
        persistent = next(
            payload for event, payload in emitted
            if event == 'persistent_session_available'
        )
        assert persistent['auth_type'] == 'tailscale'
        persistent_target = next(
            kwargs for event, kwargs in emit_targets
            if event == 'persistent_session_available'
        )
        assert persistent_target == {'to': 'restart-socket'}

        emitted.clear()
        emit_targets.clear()
        socket_events.handle_ssh_connect({
            'host': persistent['host'],
            'port': persistent['port'],
            'username': persistent['username'],
            'auth_type': persistent['auth_type'],
            'use_tmux': True,
            'reconnect_tmux_name': persistent['tmux_session_name'],
            'display_name': persistent['display_name'],
        })

    assert connected_event.wait(2)
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
    import app.network_policy as network_policy
    monkeypatch.setattr(
        network_policy.socket,
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
