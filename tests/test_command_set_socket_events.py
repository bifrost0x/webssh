"""Socket and cross-storage tests for named command sets."""
import json
from contextlib import contextmanager

import pytest

from app.storage_errors import StorageCorruptionError


pytestmark = pytest.mark.usefixtures('direct_socket_authentication')


def create_socket_user(app, username):
    from app.auth import register_socket_session, register_user
    from app.models import db

    with app.app_context():
        user, error = register_user(username, 'socket-password-123')
        assert error is None
        register_socket_session(user.id, f'{username}-socket')
        db.session.commit()
        return user.id, f'{username}-socket'


def call_socket_handler(app, monkeypatch, handler, sid, payload=None):
    from flask import request
    import app.socket_events as socket_events

    emitted = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, data=None, **kwargs: emitted.append((event, data)),
    )
    with app.test_request_context('/socket.io'):
        request.sid = sid
        if payload is None:
            acknowledgement = handler()
        else:
            acknowledgement = handler(payload)
    return acknowledgement, emitted


def test_command_set_crud_socket_events_return_structured_acknowledgements(app, monkeypatch):
    import app.socket_events as socket_events

    _user_id, sid = create_socket_user(app, 'command_set_crud')
    saved, emitted = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_save_command_set,
        sid,
        {'name': 'Bootstrap', 'steps': [{'type': 'inline', 'command': 'uptime'}]},
    )
    assert saved['success'] is True
    assert saved['command_set']['name'] == 'Bootstrap'
    assert any(event == 'command_sets_list' for event, _payload in emitted)

    listed, _emitted = call_socket_handler(
        app, monkeypatch, socket_events.handle_list_command_sets, sid
    )
    assert listed['success'] is True
    assert listed['command_sets'][0]['id'] == saved['command_set']['id']
    assert listed['command_sets'][0]['resolved_command'] == 'uptime'
    assert listed['command_sets'][0]['sudo_resolved_command'] == 'sudo uptime'

    duplicated, _emitted = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_duplicate_command_set,
        sid,
        {'command_set_id': saved['command_set']['id']},
    )
    assert duplicated['success'] is True
    assert duplicated['command_set']['id'] != saved['command_set']['id']
    assert duplicated['command_set']['name'] == 'Bootstrap Copy'

    deleted, _emitted = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_delete_command_set,
        sid,
        {'command_set_id': duplicated['command_set']['id']},
    )
    assert deleted == {
        'success': True,
        'command_set_id': duplicated['command_set']['id'],
    }


def test_profile_save_and_update_return_ack_without_connecting(app, monkeypatch):
    from app import ssh_manager
    import app.socket_events as socket_events

    _user_id, sid = create_socket_user(app, 'profile_socket_crud')
    monkeypatch.setattr(
        ssh_manager,
        'create_ssh_connection',
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError('saving a profile must not connect')
        ),
    )

    created, _emitted = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_save_profile,
        sid,
        {
            'name': 'Production',
            'host': 'example.com',
            'port': 22,
            'username': 'deploy',
            'auth_type': 'password',
        },
    )
    updated, _emitted = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_save_profile,
        sid,
        {
            'id': created['profile']['id'],
            'name': 'Production',
            'host': 'new.example.com',
            'port': 2222,
            'username': 'deploy',
            'auth_type': 'password',
        },
    )

    assert created['success'] is True
    assert updated['success'] is True
    assert updated['profile']['id'] == created['profile']['id']
    assert updated['profile']['host'] == 'new.example.com'


def test_profile_update_rejects_foreign_or_missing_id(app, monkeypatch):
    import app.socket_events as socket_events

    _user_id, sid = create_socket_user(app, 'profile_socket_missing')
    result, _emitted = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_save_profile,
        sid,
        {
            'id': 'not-owned',
            'name': 'Production',
            'host': 'example.com',
            'port': 22,
            'username': 'deploy',
            'auth_type': 'password',
        },
    )

    assert result == {'success': False, 'error': 'Profile not found'}


def test_profile_organization_socket_updates_current_users_profile(
    app, monkeypatch,
):
    import app.socket_events as socket_events

    _user_id, sid = create_socket_user(app, 'profile_organization_socket')
    created, _ = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_save_profile,
        sid,
        {
            'name': 'Production',
            'host': 'prod.example.com',
            'port': 22,
            'username': 'deploy',
            'auth_type': 'password',
        },
    )
    result, emitted = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_update_profile_organization,
        sid,
        {'profile_id': created['profile']['id'], 'favorite': True},
    )

    assert result['success'] is True
    assert result['profile']['favorite'] is True
    assert ('profile_organization_updated', result) in emitted
    assert any(event == 'profiles_list' for event, _payload in emitted)


def test_profile_organization_socket_rejects_missing_profile_id(
    app, monkeypatch,
):
    import app.socket_events as socket_events

    _user_id, sid = create_socket_user(app, 'profile_organization_missing')
    result, _ = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_update_profile_organization,
        sid,
        {'favorite': True},
    )

    assert result == {'success': False, 'error': 'Profile ID required'}


@pytest.mark.parametrize(('field', 'value', 'message'), [
    ('profile_id', None, 'Profile ID required'),
    ('expected_source_group', None, 'Invalid source group'),
    ('target_group', None, 'Invalid target group'),
    ('target_group', 'x' * 65, 'Group must not exceed 64 characters'),
    ('target_index', True, 'Invalid target index'),
    ('target_index', -1, 'Invalid target index'),
    ('target_index', '1', 'Invalid target index'),
    ('confirm_source_group_removal', 'true', 'Invalid confirmation value'),
])
def test_move_profile_socket_rejects_invalid_payload(
    app, monkeypatch, field, value, message,
):
    import app.socket_events as socket_events

    username = f'move_{field[:8]}_{len(str(value))}'
    _user_id, sid = create_socket_user(app, username)
    payload = {
        'profile_id': 'profile-1',
        'expected_source_group': 'Production',
        'target_group': 'Homelab',
        'target_index': 0,
        'confirm_source_group_removal': False,
    }
    payload[field] = value

    result, emitted = call_socket_handler(
        app, monkeypatch, socket_events.handle_move_profile, sid, payload
    )

    assert result == {'success': False, 'error': message}
    assert emitted == []


def test_move_profile_socket_requests_confirmation_without_writing_or_broadcast(
    app, monkeypatch,
):
    from app import profile_manager
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(app, 'profile_move_confirm')
    profiles = [
        {'id': 'critical', 'name': 'Critical DB', 'group': 'Databases', 'sort_order': 0},
        {'id': 'worker', 'name': 'Worker', 'group': 'Production', 'sort_order': 0},
    ]
    with app.app_context():
        assert profile_manager.save_profiles(user_id, profiles) is True

    result, emitted = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_move_profile,
        sid,
        {
            'profile_id': 'critical',
            'expected_source_group': 'Databases',
            'target_group': 'Production',
            'target_index': 1,
            'confirm_source_group_removal': False,
        },
    )

    assert result == {
        'success': False,
        'profiles': profiles,
        'requires_confirmation': True,
        'profile_id': 'critical',
        'profile_name': 'Critical DB',
        'source_group': 'Databases',
    }
    assert emitted == []
    with app.app_context():
        assert profile_manager.load_profiles(user_id) == profiles


def test_move_profile_socket_returns_authoritative_profiles_after_confirmed_write(
    app, monkeypatch,
):
    from app import profile_manager
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(app, 'profile_move_success')
    profiles = [
        {'id': 'critical', 'name': 'Critical DB', 'group': 'Databases', 'sort_order': 0},
        {'id': 'worker', 'name': 'Worker', 'group': 'Production', 'sort_order': 0},
    ]
    with app.app_context():
        assert profile_manager.save_profiles(user_id, profiles) is True

    result, emitted = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_move_profile,
        sid,
        {
            'profile_id': 'critical',
            'expected_source_group': 'Databases',
            'target_group': 'Production',
            'target_index': 1,
            'confirm_source_group_removal': True,
        },
    )

    assert result['success'] is True
    assert result['requires_confirmation'] is False
    ordered = sorted(result['profiles'], key=lambda item: item['sort_order'])
    assert [item['id'] for item in ordered] == ['worker', 'critical']
    assert ('profile_organization_updated', result) in emitted
    assert any(event == 'profiles_list' for event, _payload in emitted)


def test_move_profile_socket_returns_authoritative_state_when_source_is_stale(
    app, monkeypatch,
):
    from app import profile_manager
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(app, 'profile_move_stale')
    profiles = [
        {'id': 'api', 'name': 'API', 'group': 'Production', 'sort_order': 0},
    ]
    with app.app_context():
        assert profile_manager.save_profiles(user_id, profiles) is True

    result, emitted = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_move_profile,
        sid,
        {
            'profile_id': 'api',
            'expected_source_group': 'Homelab',
            'target_group': '',
            'target_index': 0,
        },
    )

    assert result == {
        'success': False,
        'error': 'Profile group changed; retry move',
        'profiles': profiles,
        'requires_confirmation': False,
    }
    assert emitted == []


def test_update_user_command_rejects_unknown_id_without_writing(app, monkeypatch):
    from app import command_manager

    user_id, _sid = create_socket_user(app, 'command_update_missing')
    with app.app_context():
        monkeypatch.setattr(
            command_manager,
            'save_user_commands',
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError('missing commands must not be saved')
            ),
        )
        updated, error = command_manager.update_user_command(
            user_id,
            'not-owned',
            'Missing',
            'echo missing',
            '',
            'Must not update',
            ['all'],
            'custom',
        )

        assert updated is None
        assert error == 'Command not found'
        assert command_manager.load_user_commands(user_id) == []


def test_update_user_command_translates_save_oserror(app, monkeypatch):
    from app import command_manager

    user_id, _sid = create_socket_user(app, 'command_update_save_error')
    with app.app_context():
        command = command_manager.add_user_command(
            user_id,
            'Mutable',
            'echo ready',
            '',
            'Mutable command',
            ['all'],
            'custom',
        )
        monkeypatch.setattr(
            command_manager,
            'save_user_commands',
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError('disk full')),
        )

        updated, error = command_manager.update_user_command(
            user_id,
            command['id'],
            'Mutable',
            'echo changed',
            '',
            'Mutable command',
            ['all'],
            'custom',
        )

    assert updated is None
    assert error == 'Failed to save command'


@pytest.mark.parametrize(
    ('operation', 'field', 'value'),
    [
        ('add', 'name', ['not-a-string']),
        ('add', 'command', {'not': 'a string'}),
        ('add', 'description', ['not-a-string']),
        ('add', 'parameters', ['not-a-string']),
        ('add', 'os', 'all'),
        ('add', 'category', ['not-a-string']),
        ('update', 'name', ['not-a-string']),
        ('update', 'command', {'not': 'a string'}),
        ('update', 'description', ['not-a-string']),
        ('update', 'parameters', ['not-a-string']),
        ('update', 'os', 'all'),
        ('update', 'category', ['not-a-string']),
    ],
)
def test_command_socket_rejects_truthy_wrong_types_without_writing_or_success(
    app, monkeypatch, operation, field, value
):
    from app import command_manager
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(
        app, f'invalid_{operation}_{field}'
    )
    with app.app_context():
        existing = command_manager.add_user_command(
            user_id, 'Existing', 'echo safe', '', 'Safe command',
            ['all'], 'custom'
        )
        path = command_manager.get_user_commands_file(user_id)
        before = path.read_bytes()

    payload = {
        'name': 'Candidate',
        'command': 'echo candidate',
        'parameters': '',
        'description': 'Candidate command',
        'os': ['all'],
        'category': 'custom',
    }
    handler = socket_events.handle_add_command
    if operation == 'update':
        payload['command_id'] = existing['id']
        handler = socket_events.handle_update_command
    payload[field] = value

    acknowledgement, emitted = call_socket_handler(
        app, monkeypatch, handler, sid, payload
    )

    assert acknowledgement['success'] is False
    assert len(emitted) == 1
    assert emitted[0][0] == 'error'
    assert emitted[0][1]['success'] is False
    assert emitted[0][1]['error'] == 'Invalid command data'
    assert not any(
        event in {'command_added', 'command_updated', 'commands_list'}
        for event, _payload in emitted
    )
    with app.app_context():
        assert path.read_bytes() == before
        json.loads(path.read_text(encoding='utf-8'))


@pytest.mark.parametrize('text', (['not-a-string'], {'not': 'a string'}))
def test_save_notepad_rejects_non_string_without_writing_or_success(
    app, monkeypatch, text
):
    from app import user_settings
    from app.models import User, db
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(app, f'invalid_notepad_{type(text).__name__}')
    with app.app_context():
        assert user_settings.save_user_settings(
            user_id, {'notepad': 'safe'}
        ) is True
        path = db.session.get(User, user_id).get_data_dir() / 'settings.json'
        before = path.read_bytes()

    acknowledgement, emitted = call_socket_handler(
        app, monkeypatch, socket_events.handle_save_notepad, sid, {'text': text}
    )

    assert acknowledgement == {
        'success': False,
        'error': 'Invalid notepad content',
    }
    assert emitted == [('error', acknowledgement)]
    with app.app_context():
        assert path.read_bytes() == before


def test_ssh_connect_does_not_reacquire_coordinator_or_emit_while_holding_it(
    app, monkeypatch
):
    from flask import request
    from app import post_connect_manager
    import app.socket_events as socket_events

    _user_id, sid = create_socket_user(app, 'connect_coordinator_once')
    requested = []
    emitted = []
    held = {'depth': 0}

    @contextmanager
    def instrumented_lock(key):
        requested.append(key)
        assert held['depth'] == 0, 'coordinator was reacquired'
        held['depth'] += 1
        try:
            yield
        finally:
            held['depth'] -= 1

    def record_emit(event, payload=None, **_kwargs):
        assert held['depth'] == 0, 'socket emit occurred under coordinator'
        emitted.append((event, payload))

    monkeypatch.setattr(
        socket_events,
        'storage_lock',
        instrumented_lock,
        raising=False,
    )
    monkeypatch.setattr(post_connect_manager, 'storage_lock', instrumented_lock)
    monkeypatch.setattr(socket_events, 'emit', record_emit)
    monkeypatch.setattr(
        socket_events,
        '_validate_ssh_params',
        lambda *_args, **_kwargs: (
            None, None, None, 'validation stopped connection'
        ),
    )

    with app.test_request_context('/socket.io'):
        request.sid = sid
        socket_events.handle_ssh_connect({
            'host': 'example.com',
            'port': 22,
            'username': 'deploy',
        })

    assert requested == [f'command-config:{_user_id}']
    assert emitted == [(
        'ssh_error',
        {
            'error': 'validation stopped connection',
            'client_request_id': None,
        },
    )]


def test_shutdown_rejects_new_ssh_and_quick_connections_before_network(
        app, monkeypatch):
    from flask import request
    from app import connection_pool, ssh_manager
    import app.socket_events as socket_events

    _user_id, sid = create_socket_user(app, 'shutdown_connection_gate')
    network_calls = []
    emitted = []
    monkeypatch.setattr(
        ssh_manager,
        'create_ssh_connection',
        lambda **_kwargs: network_calls.append('ssh'),
    )
    monkeypatch.setattr(
        connection_pool.temp_connection_pool,
        'create_connection',
        lambda **_kwargs: network_calls.append('quick'),
    )
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, payload=None, **_kwargs: emitted.append(
            (event, payload)
        ),
    )
    app.extensions['runtime_lifecycle'].begin_shutdown(0)

    with app.test_request_context('/socket.io'):
        request.sid = sid
        socket_events.handle_ssh_connect({
            'host': 'example.com',
            'port': 22,
            'username': 'deploy',
            'password': 'secret',
        })
        socket_events.handle_quick_connect({
            'host': 'example.com',
            'port': 22,
            'username': 'deploy',
            'password': 'secret',
        })

    assert network_calls == []
    assert emitted == [
        ('ssh_error', {
            'error': 'Server is shutting down',
            'client_request_id': None,
        }),
        ('quick_connect_error', {'error': 'Server is shutting down'}),
    ]


def test_saved_jump_host_id_is_resolved_live_before_network(app, monkeypatch):
    from flask import request
    from app import jump_host_manager, ssh_manager
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(app, 'live_jump_lookup')
    with app.app_context():
        jump_host, error = jump_host_manager.add_jump_host(
            user_id,
            'Live Bastion',
            'live-bastion.example',
            2222,
            'live-user',
            'password',
        )
        assert error is None

    emitted = []
    connector_calls = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, payload=None, **_kwargs: emitted.append(
            (event, payload)
        ),
    )
    monkeypatch.setattr(
        socket_events,
        '_validate_ssh_params',
        lambda host, port, username, **_kwargs: (
            host, int(port), username, None
        ),
    )
    monkeypatch.setattr(
        ssh_manager,
        'create_ssh_connection',
        lambda **kwargs: connector_calls.append(kwargs) or (
            None, 'local stop'
        ),
    )

    with app.test_request_context('/socket.io'):
        request.sid = sid
        socket_events.handle_ssh_connect({
            'host': 'target.example',
            'port': 22,
            'username': 'target-user',
            'auth_type': 'password',
            'password': 'target-runtime-password',
            'proxy_jump': {
                'jump_host_id': jump_host['id'],
                'host': 'attacker.example',
                'port': 9999,
                'username': 'attacker',
                'auth_type': 'key',
                'key_id': 'attacker-key',
                'password': 'jump-runtime-password',
            },
        })

    assert connector_calls[0]['proxy_jump_host'] == 'live-bastion.example'
    assert connector_calls[0]['proxy_jump_port'] == 2222
    assert connector_calls[0]['proxy_jump_username'] == 'live-user'
    assert connector_calls[0]['proxy_jump_password'] == (
        'jump-runtime-password'
    )
    assert connector_calls[0]['proxy_jump_key_content'] is None
    assert emitted == [(
        'ssh_error',
        {'error': 'local stop', 'client_request_id': None},
    )]


def test_ssh_connect_emits_stable_host_key_change_code(app, monkeypatch):
    from flask import request
    from app import ssh_manager
    import app.socket_events as socket_events

    _user_id, sid = create_socket_user(app, 'host_key_change_payload')
    emitted = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, payload=None, **_kwargs: emitted.append((event, payload)),
    )
    monkeypatch.setattr(
        socket_events,
        '_validate_ssh_params',
        lambda host, port, username, **_kwargs: (
            host, int(port), username, None
        ),
    )
    monkeypatch.setattr(
        ssh_manager,
        'create_ssh_connection',
        lambda **_kwargs: (
            None,
            ssh_manager.SSHConnectionError(
                'SSH host key changed',
                code='host_key_changed',
                context='target',
            ),
        ),
    )

    with app.test_request_context('/socket.io'):
        request.sid = sid
        socket_events.handle_ssh_connect({
            'host': 'target.example',
            'port': 22,
            'username': 'deploy',
            'password': 'secret',
            'client_request_id': 'host-key-request',
        })

    assert emitted == [(
        'ssh_error',
        {
            'error': 'SSH host key changed',
            'client_request_id': 'host-key-request',
            'code': 'host_key_changed',
            'context': 'target',
        },
    )]


def test_deleted_saved_jump_host_stops_before_rate_limit_dns_and_network(
    app, monkeypatch
):
    from flask import request
    from app import ssh_manager
    import app.socket_events as socket_events

    _user_id, sid = create_socket_user(app, 'missing_live_jump')
    emitted = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, payload=None, **_kwargs: emitted.append(
            (event, payload)
        ),
    )
    monkeypatch.setattr(
        socket_events,
        'check_socket_rate_limit',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError('rate limit must not run')
        ),
    )
    monkeypatch.setattr(
        socket_events,
        '_validate_ssh_params',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError('DNS/validation must not run')
        ),
    )
    monkeypatch.setattr(
        ssh_manager,
        'create_ssh_connection',
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError('network must not run')
        ),
    )

    with app.test_request_context('/socket.io'):
        request.sid = sid
        socket_events.handle_ssh_connect({
            'host': 'target.example',
            'port': 22,
            'username': 'target-user',
            'auth_type': 'password',
            'password': 'runtime-password',
            'proxy_jump': {
                'jump_host_id': 'deleted-jump',
                'host': 'stale.example',
                'port': 22,
                'username': 'stale',
                'password': 'runtime-jump-password',
            },
        })

    assert emitted == [(
        'ssh_error',
        {
            'error': 'Jump host reference not found',
            'client_request_id': None,
        },
    )]


def test_revoked_target_key_stops_before_rate_limit_dns_and_network(
    app, monkeypatch
):
    from flask import request
    from app import key_manager, ssh_manager
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(app, 'revoked_live_key')
    monkeypatch.setattr(
        key_manager,
        'read_key_content',
        lambda value, key_id: (
            (None, 'Key not found')
            if (value, key_id) == (user_id, 'revoked-key')
            else (_ for _ in ()).throw(AssertionError('unexpected key'))
        ),
    )
    emitted = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, payload=None, **_kwargs: emitted.append(
            (event, payload)
        ),
    )
    monkeypatch.setattr(
        socket_events,
        'check_socket_rate_limit',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError('rate limit must not run')
        ),
    )
    monkeypatch.setattr(
        socket_events,
        '_validate_ssh_params',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError('DNS/validation must not run')
        ),
    )
    monkeypatch.setattr(
        ssh_manager,
        'create_ssh_connection',
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError('network must not run')
        ),
    )

    with app.test_request_context('/socket.io'):
        request.sid = sid
        socket_events.handle_ssh_connect({
            'host': 'target.example',
            'port': 22,
            'username': 'target-user',
            'auth_type': 'key',
            'key_id': 'revoked-key',
        })

    assert emitted == [(
        'ssh_error',
        {
            'error': 'SSH key error: Key not found',
            'client_request_id': None,
        },
    )]


def test_revoked_live_jump_key_stops_before_rate_limit_dns_and_network(
    app, monkeypatch
):
    from flask import request
    from app import jump_host_manager, key_manager, ssh_manager
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(app, 'revoked_live_jump_key')
    with app.app_context():
        jump_host, error = jump_host_manager.add_jump_host(
            user_id,
            'Key Bastion',
            'live-bastion.example',
            22,
            'jump-user',
            'key',
            key_id='revoked-jump-key',
        )
        assert error is None
    monkeypatch.setattr(
        key_manager,
        'read_key_content',
        lambda value, key_id: (
            (None, 'Key not found')
            if (value, key_id) == (user_id, 'revoked-jump-key')
            else (_ for _ in ()).throw(AssertionError('unexpected key'))
        ),
    )
    emitted = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, payload=None, **_kwargs: emitted.append(
            (event, payload)
        ),
    )
    monkeypatch.setattr(
        socket_events,
        'check_socket_rate_limit',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError('rate limit must not run')
        ),
    )
    monkeypatch.setattr(
        socket_events,
        '_validate_ssh_params',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError('DNS/validation must not run')
        ),
    )
    monkeypatch.setattr(
        ssh_manager,
        'create_ssh_connection',
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError('network must not run')
        ),
    )

    with app.test_request_context('/socket.io'):
        request.sid = sid
        socket_events.handle_ssh_connect({
            'host': 'target.example',
            'port': 22,
            'username': 'target-user',
            'auth_type': 'password',
            'password': 'target-runtime-password',
            'proxy_jump': {
                'jump_host_id': jump_host['id'],
                'host': 'stale.example',
                'port': 22,
                'username': 'stale',
                'key_id': 'stale-key',
            },
        })

    assert emitted == [(
        'ssh_error',
        {
            'error': 'Jump host SSH key error: Key not found',
            'client_request_id': None,
        },
    )]


def test_target_key_internal_error_never_reaches_socket_client(
        app, monkeypatch, rsa_private_key_pem):
    from flask import request
    from app import key_encryption, key_manager, ssh_manager
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(app, 'safe_target_key_error')
    with app.app_context():
        key, error = key_manager.save_key(
            user_id, 'Target key', rsa_private_key_pem
        )
        assert error is None
    secret_error = 'sentinel-target-private-error'
    monkeypatch.setattr(
        key_encryption,
        'read_key_content',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError(secret_error)
        ),
    )
    emitted = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, payload=None, **_kwargs: emitted.append(
            (event, payload)
        ),
    )
    monkeypatch.setattr(
        socket_events,
        'check_socket_rate_limit',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError('rate limit must not run')
        ),
    )
    monkeypatch.setattr(
        socket_events,
        '_validate_ssh_params',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError('DNS/validation must not run')
        ),
    )
    monkeypatch.setattr(
        ssh_manager,
        'create_ssh_connection',
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError('network must not run')
        ),
    )

    with app.test_request_context('/socket.io'):
        request.sid = sid
        socket_events.handle_ssh_connect({
            'host': 'target.example',
            'port': 22,
            'username': 'target-user',
            'auth_type': 'key',
            'key_id': key['id'],
        })

    assert emitted == [(
        'ssh_error',
        {
            'error': 'SSH key error: Failed to read key',
            'client_request_id': None,
        },
    )]
    assert secret_error not in repr(emitted)


def test_jump_key_internal_error_never_reaches_socket_client(
        app, monkeypatch, rsa_private_key_pem):
    from flask import request
    from app import (
        jump_host_manager,
        key_encryption,
        key_manager,
        ssh_manager,
    )
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(app, 'safe_jump_key_error')
    with app.app_context():
        key, error = key_manager.save_key(
            user_id, 'Jump key', rsa_private_key_pem
        )
        assert error is None
        jump_host, error = jump_host_manager.add_jump_host(
            user_id,
            'Key Bastion',
            'bastion.example',
            22,
            'jump-user',
            'key',
            key_id=key['id'],
        )
        assert error is None
    secret_error = 'sentinel-jump-private-error'
    monkeypatch.setattr(
        key_encryption,
        'read_key_content',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError(secret_error)
        ),
    )
    emitted = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, payload=None, **_kwargs: emitted.append(
            (event, payload)
        ),
    )
    monkeypatch.setattr(
        socket_events,
        'check_socket_rate_limit',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError('rate limit must not run')
        ),
    )
    monkeypatch.setattr(
        socket_events,
        '_validate_ssh_params',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError('DNS/validation must not run')
        ),
    )
    monkeypatch.setattr(
        ssh_manager,
        'create_ssh_connection',
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError('network must not run')
        ),
    )

    with app.test_request_context('/socket.io'):
        request.sid = sid
        socket_events.handle_ssh_connect({
            'host': 'target.example',
            'port': 22,
            'username': 'target-user',
            'auth_type': 'password',
            'password': 'runtime-password',
            'proxy_jump': {
                'jump_host_id': jump_host['id'],
                'host': 'stale.example',
                'port': 22,
                'username': 'stale',
            },
        })

    assert emitted == [(
        'ssh_error',
        {
            'error': 'Jump host SSH key error: Failed to read key',
            'client_request_id': None,
        },
    )]
    assert secret_error not in repr(emitted)


def test_quick_connect_key_internal_error_never_reaches_socket_client(
        app, monkeypatch, rsa_private_key_pem):
    from app import connection_pool, key_encryption, key_manager
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(app, 'safe_quick_key_error')
    with app.app_context():
        key, error = key_manager.save_key(
            user_id, 'Quick key', rsa_private_key_pem
        )
        assert error is None
    secret_error = 'sentinel-quick-private-error'
    monkeypatch.setattr(
        key_encryption,
        'read_key_content',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError(secret_error)
        ),
    )
    monkeypatch.setattr(
        socket_events,
        'check_socket_rate_limit',
        lambda *_args, **_kwargs: False,
    )
    monkeypatch.setattr(
        socket_events,
        '_validate_ssh_params',
        lambda host, port, username, **_kwargs: (
            host, int(port), username, None
        ),
    )
    monkeypatch.setattr(
        connection_pool.temp_connection_pool,
        'create_connection',
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError('network must not run')
        ),
    )

    _acknowledgement, emitted = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_quick_connect,
        sid,
        {
            'host': 'target.example',
            'port': 22,
            'username': 'target-user',
            'key_id': key['id'],
        },
    )

    assert emitted == [(
        'quick_connect_error',
        {'error': 'SSH key error: Failed to read key'},
    )]
    assert secret_error not in repr(emitted)


def test_missing_command_delete_returns_not_found_code(app, monkeypatch):
    import app.socket_events as socket_events

    _user_id, sid = create_socket_user(app, 'missing_command_delete')
    result, emitted = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_delete_command,
        sid,
        {'command_id': 'missing'},
    )

    assert result == {
        'success': False,
        'error': 'Command not found',
        'code': 'not_found',
    }
    assert emitted == [('error', result)]


def test_jump_host_delete_returns_in_use_and_not_found_codes(
    app, monkeypatch
):
    from app import jump_host_manager, profile_manager
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(app, 'jump_delete_contract')
    with app.app_context():
        jump_host, error = jump_host_manager.add_jump_host(
            user_id,
            'Bastion',
            'bastion.example',
            22,
            'jump-user',
            'password',
        )
        assert error is None
        assert profile_manager.save_profiles(user_id, [{
            'id': 'profile-1',
            'name': 'Production',
            'jump_host_id': jump_host['id'],
        }])

    guarded, guarded_events = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_delete_jump_host,
        sid,
        {'jump_host_id': jump_host['id']},
    )
    assert guarded == {
        'success': False,
        'error': 'Jump host is used by 1 profile',
        'code': 'in_use',
        'usages': ['Production'],
    }
    assert guarded_events == [('error', guarded)]

    missing, missing_events = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_delete_jump_host,
        sid,
        {'jump_host_id': 'missing'},
    )
    assert missing == {
        'success': False,
        'error': 'Jump host not found',
        'code': 'not_found',
    }
    assert missing_events == [('error', missing)]


def test_missing_command_update_and_profile_delete_emit_structured_errors(
    app, monkeypatch
):
    import app.socket_events as socket_events

    _user_id, sid = create_socket_user(app, 'missing_command_and_profile')
    command_result, command_events = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_update_command,
        sid,
        {
            'command_id': 'not-owned',
            'name': 'Missing',
            'command': 'echo missing',
            'description': 'Must not update',
        },
    )
    profile_result, profile_events = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_delete_profile,
        sid,
        {'profile_id': 'not-owned'},
    )

    assert command_result == {
        'success': False,
        'error': 'Command not found',
        'code': 'not_found',
    }
    assert command_events == [('error', command_result)]
    assert profile_result == {
        'success': False,
        'error': 'Profile not found',
        'code': 'not_found',
    }
    assert profile_events == [('error', profile_result)]


def test_socket_command_set_errors_are_structured(app, monkeypatch):
    from app.models import User, db
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(app, 'command_set_errors')
    duplicate, _emitted = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_duplicate_command_set,
        sid,
        {'command_set_id': 'foreign-or-missing'},
    )
    assert duplicate == {
        'success': False,
        'error': 'Command set not found',
        'code': 'not_found',
    }

    with app.app_context():
        user = db.session.get(User, user_id)
        path = user.get_data_dir() / 'command_sets.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{broken', encoding='utf-8')

    listed, _emitted = call_socket_handler(
        app, monkeypatch, socket_events.handle_list_command_sets, sid
    )
    assert listed == {
        'success': False,
        'error': 'Stored data is unreadable. Please restore or remove it.',
        'code': 'storage_error',
    }


def test_command_storage_quota_error_is_structured(app, monkeypatch):
    import config
    import app.socket_events as socket_events

    _user_id, sid = create_socket_user(app, 'command_storage_quota')
    monkeypatch.setattr(config, 'COMMAND_SET_MAX_STEPS', 1)
    result, events = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_save_command_set,
        sid,
        {
            'name': 'Too many steps',
            'steps': [
                {'type': 'inline', 'command': 'echo one'},
                {'type': 'inline', 'command': 'echo two'},
            ],
        },
    )

    assert result['success'] is False
    assert result['code'] == 'quota_exceeded'
    assert result['error'].startswith('Command storage quota exceeded:')
    assert events == [('error', result)]


def test_command_mutation_rate_limit_is_structured(app, monkeypatch):
    import app.socket_events as socket_events

    _user_id, sid = create_socket_user(app, 'command_mutation_rate')
    monkeypatch.setattr(
        socket_events,
        'check_socket_rate_limit',
        lambda *_args, **_kwargs: True,
    )
    result, events = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_add_command,
        sid,
        {
            'name': 'Blocked',
            'command': 'uptime',
            'description': 'Must be rate limited',
        },
    )

    assert result == {
        'success': False,
        'error': 'Too many command changes. Please wait before trying again.',
        'code': 'rate_limited',
    }
    assert events == [('error', result)]


def test_referenced_command_set_and_library_command_cannot_be_deleted(app, monkeypatch):
    from app import command_manager, command_set_manager, profile_manager
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(app, 'command_set_delete_guards')
    with app.app_context():
        command = command_manager.add_user_command(
            user_id, 'Update', 'apt update', '', 'Update packages', ['linux'], 'system'
        )
        command_set, error = command_set_manager.upsert_command_set(user_id, {
            'name': 'Bootstrap',
            'steps': [{'type': 'library', 'command_id': command['id']}],
        })
        assert error is None
        profile, error = profile_manager.add_profile(
            user_id, 'Production', 'example.com', 22, 'deploy', 'password',
            command_set_id=command_set['id'],
        )
        assert error is None

        success, error, usages = command_manager.delete_user_command(user_id, command['id'])
        assert success is False
        assert error == 'Command is used by 1 command set'
        assert usages == [{
            'id': command_set['id'],
            'name': 'Bootstrap',
            'type': 'command_set',
        }]
        assert any(item['id'] == command['id'] for item in command_manager.load_user_commands(user_id))

    blocked, _emitted = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_delete_command_set,
        sid,
        {'command_set_id': command_set['id']},
    )
    assert blocked == {
        'success': False,
        'error': 'Command set is used by 1 profile',
        'code': 'in_use',
        'usages': [profile['name']],
    }


def test_convert_legacy_profile_creates_set_then_assigns_it(app, monkeypatch):
    from app import command_set_manager, profile_manager
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(app, 'command_set_convert')
    with app.app_context():
        profile, error = profile_manager.add_profile(
            user_id, 'Legacy', 'example.com', 22, 'deploy', 'password',
            startup_commands='echo one\r\necho two',
        )
        assert error is None

    captured_payload = {}
    real_upsert = command_set_manager.upsert_command_set

    def capture_upsert(user_id, payload):
        captured_payload.update(payload)
        return real_upsert(user_id, payload)

    monkeypatch.setattr(command_set_manager, 'upsert_command_set', capture_upsert)

    converted, _emitted = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_convert_legacy_command_set,
        sid,
        {
            'profile_id': profile['id'],
            'name': 'Legacy bootstrap',
            'use_sudo': True,
        },
    )
    assert converted['success'] is True
    assert captured_payload['use_sudo'] is False
    assert converted['command_set']['use_sudo'] is False
    assert converted['command_set']['steps'] == [
        {'type': 'inline', 'command': 'echo one\necho two'}
    ]
    assert converted['profile']['command_set_id'] == converted['command_set']['id']
    assert converted['profile']['startup_commands'] == 'echo one\necho two'

    with app.app_context():
        stored = profile_manager.get_profile(user_id, profile['id'])
        assert stored == converted['profile']


def test_convert_rejects_profile_without_legacy_commands(app, monkeypatch):
    from app import profile_manager
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(app, 'command_set_convert_empty')
    with app.app_context():
        profile, error = profile_manager.add_profile(
            user_id, 'Modern', 'example.com', 22, 'deploy', 'password'
        )
        assert error is None

    converted, _emitted = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_convert_legacy_command_set,
        sid,
        {'profile_id': profile['id'], 'name': 'No commands'},
    )
    assert converted == {
        'success': False,
        'error': 'Profile has no legacy startup commands',
        'code': 'validation_error',
    }


def test_ssh_connect_resolves_command_set_and_ignores_legacy_text(app, monkeypatch):
    from flask import request
    from app import command_set_manager, ssh_manager
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(app, 'command_set_connect')
    with app.app_context():
        command_set, error = command_set_manager.upsert_command_set(user_id, {
            'name': 'Bootstrap',
            'use_sudo': True,
            'steps': [
                {'type': 'inline', 'command': 'echo first'},
                {'type': 'inline', 'command': 'echo second'},
            ],
        })
        assert error is None

    calls = []
    monkeypatch.setattr(
        ssh_manager,
        'create_ssh_connection',
        lambda **kwargs: (calls.append(kwargs) or ('command-set-session', None)),
    )
    monkeypatch.setattr(socket_events, 'emit', lambda *_args, **_kwargs: None)

    with app.test_request_context('/socket.io', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        request.sid = sid
        socket_events.handle_ssh_connect({
            'host': 'example.com',
            'port': 22,
            'username': 'deploy',
            'password': 'secret',
            'command_set_id': command_set['id'],
            'startup_commands': 'echo must-not-run',
        })

    assert calls[0]['startup_commands'] == 'sudo echo first && sudo echo second'


def test_ssh_connect_resolves_single_library_command_with_parameter_override(
    app, monkeypatch
):
    from flask import request
    from app import command_manager, ssh_manager
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(app, 'single_command_connect')
    with app.app_context():
        command = command_manager.add_user_command(
            user_id,
            'Echo',
            'echo',
            'default',
            'Echo text',
            ['all'],
            'custom',
        )

    calls = []
    monkeypatch.setattr(
        ssh_manager,
        'create_ssh_connection',
        lambda **kwargs: (calls.append(kwargs) or ('command-session', None)),
    )
    monkeypatch.setattr(socket_events, 'emit', lambda *_args, **_kwargs: None)

    with app.test_request_context(
        '/socket.io', environ_base={'REMOTE_ADDR': '127.0.0.1'}
    ):
        request.sid = sid
        socket_events.handle_ssh_connect({
            'host': 'example.com',
            'port': 22,
            'username': 'deploy',
            'password': 'secret',
            'startup_mode': 'command',
            'command_id': command['id'],
            'parameters_override': 'hello world',
        })

    assert calls[0]['startup_commands'] == 'echo hello world'


def test_conflicting_command_modes_stop_before_dns_and_ssh(app, monkeypatch):
    from flask import request
    from app import command_manager, ssh_manager
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(app, 'conflicting_command_connect')
    with app.app_context():
        command = command_manager.add_user_command(
            user_id, 'Echo', 'echo', '', 'Echo', ['all'], 'custom'
        )

    monkeypatch.setattr(
        socket_events,
        '_validate_ssh_params',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError('connection validation or DNS must not run')
        ),
    )
    monkeypatch.setattr(
        ssh_manager,
        'create_ssh_connection',
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError('SSH manager must not run')
        ),
    )
    emitted = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, payload=None, **_kwargs: emitted.append((event, payload)),
    )

    with app.test_request_context(
        '/socket.io', environ_base={'REMOTE_ADDR': '127.0.0.1'}
    ):
        request.sid = sid
        socket_events.handle_ssh_connect({
            'host': 'must-not-resolve.invalid',
            'port': 22,
            'username': 'deploy',
            'password': 'secret',
            'startup_mode': 'command',
            'command_id': command['id'],
            'command_set_id': 'unexpected',
        })

    assert emitted == [(
        'ssh_error',
        {
            'error': 'Conflicting post-connect command configuration',
            'client_request_id': None,
        },
    )]


def test_sudo_expansion_limit_stops_before_connection_validation(app, monkeypatch):
    from flask import request
    from app import command_set_manager, ssh_manager
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(app, 'command_set_sudo_limit')
    with app.app_context():
        command_set, error = command_set_manager.upsert_command_set(user_id, {
            'name': 'Too long after sudo',
            'use_sudo': True,
            'steps': [{'type': 'inline', 'command': 'x' * 4092}],
        })
        assert error is None

    monkeypatch.setattr(
        socket_events,
        '_validate_ssh_params',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError('connection validation or DNS must not run')
        ),
    )
    monkeypatch.setattr(
        ssh_manager,
        'create_ssh_connection',
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError('SSH manager must not run')
        ),
    )
    emitted = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, payload=None, **_kwargs: emitted.append((event, payload)),
    )

    with app.test_request_context('/socket.io', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        request.sid = sid
        socket_events.handle_ssh_connect({
            'host': 'must-not-resolve.invalid',
            'port': 22,
            'username': 'deploy',
            'password': 'secret',
            'command_set_id': command_set['id'],
        })

    assert emitted == [(
        'ssh_error',
        {
            'error': 'Startup commands must not exceed 4096 characters',
            'client_request_id': None,
        },
    )]


def test_invalid_command_set_stops_before_validation_dns_and_ssh(app, monkeypatch):
    from flask import request
    from app import ssh_manager
    import app.socket_events as socket_events

    _user_id, sid = create_socket_user(app, 'command_set_no_dns')
    monkeypatch.setattr(
        socket_events,
        '_validate_ssh_params',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError('connection validation or DNS must not run')
        ),
    )
    monkeypatch.setattr(
        ssh_manager,
        'create_ssh_connection',
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError('SSH manager must not run')
        ),
    )
    emitted = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, payload=None, **_kwargs: emitted.append((event, payload)),
    )

    with app.test_request_context('/socket.io', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        request.sid = sid
        socket_events.handle_ssh_connect({
            'host': 'must-not-resolve.invalid',
            'port': 22,
            'username': 'deploy',
            'password': 'secret',
            'command_set_id': 'missing-set',
        })

    assert emitted == [(
        'ssh_error',
        {'error': 'Command set not found', 'client_request_id': None},
    )]


@pytest.mark.parametrize(
    ('mode', 'expected_error'),
    [
        ('missing_reference', "Command set 'Bootstrap' step 1 references a missing command"),
        ('oversized_resolution', 'Startup commands must not exceed 4096 characters'),
    ],
)
def test_unresolvable_saved_set_stops_before_connection_validation(
        app, monkeypatch, mode, expected_error):
    from flask import request
    from app import command_manager, command_set_manager
    import app.socket_events as socket_events

    username = f'set_{mode}'
    user_id, sid = create_socket_user(app, username)
    with app.app_context():
        command = command_manager.add_user_command(
            user_id, 'Mutable', 'echo ready', '', 'Mutable command', ['all'], 'custom'
        )
        command_set, error = command_set_manager.upsert_command_set(user_id, {
            'name': 'Bootstrap',
            'steps': [{'type': 'library', 'command_id': command['id']}],
        })
        assert error is None
        if mode == 'missing_reference':
            assert command_manager.save_user_commands(user_id, []) is True
        else:
            updated, update_error = command_manager.update_user_command(
                user_id, command['id'], 'Mutable', 'x' * 4097, '',
                'Mutable command', ['all'], 'custom'
            )
            assert update_error is None
            assert updated['id'] == command['id']

    monkeypatch.setattr(
        socket_events,
        '_validate_ssh_params',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError('connection validation or DNS must not run')
        ),
    )
    emitted = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, payload=None, **_kwargs: emitted.append((event, payload)),
    )

    with app.test_request_context('/socket.io', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        request.sid = sid
        socket_events.handle_ssh_connect({
            'host': 'must-not-resolve.invalid',
            'port': 22,
            'username': 'deploy',
            'password': 'secret',
            'command_set_id': command_set['id'],
        })

    assert emitted == [(
        'ssh_error',
        {'error': expected_error, 'client_request_id': None},
    )]


def test_add_library_command_does_not_overwrite_corrupt_storage(app):
    from app import command_manager
    from app.models import User, db

    user_id, _sid = create_socket_user(app, 'corrupt_command_library')
    with app.app_context():
        user = db.session.get(User, user_id)
        path = user.get_data_dir() / 'commands.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{broken', encoding='utf-8')

        with pytest.raises(StorageCorruptionError):
            command_manager.add_user_command(
                user_id, 'Safe', 'uptime', '', 'Check uptime', ['all'], 'custom'
            )
        assert path.read_text(encoding='utf-8') == '{broken'


def test_ssh_connect_reports_safe_storage_error_before_connector(app, monkeypatch):
    from flask import request
    from app import command_manager, ssh_manager
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(app, 'corrupt_command_connect')
    with app.app_context():
        path = command_manager.get_user_commands_file(user_id)
        path.write_text('{broken', encoding='utf-8')

    connector_calls = []
    monkeypatch.setattr(
        ssh_manager,
        'create_ssh_connection',
        lambda **kwargs: (connector_calls.append(kwargs) or ('unexpected', None)),
    )
    emitted = []
    logged = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, payload=None, **_kwargs: emitted.append((event, payload)),
    )
    monkeypatch.setattr(
        socket_events,
        'log_error',
        lambda message, **fields: logged.append((message, fields)),
    )

    with app.test_request_context(
        '/socket.io', environ_base={'REMOTE_ADDR': '127.0.0.1'}
    ):
        request.sid = sid
        socket_events.handle_ssh_connect({
            'host': 'must-not-resolve.invalid',
            'port': 22,
            'username': 'deploy',
            'password': 'secret',
            'startup_mode': 'command',
            'command_id': 'missing',
            'client_request_id': 'corrupt-1',
        })

    assert connector_calls == []
    assert emitted == [(
        'ssh_error',
        {
            'error': 'Stored data is unreadable. Please restore or remove it.',
            'code': 'storage_error',
            'client_request_id': 'corrupt-1',
        },
    )]
    assert logged == [(
        'Storage corruption detected',
        {
            'user_id': user_id,
            'store': 'commands.json',
            'path': str(path),
            'reason': 'invalid JSON',
        },
    )]
    assert '{broken' not in repr(logged)


def test_convert_legacy_profile_reports_safe_corrupt_profile_store(
    app, monkeypatch
):
    from app import profile_manager
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(app, 'corrupt_profile_convert')
    with app.app_context():
        path = profile_manager.get_user_profiles_file(user_id)
        path.write_text('{broken', encoding='utf-8')

    result, emitted = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_convert_legacy_command_set,
        sid,
        {'profile_id': 'unreadable', 'name': 'Must not create'},
    )

    assert result == {
        'success': False,
        'error': 'Stored data is unreadable. Please restore or remove it.',
        'code': 'storage_error',
    }
    assert emitted == [('error', result)]
