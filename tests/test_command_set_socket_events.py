"""Socket and cross-storage tests for named command sets."""
import pytest
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


def test_socket_command_set_errors_are_structured(app, monkeypatch):
    from app.models import User
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
        user = User.query.get(user_id)
        path = user.get_data_dir() / 'command_sets.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{broken', encoding='utf-8')

    listed, _emitted = call_socket_handler(
        app, monkeypatch, socket_events.handle_list_command_sets, sid
    )
    assert listed == {
        'success': False,
        'error': 'Command set storage is unreadable',
        'code': 'storage_error',
    }


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
            assert command_manager.update_user_command(
                user_id, command['id'], 'Mutable', 'x' * 4097, '',
                'Mutable command', ['all'], 'custom'
            ) is True

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
    from app.models import User

    user_id, _sid = create_socket_user(app, 'corrupt_command_library')
    with app.app_context():
        user = User.query.get(user_id)
        path = user.get_data_dir() / 'commands.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{broken', encoding='utf-8')

        command = command_manager.add_user_command(
            user_id, 'Safe', 'uptime', '', 'Check uptime', ['all'], 'custom'
        )

        assert command is None
        assert path.read_text(encoding='utf-8') == '{broken'
