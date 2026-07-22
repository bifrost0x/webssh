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
    assert listed == {'success': True, 'command_sets': [saved['command_set']]}

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
        assert usages == [{'id': command_set['id'], 'name': 'Bootstrap'}]
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
    from app import profile_manager
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(app, 'command_set_convert')
    with app.app_context():
        profile, error = profile_manager.add_profile(
            user_id, 'Legacy', 'example.com', 22, 'deploy', 'password',
            startup_commands='echo one\r\necho two',
        )
        assert error is None

    converted, _emitted = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_convert_legacy_command_set,
        sid,
        {'profile_id': profile['id'], 'name': 'Legacy bootstrap'},
    )
    assert converted['success'] is True
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

    assert calls[0]['startup_commands'] == 'echo first\necho second'


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
