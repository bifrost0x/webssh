"""Tests for canonical post-connect command selection and resolution."""


def create_user(app, username='post-connect-user'):
    from app.models import User, db

    with app.app_context():
        user = User(username=username, password_hash='not-used-in-this-test')
        db.session.add(user)
        db.session.commit()
        return user.id


def library_commands():
    return [
        {
            'id': 'cmd-echo',
            'name': 'Echo',
            'command': 'echo',
            'parameters': 'default',
            'description': 'Echo text',
            'os': ['all'],
            'category': 'custom',
        },
        {
            'id': 'cmd-pwd',
            'name': 'Working directory',
            'command': 'pwd',
            'parameters': '',
            'description': 'Print directory',
            'os': ['all'],
            'category': 'files',
        },
    ]


def test_infer_mode_preserves_explicit_and_legacy_profiles():
    from app.post_connect_manager import infer_mode

    assert infer_mode({'startup_mode': 'command', 'command_id': 'cmd-echo'}) == 'command'
    assert infer_mode({'command_set_id': 'set-1'}) == 'command_set'
    assert infer_mode({'startup_commands': 'pwd'}) == 'free_text'
    assert infer_mode({}) == 'none'


def test_validate_rejects_conflicting_mode_fields(app, monkeypatch):
    from app import command_manager
    from app.post_connect_manager import validate_configuration

    monkeypatch.setattr(
        command_manager, 'get_all_commands',
        lambda user_id, os_filter=None: library_commands(),
    )
    user_id = create_user(app)

    with app.app_context():
        stored, error = validate_configuration(user_id, {
            'startup_mode': 'command',
            'command_id': 'cmd-echo',
            'command_set_id': 'unexpected',
        })

    assert stored is None
    assert error == 'Conflicting post-connect command configuration'


def test_validate_projects_only_fields_for_selected_mode(app, monkeypatch):
    from app import command_manager
    from app.post_connect_manager import validate_configuration

    monkeypatch.setattr(
        command_manager, 'get_all_commands',
        lambda user_id, os_filter=None: library_commands(),
    )
    user_id = create_user(app)

    with app.app_context():
        stored, error = validate_configuration(user_id, {
            'startup_mode': 'command',
            'command_id': 'cmd-echo',
            'parameters_override': '',
            'startup_commands': 'must not survive',
        })

    assert error is None
    assert stored == {
        'startup_mode': 'command',
        'command_id': 'cmd-echo',
        'parameters_override': '',
    }
    with app.app_context():
        empty, empty_error = validate_configuration(user_id, {
            'startup_mode': 'none',
            'command_id': '',
            'startup_commands': '',
        })
    assert empty_error is None
    assert empty == {'startup_mode': 'none'}


def test_resolve_single_command_uses_default_or_override_parameters(app, monkeypatch):
    from app import command_manager
    from app.post_connect_manager import resolve_configuration

    monkeypatch.setattr(
        command_manager, 'get_all_commands',
        lambda user_id, os_filter=None: library_commands(),
    )
    user_id = create_user(app)

    with app.app_context():
        default, default_error = resolve_configuration(user_id, {
            'startup_mode': 'command',
            'command_id': 'cmd-echo',
        })
        overridden, override_error = resolve_configuration(user_id, {
            'startup_mode': 'command',
            'command_id': 'cmd-echo',
            'parameters_override': 'hello world',
        })
        empty, empty_error = resolve_configuration(user_id, {
            'startup_mode': 'command',
            'command_id': 'cmd-echo',
            'parameters_override': '',
        })

    assert (default, default_error) == ('echo default', None)
    assert (overridden, override_error) == ('echo hello world', None)
    assert (empty, empty_error) == ('echo', None)


def test_resolve_single_command_loads_the_library_once(app, monkeypatch):
    from app import command_manager
    from app.post_connect_manager import resolve_configuration

    calls = 0

    def get_commands(user_id, os_filter=None):
        nonlocal calls
        calls += 1
        return library_commands()

    monkeypatch.setattr(command_manager, 'get_all_commands', get_commands)
    user_id = create_user(app)

    with app.app_context():
        resolved, error = resolve_configuration(user_id, {
            'startup_mode': 'command',
            'command_id': 'cmd-echo',
        })

    assert (resolved, error) == ('echo default', None)
    assert calls == 1


def test_resolve_rejects_missing_command_and_invalid_parameters(app, monkeypatch):
    from app import command_manager
    from app.post_connect_manager import resolve_configuration

    monkeypatch.setattr(
        command_manager, 'get_all_commands',
        lambda user_id, os_filter=None: library_commands(),
    )
    user_id = create_user(app)

    with app.app_context():
        missing, missing_error = resolve_configuration(user_id, {
            'startup_mode': 'command',
            'command_id': 'missing',
        })
        invalid, invalid_error = resolve_configuration(user_id, {
            'startup_mode': 'command',
            'command_id': 'cmd-echo',
            'parameters_override': 'hello\x00world',
        })

    assert missing is None
    assert missing_error == 'Command not found'
    assert invalid is None
    assert invalid_error == 'Commands cannot contain NUL bytes'


def test_resolve_free_text_normalizes_and_none_is_empty(app):
    from app.post_connect_manager import resolve_configuration

    user_id = create_user(app)
    with app.app_context():
        free_text, free_text_error = resolve_configuration(user_id, {
            'startup_mode': 'free_text',
            'startup_commands': 'echo one\r\npwd\r',
        })
        empty, empty_error = resolve_configuration(user_id, {
            'startup_mode': 'none',
        })

    assert (free_text, free_text_error) == ('echo one\npwd\n', None)
    assert (empty, empty_error) == ('', None)


def test_resolve_command_set_uses_existing_safe_resolver(app, monkeypatch):
    from app import command_manager, command_set_manager
    from app.post_connect_manager import resolve_configuration

    monkeypatch.setattr(
        command_manager, 'get_all_commands',
        lambda user_id, os_filter=None: library_commands(),
    )
    user_id = create_user(app)

    with app.app_context():
        command_set, create_error = command_set_manager.upsert_command_set(user_id, {
            'name': 'Bootstrap',
            'use_sudo': True,
            'steps': [
                {'type': 'library', 'command_id': 'cmd-pwd'},
                {'type': 'inline', 'command': 'whoami'},
            ],
        })
        resolved, resolve_error = resolve_configuration(user_id, {
            'startup_mode': 'command_set',
            'command_set_id': command_set['id'],
        })

    assert create_error is None
    assert resolve_error is None
    assert resolved == 'sudo pwd && sudo whoami'
