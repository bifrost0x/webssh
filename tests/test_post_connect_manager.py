"""Tests for canonical post-connect command selection and resolution."""

import threading

import pytest

from app.storage_errors import StorageCorruptionError


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
        command_manager, '_get_all_commands_with_lock_held',
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

    monkeypatch.setattr(
        command_manager, '_get_all_commands_with_lock_held', get_commands
    )
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
        command_manager, '_get_all_commands_with_lock_held',
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
        command_manager, '_get_all_commands_with_lock_held',
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


def test_resolve_configuration_propagates_corrupt_command_store(app):
    from app import command_manager
    from app.post_connect_manager import resolve_configuration

    user_id = create_user(app, 'post-connect-corrupt-commands')
    with app.app_context():
        path = command_manager.get_user_commands_file(user_id)
        path.write_bytes(b'{broken')

        with pytest.raises(StorageCorruptionError) as exc_info:
            resolve_configuration(
                user_id,
                {'startup_mode': 'command', 'command_id': 'missing'},
            )

        assert exc_info.value.path == path


@pytest.mark.parametrize(
    ('mode', 'expected_stores'),
    [
        ('command', ('commands',)),
        ('command_set', ('command-sets', 'commands')),
    ],
)
def test_post_connect_public_resolution_uses_one_coordinator_and_store_snapshots(
    app, monkeypatch, mode, expected_stores
):
    from app import command_manager, command_set_manager, post_connect_manager
    from app.storage_utils import storage_lock as real_storage_lock

    user_id = create_user(app, f'post-connect-lock-{mode}')
    with app.app_context():
        command = command_manager.add_user_command(
            user_id, 'Reference', 'echo safe', '', 'Reference',
            ['all'], 'custom'
        )
        command_set, error = command_set_manager.upsert_command_set(
            user_id,
            {
                'name': 'Reference',
                'steps': [{
                    'type': 'library',
                    'command_id': command['id'],
                }],
            },
        )
        assert error is None

    requested = []

    def instrumented_storage_lock(key):
        requested.append(key)
        return real_storage_lock(key)

    monkeypatch.setattr(
        post_connect_manager, 'storage_lock', instrumented_storage_lock,
        raising=False,
    )
    monkeypatch.setattr(
        command_set_manager, 'storage_lock', instrumented_storage_lock
    )
    payload = {'startup_mode': mode}
    payload[f'{mode}_id'] = (
        command['id'] if mode == 'command' else command_set['id']
    )
    with app.app_context():
        resolved, error = post_connect_manager.resolve_configuration(
            user_id, payload
        )

    assert (resolved, error) == ('echo safe', None)
    assert requested == [
        f'command-config:{user_id}',
        *(f'{store}:{user_id}' for store in expected_stores),
    ]


def test_post_connect_command_resolution_blocks_writer_until_snapshot_done(
    app, monkeypatch
):
    from app import command_manager, post_connect_manager

    user_id = create_user(app, 'post-connect-snapshot-race')
    with app.app_context():
        command = command_manager.add_user_command(
            user_id, 'Mutable', 'echo old', '', 'Mutable',
            ['all'], 'custom'
        )

    snapshot_paused = threading.Event()
    continue_resolution = threading.Event()
    writer_done = threading.Event()
    resolver_result = {}
    real_index = post_connect_manager._command_index

    def paused_index(value, lock_held=False):
        result = real_index(value, lock_held=lock_held)
        snapshot_paused.set()
        assert continue_resolution.wait(timeout=2)
        return result

    monkeypatch.setattr(post_connect_manager, '_command_index', paused_index)

    def resolve():
        with app.app_context():
            resolver_result['value'] = (
                post_connect_manager.resolve_configuration(
                    user_id,
                    {
                        'startup_mode': 'command',
                        'command_id': command['id'],
                    },
                )
            )

    def write():
        with app.app_context():
            command_manager.update_user_command(
                user_id, command['id'], 'Mutable', 'echo new', '',
                'Mutable', ['all'], 'custom'
            )
        writer_done.set()

    resolver = threading.Thread(target=resolve, daemon=True)
    writer = threading.Thread(target=write, daemon=True)
    try:
        resolver.start()
        assert snapshot_paused.wait(timeout=2)
        writer.start()
        assert writer_done.wait(timeout=0.2) is False
    finally:
        continue_resolution.set()
        resolver.join(timeout=2)
        writer.join(timeout=2)

    assert resolver.is_alive() is False
    assert writer.is_alive() is False
    assert resolver_result['value'] == ('echo old', None)
