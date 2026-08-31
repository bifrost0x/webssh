"""Resource-boundary tests for persistent command configuration."""

import json

import pytest

from app.command_storage_policy import CommandStorageLimitError


def _create_user(app, username):
    from app.models import User, db

    with app.app_context():
        user = User(username=username, password_hash='unused')
        db.session.add(user)
        db.session.commit()
        return user.id


def _legacy_command(command_text, *, name='Legacy'):
    return {
        'id': 'legacy-command',
        'name': name,
        'command': command_text,
        'parameters': '',
        'description': 'Existing command',
        'os': ['all'],
        'category': 'custom',
    }


def test_new_oversized_command_is_rejected_without_creating_storage(app):
    from app import command_manager

    user_id = _create_user(app, 'oversized-command')
    with app.app_context():
        path = command_manager.get_user_commands_file(user_id)
        with pytest.raises(CommandStorageLimitError, match='command text'):
            command_manager.add_user_command(
                user_id,
                'Oversized',
                'x' * (16 * 1024 + 1),
                '',
                'Must be rejected',
                ['all'],
                'custom',
            )
        assert not path.exists()


def test_command_set_duplicate_cannot_cross_record_quota(app, monkeypatch):
    import config
    from app import command_set_manager

    user_id = _create_user(app, 'command-set-record-quota')
    monkeypatch.setattr(config, 'COMMAND_SET_MAX_RECORDS', 1)
    with app.app_context():
        created, error = command_set_manager.upsert_command_set(
            user_id,
            {
                'name': 'Bootstrap',
                'steps': [{'type': 'inline', 'command': 'uptime'}],
            },
        )
        assert error is None

        duplicate, error = command_set_manager.duplicate_command_set(
            user_id, created['id']
        )
        assert duplicate is None
        assert error == (
            'Command storage quota exceeded: more than 1 records are not allowed'
        )
        stored, load_error = command_set_manager.load_command_sets(user_id)
        assert load_error is None
        assert [item['id'] for item in stored] == [created['id']]


def test_legacy_oversized_command_can_shrink_or_be_deleted_but_not_grow(
    app, monkeypatch
):
    import config
    from app import command_manager

    user_id = _create_user(app, 'legacy-command-quota')
    monkeypatch.setattr(config, 'COMMAND_STORE_MAX_BYTES', 128)
    monkeypatch.setattr(config, 'COMMAND_CONFIG_MAX_BYTES', 128)
    with app.app_context():
        path = command_manager.get_user_commands_file(user_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps([_legacy_command('x' * (16 * 1024 + 1))], indent=2),
            encoding='utf-8',
        )

        with pytest.raises(CommandStorageLimitError, match='byte limit'):
            command_manager.update_user_command(
                user_id,
                'legacy-command',
                'Legacy expanded',
                'x' * (16 * 1024 + 1),
                '',
                'Existing command',
                ['all'],
                'custom',
            )
        assert command_manager.load_user_commands(user_id)[0]['name'] == 'Legacy'

        updated, error = command_manager.update_user_command(
            user_id,
            'legacy-command',
            'Legacy',
            'uptime',
            '',
            'Existing command',
            ['all'],
            'custom',
        )
        assert error is None
        assert updated['command'] == 'uptime'

        success, error, usages = command_manager.delete_user_command(
            user_id, 'legacy-command'
        )
        assert (success, error, usages) == (True, None, [])
        assert command_manager.load_user_commands(user_id) == []


def test_combined_command_configuration_quota_is_prospective(app, monkeypatch):
    import config
    from app import command_manager, command_set_manager

    user_id = _create_user(app, 'combined-command-quota')
    with app.app_context():
        command = command_manager.add_user_command(
            user_id,
            'Uptime',
            'uptime',
            '',
            'Show uptime',
            ['all'],
            'custom',
        )
        commands_path = command_manager.get_user_commands_file(user_id)
        monkeypatch.setattr(
            config,
            'COMMAND_CONFIG_MAX_BYTES',
            commands_path.stat().st_size + 1,
        )

        created, error = command_set_manager.upsert_command_set(
            user_id,
            {
                'name': 'Use uptime',
                'steps': [
                    {'type': 'library', 'command_id': command['id']}
                ],
            },
        )
        assert created is None
        assert error == (
            'Command storage quota exceeded: combined command data would '
            'exceed its byte limit'
        )
        sets, load_error = command_set_manager.load_command_sets(user_id)
        assert load_error is None
        assert sets == []
