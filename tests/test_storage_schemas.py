"""Behavioral schema validation for every mutable JSON store."""

import json

import pytest

from app.storage_errors import StorageCorruptionError


def _create_user(app, username='schema_user'):
    from app.models import User, db

    with app.app_context():
        user = User(username=username, password_hash='unused')
        db.session.add(user)
        db.session.commit()
        return user.id


@pytest.mark.parametrize('items', [
    [None],
    [{}],
    [{'id': 'jump-1'}],
    [{
        'id': 'jump-1', 'name': 'Jump', 'host': 'jump.example',
        'port': '22', 'username': 'deploy', 'auth_type': 'password',
    }],
])
def test_jump_host_schema_rejects_invalid_items_without_overwrite(app, items):
    from app import jump_host_manager

    user_id = _create_user(app)
    with app.app_context():
        path = jump_host_manager._get_file(user_id)
        raw = json.dumps({'jump_hosts': items}).encode()
        path.write_bytes(raw)

        with pytest.raises(StorageCorruptionError):
            jump_host_manager.add_jump_host(
                user_id, 'New', 'new.example', 22, 'deploy', 'password'
            )

        assert path.read_bytes() == raw


@pytest.mark.parametrize('items', [
    [None],
    [{}],
    [{'id': 'key-1'}],
    [{
        'id': 'key-1', 'name': 'Key', 'filename': 'key-1.pem',
        'key_type': 'RSA', 'encrypted': 'yes',
    }],
])
def test_key_metadata_schema_rejects_invalid_items_without_overwrite(app, items):
    from app import key_manager

    user_id = _create_user(app)
    with app.app_context():
        path = key_manager.get_user_keys_file(user_id)
        raw = json.dumps({'keys': items}).encode()
        path.write_bytes(raw)

        with pytest.raises(StorageCorruptionError):
            key_manager.delete_key(user_id, 'missing')

        assert path.read_bytes() == raw


@pytest.mark.parametrize('items', [
    [None],
    [{}],
    [{'id': 'profile-1'}],
    [{'id': 'profile-1', 'name': 'Legacy', 'port': '22'}],
])
def test_profile_schema_rejects_invalid_items_without_overwrite(app, items):
    from app import profile_manager

    user_id = _create_user(app)
    with app.app_context():
        path = profile_manager.get_user_profiles_file(user_id)
        raw = json.dumps({'profiles': items}).encode()
        path.write_bytes(raw)

        with pytest.raises(StorageCorruptionError):
            profile_manager.delete_profile(user_id, 'missing')

        assert path.read_bytes() == raw


@pytest.mark.parametrize('items', [
    [None],
    [{}],
    [{'id': 'command-1'}],
    [{'id': 'command-1', 'name': 'Echo', 'command': 'echo', 'os': 'all'}],
])
def test_command_schema_rejects_invalid_items_without_overwrite(app, items):
    from app import command_manager

    user_id = _create_user(app)
    with app.app_context():
        path = command_manager.get_user_commands_file(user_id)
        raw = json.dumps(items).encode()
        path.write_bytes(raw)

        with pytest.raises(StorageCorruptionError):
            command_manager.add_user_command(
                user_id, 'New', 'uptime', '', 'Status', ['all'], 'custom'
            )

        assert path.read_bytes() == raw


@pytest.mark.parametrize('items', [
    [None],
    [{}],
    [{'id': 'set-1', 'name': 'Set'}],
    [{'id': 'set-1', 'name': 'Set', 'steps': [None]}],
])
def test_command_set_schema_rejects_invalid_items_without_overwrite(app, items):
    from app import command_set_manager

    user_id = _create_user(app)
    with app.app_context():
        path = command_set_manager._command_sets_file(user_id)
        raw = json.dumps({'command_sets': items}).encode()
        path.write_bytes(raw)

        with pytest.raises(StorageCorruptionError):
            command_set_manager.duplicate_command_set(user_id, 'missing')

        assert path.read_bytes() == raw


@pytest.mark.parametrize('document', [
    None,
    [],
    {'theme': 5},
    {'notepad': None},
])
def test_user_settings_schema_rejects_invalid_document_without_overwrite(
    app, document
):
    from app import user_settings
    from app.models import User

    user_id = _create_user(app)
    with app.app_context():
        path = User.query.get(user_id).get_data_dir() / 'settings.json'
        raw = json.dumps(document).encode()
        path.write_bytes(raw)

        with pytest.raises(StorageCorruptionError):
            user_settings.save_user_settings(user_id, {'theme': 'noir'})

        assert path.read_bytes() == raw


@pytest.mark.parametrize('document', [
    None,
    [],
    {'registration_enabled': 'yes'},
])
def test_app_settings_schema_rejects_invalid_document_without_overwrite(
    tmp_path, monkeypatch, document
):
    from app import app_settings

    path = tmp_path / 'app_settings.json'
    raw = json.dumps(document).encode()
    path.write_bytes(raw)
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)

    with pytest.raises(StorageCorruptionError):
        app_settings.set_registration_enabled(True)

    assert path.read_bytes() == raw


def test_valid_legacy_shapes_and_unknown_fields_are_preserved(app):
    from app import command_manager, command_set_manager, key_manager, profile_manager

    user_id = _create_user(app)
    with app.app_context():
        profile = {'id': 'legacy-profile', 'name': 'Legacy', 'future': {'v': 1}}
        profile_manager.save_profiles(user_id, [profile])
        assert profile_manager.load_profiles(user_id) == [profile]

        command = {
            'id': 'legacy-command', 'name': 'Echo', 'command': 'echo',
            'future': {'v': 1},
        }
        command_manager.save_user_commands(user_id, [command])
        assert command_manager.load_user_commands(user_id) == [command]

        command_set = {
            'id': 'legacy-set', 'name': 'Legacy set',
            'steps': [{'type': 'inline', 'command': 'uptime', 'future': True}],
            'future': {'v': 1},
        }
        saved, error = command_set_manager._save_command_sets(
            user_id, [command_set]
        )
        assert (saved, error) == (True, None)
        assert command_set_manager.load_command_sets(user_id) == (
            [command_set], None
        )

        key = {
            'id': 'legacy-key', 'name': 'Legacy key',
            'filename': 'legacy.pem', 'key_type': 'RSA',
            'future': {'v': 1},
        }
        assert key_manager.save_keys(user_id, [key]) is True
        assert key_manager.load_keys(user_id) == [key]


def test_all_store_writers_reject_schema_invalid_final_documents(
    app, tmp_path, monkeypatch
):
    from app import (
        app_settings, command_manager, command_set_manager,
        jump_host_manager, key_manager, profile_manager, user_settings,
    )
    from app.models import User

    user_id = _create_user(app, 'invalid-writer-input')
    with app.app_context():
        command_path = command_manager.get_user_commands_file(user_id)
        set_path = command_set_manager._command_sets_file(user_id)
        profile_path = profile_manager.get_user_profiles_file(user_id)
        jump_path = jump_host_manager._get_file(user_id)
        key_path = key_manager.get_user_keys_file(user_id)
        settings_path = User.query.get(user_id).get_data_dir() / 'settings.json'
        app_path = tmp_path / 'app_settings.json'
        monkeypatch.setattr(app_settings, '_SETTINGS_FILE', app_path)

        command_path.write_bytes(b'[]')
        set_path.write_bytes(b'{"command_sets": []}')
        profile_path.write_bytes(b'{"profiles": []}')
        jump_path.write_bytes(b'{"jump_hosts": []}')
        key_path.write_bytes(b'{"keys": []}')
        settings_path.write_bytes(b'{"theme": "glass", "notepad": ""}')
        app_path.write_bytes(b'{"registration_enabled": true}')

        before = {
            path: path.read_bytes()
            for path in (
                command_path, set_path, profile_path, jump_path, key_path,
                settings_path, app_path,
            )
        }

        assert command_manager.save_user_commands(user_id, [{}]) is False
        assert command_set_manager._save_command_sets(user_id, [{}]) == (
            False, 'Invalid command set data'
        )
        assert profile_manager.save_profiles(user_id, [{}]) is False
        assert jump_host_manager.save_jump_hosts(user_id, [{}]) is False
        assert key_manager.save_keys(user_id, [{}]) is False
        assert user_settings.save_user_settings(
            user_id, {'notepad': []}
        ) is False
        assert app_settings.set_registration_enabled('yes') is False

        assert {path: path.read_bytes() for path in before} == before
