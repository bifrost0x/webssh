"""Strict persistence tests for the user command library."""

import io
import json

import pytest

from app.storage_errors import StorageCorruptionError


def _create_user(app):
    from app.models import User, db

    with app.app_context():
        user = User(username='command-store-user', password_hash='unused')
        db.session.add(user)
        db.session.commit()
        return user.id


def test_add_command_preserves_corrupt_storage(app):
    from app import command_manager

    user_id = _create_user(app)
    corrupt = b'['
    with app.app_context():
        path = command_manager.get_user_commands_file(user_id)
        path.write_bytes(corrupt)

        with pytest.raises(StorageCorruptionError) as exc_info:
            command_manager.add_user_command(
                user_id, 'Uptime', 'uptime', '', 'status', ['all'], 'custom'
            )

        assert exc_info.value.path == path
        assert path.read_bytes() == corrupt


def test_missing_command_store_keeps_empty_default(app):
    from app import command_manager

    user_id = _create_user(app)
    with app.app_context():
        assert command_manager.load_user_commands(user_id) == []


@pytest.mark.parametrize('version', [True, False, 1.0, 2.0, '1', [], {}])
def test_invalid_command_wrapper_version_is_never_migrated(app, version):
    from app import command_manager

    user_id = _create_user(app)
    original = json.dumps({'schema_version': version, 'commands': []}).encode('utf-8')
    with app.app_context():
        path = command_manager.get_user_commands_file(user_id)
        path.write_bytes(original)

        with pytest.raises(StorageCorruptionError):
            command_manager.load_user_commands(user_id)

        assert path.read_bytes() == original
        assert not list(path.parent.glob('commands.json.*.bak'))


@pytest.mark.parametrize('version', [1, 2])
def test_integer_command_wrapper_versions_still_migrate(app, version):
    from app import command_manager

    user_id = _create_user(app)
    original = json.dumps({'schema_version': version, 'commands': []}).encode('utf-8')
    with app.app_context():
        path = command_manager.get_user_commands_file(user_id)
        path.write_bytes(original)

        assert command_manager.load_user_commands(user_id) == []
        assert json.loads(path.read_text(encoding='utf-8')) == []
        backups = list(path.parent.glob('commands.json.*.bak'))
        assert len(backups) == 1
        assert backups[0].read_bytes() == original


@pytest.mark.parametrize('legacy', [False, True])
def test_system_command_unicode_survives_non_utf8_host_defaults(tmp_path, monkeypatch, legacy):
    from app import command_manager

    main_file = tmp_path / 'resources/system_commands.json'
    monkeypatch.setattr(command_manager.config, 'SYSTEM_COMMANDS_FILE', main_file)
    monkeypatch.setattr(command_manager.config, 'DATA_DIR', tmp_path)
    source = tmp_path / 'commands/system_commands.json' if legacy else main_file
    source.parent.mkdir(parents=True)
    expected = [{'id': 'unicode', 'name': 'Überblick', 'command': 'printf',
                 'description': 'Grüße 🌍'}]
    source.write_text(json.dumps(expected, ensure_ascii=False), encoding='utf-8')

    def ansi_default_open(path, mode='r', *args, **kwargs):
        kwargs.setdefault('encoding', 'cp1252')
        return io.open(path, mode, *args, **kwargs)

    monkeypatch.setattr(command_manager, 'open', ansi_default_open, raising=False)

    assert command_manager.load_system_commands() == expected
