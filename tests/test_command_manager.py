"""Strict persistence tests for the user command library."""

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
