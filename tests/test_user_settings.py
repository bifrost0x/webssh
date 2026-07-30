"""Corruption handling for per-user settings storage."""

import pytest

from app.storage_errors import StorageCorruptionError


def _create_user(app):
    from app.models import User, db

    with app.app_context():
        user = User(username='settings-store-user', password_hash='unused')
        db.session.add(user)
        db.session.commit()
        return user.id


def test_save_user_settings_preserves_corrupt_storage(app):
    from app import user_settings
    from app.models import User, db

    user_id = _create_user(app)
    corrupt = b'\xff'
    with app.app_context():
        path = db.session.get(User, user_id).get_data_dir() / 'settings.json'
        path.write_bytes(corrupt)

        with pytest.raises(StorageCorruptionError) as exc_info:
            user_settings.save_user_settings(user_id, {'theme': 'noir'})

        assert exc_info.value.path == path
        assert path.read_bytes() == corrupt


def test_missing_user_settings_store_keeps_defaults(app):
    from app import user_settings

    user_id = _create_user(app)
    with app.app_context():
        assert user_settings.get_user_settings(user_id) == user_settings.DEFAULT_SETTINGS
