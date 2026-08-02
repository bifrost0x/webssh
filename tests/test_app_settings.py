"""Corruption handling for application-wide runtime settings."""

import pytest

from app.storage_errors import StorageCorruptionError


def test_set_registration_preserves_corrupt_storage(tmp_path, monkeypatch):
    from app import app_settings

    path = tmp_path / 'app_settings.json'
    corrupt = b'{invalid'
    path.write_bytes(corrupt)
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)

    with pytest.raises(StorageCorruptionError) as exc_info:
        app_settings.set_registration_enabled(True)

    assert exc_info.value.path == path
    assert path.read_bytes() == corrupt


def test_missing_app_settings_store_uses_config_default(tmp_path, monkeypatch):
    from app import app_settings

    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', tmp_path / 'missing.json')
    monkeypatch.setattr(app_settings.config, 'REGISTRATION_ENABLED', True)

    assert app_settings.is_registration_enabled() is True
