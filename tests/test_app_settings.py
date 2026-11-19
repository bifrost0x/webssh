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


def test_gateway_requires_persisted_admin_opt_in(tmp_path, monkeypatch):
    from app import app_settings

    path = tmp_path / 'app_settings.json'
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)
    assert app_settings.is_ssh_gateway_enabled() is False
    app_settings.set_registration_enabled(False)
    assert app_settings.set_ssh_gateway_enabled(True) is True
    assert app_settings.is_ssh_gateway_enabled() is True
    assert app_settings.is_registration_enabled() is False
    assert app_settings.set_ssh_gateway_enabled(False) is False
    assert app_settings.is_ssh_gateway_enabled() is False


@pytest.mark.parametrize('value', ['true', 1, None, {}])
def test_gateway_setting_rejects_non_booleans(tmp_path, monkeypatch, value):
    from app import app_settings

    path = tmp_path / 'app_settings.json'
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)
    assert app_settings.set_ssh_gateway_enabled(value) is False
    assert not path.exists()


def test_herdr_requires_persisted_admin_opt_in(tmp_path, monkeypatch):
    from app import app_settings

    path = tmp_path / 'app_settings.json'
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)
    assert app_settings.is_herdr_enabled() is False
    app_settings.set_ssh_gateway_enabled(True)
    assert app_settings.set_herdr_enabled(True) is True
    assert app_settings.is_herdr_enabled() is True
    assert app_settings.is_ssh_gateway_enabled() is True
    assert app_settings.set_herdr_enabled(False) is False
    assert app_settings.is_herdr_enabled() is False
    assert app_settings.is_ssh_gateway_enabled() is True


@pytest.mark.parametrize('value', ['true', 1, None, {}])
def test_herdr_setting_rejects_non_booleans(tmp_path, monkeypatch, value):
    from app import app_settings

    path = tmp_path / 'app_settings.json'
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)
    assert app_settings.set_herdr_enabled(value) is False
    assert not path.exists()


def test_stored_non_boolean_herdr_setting_is_treated_as_corrupt(tmp_path, monkeypatch):
    import json
    from app import app_settings
    from app.storage_migrations import CURRENT_STORAGE_VERSIONS

    path = tmp_path / 'app_settings.json'
    document = json.dumps({
        'schema_version': CURRENT_STORAGE_VERSIONS['app_settings'],
        'herdr_enabled': 'true',
    }).encode()
    path.write_bytes(document)
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)
    with pytest.raises(StorageCorruptionError):
        app_settings.is_herdr_enabled()
    assert path.read_bytes() == document


def test_disabled_gateway_rejects_selector_but_preserves_normal_validation(tmp_path, monkeypatch):
    from app import app_settings
    from app.socket_events import _validate_ssh_params

    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', tmp_path / 'app_settings.json')
    assert _validate_ssh_params('host', 22, 'u:t', allow_gateway=True)[3]
    assert _validate_ssh_params('host', 22, ' user ', allow_gateway=True) == ('host', 22, 'user', None)


@pytest.mark.usefixtures('direct_socket_authentication')
@pytest.mark.parametrize('handler_name,event_name', [('handle_ssh_connect', 'ssh_error'), ('handle_quick_connect', 'quick_connect_error')])
def test_disabled_gateway_rejects_forged_socket_requests(app, monkeypatch, handler_name, event_name):
    from app import app_settings, socket_events, ssh_manager
    from tests.test_command_set_socket_events import create_socket_user, call_socket_handler
    _, sid = create_socket_user(app, 'gateway_disabled')
    assert app_settings.is_ssh_gateway_enabled() is False
    monkeypatch.setattr(ssh_manager, 'create_ssh_connection', lambda **kwargs: pytest.fail('Network connection attempted'))
    _, events = call_socket_handler(app, monkeypatch, getattr(socket_events, handler_name), sid, {
        'host': 'host', 'username': 'u:t', 'client_request_id': 'forged', 'gateway_interaction': 1,
    })
    errors = [payload for event, payload in events if event == event_name]
    assert len(errors) == 1
    assert 'disabled by the administrator' in errors[0]['error']
    assert not app.extensions['ssh_attempt_registry'].attempts


def test_disabled_gateway_preserves_stored_profile(app):
    from app import app_settings, profile_manager
    from tests.test_command_set_socket_events import create_socket_user
    user_id, _ = create_socket_user(app, 'stored_gateway')
    with app.app_context():
        app_settings.set_ssh_gateway_enabled(True)
        profile, error = profile_manager.add_profile(user_id, 'Gateway', 'host', 22, 'u:t', 'password')
        assert error is None
        app_settings.set_ssh_gateway_enabled(False)
        assert profile_manager.load_profiles(user_id)[0]['id'] == profile['id']
        _, error = profile_manager.add_profile(user_id, 'Blocked', 'host', 22, 'u:t', 'password')
        assert 'disabled by the administrator' in error
