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


def test_sign_in_protection_and_tailnet_restriction_defaults(tmp_path, monkeypatch):
    from app import app_settings

    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', tmp_path / 'app_settings.json')
    assert app_settings.sign_in_protection() == {
        'login_username_limit': 10,
        'login_username_global_limit': 100,
        'ratelimit_ipv6_prefix': 64,
    }
    assert app_settings.login_username_rate_limits() == ('10 per minute', '100 per minute')
    assert app_settings.ratelimit_ipv6_prefix() == 64
    assert app_settings.is_tailnet_route_restricted() is True
    assert not (tmp_path / 'app_settings.json').exists()


def test_legacy_settings_file_without_new_fields_loads_with_defaults(tmp_path, monkeypatch):
    import json
    from app import app_settings

    path = tmp_path / 'app_settings.json'
    path.write_text(json.dumps({
        'schema_version': 1,
        'registration_enabled': False,
        'ssh_gateway_enabled': True,
    }), encoding='utf-8')
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)

    assert app_settings.sign_in_protection() == app_settings.SIGN_IN_PROTECTION_DEFAULTS
    assert app_settings.is_tailnet_route_restricted() is True
    assert app_settings.is_ssh_gateway_enabled() is True
    assert app_settings.update_admin_settings({'login_username_limit': 5})
    stored = json.loads(path.read_text(encoding='utf-8'))
    assert stored['login_username_limit'] == 5
    assert stored['ssh_gateway_enabled'] is True
    assert stored['registration_enabled'] is False
    assert 'login_username_global_limit' not in stored


@pytest.mark.parametrize(('values', 'expected'), [
    ({'login_username_limit': 0}, 'login_username_limit'),
    ({'login_username_limit': 1001}, 'login_username_limit'),
    ({'login_username_limit': True}, 'login_username_limit'),
    ({'login_username_limit': 5.0}, 'login_username_limit'),
    ({'login_username_global_limit': '100'}, 'login_username_global_limit'),
    ({'ratelimit_ipv6_prefix': 47}, 'ratelimit_ipv6_prefix'),
    ({'ratelimit_ipv6_prefix': 129}, 'ratelimit_ipv6_prefix'),
    ({'unknown_limit': 5}, 'unknown_limit'),
    ({'login_username_limit': 1, 'ratelimit_ipv6_prefix': 128}, None),
    ({'login_username_limit': 1000, 'login_username_global_limit': 1000,
      'ratelimit_ipv6_prefix': 48}, None),
])
def test_sign_in_protection_validation(tmp_path, monkeypatch, values, expected):
    from app import app_settings

    path = tmp_path / 'app_settings.json'
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)
    assert app_settings.invalid_sign_in_protection_field(values) == expected
    if expected is None:
        app_settings.update_admin_settings(values)
        assert app_settings.sign_in_protection() == {
            **app_settings.SIGN_IN_PROTECTION_DEFAULTS, **values,
        }
    else:
        with pytest.raises(app_settings.SettingsUpdateError):
            app_settings.update_admin_settings(values)
        assert not path.exists()


@pytest.mark.parametrize('value', ['false', 0, None, {}])
def test_tailnet_restriction_rejects_non_booleans(tmp_path, monkeypatch, value):
    from app import app_settings

    path = tmp_path / 'app_settings.json'
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)
    with pytest.raises(app_settings.SettingsUpdateError):
        app_settings.update_admin_settings({
            'tailscale_ssh_restrict_tailnet_routes': value,
        })
    assert not path.exists()


@pytest.mark.parametrize('document', [
    {'login_username_limit': 0},
    {'login_username_global_limit': '100'},
    {'ratelimit_ipv6_prefix': 200},
    {'tailscale_ssh_restrict_tailnet_routes': 'false'},
])
def test_stored_invalid_sign_in_values_are_treated_as_corrupt(tmp_path, monkeypatch, document):
    import json
    from app import app_settings
    from app.storage_migrations import CURRENT_STORAGE_VERSIONS

    path = tmp_path / 'app_settings.json'
    raw = json.dumps({
        'schema_version': CURRENT_STORAGE_VERSIONS['app_settings'], **document,
    }).encode()
    path.write_bytes(raw)
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)
    # Corrupt storage fails closed instead of silently falling back to defaults.
    with pytest.raises(StorageCorruptionError):
        app_settings.sign_in_protection()
    with pytest.raises(StorageCorruptionError):
        app_settings.is_tailnet_route_restricted()
    assert path.read_bytes() == raw


def test_cached_settings_follow_saves_and_external_writes(tmp_path, monkeypatch):
    import json
    from app import app_settings
    from app.storage_migrations import CURRENT_STORAGE_VERSIONS

    path = tmp_path / 'app_settings.json'
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)
    assert app_settings.is_tailnet_route_restricted() is True
    app_settings.update_admin_settings({'tailscale_ssh_restrict_tailnet_routes': False})
    assert app_settings.is_tailnet_route_restricted() is False
    app_settings.update_admin_settings({'ratelimit_ipv6_prefix': 128})
    assert app_settings.ratelimit_ipv6_prefix() == 128

    # Another process, such as the admin CLI or a restore, replaces the file.
    replacement = tmp_path / 'replacement.json'
    replacement.write_text(json.dumps({
        'schema_version': CURRENT_STORAGE_VERSIONS['app_settings'],
        'ratelimit_ipv6_prefix': 56,
        'filler': 'x' * 64,
    }), encoding='utf-8')
    replacement.replace(path)
    assert app_settings.ratelimit_ipv6_prefix() == 56
    assert app_settings.is_tailnet_route_restricted() is True

    path.unlink()
    assert app_settings.ratelimit_ipv6_prefix() == 64


def test_cached_settings_skip_the_file_read_while_unchanged(tmp_path, monkeypatch):
    from app import app_settings

    path = tmp_path / 'app_settings.json'
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)
    app_settings.update_admin_settings({'login_username_limit': 4})
    app_settings._cached_document = None
    loads = []
    original = app_settings._load
    monkeypatch.setattr(app_settings, '_load', lambda: loads.append(1) or original())
    for _ in range(5):
        assert app_settings.login_username_rate_limits()[0] == '4 per minute'
        assert app_settings.is_tailnet_route_restricted() is True
    assert len(loads) == 1


def test_cache_is_keyed_by_settings_path(tmp_path, monkeypatch):
    from app import app_settings

    first = tmp_path / 'first.json'
    second = tmp_path / 'second.json'
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', first)
    app_settings.update_admin_settings({'ratelimit_ipv6_prefix': 96})
    assert app_settings.ratelimit_ipv6_prefix() == 96
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', second)
    assert app_settings.ratelimit_ipv6_prefix() == 64


def test_global_limit_below_stored_source_limit_is_rejected(tmp_path, monkeypatch):
    from app import app_settings

    path = tmp_path / 'app_settings.json'
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)
    app_settings.update_admin_settings({'login_username_limit': 50})
    with pytest.raises(app_settings.SettingsUpdateError):
        app_settings.update_admin_settings({'login_username_global_limit': 49})
    with pytest.raises(app_settings.SettingsUpdateError):
        app_settings.update_admin_settings({'login_username_limit': 101})
    assert app_settings.sign_in_protection()['login_username_global_limit'] == 100
    app_settings.update_admin_settings({'login_username_global_limit': 50})


def test_admin_update_writes_all_changes_once_and_reports_previous_values(tmp_path, monkeypatch):
    import json
    from app import app_settings

    path = tmp_path / 'app_settings.json'
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)
    writes = []
    original_write = app_settings.atomic_write_json
    monkeypatch.setattr(app_settings, 'atomic_write_json',
                        lambda target, data: (writes.append(target), original_write(target, data)))

    results = app_settings.update_admin_settings({
        'herdr_enabled': True,
        'tailscale_ssh_restrict_tailnet_routes': False,
        'login_username_limit': 20,
        'ratelimit_ipv6_prefix': 56,
    })

    assert writes == [path]
    assert results == {
        'herdr_enabled': (None, True),
        'tailscale_ssh_restrict_tailnet_routes': (True, False),
        'login_username_limit': (10, 20),
        'ratelimit_ipv6_prefix': (64, 56),
    }
    stored = json.loads(path.read_text(encoding='utf-8'))
    assert stored['herdr_enabled'] is True
    assert stored['login_username_limit'] == 20
    assert app_settings.is_tailnet_route_restricted() is False


def test_failed_admin_update_write_changes_nothing(tmp_path, monkeypatch):
    from app import app_settings

    path = tmp_path / 'app_settings.json'
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)
    assert app_settings.set_ssh_gateway_enabled(True) is True
    before = path.read_bytes()
    assert app_settings.is_tailnet_route_restricted() is True

    def fail(_target, _data):
        raise OSError('disk full')

    monkeypatch.setattr(app_settings, 'atomic_write_json', fail)
    with pytest.raises(OSError):
        app_settings.update_admin_settings({
            'herdr_enabled': True,
            'ssh_gateway_enabled': False,
            'tailscale_ssh_restrict_tailnet_routes': False,
            'login_username_limit': 3,
        })

    assert path.read_bytes() == before
    assert app_settings.is_herdr_enabled() is False
    assert app_settings.is_ssh_gateway_enabled() is True
    assert app_settings.is_tailnet_route_restricted() is True
    assert app_settings.sign_in_protection()['login_username_limit'] == 10


def test_rejected_admin_update_combination_changes_nothing(tmp_path, monkeypatch):
    from app import app_settings

    path = tmp_path / 'app_settings.json'
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)
    with pytest.raises(app_settings.SettingsUpdateError) as raised:
        app_settings.update_admin_settings({
            'herdr_enabled': True,
            'login_username_limit': 30,
            'login_username_global_limit': 20,
        })
    assert raised.value.setting == 'login_username_global_limit'
    assert raised.value.code == 'global_limit_below_source_limit'
    with pytest.raises(app_settings.SettingsUpdateError):
        app_settings.update_admin_settings({'unknown_switch': True})
    assert not path.exists()
    assert app_settings.is_herdr_enabled() is False


def test_stored_global_limit_below_source_limit_only_blocks_limit_changes(
    tmp_path, monkeypatch
):
    import json
    from app import app_settings
    from app.storage_migrations import CURRENT_STORAGE_VERSIONS

    path = tmp_path / 'app_settings.json'
    path.write_text(json.dumps({
        'schema_version': CURRENT_STORAGE_VERSIONS['app_settings'],
        'login_username_limit': 50,
        'login_username_global_limit': 20,
    }), encoding='utf-8')
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)

    # Loading keeps working with the stored pair.
    assert app_settings.login_username_rate_limits() == (
        '50 per minute', '20 per minute',
    )
    assert app_settings.update_admin_settings({
        'herdr_enabled': True, 'ratelimit_ipv6_prefix': 56,
    }) == {'herdr_enabled': (None, True), 'ratelimit_ipv6_prefix': (64, 56)}

    with pytest.raises(app_settings.SettingsUpdateError) as raised:
        app_settings.update_admin_settings({'login_username_limit': 40})
    assert raised.value.code == 'global_limit_below_source_limit'
    assert raised.value.setting == 'login_username_limit'
    with pytest.raises(app_settings.SettingsUpdateError) as raised:
        app_settings.update_admin_settings({'login_username_global_limit': 30})
    assert raised.value.setting == 'login_username_global_limit'

    assert app_settings.update_admin_settings({'login_username_limit': 20})
    assert app_settings.login_username_rate_limits() == (
        '20 per minute', '20 per minute',
    )
    assert app_settings.is_herdr_enabled() is True
