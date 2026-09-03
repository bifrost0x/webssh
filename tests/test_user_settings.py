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
        assert user_settings.get_user_settings(user_id)['confirm_session_close'] is False
        assert user_settings.get_user_settings(user_id)['disconnect_session_action'] == 'retry'


def test_legacy_user_without_close_preference_keeps_confirmation_enabled(app):
    from app import user_settings
    from app.models import User, db

    with app.app_context():
        user = User(
            username='legacy-settings-store-user',
            password_hash='unused',
            settings_default_generation=0,
        )
        db.session.add(user)
        db.session.commit()

        settings = user_settings.get_user_settings(user.id)

        assert settings['confirm_session_close'] is True
        assert settings['disconnect_session_action'] == 'retry'


@pytest.mark.parametrize('value', [False, True])
def test_close_confirmation_setting_accepts_only_booleans(value):
    from app import user_settings

    assert user_settings._valid_settings_update({
        'confirm_session_close': value,
    }) is True


@pytest.mark.parametrize('value', [None, 0, 1, 'false', [], {}])
def test_close_confirmation_setting_rejects_non_booleans(value):
    from app import user_settings

    assert user_settings._valid_settings_update({
        'confirm_session_close': value,
    }) is False


def test_close_confirmation_socket_event_returns_acknowledgement(monkeypatch):
    from types import SimpleNamespace
    from app import socket_events

    saved = []
    monkeypatch.setattr(socket_events, 'emit', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        socket_events,
        'save_user_settings',
        lambda user_id, update: saved.append((user_id, update)) or True,
    )

    response = socket_events.handle_set_confirm_session_close.__wrapped__(
        {'enabled': False},
        current_user=SimpleNamespace(id=17),
    )

    assert response == {
        'success': True,
        'confirm_session_close': False,
    }
    assert saved == [(17, {'confirm_session_close': False})]


def test_theme_socket_event_accepts_rack_console(monkeypatch):
    from types import SimpleNamespace
    from app import socket_events

    emitted = []
    saved = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, payload: emitted.append((event, payload)),
    )
    monkeypatch.setattr(
        socket_events,
        'save_user_settings',
        lambda user_id, update: saved.append((user_id, update)) or True,
    )

    socket_events.handle_set_theme.__wrapped__(
        {'theme': 'rack-console'},
        current_user=SimpleNamespace(id=17),
    )

    assert saved == [(17, {'theme': 'rack-console'})]
    assert emitted == [('theme_updated', {'theme': 'rack-console'})]


@pytest.mark.parametrize('payload', [None, {}, {'enabled': 'false'}, {'enabled': 0}])
def test_close_confirmation_socket_event_rejects_malformed_values(
    payload,
    monkeypatch,
):
    from types import SimpleNamespace
    from app import socket_events

    monkeypatch.setattr(socket_events, 'emit', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        socket_events,
        'save_user_settings',
        lambda *_args, **_kwargs: pytest.fail('invalid values must not be saved'),
    )

    response = socket_events.handle_set_confirm_session_close.__wrapped__(
        payload,
        current_user=SimpleNamespace(id=17),
    )

    assert response == {
        'success': False,
        'error': 'Invalid close confirmation setting',
    }


@pytest.mark.parametrize('value', ['retry', 'close'])
def test_disconnect_session_action_accepts_only_supported_values(value):
    from app import user_settings

    assert user_settings._valid_settings_update({
        'disconnect_session_action': value,
    }) is True


@pytest.mark.parametrize('value', [None, False, 0, '', 'remove', [], {}])
def test_disconnect_session_action_rejects_unsupported_values(value):
    from app import user_settings

    assert user_settings._valid_settings_update({
        'disconnect_session_action': value,
    }) is False


def test_disconnect_session_action_socket_event_returns_acknowledgement(monkeypatch):
    from types import SimpleNamespace
    from app import socket_events

    saved = []
    monkeypatch.setattr(socket_events, 'emit', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        socket_events,
        'save_user_settings',
        lambda user_id, update: saved.append((user_id, update)) or True,
    )

    response = socket_events.handle_set_disconnect_session_action.__wrapped__(
        {'action': 'close'},
        current_user=SimpleNamespace(id=17),
    )

    assert response == {
        'success': True,
        'disconnect_session_action': 'close',
    }
    assert saved == [(17, {'disconnect_session_action': 'close'})]


@pytest.mark.parametrize('payload', [None, {}, {'action': False}, {'action': 'remove'}])
def test_disconnect_session_action_socket_event_rejects_malformed_values(
    payload,
    monkeypatch,
):
    from types import SimpleNamespace
    from app import socket_events

    monkeypatch.setattr(socket_events, 'emit', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        socket_events,
        'save_user_settings',
        lambda *_args, **_kwargs: pytest.fail('invalid values must not be saved'),
    )

    response = socket_events.handle_set_disconnect_session_action.__wrapped__(
        payload,
        current_user=SimpleNamespace(id=17),
    )

    assert response == {
        'success': False,
        'error': 'Invalid disconnect session action',
    }
