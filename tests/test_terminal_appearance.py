"""Per-user terminal appearance validation and persistence boundaries."""

import pytest

from app.user_settings import get_user_settings, save_user_settings


VALID_APPEARANCE = {
    'font_family': 'Cascadia Code', 'font_size': 16,
    'line_height': 1.25, 'letter_spacing': -0.5, 'font_weight': 'bold',
    'background': '#123456', 'foreground': '#abcdef',
    'cursor_color': None, 'selection_background': '#aAbBcC',
    'background_opacity': 75, 'cursor_style': 'bar', 'cursor_blink': False,
}

INVALID_APPEARANCES = [
    None, [], 'theme', {'background_image': 'https://example.com/x'},
    {'font_family': ''}, {'font_family': 'a' * 65},
    {'font_family': 'mono; color:red'}, {'font_family': '"monospace"'},
    {'font_family': 'Mönospace'}, {'font_family': 'mono\n'},
    {'font_size': True}, {'font_size': 7}, {'font_size': 33},
    {'font_size': 12.5}, {'font_size': '12'},
    {'line_height': False}, {'line_height': 0.99}, {'line_height': 2.01},
    {'line_height': float('nan')}, {'line_height': float('inf')},
    {'letter_spacing': -1.01}, {'letter_spacing': 3.01},
    {'letter_spacing': True}, {'letter_spacing': float('-inf')},
    {'font_weight': 700}, {'font_weight': []},
    {'background': 'red'}, {'foreground': '#123'}, {'cursor_color': 0},
    {'selection_background': '#12345678'},
    {'background_opacity': True}, {'background_opacity': -1},
    {'background_opacity': 101}, {'background_opacity': 50.5},
    {'cursor_style': 'beam'}, {'cursor_style': {}}, {'cursor_blink': 1},
]


def _create_user(app, username):
    from app.auth import register_user
    with app.app_context():
        user, error = register_user(username, 'password123')
        assert error is None
        return user.id


def _login(client, username):
    assert client.post('/login', data={
        'username': username, 'password': 'password123',
    }).status_code == 302


@pytest.mark.parametrize('appearance', INVALID_APPEARANCES)
def test_invalid_appearance_cannot_enter_settings_storage(appearance):
    from app.user_settings import _valid_settings_update
    assert not _valid_settings_update({'terminal_appearance': appearance})


@pytest.mark.parametrize('appearance', [
    {}, VALID_APPEARANCE,
    *({'font_family': family} for family in (
        'WebSSH JetBrains Mono', 'WebSSH Hack', 'WebSSH Fira Mono',
        'WebSSH Source Code Pro', 'JetBrainsMono Nerd Font Mono',
    )),
    {'font_family': 'theme', 'font_size': None, 'background': None},
    {'font_size': 8, 'line_height': 1, 'letter_spacing': -1,
     'background_opacity': 0, 'font_weight': 'normal', 'cursor_style': 'block'},
    {'font_size': 32, 'line_height': 2, 'letter_spacing': 3,
     'background_opacity': 100, 'cursor_style': 'underline', 'cursor_blink': True},
])
def test_appearance_persists_and_reset_preserves_other_preferences(app, appearance):
    user_id = _create_user(app, 'appearance_user')
    with app.app_context():
        assert save_user_settings(user_id, {'theme': 'noir', 'terminal_appearance': appearance})
        assert get_user_settings(user_id)['terminal_appearance'] == appearance
        assert save_user_settings(user_id, {'terminal_appearance': {}})
        settings = get_user_settings(user_id)
        assert settings['terminal_appearance'] == {}
        assert settings['theme'] == 'noir'


def test_appearance_defaults_are_independent_per_user(app):
    first = _create_user(app, 'first_appearance_user')
    second = _create_user(app, 'second_appearance_user')
    with app.app_context():
        settings = get_user_settings(first)
        assert settings.get('terminal_appearance') == {}
        settings['terminal_appearance']['font_size'] = 20
        assert get_user_settings(second)['terminal_appearance'] == {}


def test_appearance_api_requires_authentication_and_isolates_users(app, client):
    first = _create_user(app, 'first_api_user')
    second = _create_user(app, 'second_api_user')
    assert client.post('/api/account/preferences', json={
        'terminal_appearance': VALID_APPEARANCE,
    }).status_code in (302, 401)
    _login(client, 'first_api_user')
    response = client.post('/api/account/preferences', json={
        'terminal_appearance': VALID_APPEARANCE,
    })
    assert response.status_code == 200
    assert response.get_json()['settings']['terminal_appearance'] == VALID_APPEARANCE
    with app.app_context():
        assert get_user_settings(first)['terminal_appearance'] == VALID_APPEARANCE
        assert get_user_settings(second)['terminal_appearance'] == {}
    reset = client.post('/api/account/preferences', json={'terminal_appearance': {}})
    assert reset.status_code == 200
    assert reset.get_json()['settings']['terminal_appearance'] == {}


def test_invalid_appearance_api_request_does_not_partially_save(app, client):
    user_id = _create_user(app, 'invalid_api_user')
    _login(client, 'invalid_api_user')
    for appearance in INVALID_APPEARANCES:
        response = client.post('/api/account/preferences', json={
            'theme': 'noir', 'terminal_appearance': appearance,
        })
        assert response.status_code == 400
    with app.app_context():
        assert get_user_settings(user_id)['theme'] == 'glass'


def test_invalid_appearance_update_preserves_existing_file(app):
    from app.models import User, db
    user_id = _create_user(app, 'stored_appearance_user')
    with app.app_context():
        assert save_user_settings(user_id, {'terminal_appearance': VALID_APPEARANCE})
        path = db.session.get(User, user_id).get_data_dir() / 'settings.json'
        previous = path.read_bytes()
        assert not save_user_settings(user_id, {'terminal_appearance': {'font_size': True}})
        assert path.read_bytes() == previous


def test_corrupt_stored_appearance_is_not_silently_overwritten(app):
    import json
    from app.models import User, db
    from app.storage_errors import StorageCorruptionError
    from app.storage_migrations import CURRENT_STORAGE_VERSIONS
    user_id = _create_user(app, 'corrupt_appearance_user')
    with app.app_context():
        path = db.session.get(User, user_id).get_data_dir() / 'settings.json'
        corrupt = json.dumps({
            'schema_version': CURRENT_STORAGE_VERSIONS['settings'],
            'terminal_appearance': {'background': 'url(https://example.com/x)'},
        }).encode()
        path.write_bytes(corrupt)
        with pytest.raises(StorageCorruptionError):
            save_user_settings(user_id, {'terminal_appearance': {}})
        assert path.read_bytes() == corrupt


def test_index_receives_saved_terminal_appearance(app, client):
    from flask import template_rendered
    user_id = _create_user(app, 'render_appearance_user')
    with app.app_context():
        assert save_user_settings(user_id, {'terminal_appearance': VALID_APPEARANCE})
    _login(client, 'render_appearance_user')
    contexts = []
    def capture(sender, template, context, **extra):
        contexts.append(context)
    with template_rendered.connected_to(capture, app):
        assert client.get('/').status_code == 200
    assert contexts[-1].get('terminal_appearance') == VALID_APPEARANCE
