"""Presentation-only localization preserves unknown authentication messages."""
from jinja2 import Environment, FileSystemLoader, select_autoescape


def render_messages(messages):
    environment = Environment(
        loader=FileSystemLoader('templates'),
        autoescape=select_autoescape(['html']),
    )
    template = environment.get_template('_auth_messages.html')
    return template.make_module({
        'get_flashed_messages': lambda **kwargs: messages,
    })


def test_known_messages_keep_english_fallback_and_translation_key():
    mapping = render_messages([]).flash_message_keys
    assert mapping['Invalid username or password'] == 'auth.invalidCredentials'
    for message, key in mapping.items():
        rendered = str(render_messages([('error', message)]).render_auth_messages())
        assert f'data-i18n="{key}"' in rendered
        assert message in rendered
        assert 'alert-error' in rendered


def test_unknown_provider_message_is_preserved_and_escaped():
    rendered = str(render_messages([
        ('error', 'Provider detail <img src=x onerror=alert(1)>'),
        ('message', '__proto__'),
    ]).render_auth_messages())
    assert 'data-i18n=' not in rendered
    assert '&lt;img src=x onerror=alert(1)&gt;' in rendered
    assert '<img' not in rendered
    assert '__proto__' in rendered


def test_registration_and_password_validation_messages_are_translated(app):
    # The texts must match what the server flashes, or the page stays English.
    import config
    from app.auth import validate_new_user, register_user

    mapping = render_messages([]).flash_message_keys
    with app.app_context():
        assert register_user('existing_user', 'password123')[1] is None
        flashed = [
            validate_new_user('ab', 'password123'),
            validate_new_user('bad name!', 'password123'),
            validate_new_user('EXISTING_user', 'password123'),
            validate_new_user('fresh_user', 'short'),
        ]
    assert all(message in mapping for message in flashed), flashed
    if config.MIN_PASSWORD_LENGTH == 8:
        assert 'New password must be at least 8 characters' in mapping
