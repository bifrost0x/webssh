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
