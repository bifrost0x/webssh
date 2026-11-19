"""CSRF tokens stay valid for the session that issued them, not a fixed hour."""

import re
import time

import pytest
from itsdangerous import TimestampSigner


@pytest.fixture(autouse=True)
def separate_browser_contexts(app, monkeypatch):
    from flask.testing import FlaskClient

    class BrowserClient(FlaskClient):
        def open(self, *args, **kwargs):
            with app.app_context():
                return super().open(*args, **kwargs)

    monkeypatch.setattr(app, 'test_client_class', BrowserClient)


def _create_user(app, username):
    from app.auth import register_user
    with app.app_context():
        user, error = register_user(username, 'password123')
        assert error is None


def _login(app, username):
    client = app.test_client()
    assert client.post('/login', data={
        'username': username, 'password': 'password123',
    }).status_code == 302
    return client


def _page_token(client):
    response = client.get('/')
    assert response.status_code == 200
    match = re.search(rb'<meta name="csrf-token" content="([^"]+)"', response.data)
    assert match
    return match.group(1).decode()


def _save_appearance(client, token):
    return client.post(
        '/api/account/preferences',
        json={'terminal_appearance': {'cursor_blink': False}},
        headers={'X-CSRFToken': token},
    )


def test_token_from_long_open_page_still_saves(app, monkeypatch):
    _create_user(app, 'csrf_long_tab')
    client = _login(app, 'csrf_long_tab')
    token = _page_token(client)
    issued = int(time.time())
    app.config['WTF_CSRF_ENABLED'] = True
    try:
        monkeypatch.setattr(TimestampSigner, 'get_timestamp', lambda self: issued + 2 * 3600)
        response = _save_appearance(client, token)
    finally:
        app.config['WTF_CSRF_ENABLED'] = False
    assert response.status_code == 200
    assert response.json['settings']['terminal_appearance'] == {'cursor_blink': False}


def test_token_is_still_bound_to_its_session(app):
    _create_user(app, 'csrf_owner')
    _create_user(app, 'csrf_other')
    token = _page_token(_login(app, 'csrf_owner'))
    other = _login(app, 'csrf_other')
    _page_token(other)
    app.config['WTF_CSRF_ENABLED'] = True
    try:
        missing = other.post('/api/account/preferences', json={'terminal_appearance': {}})
        foreign = _save_appearance(other, token)
    finally:
        app.config['WTF_CSRF_ENABLED'] = False
    for response in (missing, foreign):
        assert response.status_code == 400
        assert response.json['code'] == 'csrf_expired'
