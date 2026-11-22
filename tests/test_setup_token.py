"""A fresh instance asks for the logged setup token before creating an account."""

import pytest


@pytest.fixture
def fresh_app(app, monkeypatch):
    import config
    import app.setup_token as setup_token

    monkeypatch.setattr(setup_token, '_token', None)
    monkeypatch.setattr(config, 'DEPLOYMENT_PROFILE', 'homelab')
    monkeypatch.setattr(config, 'REGISTRATION_ENABLED', False)
    monkeypatch.setattr(config, 'BOOTSTRAP_REGISTRATION_ENABLED', True, raising=False)
    return app


def _register(client, **extra):
    return client.post('/register', data={
        'username': 'firstadmin',
        'password': 'password123',
        'confirm_password': 'password123',
        **extra,
    })


def _user_count(app):
    from app.models import User

    with app.app_context():
        return User.query.count()


@pytest.mark.parametrize('extra', [{}, {'setup_token': 'wrong-token'}, {'setup_token': ''}])
def test_first_account_needs_the_setup_token(fresh_app, extra):
    response = _register(fresh_app.test_client(), **extra)

    assert response.status_code == 200
    assert b'The setup token is missing or wrong' in response.data
    assert _user_count(fresh_app) == 0


def test_correct_setup_token_creates_the_first_administrator(fresh_app):
    from app.setup_token import current_setup_token

    client = fresh_app.test_client()
    form = client.get('/register')
    assert b'name="setup_token"' in form.data

    response = _register(client, setup_token=f' {current_setup_token()} ')

    assert response.status_code == 302
    from app.models import User
    with fresh_app.app_context():
        assert User.query.one().is_admin is True


def test_open_registration_on_an_empty_instance_also_needs_the_token(fresh_app, monkeypatch):
    import config

    monkeypatch.setattr(config, 'REGISTRATION_ENABLED', True)
    response = _register(fresh_app.test_client())

    assert b'The setup token is missing or wrong' in response.data
    assert _user_count(fresh_app) == 0


def test_existing_accounts_keep_registration_without_a_token(fresh_app, monkeypatch):
    import config
    from app.auth import register_user

    with fresh_app.app_context():
        register_user('existingadmin', 'password123')
    monkeypatch.setattr(config, 'REGISTRATION_ENABLED', True)
    client = fresh_app.test_client()

    assert b'name="setup_token"' not in client.get('/register').data
    assert _register(client).status_code == 302
    assert _user_count(fresh_app) == 2


def test_token_is_printed_only_while_no_account_exists(fresh_app, capsys):
    from app.auth import register_user
    from app.setup_token import announce_setup_token_if_unclaimed, current_setup_token

    with fresh_app.app_context():
        announce_setup_token_if_unclaimed()
        printed = capsys.readouterr().err
        assert f'WebSSH setup token: {current_setup_token()}' in printed
        # Generated once per process, not on every request.
        current_setup_token()
        assert capsys.readouterr().err == ''

    import app.setup_token as setup_token
    setup_token._token = None
    with fresh_app.app_context():
        register_user('claimed', 'password123')
        announce_setup_token_if_unclaimed()
    assert 'setup token' not in capsys.readouterr().err
