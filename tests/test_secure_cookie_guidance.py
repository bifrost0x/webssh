"""Explain a session cookie dropped because WebSSH was opened over plain HTTP."""

import json

import pytest

from tests.test_production_config import _load_config, _production_env


GUIDANCE = 'SESSION_COOKIE_SECURE=false'


@pytest.fixture
def csrf_app(app):
    app.config.update(WTF_CSRF_ENABLED=True, SESSION_COOKIE_SECURE=True)
    return app


def _post_without_session(app, base_url, headers=None):
    return app.test_client().post(
        '/login',
        data={'csrf_token': 'x', 'username': 'someone', 'password': 'password123'},
        base_url=base_url,
        headers=headers,
    )


def test_missing_secure_cookie_over_http_names_the_cause(csrf_app):
    response = _post_without_session(csrf_app, 'http://192.168.1.20:5000')

    page = response.get_data(as_text=True)
    assert response.status_code == 400
    assert 'errors.cookieRejectedTitle' in page
    assert GUIDANCE in page
    assert 'HTTPS' in page


def test_missing_cookie_over_https_keeps_the_generic_message(csrf_app):
    response = _post_without_session(csrf_app, 'https://ssh.example.com')

    page = response.get_data(as_text=True)
    assert response.status_code == 400
    assert 'auth.formExpired' in page
    assert GUIDANCE not in page


def test_missing_cookie_behind_untrusted_tls_proxy_keeps_the_generic_message(csrf_app):
    """A TLS proxy without TRUSTED_PROXIES forwards plain HTTP; the page was HTTPS."""
    response = _post_without_session(
        csrf_app,
        'http://ssh.example.com',
        headers={'Origin': 'https://ssh.example.com'},
    )

    page = response.get_data(as_text=True)
    assert response.status_code == 400
    assert 'auth.formExpired' in page
    assert GUIDANCE not in page


def test_insecure_cookie_setting_keeps_the_generic_message(csrf_app):
    csrf_app.config['SESSION_COOKIE_SECURE'] = False
    response = _post_without_session(csrf_app, 'http://192.168.1.20:5000')

    assert GUIDANCE not in response.get_data(as_text=True)


def _homelab_warnings(**overrides):
    result = _load_config(
        _production_env(DEPLOYMENT_PROFILE='homelab', **overrides),
        'import json, config; print(json.dumps(config.SECURITY_CONFIG_WARNINGS))',
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout.splitlines()[-1])


def test_homelab_start_warns_about_implicit_secure_cookies():
    warnings = _homelab_warnings(SESSION_COOKIE_SECURE=None)

    assert any('plain HTTP' in warning and GUIDANCE in warning for warning in warnings)


@pytest.mark.parametrize('value', ['true', 'false'])
def test_explicit_cookie_setting_silences_the_http_warning(value):
    warnings = _homelab_warnings(SESSION_COOKIE_SECURE=value)

    assert not any('plain HTTP' in warning for warning in warnings)
