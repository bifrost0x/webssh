"""Regression probes for reverse proxy prefixes (issue 257)."""
import pytest

@pytest.fixture(params=['', '/webssh', '/tools/webssh'])
def proxy_app(request, monkeypatch):
    monkeypatch.setenv('APPLICATION_ROOT', request.param or '/')
    monkeypatch.setenv('TRUSTED_PROXIES', '1')
    monkeypatch.setenv('CORS_ORIGINS', 'https://public.example')
    import config
    monkeypatch.setattr(config, 'APPLICATION_ROOT', '/', raising=False)
    app = request.getfixturevalue('app')
    return app, request.param

def headers(prefix):
    return {'X-Forwarded-Prefix': prefix, 'X-Forwarded-Proto': 'https',
            'X-Forwarded-Host': 'public.example', 'X-Forwarded-For': '203.0.113.9',
            'Origin': 'https://public.example'}

def login(app, prefix):
    from app.auth import register_user
    with app.app_context():
        user, error = register_user('prefix_user', 'password123')
        assert error is None
    client = app.test_client()
    response = client.post('/login', data={'username': 'prefix_user', 'password': 'password123'},
                           headers=headers(prefix), base_url='http://backend.local')
    cookie = client.get_cookie(app.config['SESSION_COOKIE_NAME'], domain='backend.local', path=prefix or '/')
    if cookie and prefix:
        client.set_cookie(cookie.key, cookie.value, domain='backend.local', path='/')
    return client, response

def test_password_default_redirect(proxy_app):
    app, prefix = proxy_app
    client, response = login(app, prefix)
    assert response.status_code == 302
    assert response.location == prefix + '/'

def test_engineio_observes_same_public_context(proxy_app, monkeypatch):
    import app as app_module
    app, prefix = proxy_app
    client, response = login(app, prefix)
    observed = []
    original = app_module._engineio_admission_user
    def capture(app, environ):
        observed.append((environ.get('SCRIPT_NAME'), environ.get('wsgi.url_scheme'),
                         environ.get('HTTP_HOST'), environ.get('REMOTE_ADDR')))
        return original(app, environ)
    monkeypatch.setattr(app_module, '_engineio_admission_user', capture)
    response = client.get('/socket.io/?EIO=4&transport=polling', headers=headers(prefix),
                          base_url='http://backend.local', environ_overrides={'REMOTE_ADDR': '10.0.0.2'})
    assert response.status_code == 200, response.get_data(as_text=True)
    assert observed == [(prefix, 'https', 'public.example', '203.0.113.9')]


@pytest.mark.parametrize('target, expected', [
    ('/', '/'), ('/admin?tab=users', '/admin?tab=users'),
    ('/webssh-other?q=1', '/webssh-other?q=1'),
    ('//evil.example', '/'), ('https://evil.example', '/'),
    ('/bad\\path', '/'), ('/bad#fragment', '/'), ('/bad\npath', '/'),
])
def test_public_continuation(proxy_app, target, expected):
    from app.auth_redirects import public_continuation
    app, prefix = proxy_app
    with app.test_request_context('/', environ_overrides={'SCRIPT_NAME': prefix}):
        assert public_continuation(target) == prefix + expected
        assert public_continuation(prefix + expected) == prefix + expected


def test_admission_diagnostics_are_bounded_and_do_not_log_session_data(proxy_app, monkeypatch):
    import app as app_module
    app, prefix = proxy_app
    events = []
    monkeypatch.setattr(app_module, 'log_warning', lambda message, **data: events.append((message, data)))
    client = app.test_client()
    for _ in range(3):
        response = client.get('/socket.io/?EIO=4&transport=polling', headers=headers(prefix))
        assert response.status_code == 401
    assert events == [('Engine.IO transport admission rejected', {'reason': 'authentication'})]


@pytest.mark.parametrize('trust', [0, 1, 2])
def test_http_and_engineio_apply_the_same_trust_depth(request, monkeypatch, trust):
    from flask import jsonify, request as http_request
    import config
    import app as app_module
    monkeypatch.setenv('TRUSTED_PROXIES', str(trust))
    monkeypatch.setenv('APPLICATION_ROOT', '')
    monkeypatch.setattr(config, 'APPLICATION_ROOT', '/', raising=False)
    app = request.getfixturevalue('app')
    observed = []
    def context(environ):
        return [environ.get(key) for key in ('SCRIPT_NAME', 'wsgi.url_scheme', 'HTTP_HOST', 'REMOTE_ADDR')]
    @app.route('/proxy-context')
    def proxy_context():
        return jsonify(context(http_request.environ))
    def capture(_app, environ):
        observed.append(context(environ))
        return None
    monkeypatch.setattr(app_module, '_engineio_admission_user', capture)
    forwarded = {
        'X-Forwarded-Prefix': '/attacker, /tools/webssh, /inner',
        'X-Forwarded-Proto': 'ftp, https, http',
        'X-Forwarded-Host': 'attacker.example, public.example, inner.example',
        'X-Forwarded-For': '192.0.2.1, 203.0.113.9, 10.0.0.3',
    }
    client = app.test_client()
    kwargs = {'headers': forwarded, 'base_url': 'http://backend.local',
              'environ_overrides': {'REMOTE_ADDR': '10.0.0.2'}}
    http = client.get('/proxy-context', **kwargs)
    client.get('/socket.io/?EIO=4&transport=polling', **kwargs)
    expected = [
        ['', 'http', 'backend.local', '10.0.0.2'],
        ['/inner', 'http', 'inner.example', '10.0.0.3'],
        ['/tools/webssh', 'https', 'public.example', '203.0.113.9'],
    ][trust]
    assert http.get_json() == expected
    assert observed == [expected]


@pytest.fixture
def proxy_browser(proxy_app):
    from flask.testing import FlaskClient
    app, prefix = proxy_app
    class ProxyClient(FlaskClient):
        def open(self, *args, **kwargs):
            kwargs.setdefault('headers', {}).update(headers(prefix))
            kwargs.setdefault('base_url', 'http://backend.local')
            return super().open(*args, **kwargs)

        def session_transaction(self, *args, **kwargs):
            kwargs.setdefault('base_url', 'http://backend.local')
            return super().session_transaction(*args, **kwargs)

        def _add_cookies_to_wsgi(self, environ):
            # The browser selects cookies on the public path before the proxy
            # strips it. Preserve the production cookie path in these tests.
            path = environ['PATH_INFO']
            environ['PATH_INFO'] = prefix + path
            try:
                super()._add_cookies_to_wsgi(environ)
            finally:
                environ['PATH_INFO'] = path
    app.test_client_class = ProxyClient
    return app.test_client()


@pytest.mark.parametrize('factor', ['totp', 'recovery', 'passkey'])
def test_second_factor_returns_a_public_continuation(proxy_app, proxy_browser, monkeypatch, factor):
    import base64
    import config
    import pyotp
    from types import SimpleNamespace
    from app.auth import register_user
    from app.models import User, TOTPAuthenticator, WebAuthnCredential, SecurityFeatureState, db
    from app.mfa_crypto import encrypt_totp_secret
    from app.recovery_service import generate_codes
    import app.webauthn_routes as webauthn_routes
    app, prefix = proxy_app
    secret = pyotp.random_base32()
    credential_id = b'prefix-passkey'
    monkeypatch.setattr(config, 'TOTP_ENABLED', True)
    monkeypatch.setattr(config, 'WEBAUTHN_ENABLED', True)
    with app.app_context():
        user, error = register_user('factor_user', 'password123')
        assert error is None
        user.mfa_enabled = True
        db.session.merge(SecurityFeatureState(feature='totp', enabled=True))
        db.session.merge(SecurityFeatureState(feature='passkey', enabled=True))
        db.session.add(TOTPAuthenticator(user_id=user.id, encrypted_secret=encrypt_totp_secret(user.id, secret), label='Test', active=True))
        db.session.add(WebAuthnCredential(user_id=user.id, credential_id=credential_id, public_key=b'test-key', sign_count=0, transports='[]', name='Test'))
        code = generate_codes(user.id, count=1)[0]
        db.session.commit()
    client = proxy_browser
    response = client.post('/login', query_string={'next': prefix + '/admin?tab=users'},
                           data={'username': 'factor_user', 'password': 'password123'})
    assert response.status_code == 200
    if factor == 'totp':
        response = client.post('/api/totp/auth/verify', json={'code': pyotp.TOTP(secret).now()})
    elif factor == 'recovery':
        response = client.post('/api/auth/recovery', json={'code': code})
    else:
        monkeypatch.setattr(webauthn_routes, 'verify_authentication_response',
                            lambda **kwargs: SimpleNamespace(new_sign_count=1))
        assert client.post('/api/webauthn/auth/options', json={}).status_code == 200
        encoded = base64.urlsafe_b64encode(credential_id).decode().rstrip('=')
        response = client.post('/api/webauthn/auth/verify', json={'credential': {'id': encoded}})
    assert response.status_code == 200, response.get_data(as_text=True)
    expected = prefix + ('/security' if factor == 'recovery' else '/admin?tab=users')
    assert response.get_json()['continuation'] == expected


def test_github_callback_preserves_public_prefix(proxy_app, proxy_browser, monkeypatch):
    from tests.test_github_auth_routes import _create_user, _configure, _provider, _begin_login
    from app.models import GitHubIdentity, db
    app, prefix = proxy_app
    admin_id = _create_user(app, 'github_admin', is_admin=True)
    user_id = _create_user(app, 'github_user')
    from app.github_auth_service import update_settings
    with app.app_context():
        update_settings({'enabled': True, 'client_id': 'Iv1234567890abcdef',
                         'client_secret': 'a' * 40,
                         'redirect_uri': 'https://public.example' + prefix + '/auth/github/callback',
                         'auto_provision': False, 'allowed_orgs': []}, admin_id)
    with app.app_context():
        db.session.add(GitHubIdentity(user_id=user_id, github_user_id='12345', login='old-name'))
        db.session.commit()
    state = _begin_login(proxy_browser)
    _provider(monkeypatch)
    response = proxy_browser.get('/auth/github/callback', query_string={'code': 'code', 'state': state})
    assert response.status_code == 302
    assert response.location == prefix + '/'


def test_oidc_callback_preserves_public_prefix(proxy_app, proxy_browser, monkeypatch):
    import config
    import app.oidc_routes as routes
    from tests.test_oidc_routes import _create_user, _prepare_oidc_callback, _signed_provider
    app, prefix = proxy_app
    monkeypatch.setattr(config, 'OIDC_ENABLED', True)
    monkeypatch.setattr(config, 'OIDC_ISSUER', 'https://issuer.example')
    monkeypatch.setattr(config, 'OIDC_ALLOWED_SUBJECTS', set())
    monkeypatch.setattr(config, 'OIDC_ALLOWED_DOMAINS', set())
    user_id = _create_user(app, 'oidc_user')
    _prepare_oidc_callback(app, proxy_browser, user_id, state='prefix-state', subject='prefix-subject')
    monkeypatch.setattr(routes, '_client', lambda: _signed_provider('prefix-state',
                        {'iss': 'https://issuer.example', 'sub': 'prefix-subject'}))
    response = proxy_browser.get('/oidc/callback?state=prefix-state')
    assert response.status_code == 302
    assert response.location == prefix + '/'



def test_wrong_origin_is_rejected_without_weakening_authentication(proxy_app):
    app, prefix = proxy_app
    client, _response = login(app, prefix)
    forwarded = headers(prefix)
    forwarded['Origin'] = 'https://wrong.example'
    response = client.get('/socket.io/?EIO=4&transport=polling', headers=forwarded,
                          base_url='http://backend.local')
    assert response.status_code == 400


def test_unstripped_prefix_is_not_a_backend_socketio_route(proxy_app):
    app, prefix = proxy_app
    if not prefix:
        return
    client, _response = login(app, prefix)
    response = client.get(prefix + '/socket.io/?EIO=4&transport=polling', headers=headers(prefix),
                          base_url='http://backend.local')
    assert response.status_code == 404
