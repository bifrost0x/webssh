"""Authorization behavior for the optional admin panel."""

import pytest

from tests.step_up_helpers import password_step_up_headers


ADMIN_REQUESTS = (
    pytest.param('get', '/admin', None, id='admin-page'),
    pytest.param('get', '/admin/api/users', None, id='list-users'),
    pytest.param(
        'post',
        '/admin/api/users',
        {'username': 'createduser', 'password': 'password123'},
        id='create-user',
    ),
    pytest.param(
        'post',
        '/admin/api/users/{target_id}/unlock',
        None,
        id='user-action',
    ),
    pytest.param('get', '/admin/api/audit', None, id='audit-log'),
    pytest.param('get', '/admin/api/settings', None, id='get-settings'),
    pytest.param(
        'post',
        '/admin/api/settings',
        {'registration_enabled': True},
        id='set-settings',
    ),
    pytest.param(
        'get',
        '/admin/api/security-features',
        None,
        id='get-security-features',
    ),
    pytest.param(
        'post',
        '/admin/api/security-features/totp',
        {'enabled': False},
        id='set-security-feature',
    ),
)

ADMIN_RULE_PATHS = (
    pytest.param('/admin', id='admin-page'),
    pytest.param('/admin/api/users', id='users'),
    pytest.param('/admin/api/users/1/lock', id='user-action'),
    pytest.param('/admin/api/audit', id='audit-log'),
    pytest.param('/admin/api/settings', id='settings'),
    pytest.param('/admin/api/security-features', id='security-features'),
    pytest.param(
        '/admin/api/security-features/totp',
        id='security-feature',
    ),
)


def _create_user(username, password='password123', *, is_admin=False):
    from app.auth import register_user

    user, error = register_user(username, password)
    assert error is None
    user.is_admin = is_admin
    return user


def _login(client, username, password='password123'):
    response = client.post('/login', data={
        'username': username,
        'password': password,
    })
    assert response.status_code == 302


def _prepare_role(app, client, role):
    from app.models import db

    with app.app_context():
        admin = _create_user('adminuser', is_admin=True)
        target = _create_user('targetuser')
        normal_user = _create_user('normaluser')
        locked_user = _create_user('lockeduser')
        locked_user.is_locked = True
        db.session.commit()

        target_id = target.id
        locked_user_id = locked_user.id
        admin_username = admin.username
        normal_username = normal_user.username

    if role == 'admin':
        _login(client, admin_username)
    elif role == 'normal':
        _login(client, normal_username)
    elif role == 'locked':
        with client.session_transaction() as session:
            session['_user_id'] = str(locked_user_id)
            session['_fresh'] = True

    return target_id


def _admin_request(client, method, path, data, target_id, headers=None):
    request = getattr(client, method)
    path = path.format(target_id=target_id)
    if data is None:
        return request(path, headers=headers)
    return request(path, json=data, headers=headers)


def _mutation_step_up(client, path, data, target_id):
    resolved = path.format(target_id=target_id)
    if resolved == '/admin/api/users':
        return password_step_up_headers(client, 'user.create', data['username'])[0]
    if resolved.endswith('/unlock'):
        return password_step_up_headers(
            client, 'user.manage', f'{target_id}:unlock'
        )[0]
    if resolved == '/admin/api/settings':
        return password_step_up_headers(client, 'settings.update', 'global')[0]
    if resolved.endswith('/security-features/totp'):
        return password_step_up_headers(
            client, 'security_feature.update', 'totp'
        )[0]
    return None


def test_admin_mutations_reject_non_object_json(app, client):
    target_id = _prepare_role(app, client, 'admin')
    requests = (
        (
            'post',
            '/admin/api/users',
            password_step_up_headers(
                client, 'user.create', 'invalid-payload'
            )[0],
        ),
        (
            'post',
            '/admin/api/settings',
            password_step_up_headers(client, 'settings.update', 'global')[0],
        ),
        (
            'delete',
            f'/admin/api/users/{target_id}/mfa',
            password_step_up_headers(
                client, 'user.mfa_reset', target_id
            )[0],
        ),
    )

    responses = [
        getattr(client, method)(path, json=['unexpected'], headers=headers)
        for method, path, headers in requests
    ]

    assert [response.status_code for response in responses] == [400, 400, 400]


@pytest.mark.parametrize(
    'payload',
    (
        {'username': ['invalid'], 'password': 'password123'},
        {'username': 'new-user', 'password': ['invalid']},
        {
            'username': 'new-user',
            'password': 'password123',
            'is_admin': 'false',
        },
    ),
)
def test_admin_create_user_rejects_malformed_fields(app, client, payload):
    _prepare_role(app, client, 'admin')
    username = payload.get('username')
    target = (
        username.strip()
        if isinstance(username, str)
        else 'invalid-payload'
    )

    response = client.post(
        '/admin/api/users',
        json=payload,
        headers=password_step_up_headers(client, 'user.create', target)[0],
    )

    assert response.status_code == 400
    assert response.get_json()['error'] == 'Invalid user payload'


@pytest.mark.parametrize('role', ('anonymous', 'normal', 'locked', 'admin'))
@pytest.mark.parametrize(('method', 'path', 'data'), ADMIN_REQUESTS)
def test_every_admin_route_is_hidden_when_panel_is_disabled(
    app, client, monkeypatch, role, method, path, data
):
    import config

    target_id = _prepare_role(app, client, role)
    monkeypatch.setattr(config, 'ADMIN_PANEL_ENABLED', False)

    response = _admin_request(client, method, path, data, target_id)

    assert response.status_code == 404


@pytest.mark.parametrize('path', ADMIN_RULE_PATHS)
def test_disabled_admin_rules_hide_automatic_options(app, client, monkeypatch, path):
    import config

    monkeypatch.setattr(config, 'ADMIN_PANEL_ENABLED', False)

    response = client.options(path)

    assert response.status_code == 404


def test_disabled_admin_request_does_not_load_the_flask_login_user(
    app, client, monkeypatch
):
    import config
    from app.auth import login_manager

    def fail_if_called(_user_id):
        raise AssertionError('Flask-Login user loader must not run')

    with client.session_transaction() as session:
        session['_user_id'] = '1'
        session['_fresh'] = True
    monkeypatch.setattr(login_manager, '_user_callback', fail_if_called)
    monkeypatch.setattr(config, 'ADMIN_PANEL_ENABLED', False)

    response = client.get('/admin')

    assert response.status_code == 404


@pytest.mark.parametrize(('method', 'path', 'data'), ADMIN_REQUESTS)
def test_enabled_admin_routes_redirect_anonymous_users(app, client, method, path, data):
    response = _admin_request(client, method, path, data, target_id=1)

    assert response.status_code == 302
    assert '/login?next=' in response.headers['Location']


@pytest.mark.parametrize(('method', 'path', 'data'), ADMIN_REQUESTS)
def test_enabled_admin_routes_reject_normal_users(app, client, method, path, data):
    target_id = _prepare_role(app, client, 'normal')

    response = _admin_request(client, method, path, data, target_id)

    assert response.status_code == 403


@pytest.mark.parametrize(('method', 'path', 'data'), ADMIN_REQUESTS)
def test_enabled_admin_routes_redirect_locked_users(app, client, method, path, data):
    target_id = _prepare_role(app, client, 'locked')

    response = _admin_request(client, method, path, data, target_id)

    assert response.status_code == 302


@pytest.mark.parametrize(
    ('method', 'path', 'data', 'expected_status'),
    (
        pytest.param('get', '/admin', None, 302, id='admin-page'),
        pytest.param('get', '/admin/api/users', None, 200, id='list-users'),
        pytest.param(
            'post',
            '/admin/api/users',
            {'username': 'createduser', 'password': 'password123'},
            201,
            id='create-user',
        ),
        pytest.param(
            'post',
            '/admin/api/users/{target_id}/unlock',
            None,
            200,
            id='user-action',
        ),
        pytest.param('get', '/admin/api/audit', None, 200, id='audit-log'),
        pytest.param('get', '/admin/api/settings', None, 200, id='get-settings'),
        pytest.param(
            'post',
            '/admin/api/settings',
            {'registration_enabled': True},
            200,
            id='set-settings',
        ),
        pytest.param(
            'get',
            '/admin/api/security-features',
            None,
            200,
            id='get-security-features',
        ),
        pytest.param(
            'post',
            '/admin/api/security-features/totp',
            {'enabled': False},
            200,
            id='set-security-feature',
        ),
    ),
)
def test_enabled_admin_routes_allow_administrators(
    app, client, method, path, data, expected_status
):
    target_id = _prepare_role(app, client, 'admin')

    headers = (
        _mutation_step_up(client, path, data, target_id)
        if method == 'post'
        else None
    )
    response = _admin_request(client, method, path, data, target_id, headers)

    assert response.status_code == expected_status
    if path == '/admin':
        assert response.headers['Location'].endswith('/settings#users')


def test_admin_settings_rejects_non_boolean_without_overwriting(
    app, client, tmp_path, monkeypatch
):
    from app import app_settings

    _prepare_role(app, client, 'admin')
    path = tmp_path / 'app_settings.json'
    original = b'{"registration_enabled": false, "future": 1}'
    path.write_bytes(original)
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)

    response = client.post(
        '/admin/api/settings',
        json={'registration_enabled': 'true'},
        headers=password_step_up_headers(
            client, 'settings.update', 'global'
        )[0],
    )

    assert response.status_code == 400
    assert response.get_json() == {
        'error': 'registration_enabled must be a boolean'
    }
    assert path.read_bytes() == original


def test_production_profile_rejects_enabling_registration(
    app,
    client,
    tmp_path,
    monkeypatch,
):
    import config
    from app import app_settings

    _prepare_role(app, client, 'admin')
    path = tmp_path / 'app_settings.json'
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)
    monkeypatch.setattr(
        config,
        'DEPLOYMENT_PROFILE',
        'production',
        raising=False,
    )

    response = client.post(
        '/admin/api/settings',
        json={'registration_enabled': True},
        headers=password_step_up_headers(
            client, 'settings.update', 'global'
        )[0],
    )

    assert response.status_code == 400
    assert response.get_json() == {
        'error': 'Registration cannot be enabled in the production profile'
    }
    assert not path.exists()


def test_security_feature_status_exposes_all_supported_gates(app, client):
    _prepare_role(app, client, 'admin')

    response = client.get('/admin/api/security-features')

    assert response.status_code == 200
    features = response.get_json()['features']
    assert [feature['name'] for feature in features] == [
        'passkey',
        'totp',
        'oidc',
        'ldap',
        'recovery',
    ]
    assert all(set(feature) == {
        'name',
        'deployment_allowed',
        'ready',
        'admin_enabled',
        'active',
        'reason',
        'configuration_keys',
        'documentation_url',
    } for feature in features)


def test_admin_page_includes_security_feature_controls(app, client):
    _prepare_role(app, client, 'admin')

    response = client.get('/settings')

    assert response.status_code == 200
    assert b'id="securityFeatureList"' in response.data
    assert b'id="securityFeatureStatus"' in response.data


def test_security_feature_enable_returns_same_unavailable_reason_as_status(
    app,
    client,
):
    _prepare_role(app, client, 'admin')
    before = client.get('/admin/api/security-features').get_json()
    oidc_before = next(
        feature for feature in before['features']
        if feature['name'] == 'oidc'
    )

    response = client.post(
        '/admin/api/security-features/oidc',
        json={'enabled': True},
        headers=password_step_up_headers(
            client, 'security_feature.update', 'oidc'
        )[0],
    )

    assert response.status_code == 409
    assert response.get_json() == {
        'error': oidc_before['reason'],
        'feature': oidc_before,
    }


def test_security_feature_update_requires_a_boolean(app, client):
    from app.models import SecurityFeatureState

    _prepare_role(app, client, 'admin')

    response = client.post(
        '/admin/api/security-features/totp',
        json={'enabled': 'true'},
        headers=password_step_up_headers(
            client, 'security_feature.update', 'totp'
        )[0],
    )

    assert response.status_code == 400
    assert response.get_json() == {'error': 'enabled must be a boolean'}
    with app.app_context():
        assert SecurityFeatureState.query.filter_by(feature='totp').first() is None


def test_security_feature_update_activates_ready_totp(
    app,
    client,
    monkeypatch,
):
    import config

    _prepare_role(app, client, 'admin')
    monkeypatch.setattr(config, 'TOTP_ENABLED', True)
    app.extensions.setdefault('security_feature_readiness', {})['totp'] = (
        True,
        None,
    )

    response = client.post(
        '/admin/api/security-features/totp',
        json={'enabled': True},
        headers=password_step_up_headers(
            client, 'security_feature.update', 'totp'
        )[0],
    )

    assert response.status_code == 200
    feature = response.get_json()['feature']
    assert feature['admin_enabled'] is True
    assert feature['active'] is True
    assert feature['reason'] is None


def test_disabling_active_feature_requires_session_fallback_confirmation(
    app,
    client,
    monkeypatch,
):
    import config
    from app.models import SecurityFeatureState, db

    _prepare_role(app, client, 'admin')
    monkeypatch.setattr(config, 'TOTP_ENABLED', True)
    app.extensions.setdefault('security_feature_readiness', {})['totp'] = (
        True,
        None,
    )
    with app.app_context():
        db.session.add(SecurityFeatureState(feature='totp', enabled=True))
        db.session.commit()

    rejected = client.post(
        '/admin/api/security-features/totp',
        json={'enabled': False},
        headers=password_step_up_headers(
            client, 'security_feature.update', 'totp'
        )[0],
    )
    accepted = client.post(
        '/admin/api/security-features/totp',
        json={
            'enabled': False,
            'confirm_session_fallback': True,
        },
        headers=password_step_up_headers(
            client, 'security_feature.update', 'totp'
        )[0],
    )

    assert rejected.status_code == 409
    assert rejected.get_json()['code'] == 'session_fallback_confirmation_required'
    assert 'not be terminated' in rejected.get_json()['message']
    assert accepted.status_code == 200
    assert accepted.get_json()['feature']['active'] is False


def test_admin_mfa_reset_removes_all_factors_and_revokes_target(
    app, client, monkeypatch
):
    from app import user_lifecycle
    from app.models import (
        RecoveryCode,
        TOTPAuthenticator,
        TOTPEnrollment,
        User,
        WebAuthnCredential,
        db,
    )

    target_id = _prepare_role(app, client, 'admin')
    with app.app_context():
        target = db.session.get(User, target_id)
        original_generation = target.auth_generation
        target.mfa_enabled = True
        db.session.add_all((
            WebAuthnCredential(
                user_id=target_id,
                credential_id=b'reset-passkey',
                public_key=b'public-key',
                transports='[]',
            ),
            RecoveryCode(user_id=target_id, code_hash=b'r' * 32),
        ))
        db.session.commit()
    revoked = []
    monkeypatch.setattr(
        user_lifecycle,
        'revoke_user_access',
        lambda user_id, socketio_instance=None: revoked.append(user_id),
    )
    headers = password_step_up_headers(
        client, 'user.mfa_reset', target_id
    )[0]

    response = client.delete(
        f'/admin/api/users/{target_id}/mfa',
        json={'confirm_username': 'targetuser'},
        headers=headers,
    )

    assert response.status_code == 200
    assert revoked == [target_id]
    with app.app_context():
        target = db.session.get(User, target_id)
        assert target.mfa_enabled is False
        assert target.auth_generation == original_generation + 1
        assert WebAuthnCredential.query.filter_by(user_id=target_id).count() == 0
        assert RecoveryCode.query.filter_by(user_id=target_id).count() == 0
        assert TOTPAuthenticator.query.filter_by(user_id=target_id).count() == 0
        assert TOTPEnrollment.query.filter_by(user_id=target_id).count() == 0


def test_disabled_panel_hides_admin_navigation(app, client, monkeypatch):
    import config

    _prepare_role(app, client, 'admin')
    monkeypatch.setattr(config, 'ADMIN_PANEL_ENABLED', False)

    response = client.get('/settings')

    assert response.status_code == 200
    assert b'Administration' not in response.data
    assert b'data-tab="users"' not in response.data


def test_enabled_panel_shows_admin_navigation_to_administrators(app, client):
    _prepare_role(app, client, 'admin')

    response = client.get('/settings')

    assert response.status_code == 200
    assert b'Administration' in response.data
    assert b'data-tab="users"' in response.data
