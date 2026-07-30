"""Authorization behavior for the optional admin panel."""

import pytest


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
)

ADMIN_RULE_PATHS = (
    pytest.param('/admin', id='admin-page'),
    pytest.param('/admin/api/users', id='users'),
    pytest.param('/admin/api/users/1/lock', id='user-action'),
    pytest.param('/admin/api/audit', id='audit-log'),
    pytest.param('/admin/api/settings', id='settings'),
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


def _admin_request(client, method, path, data, target_id):
    request = getattr(client, method)
    path = path.format(target_id=target_id)
    if data is None:
        return request(path)
    return request(path, json=data)


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
        pytest.param('get', '/admin', None, 200, id='admin-page'),
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
    ),
)
def test_enabled_admin_routes_allow_administrators(
    app, client, method, path, data, expected_status
):
    target_id = _prepare_role(app, client, 'admin')

    response = _admin_request(client, method, path, data, target_id)

    assert response.status_code == expected_status


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
    )

    assert response.status_code == 400
    assert response.get_json() == {
        'error': 'Registration cannot be enabled in the production profile'
    }
    assert not path.exists()


def test_disabled_panel_hides_admin_navigation(app, client, monkeypatch):
    import config

    _prepare_role(app, client, 'admin')
    monkeypatch.setattr(config, 'ADMIN_PANEL_ENABLED', False)

    response = client.get('/')

    assert response.status_code == 200
    assert b'id="adminPanelBtn"' not in response.data


def test_enabled_panel_shows_admin_navigation_to_administrators(app, client):
    _prepare_role(app, client, 'admin')

    response = client.get('/')

    assert response.status_code == 200
    assert b'id="adminPanelBtn"' in response.data
