"""Authorization behavior for the optional admin panel."""

import pytest

from tests.step_up_helpers import password_step_up_headers


ADMIN_REQUESTS = (
    pytest.param('get', '/admin/api/operations/details', None, id='operations-details'),
    pytest.param('post', '/admin/api/operations/connections/unknown/disconnect', None, id='operations-disconnect'),
    pytest.param('post', '/admin/api/operations/transfers/unknown/cancel', None, id='operations-cancel'),
    pytest.param('get', '/admin/api/operations', None, id='operations'),
    pytest.param('post', '/admin/api/settings', {'ssh_gateway_enabled': True}, id='set-gateway'),
    pytest.param('post', '/admin/api/settings', {'herdr_enabled': True}, id='set-herdr'),
    pytest.param('post', '/admin/api/settings', {'login_username_limit': 1}, id='set-sign-in-protection'),
    pytest.param('post', '/admin/api/settings', {'tailscale_ssh_restrict_tailnet_routes': False}, id='set-tailnet-restriction'),
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
    pytest.param('/admin/api/operations/details', id='operations-details'),
    pytest.param('/admin/api/operations/connections/unknown/disconnect', id='operations-disconnect'),
    pytest.param('/admin/api/operations/transfers/unknown/cancel', id='operations-cancel'),
    pytest.param('/admin/api/operations', id='operations'),
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
        assert response.headers['Location'].endswith('/settings?section=users')


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


def test_admin_settings_reports_first_invalid_boolean(
    app, client, tmp_path, monkeypatch
):
    from app import app_settings

    _prepare_role(app, client, 'admin')
    path = tmp_path / 'app_settings.json'
    original = b'{"registration_enabled": false}'
    path.write_bytes(original)
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)

    response = client.post(
        '/admin/api/settings',
        json={
            'tailscale_ssh_restrict_tailnet_routes': 'no',
            'support_links_enabled': 0,
            'herdr_enabled': 'yes',
            'ssh_gateway_enabled': None,
            'automation_enabled': [],
            'credentials_enabled': 'true',
            'registration_enabled': 'true',
        },
        headers=password_step_up_headers(
            client, 'settings.update', 'global'
        )[0],
    )

    assert response.status_code == 400
    assert response.get_json() == {
        'error': 'credentials_enabled must be a boolean'
    }
    assert path.read_bytes() == original


@pytest.mark.parametrize(('payload', 'error'), [
    (
        {'automation_enabled': 1, 'ssh_gateway_enabled': 'x'},
        'automation_enabled must be a boolean',
    ),
    (
        {'ssh_gateway_enabled': 'x', 'herdr_enabled': 'x'},
        'ssh_gateway_enabled must be a boolean',
    ),
    (
        {'herdr_enabled': 'x', 'support_links_enabled': 'x'},
        'herdr_enabled must be a boolean',
    ),
    (
        {
            'support_links_enabled': 'x',
            'tailscale_ssh_restrict_tailnet_routes': 'x',
        },
        'support_links_enabled must be a boolean',
    ),
    (
        {
            'tailscale_ssh_restrict_tailnet_routes': 'x',
            'login_username_limit': 0,
        },
        'tailscale_ssh_restrict_tailnet_routes must be a boolean',
    ),
])
def test_admin_settings_boolean_errors_keep_their_order(
    app, client, payload, error
):
    _prepare_role(app, client, 'admin')

    response = client.post(
        '/admin/api/settings',
        json=payload,
        headers=password_step_up_headers(
            client, 'settings.update', 'global'
        )[0],
    )

    assert response.status_code == 400
    assert response.get_json() == {'error': error}


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


def test_gateway_settings_require_step_up_and_persist(app, client):
    from app import app_settings
    _prepare_role(app, client, 'admin')
    assert client.get('/admin/api/settings').get_json()['ssh_gateway_enabled'] is False
    response = client.post('/admin/api/settings', json={'ssh_gateway_enabled': True})
    assert response.status_code == 403
    assert app_settings.is_ssh_gateway_enabled() is False
    for enabled in (True, False):
        response = client.post('/admin/api/settings', json={'ssh_gateway_enabled': enabled},
            headers=password_step_up_headers(client, 'settings.update', 'global')[0])
        assert response.status_code == 200
        assert response.get_json()['ssh_gateway_enabled'] is enabled
        assert app_settings.is_ssh_gateway_enabled() is enabled
        assert client.get('/admin/api/settings').get_json()['ssh_gateway_enabled'] is enabled
        assert f'name="ssh-gateway-enabled" content="{str(enabled).lower()}"'.encode() in client.get('/').data


def test_invalid_gateway_setting_does_not_change_registration(app, client):
    from app import app_settings
    _prepare_role(app, client, 'admin')
    original = app_settings.is_registration_enabled()
    response = client.post('/admin/api/settings',
        json={'ssh_gateway_enabled': 'true', 'registration_enabled': not original},
        headers=password_step_up_headers(client, 'settings.update', 'global')[0])
    assert response.status_code == 400
    assert app_settings.is_registration_enabled() is original
    assert app_settings.is_ssh_gateway_enabled() is False


def test_herdr_setting_requires_step_up_and_persists(app, client, monkeypatch):
    import app as app_module
    from app import app_settings
    _prepare_role(app, client, 'admin')
    records = []
    original_log = app_module.log_info
    monkeypatch.setattr(app_module, 'log_info', lambda message, **fields: (
        records.append((message, fields)), original_log(message, **fields)))
    assert client.get('/admin/api/settings').get_json()['herdr_enabled'] is False
    assert b'name="herdr-enabled" content="false"' in client.get('/').data
    response = client.post('/admin/api/settings', json={'herdr_enabled': True})
    assert response.status_code == 403
    assert app_settings.is_herdr_enabled() is False
    assert not records
    for enabled in (True, False):
        response = client.post('/admin/api/settings', json={'herdr_enabled': enabled},
            headers=password_step_up_headers(client, 'settings.update', 'global')[0])
        assert response.status_code == 200
        assert response.get_json()['herdr_enabled'] is enabled
        assert app_settings.is_herdr_enabled() is enabled
        assert client.get('/admin/api/settings').get_json()['herdr_enabled'] is enabled
        assert f'name="herdr-enabled" content="{str(enabled).lower()}"'.encode() in client.get('/').data
    changes = [fields for message, fields in records if message == 'Admin changed Herdr setting']
    assert [fields['herdr_enabled'] for fields in changes] == [True, False]
    assert all(fields['admin'] for fields in changes)


@pytest.mark.parametrize('value', ['true', 1, None, []])
def test_invalid_herdr_setting_is_rejected(app, client, value):
    from app import app_settings
    _prepare_role(app, client, 'admin')
    response = client.post('/admin/api/settings', json={'herdr_enabled': value},
        headers=password_step_up_headers(client, 'settings.update', 'global')[0])
    assert response.status_code == 400
    assert response.get_json() == {'error': 'herdr_enabled must be a boolean'}
    assert app_settings.is_herdr_enabled() is False


def test_invalid_field_keeps_herdr_setting_unchanged(app, client):
    from app import app_settings
    _prepare_role(app, client, 'admin')
    original = app_settings.is_registration_enabled()
    for payload in (
        {'herdr_enabled': True, 'ssh_gateway_enabled': 'true'},
        {'herdr_enabled': 'true', 'ssh_gateway_enabled': True, 'registration_enabled': not original},
    ):
        response = client.post('/admin/api/settings', json=payload,
            headers=password_step_up_headers(client, 'settings.update', 'global')[0])
        assert response.status_code == 400
        assert app_settings.is_herdr_enabled() is False
        assert app_settings.is_ssh_gateway_enabled() is False
        assert app_settings.is_registration_enabled() is original


def test_support_links_setting_requires_step_up_and_hides_the_links(app, client):
    from app import app_settings
    _prepare_role(app, client, 'admin')
    sponsor = b'href="https://github.com/bifrost0x/webssh?sponsor=1"'
    assert client.get('/admin/api/settings').get_json()['support_links_enabled'] is True
    assert sponsor in client.get('/').data
    assert b'settings-support-card' in client.get('/settings').data

    response = client.post('/admin/api/settings', json={'support_links_enabled': False})
    assert response.status_code == 403
    assert app_settings.is_support_links_enabled() is True

    for enabled in (False, True):
        response = client.post('/admin/api/settings', json={'support_links_enabled': enabled},
            headers=password_step_up_headers(client, 'settings.update', 'global')[0])
        assert response.status_code == 200
        assert response.get_json()['support_links_enabled'] is enabled
        assert app_settings.is_support_links_enabled() is enabled
        assert (sponsor in client.get('/').data) is enabled
        assert (b'settings-support-card' in client.get('/settings').data) is enabled


def test_invalid_support_links_setting_is_rejected(app, client):
    from app import app_settings
    _prepare_role(app, client, 'admin')
    response = client.post('/admin/api/settings',
        json={'support_links_enabled': 'false', 'ssh_gateway_enabled': True},
        headers=password_step_up_headers(client, 'settings.update', 'global')[0])
    assert response.status_code == 400
    assert app_settings.is_support_links_enabled() is True
    assert app_settings.is_ssh_gateway_enabled() is False
    assert app_settings.set_support_links_enabled('false') is False


@pytest.mark.parametrize(('role', 'panel', 'expected'), [
    ('admin', True, 'true'),
    ('admin', False, 'false'),
    ('normal', True, 'false'),
])
def test_workspace_marks_administrators_for_admin_setting_links(
    app, client, monkeypatch, role, panel, expected,
):
    import config

    _prepare_role(app, client, role)
    monkeypatch.setattr(config, 'ADMIN_PANEL_ENABLED', panel)
    page = client.get('/').get_data(as_text=True)
    assert f'<meta name="current-user-admin" content="{expected}">' in page


@pytest.mark.parametrize('enabled', [True, False])
def test_settings_report_whether_tailscale_ssh_is_enabled(app, client, monkeypatch, enabled):
    import config

    _prepare_role(app, client, 'admin')
    monkeypatch.setattr(config, 'TAILSCALE_SSH_ENABLED', enabled)
    assert client.get('/admin/api/settings').get_json()['tailscale_ssh_enabled'] is enabled


def test_sign_in_protection_defaults_are_reported(app, client):
    _prepare_role(app, client, 'admin')
    data = client.get('/admin/api/settings').get_json()
    assert data['login_username_limit'] == 10
    assert data['login_username_global_limit'] == 100
    assert data['ratelimit_ipv6_prefix'] == 128
    assert data['tailscale_ssh_restrict_tailnet_routes'] is True


def test_sign_in_protection_requires_step_up_and_is_audited(app, client, caplog):
    import logging
    from app import app_settings

    _prepare_role(app, client, 'admin')
    payload = {
        'login_username_limit': 7,
        'login_username_global_limit': 250,
        'ratelimit_ipv6_prefix': 56,
    }
    response = client.post('/admin/api/settings', json=payload)
    assert response.status_code == 403
    assert app_settings.sign_in_protection() == app_settings.SIGN_IN_PROTECTION_DEFAULTS

    caplog.set_level(logging.INFO, logger='security_audit')
    response = client.post('/admin/api/settings', json=payload,
        headers=password_step_up_headers(client, 'settings.update', 'global')[0])

    assert response.status_code == 200
    assert {name: response.get_json()[name] for name in payload} == payload
    assert app_settings.sign_in_protection() == payload
    assert app_settings.login_username_rate_limits() == ('7 per minute', '250 per minute')
    events = [(record.levelno, record.getMessage()) for record in caplog.records
              if record.name == 'security_audit']
    # Raising the ceiling weakens protection; the other two tighten it.
    for name, old, new, level in (('login_username_limit', 10, 7, logging.INFO),
                                  ('login_username_global_limit', 100, 250, logging.WARNING),
                                  ('ratelimit_ipv6_prefix', 128, 56, logging.INFO)):
        assert any(
            levelno == level
            and 'APPLICATION_FEATURE_CHANGED' in event and f'feature={name}' in event
            and f'previous_value={old}' in event and f'value={new}' in event
            and 'admin=adminuser' in event
            for levelno, event in events
        ), (name, events)


@pytest.mark.parametrize(('payload', 'level'), [
    ({'login_username_limit': 50}, 'WARNING'),
    ({'login_username_limit': 5}, 'INFO'),
    ({'login_username_global_limit': 500}, 'WARNING'),
    ({'login_username_global_limit': 20}, 'INFO'),
    ({'ratelimit_ipv6_prefix': 128}, 'WARNING'),
    ({'ratelimit_ipv6_prefix': 48}, 'INFO'),
])
def test_sign_in_protection_audit_level_follows_the_direction(app, client, caplog, payload, level):
    import logging
    from app import app_settings

    _prepare_role(app, client, 'admin')
    # Start from a grouped prefix so that both directions are a change.
    app_settings.update_admin_settings({'ratelimit_ipv6_prefix': 64})
    caplog.set_level(logging.INFO, logger='security_audit')
    response = client.post('/admin/api/settings', json=payload,
        headers=password_step_up_headers(client, 'settings.update', 'global')[0])
    assert response.status_code == 200
    (name,) = payload
    records = [record for record in caplog.records
               if record.name == 'security_audit' and f'feature={name}' in record.getMessage()]
    assert [record.levelname for record in records] == [level]


def test_global_limit_below_source_limit_is_rejected(app, client):
    from app import app_settings

    _prepare_role(app, client, 'admin')
    headers = password_step_up_headers(client, 'settings.update', 'global')[0]
    response = client.post('/admin/api/settings', headers=headers, json={
        'herdr_enabled': True, 'login_username_limit': 30,
        'login_username_global_limit': 20,
    })
    assert response.status_code == 400
    body = response.get_json()
    assert body['code'] == 'global_limit_below_source_limit'
    assert body['setting'] == 'login_username_global_limit'
    assert app_settings.sign_in_protection() == app_settings.SIGN_IN_PROTECTION_DEFAULTS
    assert app_settings.is_herdr_enabled() is False

    # The stored per-source limit counts when only the ceiling is sent.
    response = client.post('/admin/api/settings', json={'login_username_global_limit': 9},
        headers=password_step_up_headers(client, 'settings.update', 'global')[0])
    assert response.status_code == 400
    assert response.get_json()['code'] == 'global_limit_below_source_limit'


def test_failed_settings_write_applies_nothing(app, client, monkeypatch, caplog):
    import logging
    from app import app_settings

    _prepare_role(app, client, 'admin')
    assert app_settings.is_ssh_gateway_enabled() is False

    def fail(_target, _data):
        raise OSError('disk full')

    original_write = app_settings.atomic_write_json
    monkeypatch.setattr(app_settings, 'atomic_write_json', fail)
    caplog.set_level(logging.INFO, logger='security_audit')
    response = client.post('/admin/api/settings', json={
        'ssh_gateway_enabled': True, 'herdr_enabled': True,
        'tailscale_ssh_restrict_tailnet_routes': False,
        'login_username_limit': 3, 'credentials_enabled': True,
    }, headers=password_step_up_headers(client, 'settings.update', 'global')[0])

    assert response.status_code == 500
    assert response.get_json() == {'error': 'Settings could not be saved'}
    monkeypatch.setattr(app_settings, 'atomic_write_json', original_write)
    assert app_settings.is_ssh_gateway_enabled() is False
    assert app_settings.is_herdr_enabled() is False
    assert app_settings.is_tailnet_route_restricted() is True
    assert app_settings.sign_in_protection()['login_username_limit'] == 10
    assert app_settings.is_credentials_enabled() is False
    assert not [record for record in caplog.records
                if 'APPLICATION_FEATURE_CHANGED' in record.getMessage()]


def test_unchanged_sign_in_protection_value_is_not_audited(app, client, caplog):
    import logging

    _prepare_role(app, client, 'admin')
    caplog.set_level(logging.INFO, logger='security_audit')
    response = client.post('/admin/api/settings', json={'login_username_limit': 10},
        headers=password_step_up_headers(client, 'settings.update', 'global')[0])
    assert response.status_code == 200
    assert not [record for record in caplog.records
                if 'feature=login_username_limit' in record.getMessage()]


@pytest.mark.parametrize(('name', 'value'), [
    ('login_username_limit', 0),
    ('login_username_limit', 1001),
    ('login_username_limit', '10'),
    ('login_username_limit', 10.0),
    ('login_username_limit', True),
    ('login_username_limit', None),
    ('login_username_global_limit', 0),
    ('login_username_global_limit', 5000),
    ('ratelimit_ipv6_prefix', 47),
    ('ratelimit_ipv6_prefix', 129),
    ('ratelimit_ipv6_prefix', '64'),
])
def test_invalid_sign_in_protection_value_changes_nothing(app, client, name, value):
    from app import app_settings

    _prepare_role(app, client, 'admin')
    # A valid sibling must not be stored when another field is rejected.
    payload = {'herdr_enabled': True, 'login_username_global_limit': 500,
               'ratelimit_ipv6_prefix': 96, name: value}
    response = client.post('/admin/api/settings', json=payload,
        headers=password_step_up_headers(client, 'settings.update', 'global')[0])

    assert response.status_code == 400
    body = response.get_json()
    assert body['setting'] == name
    low, high = app_settings.SIGN_IN_PROTECTION_BOUNDS[name]
    assert (body['min'], body['max']) == (low, high)
    assert app_settings.sign_in_protection() == app_settings.SIGN_IN_PROTECTION_DEFAULTS
    assert app_settings.is_herdr_enabled() is False


def test_saved_username_limit_applies_to_the_next_login(app, client):
    _prepare_role(app, client, 'admin')
    response = client.post('/admin/api/settings', json={'login_username_limit': 2},
        headers=password_step_up_headers(client, 'settings.update', 'global')[0])
    assert response.status_code == 200
    client.post('/logout')

    limited = []
    for _attempt in range(3):
        response = client.post('/login', data={'username': 'targetuser', 'password': 'wrong'},
                               environ_base={'REMOTE_ADDR': '198.51.100.30'})
        limited.append('Too many login attempts' in response.get_data(as_text=True))
    assert limited == [False, False, True]


def test_tailnet_restriction_requires_step_up_and_is_audited(app, client, caplog):
    import logging
    from app import app_settings

    _prepare_role(app, client, 'admin')
    response = client.post('/admin/api/settings',
                           json={'tailscale_ssh_restrict_tailnet_routes': False})
    assert response.status_code == 403
    assert app_settings.is_tailnet_route_restricted() is True

    caplog.set_level(logging.INFO, logger='security_audit')
    for enabled in (False, True):
        response = client.post('/admin/api/settings',
            json={'tailscale_ssh_restrict_tailnet_routes': enabled},
            headers=password_step_up_headers(client, 'settings.update', 'global')[0])
        assert response.status_code == 200
        assert response.get_json()['tailscale_ssh_restrict_tailnet_routes'] is enabled
        assert app_settings.is_tailnet_route_restricted() is enabled
    changes = [record for record in caplog.records
               if 'feature=tailscale_ssh_restrict_tailnet_routes' in record.getMessage()]
    assert [(record.levelno, 'enabled=True' in record.getMessage()) for record in changes] == [
        (logging.WARNING, False), (logging.INFO, True)]


@pytest.mark.parametrize('name', ['registration_enabled', 'ssh_gateway_enabled'])
def test_opening_registration_or_the_gateway_is_audited_as_warning(
    app, client, caplog, monkeypatch, name
):
    import logging

    import config

    monkeypatch.setattr(config, 'REGISTRATION_ENABLED', False)
    _prepare_role(app, client, 'admin')
    caplog.set_level(logging.INFO, logger='security_audit')
    for enabled in (True, True, False):
        response = client.post('/admin/api/settings', json={name: enabled},
            headers=password_step_up_headers(client, 'settings.update', 'global')[0])
        assert response.status_code == 200
    changes = [record for record in caplog.records
               if f'feature={name}' in record.getMessage()]
    # Saving an already enabled switch again does not open anything further.
    assert [(record.levelno, f'enabled={value}' in record.getMessage())
            for record, value in zip(changes, (True, True, False))] == [
        (logging.WARNING, True), (logging.INFO, True), (logging.INFO, True)]


def test_saving_the_registration_default_is_not_audited_as_warning(
    app, client, caplog, monkeypatch
):
    import logging

    import config

    monkeypatch.setattr(config, 'REGISTRATION_ENABLED', True)
    _prepare_role(app, client, 'admin')
    caplog.set_level(logging.INFO, logger='security_audit')
    response = client.post('/admin/api/settings', json={'registration_enabled': True},
        headers=password_step_up_headers(client, 'settings.update', 'global')[0])
    assert response.status_code == 200
    levels = [record.levelno for record in caplog.records
              if 'feature=registration_enabled' in record.getMessage()]
    assert levels == [logging.INFO]


@pytest.mark.parametrize('name', ['credentials_enabled', 'automation_enabled'])
def test_unchanged_feature_policy_is_not_audited(app, client, caplog, name):
    import logging

    _prepare_role(app, client, 'admin')
    caplog.set_level(logging.INFO, logger='security_audit')
    for _ in range(2):
        response = client.post('/admin/api/settings', json={name: True},
            headers=password_step_up_headers(client, 'settings.update', 'global')[0])
        assert response.status_code == 200
    changes = [record for record in caplog.records
               if 'APPLICATION_FEATURE_CHANGED' in record.getMessage()
               and f'feature={name}' in record.getMessage()]
    assert len(changes) == 1


@pytest.mark.parametrize('value', ['false', 0, None, []])
def test_invalid_tailnet_restriction_is_rejected(app, client, value):
    from app import app_settings

    _prepare_role(app, client, 'admin')
    response = client.post('/admin/api/settings',
        json={'tailscale_ssh_restrict_tailnet_routes': value, 'login_username_limit': 3},
        headers=password_step_up_headers(client, 'settings.update', 'global')[0])
    assert response.status_code == 400
    assert response.get_json() == {
        'error': 'tailscale_ssh_restrict_tailnet_routes must be a boolean'
    }
    assert app_settings.is_tailnet_route_restricted() is True
    assert app_settings.sign_in_protection()['login_username_limit'] == 10


def test_admin_page_renders_sign_in_protection_controls(app, client):
    _prepare_role(app, client, 'admin')
    page = client.get('/settings?section=settings').get_data(as_text=True)
    for fragment in ('id="signInProtection"', 'id="signInUsernameLimit"',
                     'id="signInUsernameGlobalLimit"', 'id="signInIpv6Prefix"',
                     'id="settingTailnetRestriction"'):
        assert fragment in page


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
            'impact_approval': client.get('/admin/api/security-features/totp/impact').get_json()['approval'],
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


def test_admin_user_and_setting_changes_reach_the_security_audit_log(app, client, caplog):
    import logging

    target_id = _prepare_role(app, client, 'admin')
    caplog.set_level(logging.INFO, logger='security_audit')

    def call(method, path, action, target, payload=None):
        headers = password_step_up_headers(client, action, target)[0]
        response = getattr(client, method)(path, json=payload, headers=headers)
        assert response.status_code in (200, 201), response.get_data(as_text=True)

    call('post', '/admin/api/users', 'user.create', 'auditeduser',
         {'username': 'auditeduser', 'password': 'password123456', 'is_admin': False})
    call('post', f'/admin/api/users/{target_id}/lock', 'user.manage', f'{target_id}:lock')
    call('delete', f'/admin/api/users/{target_id}/mfa', 'user.mfa_reset', target_id,
         {'confirm_username': 'targetuser'})
    call('post', '/admin/api/settings', 'settings.update', 'global', {'herdr_enabled': True})

    events = [
        record.getMessage() for record in caplog.records
        if record.name == 'security_audit'
    ]
    for expected in (
        ('ADMIN_USER_CREATED', 'user=auditeduser', 'admin=adminuser'),
        ('ADMIN_USER_CHANGED', 'user=targetuser', 'action=lock'),
        ('ADMIN_USER_MFA_RESET', 'user=targetuser'),
        ('APPLICATION_FEATURE_CHANGED', 'feature=herdr_enabled', 'enabled=True'),
    ):
        assert any(all(part in event for part in expected) for event in events), (expected, events)


def test_admin_list_marks_config_managed_admins(app, client, monkeypatch):
    import config

    _prepare_role(app, client, 'admin')
    # Exact names of administrators only, as sync_admin_users matches them.
    monkeypatch.setattr(config, 'ADMIN_USERS', ['adminuser', 'TargetUser', 'normaluser'])

    response = client.get('/admin/api/users')

    assert response.status_code == 200
    flags = {
        user['username']: user['admin_managed_by_config']
        for user in response.get_json()['users']
    }
    assert flags == {
        'adminuser': True,
        'targetuser': False,
        'normaluser': False,
        'lockeduser': False,
    }


def test_demote_config_managed_admin_is_refused(app, client, monkeypatch):
    import config
    from app.models import User, db

    _prepare_role(app, client, 'admin')
    with app.app_context():
        listed = _create_user('listedadmin', is_admin=True)
        db.session.commit()
        listed_id = listed.id
    monkeypatch.setattr(config, 'ADMIN_USERS', ['listedadmin'])

    path = f'/admin/api/users/{listed_id}/demote'
    headers = password_step_up_headers(client, 'user.manage', f'{listed_id}:demote')[0]
    response = client.post(path, headers=headers)

    assert response.status_code == 409
    assert response.get_json() == {'error': (
        'This account is an administrator through the ADMIN_USERS setting; '
        'remove it from ADMIN_USERS and restart before demoting it'
    )}
    with app.app_context():
        assert db.session.get(User, listed_id).is_admin is True

    monkeypatch.setattr(config, 'ADMIN_USERS', [])
    headers = password_step_up_headers(client, 'user.manage', f'{listed_id}:demote')[0]
    assert client.post(path, headers=headers).status_code == 200
    with app.app_context():
        assert db.session.get(User, listed_id).is_admin is False


def test_locked_listed_admin_is_not_config_managed_and_can_be_demoted(
    app, client, monkeypatch,
):
    import config
    from app.auth import sync_admin_users
    from app.models import User, db

    _prepare_role(app, client, 'admin')
    with app.app_context():
        locked = _create_user('lockedlistedadmin', is_admin=True)
        locked.is_locked = True
        db.session.commit()
        locked_id = locked.id
    monkeypatch.setattr(config, 'ADMIN_USERS', ['adminuser', 'lockedlistedadmin'])

    listing = client.get('/admin/api/users')

    assert listing.status_code == 200
    flags = {
        user['username']: user['admin_managed_by_config']
        for user in listing.get_json()['users']
    }
    assert flags['adminuser'] is True
    assert flags['lockedlistedadmin'] is False

    path = f'/admin/api/users/{locked_id}/demote'
    headers = password_step_up_headers(client, 'user.manage', f'{locked_id}:demote')[0]
    response = client.post(path, headers=headers)

    assert response.status_code == 200
    with app.app_context():
        sync_admin_users()
        assert db.session.get(User, locked_id).is_admin is False
