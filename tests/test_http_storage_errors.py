"""Safe HTTP boundaries for typed persistent-storage corruption."""


GENERIC_ERROR = 'Stored data is unreadable. Please restore or remove it.'


def _create_user(app, username, *, admin=False):
    from app.auth import register_user
    from app.models import db

    with app.app_context():
        user, error = register_user(username, 'password123')
        assert error is None
        user.is_admin = admin
        db.session.commit()
        return user.id


def _login(client, username):
    response = client.post(
        '/login',
        data={'username': username, 'password': 'password123'},
    )
    assert response.status_code == 302


def test_corrupt_user_settings_returns_safe_html_without_render_recursion(
    app, client
):
    from app.models import User, db

    user_id = _create_user(app, 'corrupt_html_settings')
    _login(client, 'corrupt_html_settings')
    corrupt = b'{private-user-setting'
    with app.app_context():
        path = db.session.get(User, user_id).get_data_dir() / 'settings.json'
        path.write_bytes(corrupt)

    response = client.get('/')

    assert response.status_code == 503
    assert response.content_type.startswith('text/html')
    assert GENERIC_ERROR.encode() in response.data
    assert corrupt not in response.data


def test_corrupt_app_settings_in_context_processor_returns_safe_html(
    app, client, tmp_path, monkeypatch
):
    from app import app_settings

    path = tmp_path / 'app_settings.json'
    corrupt = b'{private-app-setting'
    path.write_bytes(corrupt)
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)

    response = client.get('/login')

    assert response.status_code == 503
    assert response.content_type.startswith('text/html')
    assert response.data.count(GENERIC_ERROR.encode()) == 1
    assert corrupt not in response.data


def test_corrupt_app_settings_admin_api_returns_structured_json_and_safe_log(
    app, client, tmp_path, monkeypatch
):
    import app as app_package
    from app import app_settings

    _create_user(app, 'corrupt_api_admin', admin=True)
    _login(client, 'corrupt_api_admin')
    path = tmp_path / 'app_settings.json'
    corrupt = b'{private-admin-setting'
    path.write_bytes(corrupt)
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)
    logged = []
    monkeypatch.setattr(
        app_package,
        'log_error',
        lambda message, **fields: logged.append((message, fields)),
    )

    response = client.get('/admin/api/settings')

    assert response.status_code == 503
    assert response.get_json() == {
        'success': False,
        'error': GENERIC_ERROR,
        'code': 'storage_error',
    }
    assert logged == [(
        'Storage corruption detected',
        {
            'store': 'app_settings.json',
            'path': str(path),
            'reason': 'invalid JSON',
        },
    )]
    assert corrupt.decode() not in repr(logged)


def test_corrupt_app_settings_admin_post_does_not_overwrite_bytes(
    app, client, tmp_path, monkeypatch
):
    from app import app_settings

    _create_user(app, 'corrupt_post_admin', admin=True)
    _login(client, 'corrupt_post_admin')
    path = tmp_path / 'app_settings.json'
    corrupt = b'{private-post-setting'
    path.write_bytes(corrupt)
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)

    response = client.post(
        '/admin/api/settings',
        json={'registration_enabled': True},
    )

    assert response.status_code == 503
    assert response.get_json()['code'] == 'storage_error'
    assert path.read_bytes() == corrupt
