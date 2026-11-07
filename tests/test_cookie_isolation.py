"""Parallel instances must not share authentication cookies."""
import re


def test_named_session_cookie_ignores_legacy_cookie_and_keeps_csrf_enforced(app):
    from app.auth import register_user
    with app.app_context():
        _user, error = register_user('cookie_test_admin', 'Cookie-Test-Password1!')
        assert error is None
    app.config.update(
        WTF_CSRF_ENABLED=True,
        SESSION_COOKIE_NAME='webssh_review_session',
        REMEMBER_COOKIE_NAME='webssh_review_remember',
        SESSION_COOKIE_SECURE=False,
    )
    client = app.test_client()
    client.set_cookie('session', 'legacy-instance-cookie', secure=True)
    page = client.get('/login')
    assert page.status_code == 200
    token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page.get_data(as_text=True)).group(1)
    assert client.get_cookie('session').value == 'legacy-instance-cookie'
    assert client.get_cookie('webssh_review_session') is not None
    response = client.post('/login', data={
        'csrf_token': token, 'username': 'missing-user', 'password': 'Invalid-Password!',
    })
    assert response.status_code == 200
    assert 'CSRF' not in response.get_data(as_text=True)
    assert client.post('/login', data={
        'username': 'missing-user', 'password': 'Invalid-Password!',
    }).status_code == 400
    without_session = app.test_client()
    rejected = without_session.post('/login', data={
        'csrf_token': token, 'username': 'missing-user', 'password': 'Invalid-Password!',
    })
    assert rejected.status_code == 400
    assert 'CSRF session token is missing' in rejected.get_data(as_text=True)
