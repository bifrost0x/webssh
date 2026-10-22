"""The chmod setup hint follows instance configuration, not source support."""

import pytest


@pytest.mark.parametrize('enabled', [False, True])
def test_index_exposes_instance_chmod_setting(app, client, monkeypatch, enabled):
    import config
    from app.auth import register_user

    monkeypatch.setattr(config, 'SFTP_CHMOD_ENABLED', enabled)
    with app.app_context():
        _, error = register_user('chmod_hint_user', 'password123')
        assert error is None
    assert client.post('/login', data={
        'username': 'chmod_hint_user', 'password': 'password123',
    }).status_code == 302

    response = client.get('/')

    assert response.status_code == 200
    value = 'true' if enabled else 'false'
    assert f'data-sftp-chmod-enabled="{value}"'.encode() in response.data
