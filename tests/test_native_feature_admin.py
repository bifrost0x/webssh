from tests.test_admin_routes import _prepare_role
from tests.step_up_helpers import password_step_up_headers


def test_runtime_feature_controls_require_admin_step_up_and_preserve_data(app, client):
    _prepare_role(app, client, 'admin')
    response = client.get('/admin/api/settings')
    assert response.status_code == 200
    assert response.json['credentials_enabled'] is False
    assert response.json['automation_enabled'] is False
    assert client.post('/admin/api/settings', json={'credentials_enabled': True}).status_code == 403
    headers = password_step_up_headers(client, 'settings.update', 'global')[0]
    response = client.post('/admin/api/settings', json={'credentials_enabled': True, 'automation_enabled': True}, headers=headers)
    assert response.status_code == 200
    assert response.json['credentials_enabled'] is True
    assert response.json['automation_enabled'] is True
    headers = password_step_up_headers(client, 'settings.update', 'global')[0]
    response = client.post('/admin/api/settings', json={'credentials_enabled': False}, headers=headers)
    assert response.status_code == 200
    assert response.json['automation_enabled'] is True


def test_invalid_feature_value_does_not_partially_apply(app, client):
    _prepare_role(app, client, 'admin')
    headers = password_step_up_headers(client, 'settings.update', 'global')[0]
    response = client.post('/admin/api/settings', json={'credentials_enabled': True, 'automation_enabled': 'yes'}, headers=headers)
    assert response.status_code == 400
    assert client.get('/admin/api/settings').json['credentials_enabled'] is False
