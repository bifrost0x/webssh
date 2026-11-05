from tests.test_admin_routes import _prepare_role


def test_tour_requires_login(client):
    assert client.get('/api/account/tour').status_code in (302, 401)
    assert client.post('/api/account/tour', json={'state': 'completed'}).status_code in (302, 401)


def test_tour_persists_only_own_progress_and_rejects_extra_settings(app, client):
    _prepare_role(app, client, 'normal')
    before = client.get('/api/account/tour').json
    assert before['state'] == 'new'
    assert before['admin_url'] is None
    assert before['administrator'] is False
    assert client.post('/api/account/tour', json={'state': 'completed', 'theme': 'paper'}).status_code == 400
    assert client.post('/api/account/tour', json={'state': {}}).status_code == 400
    assert client.post('/api/account/tour', json={'state': 'completed', 'acknowledged': True}).status_code == 200
    assert client.get('/api/account/tour').json['state'] == 'completed'
    assert client.post('/api/account/tour', json={'state': 'completed'}).status_code == 400
    assert client.post('/api/account/tour', json={'state': 'dismissed'}).status_code == 200
    assert client.get('/api/account/tour').json['state'] == 'new'
    assert client.post('/api/account/tour', json={'state': 'new'}).status_code == 200


def test_tour_allowlists_configuration_and_uses_effective_policy(app, client, monkeypatch):
    import config
    from app.app_settings import set_automation_enabled
    _prepare_role(app, client, 'admin')
    monkeypatch.setattr(config, 'SMB_ENABLED', True)
    monkeypatch.setattr(config, 'OIDC_CLIENT_SECRET', 'must-not-appear', raising=False)
    with app.app_context():
        set_automation_enabled(True)
    response = client.get('/api/account/tour')
    assert response.status_code == 200
    assert response.headers['Cache-Control'] == 'no-store'
    assert response.json['admin_url'] == '/admin'
    facts = {item['key']: item['enabled'] for item in response.json['facts']}
    assert facts['SMB_ENABLED'] is True
    assert facts['automation_enabled'] is True
    assert 'must-not-appear' not in response.get_data(as_text=True)
    assert all(set(item) <= {'key', 'enabled', 'configured', 'source'} for item in response.json['facts'])


def test_tour_does_not_serve_local_documents(app, client):
    _prepare_role(app, client, 'normal')
    assert client.get('/help/tour/credentials.md').status_code == 404
    assert client.get('/help/tour/project-planning.md').status_code == 404
