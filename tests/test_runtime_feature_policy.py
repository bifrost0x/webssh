import pytest
from tests.test_admin_routes import _prepare_role
from tests.step_up_helpers import password_step_up_headers

@pytest.mark.parametrize('name,key',[('sftp_chmod_enabled','SFTP_CHMOD_ENABLED'),('server_operations_enabled','SERVER_OPERATIONS_ENABLED'),('tmux_enabled','TMUX_ENABLED'),('tmux_default','TMUX_DEFAULT')])
def test_runtime_policy_preserves_explicit_values_and_saved_admin_choice(app, client, monkeypatch, name, key):
    import config
    from app.app_settings import runtime_feature_status, set_runtime_feature, migrate_runtime_features
    _prepare_role(app,client,'admin')
    monkeypatch.setattr(config,'EXPLICIT_ENVIRONMENT_KEYS',frozenset())
    set_runtime_feature(name,False)
    monkeypatch.setattr(config,key,True)
    monkeypatch.setattr(config,'EXPLICIT_ENVIRONMENT_KEYS',frozenset({key}))
    assert runtime_feature_status(name)['enabled'] is True
    headers=password_step_up_headers(client,'settings.update','global')[0]
    result=client.post('/admin/api/settings',json={name:False,'credentials_enabled':True},headers=headers)
    assert result.status_code==409
    assert client.get('/admin/api/settings').json['credentials_enabled'] is False
    migrate_runtime_features()
    monkeypatch.setattr(config,'EXPLICIT_ENVIRONMENT_KEYS',frozenset())
    assert runtime_feature_status(name)['enabled'] is False
    headers=password_step_up_headers(client,'settings.update','global')[0]
    assert client.post('/admin/api/settings',json={name:True},headers=headers).status_code==200
    assert runtime_feature_status(name)['enabled'] is True

@pytest.mark.parametrize('enabled',[True,False])
@pytest.mark.parametrize('name,key', [('tmux_enabled','TMUX_ENABLED'),('tmux_default','TMUX_DEFAULT'),('server_operations_enabled','SERVER_OPERATIONS_ENABLED'),('sftp_chmod_enabled','SFTP_CHMOD_ENABLED')])
def test_legacy_compose_value_survives_removing_override(app,monkeypatch,enabled,name,key):
    import config
    from app import app_settings
    monkeypatch.setattr(config,key,enabled)
    monkeypatch.setattr(config,'EXPLICIT_ENVIRONMENT_KEYS',frozenset({key}))
    app_settings.migrate_runtime_features()
    monkeypatch.setattr(config,'EXPLICIT_ENVIRONMENT_KEYS',frozenset())
    monkeypatch.setattr(config,key,not enabled)
    status=app_settings.runtime_feature_status(name)
    assert status['enabled'] is enabled
    assert status['migrated'] is True
    assert status['locked'] is False


def test_runtime_policy_backend_uses_admin_value(app,client,monkeypatch):
    import config
    from app.app_settings import set_runtime_feature
    _prepare_role(app,client,'admin')
    monkeypatch.setattr(config,'EXPLICIT_ENVIRONMENT_KEYS',frozenset())
    monkeypatch.setattr(config,'SERVER_OPERATIONS_ENABLED',True)
    set_runtime_feature('server_operations_enabled',False)
    assert client.post('/api/server-operations/intents',json={}).json['code']=='disabled'
    set_runtime_feature('server_operations_enabled',True)
    assert client.post('/api/server-operations/intents',json={}).json['code']!='disabled'
