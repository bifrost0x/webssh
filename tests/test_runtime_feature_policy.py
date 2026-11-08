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


@pytest.mark.parametrize('enabled', [True, False])
def test_image_only_upgrade_keeps_legacy_compose_authoritative(app, client, monkeypatch, enabled):
    import config
    from app import app_settings
    _prepare_role(app, client, 'admin')
    monkeypatch.setattr(config, 'TMUX_ENABLED', enabled)
    monkeypatch.setattr(config, 'EXPLICIT_ENVIRONMENT_KEYS', frozenset({'TMUX_ENABLED'}))
    app_settings.migrate_runtime_features()
    app_settings.migrate_runtime_features()
    policy = client.get('/admin/api/settings').json['runtime_features']['tmux_enabled']
    assert policy['enabled'] is enabled
    assert policy['saved_value'] is enabled
    assert policy['locked'] is True
    assert policy['source'] == 'compose'
    headers = password_step_up_headers(client, 'settings.update', 'global')[0]
    assert client.post('/admin/api/settings', json={'tmux_enabled': not enabled}, headers=headers).status_code == 409
    assert app_settings.runtime_feature_enabled('tmux_enabled') is enabled


def test_new_install_has_editable_tmux_without_compose_override(app, client, monkeypatch):
    import config
    _prepare_role(app, client, 'admin')
    monkeypatch.setattr(config, 'EXPLICIT_ENVIRONMENT_KEYS', frozenset())
    policy = client.get('/admin/api/settings').json['runtime_features']['tmux_enabled']
    assert policy['locked'] is False
    headers = password_step_up_headers(client, 'settings.update', 'global')[0]
    result = client.post('/admin/api/settings', json={'tmux_enabled': True}, headers=headers)
    assert result.status_code == 200
    assert result.json['runtime_features']['tmux_enabled']['enabled'] is True
    assert result.json['runtime_features']['tmux_enabled']['source'] == 'admin'


def test_registration_environment_is_only_the_initial_value(app, client, monkeypatch):
    import config
    from app.app_settings import is_registration_enabled
    _prepare_role(app, client, 'admin')
    monkeypatch.setattr(config, 'REGISTRATION_ENABLED', True)
    monkeypatch.setattr(config, 'EXPLICIT_ENVIRONMENT_KEYS', frozenset({'REGISTRATION_ENABLED'}))
    settings = client.get('/admin/api/settings').json
    assert settings['setting_sources']['registration_enabled']['locked'] is False
    headers = password_step_up_headers(client, 'settings.update', 'global')[0]
    closed = client.post('/admin/api/settings', json={'registration_enabled': False}, headers=headers)
    assert closed.status_code == 200
    assert closed.json['registration_enabled'] is False
    assert is_registration_enabled() is False


def test_production_profile_locks_registration_closed(app, client, monkeypatch):
    import config
    from app.app_settings import is_registration_enabled, native_setting_sources
    monkeypatch.setattr(config, 'DEPLOYMENT_PROFILE', 'production')
    monkeypatch.setattr(config, 'REGISTRATION_ENABLED', True)
    assert is_registration_enabled() is False
    assert native_setting_sources()['registration_enabled'] == {
        'locked': True, 'environment_key': 'REGISTRATION_ENABLED', 'source': 'production'}


def test_automation_environment_override_locks_the_admin_switch(app, client, monkeypatch):
    import config
    _prepare_role(app, client, 'admin')
    monkeypatch.setattr(config, 'AUTOMATION_ENABLED', False)
    monkeypatch.setattr(config, 'EXPLICIT_ENVIRONMENT_KEYS', frozenset({'AUTOMATION_ENABLED'}))
    headers = password_step_up_headers(client, 'settings.update', 'global')[0]
    response = client.post('/admin/api/settings', json={'automation_enabled': True}, headers=headers)
    assert response.status_code == 409
    assert response.json['code'] == 'deployment_locked'


def test_admin_toggle_does_not_revoke_again_on_restart(app):
    from app import app_settings
    app_settings.migrate_feature_policies()
    app_settings.set_automation_enabled(True)
    revision = app_settings.get_automation_policy_revision()
    app_settings.migrate_feature_policies()
    assert app_settings.get_automation_policy_revision() == revision
