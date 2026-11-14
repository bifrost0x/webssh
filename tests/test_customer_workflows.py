import pytest
from tests.test_automation_service import context


def test_customer_endpoints_require_authentication(client):
    for path in ('/api/account/workspace-presets', '/api/account/recovery-check'):
        assert client.get(path).status_code in (302, 401)


def test_presets_roundtrip_and_reject_foreign_hosts(app, client, context):
    uid, _, _, profile = context
    preset = {'id': 'daily', 'name': 'Daily work', 'layout': 2, 'profile_ids': [profile['id']]}
    response = client.put('/api/account/workspace-presets', json={'presets': [preset]})
    assert response.status_code == 200
    assert response.json['presets'] == [preset]
    assert client.get('/api/account/workspace-presets').json['presets'] == [preset]
    assert client.put('/api/account/workspace-presets', json={'presets': [{**preset, 'profile_ids': ['foreign']}]}).status_code == 400
    assert client.get('/api/account/workspace-presets').json['presets'] == [preset]
    from app.auth import register_user
    with app.app_context():
        other, error = register_user('other_preset_owner', 'password123')
        assert error is None
        from app.user_settings import get_user_settings
        assert get_user_settings(other.id).get('workspace_presets', []) == []


@pytest.mark.parametrize('value', [None, {}, 'x', [{'id': 'x', 'name': 'n', 'layout': True, 'profile_ids': []}], [{'id': 'x', 'name': 'n', 'layout': 1, 'profile_ids': [], 'password': 'bad'}]])
def test_presets_reject_invalid_storage_updates(app, context, value):
    from app.user_settings import save_user_settings
    assert save_user_settings(context[0], {'workspace_presets': value}) is False


def test_recovery_check_only_owned_metadata(app, client, context, monkeypatch):
    uid, _, _, profile = context
    from app.auth import register_user
    from app.profile_manager import add_profile
    from app.key_manager import load_keys
    with app.app_context():
        other, _ = register_user('other_recovery_owner', 'password123')
        add_profile(other.id, 'PRIVATE-HOST-NAME', 'private.example', 22, 'private-user', 'password')
    response = client.get('/api/account/recovery-check')
    assert response.status_code == 200
    assert response.headers['Cache-Control'] == 'no-store'
    assert 'PRIVATE-HOST-NAME' not in response.get_data(as_text=True)
    assert 'private.example' not in response.get_data(as_text=True)
    assert response.json['coverage']['remote_credentials'] == 'excluded'
    assert response.json['hosts'][0]['id'] == profile['id']
    assert response.json['hosts'][0]['credential'] == 'password_required'
    assert 'secret' not in response.get_data(as_text=True).lower()


def test_normal_restore_marks_recovery_but_internal_rollback_does_not(tmp_path, monkeypatch):
    from app import backup_manager
    import json
    monkeypatch.setattr(backup_manager, '_restore_archive', lambda *a, **k: 'restored')
    assert backup_manager.restore_backup('fixture.zip', tmp_path) == 'restored'
    marker = json.loads((tmp_path / 'recovery-check.json').read_text())
    assert marker['remote_credentials_excluded'] is True
    assert marker['restored_at']
    before = (tmp_path / 'recovery-check.json').read_bytes()
    backup_manager._restore_recovery_snapshot('fixture.zip', tmp_path)
    assert (tmp_path / 'recovery-check.json').read_bytes() == before


def test_deleted_host_does_not_block_unrelated_preset_changes(app, client, context, monkeypatch):
    _, _, _, profile = context
    old = {'id': 'old', 'name': 'Old server', 'layout': 1, 'profile_ids': [profile['id']]}
    assert client.put('/api/account/workspace-presets', json={'presets': [old]}).status_code == 200
    from app import profile_manager
    monkeypatch.setattr(profile_manager, 'load_profiles', lambda user_id: [])
    new = {'id': 'new', 'name': 'Empty layout', 'layout': 2, 'profile_ids': []}
    assert client.put('/api/account/workspace-presets', json={'presets': [old, new]}).status_code == 200
    assert client.put('/api/account/workspace-presets', json={'presets': [old]}).status_code == 200
    assert client.put('/api/account/workspace-presets', json={'presets': [old, {**new, 'profile_ids': [profile['id']]}]}).status_code == 400
