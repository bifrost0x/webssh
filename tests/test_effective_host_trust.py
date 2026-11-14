"""Effective trust must explain runtime matching without global inventory leaks."""
import json

import paramiko
import pytest

from app.host_key_store import HostKeyStore
from tests.test_host_key_routes import _create_user, _login


def line(host, key, marker=''):
    return f'{marker + " " if marker else ""}{host} {key.get_name()} {key.get_base64()}\n'


def test_effective_trust_matches_runtime_precedence_revocation_and_ports(tmp_path):
    store = HostKeyStore(1, tmp_path / 'global', tmp_path / 'users')
    personal, global_key = [paramiko.RSAKey.generate(1024) for _ in range(2)]
    store.user_path.parent.mkdir(parents=True)
    store.user_path.write_text(line('app.example', personal), encoding='utf8')
    store.global_path.write_text(line('*.example,!excluded.example', global_key)
                                 + line('[app.example]:2222', global_key)
                                 + line('blocked.example', global_key, '@revoked'), encoding='utf8')
    targets = [{'id': host + str(port), 'host': host, 'port': port} for host, port in
               [('app.example', 22), ('app.example', 2222), ('excluded.example', 22), ('blocked.example', 22)]]
    reports = store.effective_targets(targets)
    assert [(key['scope'], key['status']) for key in reports[0]['keys']] == [('user', 'effective'), ('global', 'overridden')]
    assert reports[1]['keys'][0]['scope'] == 'global'
    assert reports[2]['keys'] == []
    assert all(key['status'] == 'revoked' for key in reports[3]['keys'])
    assert reports[0]['keys'][0]['fingerprint'] != reports[0]['keys'][1]['fingerprint']
    assert '*.example' not in json.dumps(reports)
    client = paramiko.SSHClient()
    store.load_into(client)
    assert client.get_host_keys().check('app.example', personal)
    assert not client.get_host_keys().check('blocked.example', global_key)


def test_hashed_personal_key_revoked_globally_falls_back_to_unrevoked_global(tmp_path):
    store = HostKeyStore(1, tmp_path / 'global', tmp_path / 'users')
    personal, replacement = [paramiko.RSAKey.generate(1024) for _ in range(2)]
    store.user_path.parent.mkdir(parents=True)
    store.user_path.write_text(line(paramiko.HostKeys.hash_host('app.example'), personal), encoding='utf8')
    store.global_path.write_text(line('app.example', personal, '@revoked') + line('app.example', replacement), encoding='utf8')
    keys = store.effective_targets([{'host': 'app.example', 'port': 22}])[0]['keys']
    assert [(key['scope'], key['status']) for key in keys] == [('user', 'revoked'), ('global', 'effective'), ('global', 'revoked')]


def test_personal_deletion_reveals_global_trust_instead_of_revoking_it(tmp_path):
    store = HostKeyStore(1, tmp_path / 'global', tmp_path / 'users')
    personal, inherited = [paramiko.RSAKey.generate(1024) for _ in range(2)]
    store.user_path.parent.mkdir(parents=True)
    store.user_path.write_text(line('app.example', personal), encoding='utf8')
    store.global_path.write_text(line('app.example', inherited), encoding='utf8')
    target = {'host': 'app.example', 'port': 22}
    before = store.effective_targets([target])[0]['keys']
    assert store.delete_entry(store.list_entries()[0]['id'])
    after = store.effective_targets([target])[0]['keys']
    assert len(after) == 1
    assert after[0]['scope'] == 'global' and after[0]['status'] == 'effective'
    assert after[0]['fingerprint'] == before[1]['fingerprint']
    client = paramiko.SSHClient()
    store.load_into(client)
    assert client.get_host_keys().check('app.example', inherited)


def test_deletion_impact_predicts_global_fallback_and_preserves_raw_files(tmp_path):
    store = HostKeyStore(1, tmp_path / 'global', tmp_path / 'users')
    personal, inherited = [paramiko.RSAKey.generate(1024) for _ in range(2)]
    store.user_path.parent.mkdir(parents=True)
    user_raw = line('app.example,orphan.example', personal)
    global_raw = line('app.example,private-global.example', inherited)
    store.user_path.write_text(user_raw, encoding='utf8')
    store.global_path.write_text(global_raw, encoding='utf8')
    entry_id = store.list_entries()[0]['id']
    targets = [{'host': 'app.example', 'port': 22}]
    preview = store.deletion_impact(entry_id, targets)
    assert preview['unresolved'] is True
    assert len(preview['targets']) == 1
    assert [(key['scope'], key['status']) for key in preview['targets'][0]['keys']] == [('global', 'effective')]
    assert 'private-global' not in json.dumps(preview)
    assert personal.get_base64() not in json.dumps(preview)
    assert store.user_path.read_text(encoding='utf8') == user_raw
    assert store.global_path.read_text(encoding='utf8') == global_raw
    assert store.delete_entry(entry_id, expected_revision=preview['revision'])


def test_deletion_impact_handles_hashed_revocation_and_refuses_stale_preview(tmp_path):
    store = HostKeyStore(1, tmp_path / 'global', tmp_path / 'users')
    key = paramiko.RSAKey.generate(1024)
    store.user_path.parent.mkdir(parents=True)
    store.user_path.write_text(line(paramiko.HostKeys.hash_host('app.example'), key, '@revoked'), encoding='utf8')
    store.global_path.write_text(line('app.example', key), encoding='utf8')
    entry_id = store.list_entries()[0]['id']
    preview = store.deletion_impact(entry_id, [{'host': 'app.example', 'port': 22}])
    assert preview['unresolved'] is False
    assert preview['targets'][0]['keys'][0]['status'] == 'effective'
    assert store.deletion_impact(entry_id, [])['unresolved'] is True
    store.global_path.write_text('', encoding='utf8')
    with pytest.raises(ValueError, match='trust_changed'):
        store.delete_entry(entry_id, expected_revision=preview['revision'])
    with pytest.raises(ValueError, match='trust_changed'):
        store.delete_entry(entry_id, expected_revision='é')
    assert store.list_entries()[0]['id'] == entry_id
    assert store.deletion_impact('0' * 64, []) is None


def test_effective_route_is_owned_and_preserves_orphan_personal_entries(app, client, monkeypatch):
    import config
    import app.profile_manager as profiles
    import app.jump_host_manager as jumps
    owner = _create_user(app, 'trust_owner')
    other = _create_user(app, 'trust_other')
    key = paramiko.RSAKey.generate(1024)
    config.KNOWN_HOSTS_FILE.write_text(line('mine.example,private-global.example', key) + line('other.example', key), encoding='utf8')
    store = HostKeyStore(owner, config.KNOWN_HOSTS_FILE, config.USERS_DIR)
    store.user_path.parent.mkdir(parents=True, exist_ok=True)
    store.user_path.write_text(line('orphan.example', key), encoding='utf8')
    calls = []
    monkeypatch.setattr(profiles, 'load_profiles', lambda user_id: calls.append(user_id) or [{'id': 'mine', 'name': 'Mine', 'host': 'mine.example', 'port': 22}])
    monkeypatch.setattr(jumps, 'load_jump_hosts', lambda user_id: calls.append(user_id) or [])
    assert client.get('/api/host-keys/effective').status_code in (302, 401)
    _login(client, 'trust_owner')
    response = client.get('/api/host-keys/effective?host=other.example&user_id=' + str(other))
    assert response.status_code == 200
    assert calls == [owner, owner]
    assert response.get_json()['targets'][0]['host'] == 'mine.example'
    assert 'private-global' not in response.text and 'other.example' not in response.text
    assert key.get_base64() not in response.text
    assert client.get('/api/host-keys').get_json()['entries'][0]['host'] == 'orphan.example'
    entry_id = store.list_entries()[0]['id']
    preview = client.get(f'/api/host-keys/{entry_id}/deletion-impact')
    assert preview.status_code == 200
    assert preview.get_json()['unresolved'] is True
    assert preview.headers['Cache-Control'] == 'no-store'
    other_store = HostKeyStore(other, config.KNOWN_HOSTS_FILE, config.USERS_DIR)
    other_store.user_path.parent.mkdir(parents=True, exist_ok=True)
    other_store.user_path.write_text(line('other.example', key), encoding='utf8')
    foreign_id = other_store.list_entries()[0]['id']
    assert client.get(f'/api/host-keys/{foreign_id}/deletion-impact').status_code == 404
    config.KNOWN_HOSTS_FILE.write_text(line('mine.example', key), encoding='utf8')
    assert client.delete(f'/api/host-keys/{entry_id}', headers={'If-Match': preview.get_json()['revision']}).status_code == 409
    assert store.list_entries()[0]['id'] == entry_id
    monkeypatch.setattr(config, 'HOST_KEY_MANAGEMENT_ENABLED', False)
    assert client.get('/api/host-keys/effective').status_code == 404
    assert client.get(f'/api/host-keys/{entry_id}/deletion-impact').status_code == 404
