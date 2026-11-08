"""Shared vault ownership, typed bindings and independent record generations."""
import json
import pytest

from app.automation_store import AutomationError
from tests.test_automation_service import context

PASSPHRASE = 'a separate strong vault passphrase 2026'


def test_shared_state_is_available_without_automation_but_requires_https(app, client, context, monkeypatch):
    import config
    monkeypatch.setattr(config, 'AUTOMATION_ENABLED', False)
    assert client.get('/api/credentials/state').status_code == 403
    response = client.get('/api/credentials/state', base_url='https://localhost')
    assert response.status_code == 200
    assert response.json['profiles'][0]['kind'] == 'ssh'
    assert response.json['vault']['exists'] is False


def test_connection_uses_current_owned_exact_destination(app, context, monkeypatch):
    uid, aid, _book, profile = context
    service = app.extensions['credentials']
    service.vault.setup(uid, aid, PASSPHRASE)
    service.vault.put(uid, aid, profile, 'remote-secret')
    with app.test_request_context(base_url='https://localhost'):
        assert service.connection_password(uid, aid, 'ssh', profile['id'], profile) == 'remote-secret'
        for change in ({'host': 'other.example'}, {'username': 'root'}, {'port': 2222}, {'jump_host_id': 'other'}):
            with pytest.raises(AutomationError):
                service.connection_password(uid, aid, 'ssh', profile['id'], dict(profile, **change))
        for kind, resource_id in [('jump', profile['id']), ('ssh', 'missing'), ('smb', 'smb:missing')]:
            with pytest.raises(AutomationError):
                service.connection_password(uid, aid, kind, resource_id, profile)
        monkeypatch.setattr('app.credential_service.load_profiles', lambda _uid: [])
        with pytest.raises(AutomationError):
            service.connection_password(uid, aid, 'ssh', profile['id'], profile)
    with app.test_request_context(base_url='http://localhost'):
        with pytest.raises(AutomationError, match='https_required'):
            service.connection_password(uid, aid, 'ssh', profile['id'], profile)


def test_unrelated_mutation_preserves_preview_but_used_aba_and_unlock_invalidate(app, context):
    uid, aid, book, profile = context
    service = app.extensions['automation']
    service.vault.setup(uid, aid, PASSPHRASE)
    service.vault.put(uid, aid, profile, 'original')
    preview = service.prepare_run(uid, aid, dict(runbook_id=book['id'], profile_ids=[profile['id']]))
    intent = service.intent(preview['intent'], uid, aid)
    service.vault.put(uid, aid, dict(id='smb:other', kind='smb', host='files.example', port=445,
        username='user', domain='domain', share='share', auth_type='password'), 'unrelated')
    service.validate_run(intent)
    service.vault.put(uid, aid, profile, 'replacement')
    service.vault.put(uid, aid, profile, 'original')
    with pytest.raises(AutomationError, match='preview_changed'):
        service.validate_run(intent)
    preview = service.prepare_run(uid, aid, dict(runbook_id=book['id'], profile_ids=[profile['id']]))
    intent = service.intent(preview['intent'], uid, aid)
    service.vault.unlock(uid, aid, PASSPHRASE)
    with pytest.raises(AutomationError, match='preview_changed'):
        service.validate_run(intent)


def test_typed_records_bind_smb_domain_share_and_do_not_collide(app, context, monkeypatch):
    uid, aid, _book, profile = context
    service = app.extensions['credentials']
    jump = dict(profile)
    share = dict(id=profile['id'], name='Files', host=profile['host'], username=profile['username'],
                 domain='domain', share='documents')
    monkeypatch.setattr('app.credential_service.load_jump_hosts', lambda _uid: [jump])
    monkeypatch.setattr('app.credential_service.load_smb_shares', lambda _uid: [share])
    service.vault.setup(uid, aid, PASSPHRASE)
    with app.test_request_context(base_url='https://localhost'):
        for kind, resource_id in [('ssh', profile['id']), ('jump', 'jump:'+profile['id']), ('smb', 'smb:'+profile['id'])]:
            resource = service.resolve_resource(uid, resource_id)
            service.vault.put(uid, aid, resource, kind+'-secret')
            assert service.connection_password(uid, aid, kind, resource_id, resource) == kind+'-secret'
        resource = service.resolve_resource(uid, 'smb:'+profile['id'])
        for changed in ({'domain': 'other'}, {'share': 'other'}, {'port': 22}):
            with pytest.raises(AutomationError):
                service.connection_password(uid, aid, 'smb', resource['id'], dict(resource, **changed))
    assert len(service.vault.status(uid, aid)['credentials']) == 3


def test_v1_unlock_is_read_only_and_authorized_migration_preserves_unchanged_generation(app, context, monkeypatch):
    import os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from app.automation_vault import _derive, _encode
    from app.automation_store import profile_fingerprint
    uid, aid, _book, profile = context
    vault = app.extensions['credentials'].vault
    salt, nonce = os.urandom(16), os.urandom(12)
    key = _derive(PASSPHRASE, salt)
    plaintext = json.dumps({profile['id']: dict(password='legacy-secret', fingerprint=profile_fingerprint(profile))}).encode()
    document = dict(version=1, kdf='scrypt-131072-8-1', salt=_encode(salt), nonce=_encode(nonce),
                    ciphertext=_encode(AESGCM(key).encrypt(nonce, plaintext, vault._aad(uid))))
    vault.path(uid).write_text(json.dumps(document))
    before = vault.path(uid).read_bytes()
    vault.unlock(uid, aid, PASSPHRASE)
    assert vault.password(uid, aid, profile) == 'legacy-secret'
    generation = vault.generations(uid, aid, [profile])
    assert vault.path(uid).read_bytes() == before
    with monkeypatch.context() as failing:
        def fail(*_args):
            raise OSError('simulated atomic write failure')
        failing.setattr('app.automation_vault.write_document', fail)
        with pytest.raises(OSError):
            vault.put(uid, aid, dict(profile, id='unrelated'), 'new-secret')
    assert vault.path(uid).read_bytes() == before
    assert vault.generations(uid, aid, [profile]) == generation
    vault.put(uid, aid, dict(profile, id='unrelated'), 'new-secret')
    assert json.loads(vault.path(uid).read_text())['version'] == 2
    assert vault.generations(uid, aid, [profile]) == generation
    vault.lock(uid)
    vault.unlock(uid, aid, PASSPHRASE)
    assert vault.password(uid, aid, profile) == 'legacy-secret'


def test_pending_connection_generation_tracks_used_changes_and_global_lock(app, context, monkeypatch):
    uid, aid, _book, profile = context
    service = app.extensions['credentials']
    service.vault.setup(uid, aid, PASSPHRASE)
    service.vault.put(uid, aid, profile, 'secret')
    token = service.connection_generation(uid, aid, 'ssh', profile['id'], profile)
    service.vault.put(uid, aid, dict(profile, id='unrelated'), 'other')
    assert service.connection_generation(uid, aid, 'ssh', profile['id'], profile) == token
    service.vault.put(uid, aid, profile, 'secret')
    assert service.connection_generation(uid, aid, 'ssh', profile['id'], profile) != token
    token = service.connection_generation(uid, aid, 'ssh', profile['id'], profile)
    service.vault.delete(uid, aid, profile['id'])
    with pytest.raises(AutomationError, match='credential_missing'):
        service.connection_generation(uid, aid, 'ssh', profile['id'], profile)
    service.vault.put(uid, aid, profile, 'secret')
    assert service.connection_generation(uid, aid, 'ssh', profile['id'], profile) != token
    service.revoke(uid)
    with pytest.raises(AutomationError, match='vault_locked'):
        service.connection_generation(uid, aid, 'ssh', profile['id'], profile)
    service.vault.unlock(uid, aid, PASSPHRASE)
    assert service.connection_generation(uid, aid, 'ssh', profile['id'], profile) != token
    lease = service.vault._leases[uid]
    monkeypatch.setattr('app.automation_vault.time.monotonic', lambda: lease['expires']+1)
    with pytest.raises(AutomationError, match='vault_locked'):
        service.connection_password(uid, aid, 'ssh', profile['id'], profile)


def test_saved_route_change_invalidates_both_credential_use_and_pending_put(app, context, monkeypatch):
    uid, aid, _book, profile = context
    service = app.extensions['credentials']
    jump = dict(profile, id='jump-one', host='bastion.example')
    routed = dict(profile, jump_host_id=jump['id'])
    monkeypatch.setattr('app.credential_service.load_profiles', lambda _uid: [routed])
    monkeypatch.setattr('app.credential_service.load_jump_hosts', lambda _uid: [jump])
    service.vault.setup(uid, aid, PASSPHRASE)
    resource = service.resolve_resource(uid, profile['id'])
    service.vault.put(uid, aid, resource, 'secret')
    assert service.connection_password(uid, aid, 'ssh', profile['id'], routed) == 'secret'
    intent = service.prepare_vault(uid, aid, dict(operation='put', profile_id=profile['id']))
    jump['host'] = 'other.example'
    with pytest.raises(AutomationError, match='credential_missing'):
        service.connection_password(uid, aid, 'ssh', profile['id'], routed)
    with pytest.raises(AutomationError, match='preview_changed'):
        service.apply_vault(intent['intent'], uid, aid, dict(password='replacement'))


def test_shared_vault_step_up_works_with_automation_disabled_and_is_action_bound(app, client, context, monkeypatch):
    import config
    monkeypatch.setattr(config, 'AUTOMATION_ENABLED', False)
    secure = dict(base_url='https://localhost')
    response = client.post('/api/credentials/intents', json=dict(operation='setup'), **secure)
    assert response.status_code == 200
    token = response.json['intent']
    body = dict(intent=token, passphrase=PASSPHRASE, acknowledged=True)
    assert client.post('/api/credentials/apply', json=body, **secure).status_code == 403
    started = client.post('/api/account/step-up/intents', json=dict(action='credentials.vault', target=token), **secure)
    assert started.status_code == 200
    approved = client.post('/api/account/step-up/password', json=dict(intent=started.json['intent'], password='password123'), **secure)
    assert approved.status_code == 200
    headers = {'X-WebSSH-Step-Up': approved.json['grant']}
    response = client.post('/api/credentials/apply', json=body, headers=headers, **secure)
    assert response.status_code == 200
    assert response.json['unlocked'] is True
    assert PASSPHRASE not in str(response.json)
    assert client.post('/api/credentials/apply', json=body, headers=headers, **secure).status_code == 409
    assert client.post('/api/credentials/lock', json={}, **secure).status_code == 200
    assert not client.get('/api/credentials/state', **secure).json['vault']['unlocked']


def test_lock_invalidates_intent_before_queued_apply_enters_account_access(app, context, monkeypatch):
    from contextlib import contextmanager
    from app.data_access import user_data_access
    uid, aid, _book, _profile = context
    service = app.extensions['credentials']
    service.vault.setup(uid, aid, PASSPHRASE)
    service.vault.lock(uid)
    token = service.prepare_vault(uid, aid, dict(operation='unlock'))['intent']
    @contextmanager
    def interleaved_access(user_id):
        service.revoke(user_id)
        with user_data_access(user_id) as access:
            yield access
    monkeypatch.setattr('app.credential_service.user_data_access', interleaved_access)
    with pytest.raises(AutomationError, match='invalid_intent'):
        service.apply_vault(token, uid, aid, dict(passphrase=PASSPHRASE))
    assert not service.vault.status(uid, aid)['unlocked']


def test_automation_checks_used_generation_again_during_fast_authentication(app, context, monkeypatch):
    from contextlib import contextmanager
    import threading
    import config
    monkeypatch.setattr(config, 'AUTOMATION_ENABLED', True)
    uid, aid, book, profile = context
    service = app.extensions['automation']
    service.vault.setup(uid, aid, PASSPHRASE)
    service.vault.put(uid, aid, profile, 'original')
    observed = []
    completed = threading.Event()
    @contextmanager
    def connect(_uid, _profile, _password, cancelled, *_args, **_kwargs):
        observed.append(cancelled())
        service.vault.put(uid, aid, profile, 'replacement')
        observed.append(cancelled())
        completed.set()
        raise AutomationError('cancelled')
        yield  # pragma: no cover
    monkeypatch.setattr('app.automation_service.connect_profile', connect)
    token = service.prepare_run(uid, aid, dict(runbook_id=book['id'], profile_ids=[profile['id']]))['intent']
    service.start(token, uid, aid, '1')
    assert completed.wait(5)
    assert observed == [False, True]


def test_ambiguous_legacy_resource_ids_fail_closed(app, context, monkeypatch):
    uid, _aid, _book, profile = context
    service = app.extensions['credentials']
    monkeypatch.setattr('app.credential_service.load_profiles', lambda _uid: [dict(profile, id='jump:legacy')])
    monkeypatch.setattr('app.credential_service.load_jump_hosts', lambda _uid: [dict(profile, id='legacy')])
    with pytest.raises(AutomationError, match='invalid_targets'):
        service.resolve_resource(uid, 'jump:legacy')


@pytest.mark.parametrize('url,fragment', [('/credentials?embed=1', '#passwords'),
    ('/credentials', '#passwords'), ('/credentials?embed=true', '#passwords'),
    ('/automation?embed=1', '#automation'), ('/api/credentials/state?embed=1', None)])
def test_legacy_credential_urls_redirect_to_native_shell_and_deny_framing(app, client, context, url, fragment):
    response = client.get(url, base_url='https://localhost')
    assert response.status_code == (302 if fragment else 200)
    if fragment:
        assert response.headers['Location'].endswith('/' + fragment)
        assert '<iframe' not in response.get_data(as_text=True).lower()
    assert response.headers['X-Frame-Options'] == 'DENY'
    assert "frame-ancestors 'none';" in response.headers['Content-Security-Policy']


def test_history_keeps_optional_runbook_identity_and_reads_legacy_records(app, context, monkeypatch):
    uid, aid, book, profile = context
    service = app.extensions['automation']
    service.vault.setup(uid, aid, PASSPHRASE)
    service.vault.put(uid, aid, profile, 'secret')
    jobs = []
    monkeypatch.setattr(app.extensions['runtime_lifecycle'], 'start_job', lambda *args, **kwargs: jobs.append(args))
    token = service.prepare_run(uid, aid, dict(runbook_id=book['id'], profile_ids=[profile['id']]))['intent']
    record = service.start(token, uid, aid, '1')
    assert record['runbook_id'] == book['id']
    service._active.clear()
    assert service.history(uid)[0]['runbook_id'] == book['id']
    legacy = dict(record, id='legacy-run')
    del legacy['runbook_id']
    service._persist(uid, legacy)
    history = service.history(uid)
    assert 'runbook_id' not in history[0]
    assert history[1]['runbook_id'] == book['id']
    # The worker owns the reservation; execute the captured cancelled job to release it.
    import threading
    cancelled = threading.Event()
    cancelled.set()
    jobs[0][1](cancelled)


def test_vault_status_marks_changed_endpoint_and_jump_route_without_hiding_records(app, context, monkeypatch):
    uid, aid, _book, profile = context
    service = app.extensions['credentials']
    jump = dict(profile, id='bastion', host='bastion.example')
    resources = [dict(profile), dict(profile, id='routed', jump_host_id='bastion')]
    monkeypatch.setattr('app.credential_service.load_profiles', lambda _uid: resources)
    monkeypatch.setattr('app.credential_service.load_jump_hosts', lambda _uid: [jump])
    service.vault.setup(uid, aid, PASSPHRASE)
    for resource in service.resources(uid):
        service.vault.put(uid, aid, resource, 'secret')
    assert all(item['valid'] for item in service.vault_status(uid, aid)['credentials'])
    resources[0]['host'] = 'changed.example'
    jump['host'] = 'changed-bastion.example'
    status = service.vault_status(uid, aid)
    assert len(status['credentials']) == 3
    assert not any(item['valid'] for item in status['credentials'])
    assert 'secret' not in json.dumps(status)
    resources.clear()
    assert not any(item['valid'] for item in service.vault_status(uid, aid)['credentials'])
