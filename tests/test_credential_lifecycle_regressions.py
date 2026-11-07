"""Saved passwords stay removable and imports keep the shared lock order."""
import threading

import pytest

from app.automation_store import AutomationError
from tests.test_automation_service import context  # noqa: F401  (fixture)


def _assign(service, uid, profile, record):
    service.assign_named(uid, profile['id'], record['id'], True)
    assert profile['id'] in service.named.read(uid)['assignments']


def test_deleting_a_host_no_longer_blocks_deleting_its_password(app, context):
    from app.profile_manager import add_profile, delete_profile
    uid, aid, _book, _profile = context
    service = app.extensions['credentials']
    record = service.create_named(uid, dict(name='Orphaned', password='orphan-secret'))
    profile, error = add_profile(uid, 'Temporary', 'temporary.example', 22, 'operator', 'password')
    assert error is None
    _assign(service, uid, profile, record)
    assert delete_profile(uid, profile['id']) == (True, None)

    state = service.native_state(uid, aid)
    listed = next(item for item in state['credentials'] if item['id'] == record['id'])
    assert listed['uses'] == []

    service.delete_named(uid, record['id'])
    document = service.named.read(uid)
    assert record['id'] not in document['credentials']
    assert profile['id'] not in document['assignments']


def test_live_assignment_still_blocks_deletion_while_enabled(app, context):
    uid, _aid, _book, profile = context
    service = app.extensions['credentials']
    record = service.create_named(uid, dict(name='In use', password='live-secret'))
    _assign(service, uid, profile, record)
    with pytest.raises(AutomationError, match='credential_in_use'):
        service.delete_named(uid, record['id'])


def test_users_can_erase_passwords_after_an_administrator_disables_storage(app, client, context):
    from app.app_settings import set_credentials_enabled
    uid, _aid, _book, profile = context
    service = app.extensions['credentials']
    record = service.create_named(uid, dict(name='Erase me', password='erase-secret'))
    _assign(service, uid, profile, record)
    set_credentials_enabled(False)
    secure = dict(base_url='https://localhost')

    # Other mutations remain refused while disabled.
    refused = client.post('/api/credentials/intents', json=dict(operation='native', mutation=dict(method='create', name='New', password='x')), **secure)
    assert refused.status_code == 403
    assert refused.json['code'] == 'credentials_disabled'

    mutation = dict(method='delete', credential_id=record['id'])
    prepared = client.post('/api/credentials/intents', json=dict(operation='native', mutation=mutation), **secure)
    assert prepared.status_code == 200, prepared.json
    deleted = client.delete(f"/api/credentials/{record['id']}", json=dict(intent=prepared.json['intent']), **secure)
    assert deleted.status_code == 200, deleted.json
    document = service.named.read(uid)
    assert record['id'] not in document['credentials']
    assert profile['id'] not in document['assignments']
    assert 'erase-secret' not in deleted.get_data(as_text=True)


def test_legacy_vault_reset_is_allowed_while_disabled(app, context):
    from app.app_settings import set_credentials_enabled
    uid, aid, _book, _profile = context
    service = app.extensions['credentials']
    service.vault.setup(uid, aid, 'separate vault passphrase long enough')
    set_credentials_enabled(False)
    token = service.prepare_vault(uid, aid, dict(operation='reset'))['intent']
    service._apply_vault(token, uid, aid, dict(confirmation='DELETE VAULT'))
    assert not service.vault.path(uid).exists()
    with pytest.raises(AutomationError, match='credentials_disabled'):
        service.prepare_vault(uid, aid, dict(operation='unlock'))


def test_legacy_import_resolves_resources_before_taking_the_named_lock(app, context, monkeypatch):
    """Resource managers lock command-config before named-credentials."""
    uid, aid, _book, profile = context
    service = app.extensions['credentials']
    service.vault.setup(uid, aid, 'separate vault passphrase long enough')
    service.vault.put(uid, aid, profile, 'legacy-secret')
    service.vault.lock(uid)

    original_resolve = service.resolve_resource
    held = []

    def tracking(user_id, resource_id):
        held.append(resource_id)
        return original_resolve(user_id, resource_id)

    monkeypatch.setattr(service, 'resolve_resource', tracking)
    original_mutate = service.named.mutate
    inside = []

    def mutate(user_id, operation):
        def wrapped(document):
            inside.append(True)
            before = len(held)
            result = operation(document)
            assert len(held) == before, 'resource resolution inside the named-credentials lock'
            return result
        return original_mutate(user_id, wrapped)

    monkeypatch.setattr(service.named, 'mutate', mutate)
    service.import_legacy(uid, aid, 'separate vault passphrase long enough')
    assert inside == [True]
    assert held, 'legacy records were resolved'
    assert profile['id'] in service.named.read(uid)['assignments']


def test_concurrent_import_and_assignment_complete(app, context):
    from app.profile_manager import add_profile
    uid, aid, _book, profile = context
    service = app.extensions['credentials']
    service.vault.setup(uid, aid, 'separate vault passphrase long enough')
    service.vault.put(uid, aid, profile, 'legacy-secret')
    service.vault.lock(uid)
    record = service.create_named(uid, dict(name='Concurrent', password='concurrent-secret'))
    other, error = add_profile(uid, 'Other', 'other.example', 22, 'operator', 'password')
    assert error is None
    errors = []
    ctx = app.app_context

    def run(callback):
        with ctx():
            try:
                callback()
            except Exception as exc:  # surfaced below
                errors.append(exc)

    threads = [
        threading.Thread(target=run, args=(lambda: service.import_legacy(uid, aid, 'separate vault passphrase long enough'),)),
        threading.Thread(target=run, args=(lambda: service.assign_named(uid, other['id'], record['id'], True),)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)
    assert not any(thread.is_alive() for thread in threads), 'deadlock'
    assert errors == []
