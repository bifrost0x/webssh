import json
import pytest
from app.automation_store import AutomationError, normalize_runbook, profile_fingerprint
from app.automation_vault import Vault

PASSPHRASE = 'a separate strong vault passphrase 2026'

@pytest.fixture
def owner(app):
    from app.models import User, db
    with app.app_context():
        user = User(username='auto_owner', is_admin=False)
        user.set_password('a-test-password')
        db.session.add(user)
        db.session.commit()
        yield user.id

def test_vault_ciphertext_binding_and_no_secret_response(app, owner):
    with app.app_context():
        vault = Vault()
        vault.setup(owner, 'session-a', PASSPHRASE)
        profile = dict(id='p1', host='server.example', port=22, username='operator', auth_type='password')
        result = vault.put(owner, 'session-a', profile, 'remote-secret')
        assert 'remote-secret' not in json.dumps(result)
        assert vault.password(owner, 'session-a', profile) == 'remote-secret'
        path = vault.path(owner)
        assert 'remote-secret' not in path.read_text()
        assert 'server.example' not in path.read_text()
        changed = dict(profile, username='root')
        with pytest.raises(AutomationError, match='credential_missing'):
            vault.password(owner, 'session-a', changed)
        with pytest.raises(AutomationError, match='vault_locked'):
            vault.password(owner, 'session-b', profile)
        vault.lock(owner)
        with pytest.raises(AutomationError, match='vault_locked'):
            vault.password(owner, 'session-a', profile)
        with pytest.raises(AutomationError, match='vault_unlock_failed'):
            vault.unlock(owner, 'session-a', 'incorrect passphrase long enough')
        vault.unlock(owner, 'session-a', PASSPHRASE)
        assert vault.password(owner, 'session-a', profile) == 'remote-secret'
        document = json.loads(path.read_text())
        document['ciphertext'] = document['ciphertext'][:-4] + 'AAAA'
        path.write_text(json.dumps(document))
        with pytest.raises(AutomationError):
            vault.password(owner, 'session-a', profile)

def test_vault_absolute_expiry_and_lock_zeroes_key(app, owner, monkeypatch):
    import app.automation_vault as module
    now = [100.0]
    monkeypatch.setattr(module.time, 'monotonic', lambda: now[0])
    with app.app_context():
        vault = Vault()
        vault.setup(owner, 'session-a', PASSPHRASE)
        key = vault._leases[owner]['key']
        now[0] += 901
        assert vault.status(owner, 'session-a')['unlocked'] is False
        assert not any(key)

def test_runbook_validation_and_fingerprint():
    book = normalize_runbook(dict(name='Inventory', steps=[dict(name='Kernel', command='uname -a', timeout=20, sudo=False)], stop_on_error=True))
    assert book['steps'][0]['timeout'] == 20
    for changes in [dict(steps=[]), dict(stop_on_error='false'), dict(steps=[dict(name='x', command='id', timeout=True, sudo=False)]), dict(steps=[dict(name='x', command='x'*8193, timeout=20, sudo=False)])]:
        with pytest.raises(AutomationError):
            normalize_runbook(dict(book, **changes))
    profile = dict(id='a', host='a.example', port=22, username='u', auth_type='password')
    assert profile_fingerprint(profile) != profile_fingerprint(dict(profile, port=2222))
    assert profile_fingerprint(profile) == profile_fingerprint(dict(profile, name='New label'))

def test_vault_passphrase_change_and_account_substitution(app, owner):
    from app.models import User, db
    with app.app_context():
        vault = Vault()
        vault.setup(owner, 'session-a', PASSPHRASE)
        profile = dict(id='p1', host='a.example', port=22, username='u', auth_type='password')
        vault.put(owner, 'session-a', profile, 'remote-secret')
        vault.change_passphrase(owner, 'session-a', 'new separate passphrase long enough')
        vault.lock(owner)
        with pytest.raises(AutomationError): vault.unlock(owner, 'session-a', PASSPHRASE)
        vault.unlock(owner, 'session-a', 'new separate passphrase long enough')
        assert vault.password(owner, 'session-a', profile) == 'remote-secret'
        other = User(username='other_owner', is_admin=False)
        other.set_password('test-password')
        db.session.add(other); db.session.commit()
        vault.path(other.id).write_bytes(vault.path(owner).read_bytes())
        with pytest.raises(AutomationError):
            vault.unlock(other.id, 'session-b', 'new separate passphrase long enough')
        vault.reset(owner, 'session-a')
        assert not vault.status(owner, 'session-a')['exists']

def test_global_kdf_admission_rejects_before_waiting_for_vault_lock(app, owner):
    import app.automation_vault as module
    import threading
    with app.app_context():
        vault=Vault()
        module._KDF.acquire()
        try:
            with pytest.raises(AutomationError,match='busy'):
                vault.setup(owner,'session-a',PASSPHRASE)
        finally:
            module._KDF.release()

def test_corrupt_vault_is_not_silently_overwritten(app,owner):
    with app.app_context():
        vault=Vault()
        vault.setup(owner,'session-a',PASSPHRASE)
        path=vault.path(owner)
        path.write_text('{broken',encoding='utf-8')
        before=path.read_bytes()
        from app.storage_errors import StorageCorruptionError
        with pytest.raises((AutomationError,StorageCorruptionError)):
            vault.setup(owner,'session-a',PASSPHRASE)
        assert path.read_bytes()==before
