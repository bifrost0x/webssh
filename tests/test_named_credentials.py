import pytest
from tests.test_automation_service import context
from app.automation_store import AutomationError


def test_profile_metadata_edit_preserves_assignment_and_changed_target_requires_reassignment(app, context):
    from app.profile_manager import upsert_profile
    uid, aid, _, profile = context
    service = app.extensions['credentials']
    record = service.create_named(uid, dict(name='Login', password='assigned-secret'))
    service.assign_named(uid, profile['id'], record['id'], True)
    before = service.named.path(uid).read_bytes()
    renamed, error = upsert_profile(uid, dict(profile, name='Renamed host'))
    assert error is None
    assert service.named.path(uid).read_bytes() == before
    assert service.connection_password(uid, aid, 'ssh', profile['id'], renamed) == 'assigned-secret'
    changed, error = upsert_profile(uid, dict(renamed, host='different.example'))
    assert error is None
    assert service.named.path(uid).read_bytes() == before
    with pytest.raises(AutomationError):
        service.connection_password(uid, aid, 'ssh', profile['id'], changed)


def test_named_encrypted_reusable_and_rotation_scoped(app, context, monkeypatch):
    from app.app_settings import set_credentials_enabled
    uid, aid, _, profile = context
    set_credentials_enabled(True)
    service = app.extensions['credentials']
    first = service.create_named(uid, dict(name='Login',username='operator',password='unique-secret'))
    service.assign_named(uid, profile['id'], first['id'], True)
    assert service.connection_password(uid, aid, 'ssh', profile['id'], profile) == 'unique-secret'
    before = service.connection_generation(uid, aid, 'ssh', profile['id'], profile)
    service.create_named(uid, dict(name='Other',password='another-secret'))
    assert service.connection_generation(uid, aid, 'ssh', profile['id'], profile) == before
    service.update_named(uid, first['id'], dict(name='Renamed'))
    assert service.connection_generation(uid, aid, 'ssh', profile['id'], profile) == before
    service.update_named(uid, first['id'], dict(password='replacement'))
    assert service.connection_generation(uid, aid, 'ssh', profile['id'], profile) != before
    assert b'unique-secret' not in service.named.path(uid).read_bytes()
    with pytest.raises(AutomationError, match='credential_in_use'):
        service.delete_named(uid, first['id'])
    monkeypatch.setattr('app.credential_service.load_profiles', lambda _uid: [dict(profile,host='changed')])
    with pytest.raises(AutomationError):
        service.connection_password(uid, aid, 'ssh', profile['id'], dict(profile,host='changed'))


def test_named_disabled_and_cross_owner(app, context):
    from app.app_settings import set_credentials_enabled
    uid, aid, _, profile = context
    service = app.extensions['credentials']
    set_credentials_enabled(False)
    with pytest.raises(AutomationError, match='credentials_disabled'):
        service.create_named(uid, dict(name='Login',password='secret'))
    set_credentials_enabled(True)
    record = service.create_named(uid, dict(name='Login',password='secret'))
    with pytest.raises(AutomationError):
        service.assign_named(uid, 'foreign-resource', record['id'], True)

def test_native_import_preserves_legacy_and_is_idempotent(app, context):
    from app.app_settings import set_credentials_enabled
    uid,aid,_,profile=context
    set_credentials_enabled(True)
    service=app.extensions['credentials']
    service.vault.setup(uid,aid,'a long separate legacy passphrase')
    service.vault.put(uid,aid,profile,'old-secret')
    before=service.vault.path(uid).read_bytes()
    service.import_legacy(uid,aid,'a long separate legacy passphrase')
    service.import_legacy(uid,aid,'a long separate legacy passphrase')
    assert service.vault.path(uid).read_bytes()==before
    assert len(service.native_state(uid,aid)['credentials'])==1
    service.vault.lock(uid)
    assert service.password(uid,aid,profile)=='old-secret'


def test_create_and_assign_is_atomic_on_storage_failure(app, context,monkeypatch):
    from app.app_settings import set_credentials_enabled
    uid,aid,_,profile=context
    set_credentials_enabled(True)
    service=app.extensions['credentials']
    def fail(*args): raise OSError('write failure')
    monkeypatch.setattr('app.credential_store.write_document',fail)
    with pytest.raises(OSError):
        service.create_assigned(uid,profile['id'],dict(name='Inline',password='inline-secret'),True)
    assert service.named.read(uid)['credentials']=={}

def test_quick_target_token_rejects_changes_rotation_and_other_session(app,context):
    from app.app_settings import set_credentials_enabled
    uid,aid,_,profile=context
    set_credentials_enabled(True)
    service=app.extensions['credentials']
    record=service.create_named(uid,dict(name='Quick',password='quick-secret'))
    token=service.authorize_target(uid,aid,dict(credential_id=record['id'],target=profile,confirm_target=True))['credential_target_token']
    assert service.target_password(uid,aid,record['id'],profile,token)=='quick-secret'
    with pytest.raises(AutomationError): service.target_password(uid,aid,record['id'],dict(profile,host='changed'),token)
    with pytest.raises(AutomationError): service.target_password(uid,aid+1,record['id'],profile,token)
    service.update_named(uid,record['id'],dict(password='replacement'))
    with pytest.raises(AutomationError): service.target_password(uid,aid,record['id'],profile,token)

def test_inline_new_resource_rolls_back_when_credential_write_fails(app,context,monkeypatch):
    from app.app_settings import set_credentials_enabled
    uid,aid,_,profile=context
    set_credentials_enabled(True)
    service=app.extensions['credentials']
    original=service.resources(uid)
    def fail(*args): raise OSError('storage failure')
    monkeypatch.setattr('app.credential_store.write_document',fail)
    with pytest.raises(OSError):
        service.create_for_resource(uid,dict(resource_kind='ssh',resource=dict(name='New',host='new.example',port=22,username='operator',auth_type='password'),name='Inline',password='secret',confirm_target=True))
    assert service.resources(uid)==original

def test_native_http_uses_authenticated_single_use_intent_without_password_prompt(app,client,context):
    from app.app_settings import set_credentials_enabled
    uid,aid,_,profile=context
    set_credentials_enabled(True)
    secure=dict(base_url='https://localhost')
    payload=dict(name='HTTP',password='http-only-secret')
    prepared=client.post('/api/credentials/intents',json=dict(operation='native',mutation=dict(method='create',**payload)),**secure)
    assert prepared.status_code==200
    token=prepared.json['intent']
    changed=client.post('/api/credentials',json=dict(intent=token,name='Changed',password=payload['password']),**secure)
    assert changed.status_code==409
    response=client.post('/api/credentials',json=dict(intent=token,**payload),**secure)
    assert response.status_code==200
    assert response.json['credentials'][0]['name']=='HTTP'
    assert 'http-only-secret' not in response.get_data(as_text=True)
    assert client.post('/api/credentials',json=dict(intent=token,**payload),**secure).status_code==409


def test_native_twenty_host_batch_does_not_hit_password_guess_limit(app,client,context):
    from app.profile_manager import add_profile
    uid,aid,_,_=context
    service=app.extensions['credentials']
    record=service.create_named(uid,dict(name='Shared batch password',password='batch-secret'))
    secure=dict(base_url='https://localhost')
    for index in range(20):
        profile,error=add_profile(uid,f'Batch {index}',f'host-{index}.example',22,'operator','password')
        assert error is None
        payload=dict(resource_id=profile['id'],credential_id=record['id'],confirm_target=True)
        prepared=client.post('/api/credentials/intents',json=dict(operation='native',mutation=dict(method='assign',**payload)),**secure)
        assert prepared.status_code==200
        applied=client.post('/api/credentials/assign',json=dict(intent=prepared.json['intent'],**payload),**secure)
        assert applied.status_code==200
    assert len(service.named.read(uid)['assignments'])==20


def test_native_mutations_keep_csrf_https_ownership_and_revocation(app,client,context):
    from app.app_settings import set_credentials_enabled
    from app.auth import register_user
    import re
    uid,aid,_,_=context
    service=app.extensions['credentials']
    payload=dict(name='CSRF protected',password='private-secret')
    mutation=dict(method='create',**payload)
    secure=dict(base_url='https://localhost')
    token=service.prepare_vault(uid,aid,dict(operation='native',mutation=mutation))['intent']
    assert client.post('/api/credentials',json=dict(intent=token,**payload)).status_code==403
    app.config['WTF_CSRF_ENABLED']=True
    assert client.post('/api/credentials',json=dict(intent=token,**payload),**secure).status_code==400
    html=client.get('/',**secure).get_data(as_text=True)
    csrf=re.search(r'name="csrf-token" content="([^"]+)"',html).group(1)
    headers={'X-CSRFToken':csrf,'Referer':'https://localhost/'}
    assert client.post('/api/credentials',json=dict(intent=token,**payload),headers=headers,**secure).status_code==200
    app.config['WTF_CSRF_ENABLED']=False
    token=service.prepare_vault(uid,aid,dict(operation='native',mutation=mutation))['intent']
    other,error=register_user('other_credential_owner','other-password')
    assert error is None
    second=app.test_client()
    # The fixture retains an app context; do not reuse Flask-Login's cached user
    # when switching between independent browser clients.
    from flask import g
    g.pop('_login_user', None)
    assert second.post('/login',data={'username':other.username,'password':'other-password'}).status_code==302
    g.pop('_login_user', None)
    assert second.post('/api/credentials',json=dict(intent=token,**payload),**secure).status_code==409
    set_credentials_enabled(False)
    set_credentials_enabled(True)
    g.pop('_login_user', None)
    assert client.post('/api/credentials',json=dict(intent=token,**payload),**secure).status_code==409
    assert len(service.named.read(uid)['credentials'])==1
    assert not service.named.read(other.id)['credentials']

@pytest.mark.parametrize('method',['create','assign'])
def test_native_intent_freezes_resource_before_apply(app,context,method):
    from app.app_settings import set_credentials_enabled
    from app.profile_manager import upsert_profile
    uid,aid,_,profile=context
    set_credentials_enabled(True)
    service=app.extensions['credentials']
    record=service.create_named(uid,dict(name='Existing',password='secret'))
    mutation=dict(method=method,resource_id=profile['id'],confirm_target=True)
    if method=='create': mutation.update(name='New',password='new-secret')
    else: mutation['credential_id']=record['id']
    token=service.prepare_vault(uid,aid,dict(operation='native',mutation=mutation))['intent']
    upsert_profile(uid,dict(profile,host='changed.example'))
    with pytest.raises(AutomationError,match='preview_changed'):
        service.apply_native_assignment(uid,aid,token,mutation)
    assert not service.named.read(uid)['assignments']


def test_quick_token_policy_and_jump_revision_are_frozen(app,context,monkeypatch):
    from app.app_settings import set_credentials_enabled
    uid,aid,_,profile=context
    set_credentials_enabled(True)
    service=app.extensions['credentials']
    record=service.create_named(uid,dict(name='Quick',password='secret'))
    jump=dict(profile,id='jump',host='bastion.example')
    monkeypatch.setattr('app.credential_service.load_jump_hosts',lambda _uid:[jump])
    target=dict(profile,jump_host_id='jump')
    token=service.authorize_target(uid,aid,dict(credential_id=record['id'],target=target,confirm_target=True))['credential_target_token']
    jump['host']='changed.example'
    with pytest.raises(AutomationError): service.target_password(uid,aid,record['id'],target,token)
    target=dict(profile)
    token=service.authorize_target(uid,aid,dict(credential_id=record['id'],target=target,confirm_target=True))['credential_target_token']
    set_credentials_enabled(False);set_credentials_enabled(True)
    with pytest.raises(AutomationError): service.target_password(uid,aid,record['id'],target,token)

def test_assignment_holds_destination_lock_through_write(app,context,monkeypatch):
    import threading
    from app.app_settings import set_credentials_enabled
    from app.profile_manager import upsert_profile
    uid,aid,_,profile=context
    set_credentials_enabled(True)
    service=app.extensions['credentials']
    record=service.create_named(uid,dict(name='Shared',password='secret'))
    mutation=dict(method='assign',resource_id=profile['id'],credential_id=record['id'],confirm_target=True)
    token=service.prepare_vault(uid,aid,dict(operation='native',mutation=mutation))['intent']
    at_write=threading.Event();release=threading.Event();attempted=threading.Event();finished=threading.Event();errors=[]
    original=service.named.mutate
    def paused(*args):
        at_write.set()
        assert release.wait(5)
        return original(*args)
    monkeypatch.setattr(service.named,'mutate',paused)
    def apply():
        try:
            with app.app_context(): service.apply_native_assignment(uid,aid,token,mutation)
        except BaseException as e: errors.append(e)
    def edit():
        try:
            with app.app_context():
                attempted.set()
                result,error=upsert_profile(uid,dict(profile,host='changed.example'))
                assert error is None
        except BaseException as e: errors.append(e)
        finally: finished.set()
    assigning=threading.Thread(target=apply);assigning.start()
    assert at_write.wait(5)
    editing=threading.Thread(target=edit);editing.start()
    assert attempted.wait(5)
    assert not finished.wait(.1)
    release.set();assigning.join(5);editing.join(5)
    assert not assigning.is_alive() and not editing.is_alive() and not errors
    with pytest.raises(AutomationError):
        service.connection_password(uid,aid,'ssh',profile['id'],dict(profile,host='changed.example'))

def test_concurrent_authenticated_requests_cannot_apply_one_native_intent_twice(app,client,context,monkeypatch):
    import threading
    uid,aid,_,profile=context
    service=app.extensions['credentials']
    payload=dict(name='One action',password='secret')
    secure=dict(base_url='https://localhost')
    token=service.prepare_vault(uid,aid,dict(operation='native',mutation=dict(method='create',**payload)))['intent']
    second=app.test_client()
    cookie=client.get_cookie(app.config.get('SESSION_COOKIE_NAME','session'))
    second.set_cookie(cookie.key,cookie.value)
    entered=threading.Event();release=threading.Event();results=[]
    original=service.create_named
    calls=[]
    def pause(*args):
        calls.append(True)
        if len(calls)==1:
            entered.set()
            assert release.wait(5)
        return original(*args)
    monkeypatch.setattr(service,'create_named',pause)
    def first_request():
        results.append(client.post('/api/credentials',json=dict(intent=token,**payload),**secure).status_code)
    worker=threading.Thread(target=first_request);worker.start()
    try:
        assert entered.wait(5)
        response=second.post('/api/credentials',json=dict(intent=token,**payload),**secure)
        assert response.status_code==409
    finally:
        release.set();worker.join(5)
    assert results==[200]
    assert len(service.named.read(uid)['credentials'])==1

@pytest.mark.parametrize('method', ['assign', 'create'])
def test_native_replacement_requires_specific_consent_and_freezes_assignment(app, context, method):
    uid, aid, _, profile = context
    service = app.extensions['credentials']
    first = service.create_assigned(uid, profile['id'], dict(name='Old', password='old'), True)
    other = service.create_named(uid, dict(name='New', password='new'))
    mutation = dict(method=method, resource_id=profile['id'], confirm_target=True)
    mutation.update(dict(credential_id=other['id']) if method == 'assign' else dict(name='Created', password='created'))
    with pytest.raises(AutomationError, match='replacement_confirmation_required'):
        service.prepare_vault(uid, aid, dict(operation='native', mutation=mutation))
    mutation['replace_credential_id'] = first['id']
    token = service.prepare_vault(uid, aid, dict(operation='native', mutation=mutation))['intent']
    original = service.named.read(uid)['assignments'][profile['id']]
    def race(doc):
        doc['assignments'][profile['id']]['generation'] = 'concurrent-generation'
    service.named.mutate(uid, race)
    with pytest.raises(AutomationError, match='preview_changed'):
        service.apply_native_assignment(uid, aid, token, mutation)
    assert len(service.named.read(uid)['credentials']) == 2
    token = service.prepare_vault(uid, aid, dict(operation='native', mutation=mutation))['intent']
    service.apply_native_assignment(uid, aid, token, mutation)
    state = service.native_state(uid, aid)
    assert not next(item for item in state['credentials'] if item['id'] == first['id'])['uses']
    assert sum(len(item['uses']) for item in state['credentials']) == 1


def test_native_same_assignment_keeps_schedule_generation(app, context):
    uid, aid, _, profile = context
    service = app.extensions['credentials']
    record = service.create_assigned(uid, profile['id'], dict(name='Same', password='secret'), True)
    before = service.schedule_generations(uid, [profile])
    mutation = dict(method='assign', resource_id=profile['id'], credential_id=record['id'], confirm_target=True)
    token = service.prepare_vault(uid, aid, dict(operation='native', mutation=mutation))['intent']
    service.apply_native_assignment(uid, aid, token, mutation)
    assert service.schedule_generations(uid, [profile]) == before

@pytest.mark.parametrize('remove', [False, True])
def test_native_assignment_compare_occurs_inside_named_mutation(app, context, monkeypatch, remove):
    uid, aid, _, profile = context
    service = app.extensions['credentials']
    record = service.create_assigned(uid, profile['id'], dict(name='Current', password='secret'), True)
    previous = service.named.read(uid)['assignments'][profile['id']]
    mutation = dict(method='assign', resource_id=profile['id'], credential_id=None if remove else record['id'], confirm_target=True, expected_assignment=previous)
    token = service.prepare_vault(uid, aid, dict(operation='native', mutation=mutation))['intent']
    original = service.named.mutate
    def intervening_writer(owner, operation):
        original(owner, lambda doc: doc['assignments'][profile['id']].update(generation='intervening-write'))
        return original(owner, operation)
    monkeypatch.setattr(service.named, 'mutate', intervening_writer)
    with pytest.raises(AutomationError, match='preview_changed'):
        service.apply_native_assignment(uid, aid, token, mutation)
    assert service.named.read(uid)['assignments'][profile['id']]['credential_id'] == record['id']
    with pytest.raises(AutomationError, match='preview_changed'):
        service.prepare_vault(uid, aid, dict(operation='native', mutation=mutation))
