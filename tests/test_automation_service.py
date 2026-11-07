import pytest
from app.automation_store import AutomationError, save_runbook
from app.automation_service import AutomationService

@pytest.fixture
def context(app, client, monkeypatch):
    # Unit fixtures use unreachable hosts; trust is covered explicitly in
    # test_automation_host_key_preflight and by the OpenSSH integration tests.
    from app.host_key_store import HostKeyStore
    monkeypatch.setattr(HostKeyStore, 'has_trusted_key', lambda self, hostname, port=22: True)
    from app.auth import register_user
    from app.models import AuthenticationSession
    from app.profile_manager import add_profile
    with app.app_context():
        from app.app_settings import set_credentials_enabled, set_automation_enabled
        set_credentials_enabled(True)
        set_automation_enabled(True)
        user, error = register_user('automation_user', 'password123')
        assert error is None
        uid = user.id
        book = save_runbook(uid, dict(name='Check', steps=[dict(name='Identity', command='id', timeout=5, sudo=False)]))
        profile, error = add_profile(uid, 'Server', 'server.example', 22, 'operator', 'password')
        assert error is None
    assert client.post('/login', data=dict(username='automation_user', password='password123')).status_code == 302
    with app.app_context():
        auth_id = AuthenticationSession.query.filter_by(user_id=uid).first().id
        yield uid, auth_id, book, profile

def test_preview_frozen_owned_and_single_use(app, context, monkeypatch):
    uid, aid, book, profile = context
    service = AutomationService(app)
    service.vault.setup(uid, aid, 'separate vault passphrase long enough')
    service.vault.put(uid, aid, profile, 'secret-password')
    preview = service.prepare_run(uid, aid, dict(runbook_id=book['id'], profile_ids=[profile['id']], groups=[]))
    token = preview['intent']
    assert preview['targets'][0]['host'] == 'server.example'
    assert 'secret-password' not in str(preview)
    with pytest.raises(AutomationError): service.intent(token, uid+1, aid)
    with pytest.raises(AutomationError): service.intent(token, uid, aid+1)
    assert service.intent(token, uid, aid, consume=True)['kind'] == 'run'
    with pytest.raises(AutomationError): service.intent(token, uid, aid)

def test_changes_expiry_and_unsupported_fail_before_execution(app, context, monkeypatch):
    uid, aid, book, profile = context
    service = AutomationService(app)
    service.vault.setup(uid, aid, 'separate vault passphrase long enough')
    service.vault.put(uid, aid, profile, 'secret-password')
    with pytest.raises(AutomationError):
        service.prepare_run(uid, aid, dict(runbook_id=book['id'], profile_ids=['foreign-profile'], groups=[]))
    with pytest.raises(AutomationError):
        service.prepare_run(uid, aid, dict(runbook_id=book['id'], profile_ids=[], groups=['missing']))
    preview = service.prepare_run(uid, aid, dict(runbook_id=book['id'], profile_ids=[profile['id']], groups=[]))
    service.vault.put(uid, aid, profile, 'replacement')
    with pytest.raises(AutomationError, match='preview_changed'):
        service.validate_run(service.intent(preview['intent'], uid, aid))
    monkeypatch.setattr('app.automation_service.time.monotonic', lambda: 10**12)
    with pytest.raises(AutomationError): service.intent(preview['intent'], uid, aid)

@pytest.mark.parametrize('step_status,run_status', [('succeeded','succeeded'),('failed','failed'),('unknown','unknown')])
def test_background_execution_history_and_quota_release(app, context, monkeypatch, step_status, run_status):
    import time
    from contextlib import contextmanager
    import config
    monkeypatch.setattr(config, 'AUTOMATION_ENABLED', True)
    uid, aid, book, profile = context
    service = AutomationService(app)
    service.vault.setup(uid, aid, 'separate vault passphrase long enough')
    service.vault.put(uid, aid, profile, 'remote-password')
    @contextmanager
    def connect(*args, **kwargs):
        assert args[2] == 'remote-password'
        yield object()
    monkeypatch.setattr('app.automation_service.connect_profile', connect)
    def execute(_transport, _step, _cancelled, secrets, budget):
        assert secrets == ('remote-password',) and budget > 0
        return dict(status=step_status, exit_code=0 if step_status=='succeeded' else None, duration=.1,
                    reason=None if step_status=='succeeded' else 'timeout' if step_status=='unknown' else 'nonzero_exit',
                    stdout='<script>literal output</script>', stderr='failure detail', output_truncated=False)
    monkeypatch.setattr('app.automation_service.execute_step', execute)
    preview = service.prepare_run(uid, aid, dict(runbook_id=book['id'], profile_ids=[profile['id']]))
    service.start(preview['intent'], uid, aid, '1')
    deadline = time.monotonic()+5
    while uid in service._active and time.monotonic() < deadline:
        time.sleep(.01)
    assert uid not in service._active
    history = service.history(uid)
    assert history[0]['status'] == run_status
    assert history[0]['targets'][0]['steps'][0]['status'] == step_status
    assert 'remote-password' not in str(history)
    assert 'command' not in str(history)
    assert history[0]['targets'][0]['steps'][0]['stdout'] == '<script>literal output</script>'
    assert AutomationService(app).history(uid) == history
    with pytest.raises(AutomationError): service.start(preview['intent'], uid, aid, '1')

def test_groups_are_expanded_deduplicated_and_profile_edits_invalidate(app, context):
    from app.profile_manager import update_profile_organization, upsert_profile
    uid, aid, book, profile = context
    service = AutomationService(app)
    service.vault.setup(uid, aid, 'separate vault passphrase long enough')
    service.vault.put(uid, aid, profile, 'remote-password')
    update_profile_organization(uid, profile['id'], {'group':'Fleet'})
    data = dict(runbook_id=book['id'], profile_ids=[profile['id']], groups=['Fleet'])
    preview = service.prepare_run(uid, aid, data)
    assert len(preview['targets']) == 1
    payload = dict(profile, username='another')
    updated, error = upsert_profile(uid, payload)
    assert error is None
    with pytest.raises(AutomationError, match='preview_changed'):
        service.validate_run(service.intent(preview['intent'], uid, aid))

def test_worker_cannot_persist_into_recreated_account(app, context, monkeypatch):
    import time
    from contextlib import contextmanager
    import config
    from app.models import User, db
    from app.user_lifecycle import delete_user_account
    monkeypatch.setattr(config,'AUTOMATION_ENABLED',True)
    uid, aid, book, profile = context
    service = app.extensions['automation']
    service.vault.setup(uid,aid,'separate vault passphrase long enough')
    service.vault.put(uid,aid,profile,'remote-password')
    replacement_path = []
    @contextmanager
    def connect(*args, **kwargs):
        yield object()
    def execute(*args):
        old = db.session.get(User,uid)
        delete_user_account(old)
        replacement = User(id=uid,username='replacement_account',is_admin=False)
        replacement.set_password('another-test-password')
        db.session.add(replacement);db.session.commit()
        replacement_path.append(replacement.get_data_dir() / 'automation-runs.json')
        return dict(status='succeeded',exit_code=0,duration=.1)
    monkeypatch.setattr('app.automation_service.connect_profile',connect)
    monkeypatch.setattr('app.automation_service.execute_step',execute)
    preview = service.prepare_run(uid,aid,dict(runbook_id=book['id'],profile_ids=[profile['id']]))
    service.start(preview['intent'],uid,aid,'1')
    deadline=time.monotonic()+5
    while uid in service._active and time.monotonic()<deadline:time.sleep(.01)
    assert replacement_path
    assert not replacement_path[0].exists(), 'old run metadata crossed the account incarnation fence'

def test_unknown_outcome_survives_history_write_failure(app, context, monkeypatch):
    import time
    from contextlib import contextmanager
    import config
    monkeypatch.setattr(config,'AUTOMATION_ENABLED',True)
    uid,aid,book,profile=context
    service=app.extensions['automation']
    service.vault.setup(uid,aid,'separate vault passphrase long enough')
    service.vault.put(uid,aid,profile,'remote-password')
    @contextmanager
    def connect(*args,**kwargs):yield object()
    monkeypatch.setattr('app.automation_service.connect_profile',connect)
    monkeypatch.setattr('app.automation_service.execute_step',lambda *a:dict(status='unknown',exit_code=None,duration=.1))
    original=service._persist
    failed=[False]
    def persist(owner,record):
        if not failed[0] and any(s['status']=='unknown' for target in record['targets'] for s in target['steps']):
            failed[0]=True
            raise OSError('simulated history write interruption')
        return original(owner,record)
    monkeypatch.setattr(service,'_persist',persist)
    preview=service.prepare_run(uid,aid,dict(runbook_id=book['id'],profile_ids=[profile['id']]))
    service.start(preview['intent'],uid,aid,'1')
    deadline=time.monotonic()+5
    while uid in service._active and time.monotonic()<deadline:time.sleep(.01)
    assert failed[0]
    record=service.history(uid)[0]
    assert record['status']=='unknown'
    assert record['targets'][0]['status']=='unknown'

def test_connection_failures_have_safe_actionable_reason(app,context,monkeypatch):
    import time,paramiko
    from contextlib import contextmanager
    import config
    monkeypatch.setattr(config,'AUTOMATION_ENABLED',True)
    uid,aid,book,profile=context
    service=app.extensions['automation']
    service.vault.setup(uid,aid,'separate vault passphrase long enough')
    service.vault.put(uid,aid,profile,'remote-password')
    @contextmanager
    def connect(*args,**kwargs):
        raise paramiko.AuthenticationException('sensitive-server-text')
        yield
    monkeypatch.setattr('app.automation_service.connect_profile',connect)
    preview=service.prepare_run(uid,aid,dict(runbook_id=book['id'],profile_ids=[profile['id']]))
    service.start(preview['intent'],uid,aid,'1')
    deadline=time.monotonic()+5
    while uid in service._active and time.monotonic()<deadline:time.sleep(.01)
    record=service.history(uid)[0]
    assert record['targets'][0]['reason']=='authentication_failed'
    assert 'sensitive-server-text' not in str(record)

def test_history_accepts_legacy_and_new_output_but_rejects_oversized(tmp_path):
    import json
    from app.storage_errors import StorageCorruptionError
    path = tmp_path / 'history.json'
    step = dict(name='Step', status='succeeded', exit_code=0, duration=1)
    target = dict(id='host', name='Host', host='example.test', port=22, username='user', group=None,
                  status='succeeded', reason=None, steps=[step])
    run = dict(id='run', name='Run', created_at='now', status='succeeded', targets=[target])
    document = dict(version=1, runs=[run])
    path.write_text(json.dumps(document))
    assert AutomationService._read_history(path) == document
    step.update(reason=None, stdout='\U0001f600'*2048, stderr='', output_truncated=True)
    path.write_text(json.dumps(document))
    assert AutomationService._read_history(path) == document
    step['stderr'] = 'x'
    path.write_text(json.dumps(document))
    with pytest.raises(StorageCorruptionError): AutomationService._read_history(path)


def test_history_current_run_never_silently_evicted(app, context):
    from app.automation_store import MAX_STORE_BYTES
    uid, _, _, _ = context
    service = AutomationService(app)
    # Even an invalid oversized caller cannot erase history by popping its own record.
    with pytest.raises(AutomationError, match='storage_limit'):
        service._persist(uid, dict(id='oversized', name='x'*MAX_STORE_BYTES))

def test_run_output_budget_retains_current_run_and_still_executes_every_step(app, context, monkeypatch):
    import json
    import time
    from contextlib import contextmanager
    from app.automation_store import MAX_STORE_BYTES, user_path
    from app.automation_transport import execute_step as real_execute
    uid, aid, book, profile = context
    service = AutomationService(app)
    book = save_runbook(uid, dict(book, steps=[dict(name=f'Step {n}', command='id', timeout=5, sudo=False) for n in range(20)]))
    service.vault.setup(uid, aid, 'separate vault passphrase long enough')
    service.vault.put(uid, aid, profile, 'remote-password')
    budgets = []
    @contextmanager
    def connect(*args, **kwargs): yield object()
    class Channel:
        closed = False
        pending = True
        @property
        def eof_received(self): return not self.pending
        def recv_ready(self): return self.pending
        def recv(self, size):
            self.pending = False
            return ('\U0001f600'*4096).encode()
        def recv_stderr_ready(self): return False
        def recv_stderr(self, size): return b''
        def exit_status_ready(self): return not self.pending
        def recv_exit_status(self): return 0
        def shutdown_write(self): pass
        def close(self): self.closed = True
    def execute(transport, step, cancelled, secrets, budget):
        budgets.append(budget)
        return real_execute(transport, step, cancelled, secrets, budget)
    monkeypatch.setattr('app.automation_service.connect_profile', connect)
    monkeypatch.setattr('app.automation_service.execute_step', execute)
    monkeypatch.setattr('app.automation_transport.paramiko_channels.open_exec_channel', lambda *a, **kw: (kw['before_exec'](), Channel())[1])
    preview = service.prepare_run(uid, aid, dict(runbook_id=book['id'], profile_ids=[profile['id']]))
    started = service.start(preview['intent'], uid, aid, '1')
    deadline = time.monotonic()+10
    while uid in service._active and time.monotonic() < deadline: time.sleep(.01)
    assert uid not in service._active
    history = AutomationService(app).history(uid)
    assert history[0]['id'] == started['id'] and history[0]['status'] == 'succeeded'
    steps = history[0]['targets'][0]['steps']
    assert len(budgets) == 20 and budgets[-1] == 0
    assert sum(len(s['stdout'].encode())+len(s['stderr'].encode()) for s in steps) == 65536
    assert all(s['output_truncated'] for s in steps)
    assert len(json.dumps(dict(version=1, runs=history)).encode()) <= MAX_STORE_BYTES
    assert user_path(uid, 'automation-runs.json').stat().st_size <= MAX_STORE_BYTES
