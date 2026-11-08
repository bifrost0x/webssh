import pytest
from tests.test_automation_service import context
from tests.step_up_helpers import account_password_step_up_headers
from tests.test_proxy_prefix_regression import proxy_app, headers as proxy_headers, login as proxy_login

@pytest.fixture
def enabled(monkeypatch, client):
    import config
    monkeypatch.setattr(config, 'AUTOMATION_ENABLED', True)
    monkeypatch.setattr(config, 'AUTOMATION_ALLOW_INSECURE_LOOPBACK', True)
    # Credential writes now require TLS even in the automation loopback lab.
    original_open=client.open
    def secure_vault(*args,**kwargs):
        path=args[0] if args else kwargs.get('path','')
        if str(path).startswith(('/api/automation/vault','/api/account/step-up')):
            kwargs.setdefault('base_url','https://localhost')
        return original_open(*args,**kwargs)
    monkeypatch.setattr(client,'open',secure_vault)

def test_disabled_and_authentication(app, client):
    assert client.get('/api/automation/state').status_code in (302,401)

@pytest.mark.parametrize('headers', [
    {'Forwarded': 'for=127.0.0.1'},
    {'X-Forwarded-For': '127.0.0.1'},
    {'X-Forwarded-Proto': 'http'},
])
def test_insecure_loopback_rejects_proxy_headers(app, client, context, enabled, headers):
    response = client.get('/api/automation/state', headers=headers)
    assert response.status_code == 403
    assert response.json['code'] == 'https_required'

def test_insecure_loopback_rejects_configured_proxy(app, client, context, enabled, monkeypatch):
    import config
    monkeypatch.setattr(config, 'TRUSTED_PROXIES', 1)
    response = client.get('/api/automation/state')
    assert response.status_code == 403
    assert response.json['code'] == 'https_required'

@pytest.mark.parametrize('operation', [[], {}, None, 12])
def test_vault_rejects_invalid_operation_type(app, client, context, enabled, operation):
    response = client.post('/api/automation/vault/intents', json={'operation': operation})
    assert response.status_code == 400
    assert response.json['code'] == 'invalid_request'

def test_vault_apply_requires_valid_intent(app, client, context, enabled):
    response = client.post('/api/automation/vault/apply', json={})
    assert response.status_code == 409
    assert response.json['code'] == 'invalid_intent'

def test_automation_page_preserves_deployment_prefix_and_private_cache(proxy_app):
    app, prefix = proxy_app
    client, _ = proxy_login(app, prefix)
    response = client.get('/automation', headers=proxy_headers(prefix), base_url='http://backend.local')
    assert response.status_code == 302
    assert response.headers['Location'] == f'{prefix}/#automation'
    shell = client.get('/', headers=proxy_headers(prefix), base_url='http://backend.local')
    assert shell.status_code == 200
    page = shell.get_data(as_text=True)
    assert f'name="app-root" content="{prefix or "/"}"' in page
    assert 'id="automationNavBtn"' in page
    assert 'id="automationNativeView"' in page
    assert f'{prefix}/static/js/automation.js?' in page
    assert response.headers['Cache-Control'] == 'no-store'

def test_vault_requires_exact_step_up_and_no_password_read(app, client, context, enabled):
    uid, aid, book, profile = context
    prepared = client.post('/api/automation/vault/intents', json=dict(operation='setup'))
    assert prepared.status_code == 200
    token = prepared.json['intent']
    body = dict(intent=token, passphrase='a separate strong vault passphrase', acknowledged=True)
    assert client.post('/api/automation/vault/apply', json=body).status_code == 403
    headers, _ = account_password_step_up_headers(client, action='automation.vault', target=token, password='password123')
    response = client.post('/api/automation/vault/apply', json=body, headers=headers)
    assert response.status_code == 200
    assert response.json['unlocked'] is True
    assert 'passphrase' not in str(response.json)
    assert client.post('/api/automation/vault/apply', json=body, headers=headers).status_code in (403,409)
    assert client.post('/api/automation/vault/lock', json={}).status_code == 200
    assert client.get('/api/automation/state').json['vault']['unlocked'] is False

def test_https_and_disabled_operator_gate(app, client, context, enabled, monkeypatch):
    import config
    monkeypatch.setattr(config, 'AUTOMATION_ALLOW_INSECURE_LOOPBACK', False)
    assert client.get('/api/automation/state').status_code == 403
    assert client.get('/api/automation/state', base_url='https://localhost').status_code == 200
    from app.app_settings import set_automation_enabled
    set_automation_enabled(False)
    assert client.post('/api/automation/preview', json={}, base_url='https://localhost').status_code == 403

def test_vault_intent_cannot_authorize_run(app, client, context, enabled):
    token = client.post('/api/automation/vault/intents', json=dict(operation='setup')).json['intent']
    response = client.post('/api/account/step-up/intents', json=dict(action='automation.run', target=token))
    assert response.status_code == 400

def test_csrf_required(app, client, context, enabled):
    app.config['WTF_CSRF_ENABLED'] = True
    assert client.post('/api/automation/vault/lock', json={}).status_code == 400

def test_logout_immediately_locks_vault(app, client, context, enabled):
    uid, aid, _, _ = context
    with app.app_context():
        vault = app.extensions['automation'].vault
        vault.setup(uid, aid, 'separate vault passphrase long enough')
        key = vault._leases[uid]['key']
    assert client.post('/logout').status_code == 302
    assert uid not in vault._leases
    assert not any(key)

def test_lock_invalidates_pending_unlock_intents(app,client,context,enabled):
    uid,aid,_,_=context
    with app.app_context():app.extensions['automation'].vault.setup(uid,aid,'separate vault passphrase long enough')
    token=client.post('/api/automation/vault/intents',json=dict(operation='unlock')).json['intent']
    headers,_=account_password_step_up_headers(client,action='automation.vault',target=token)
    assert client.post('/api/automation/vault/lock',json={}).status_code==200
    response=client.post('/api/automation/vault/apply',json=dict(intent=token,passphrase='separate vault passphrase long enough'),headers=headers)
    assert response.status_code==409
    assert not client.get('/api/automation/state').json['vault']['unlocked']


def test_schedule_run_now_requires_fresh_step_up_and_consumes_once(app, client, context, enabled, monkeypatch):
    from datetime import datetime, timezone
    from tests.test_automation_schedules import activate
    uid, aid, book, profile = context
    service = app.extensions['automation_schedules']
    credentials = service.automation.credentials
    monkeypatch.setattr(credentials, 'generations', lambda *args: {'one': 'generation'})
    monkeypatch.setattr(credentials, 'schedule_generations', lambda *args: {'one': 'generation'})
    monkeypatch.setattr(credentials, 'password', lambda *args: 'test-only')
    schedule = activate((service, uid, aid, book, profile), datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc))
    response = client.post(f"/api/automation/schedules/{schedule['id']}/preview-run", json={})
    assert response.status_code == 200
    token = response.json['intent']
    body = dict(intent=token, confirmation='1')
    assert client.post('/api/automation/start', json=body).json['code'] == 'step_up_required'
    headers, _ = account_password_step_up_headers(client, action='automation.run', target=token, password='password123')
    # Capture dispatch at the lifecycle boundary; authorization and intent
    # consumption still use the production start path.
    jobs = []
    monkeypatch.setattr(app.extensions['runtime_lifecycle'], 'start_job', lambda *args, **kwargs: jobs.append(args))
    assert client.post('/api/automation/start', json=body, headers=headers).status_code == 202
    assert len(jobs) == 1
    assert client.post('/api/automation/start', json=body, headers=headers).status_code == 409
    assert service.list(uid) == [schedule]
    import threading
    cancelled = threading.Event()
    cancelled.set()
    jobs[0][1](cancelled)

def test_library_delete_requires_csrf_and_preserves_book(app, client, context, enabled):
    from app.automation_store import runbooks
    uid, _, book, _ = context
    app.config['WTF_CSRF_ENABLED'] = True
    response = client.delete('/api/automation/runbooks/' + book['id'])
    assert response.status_code == 400
    assert any(item['id'] == book['id'] for item in runbooks(uid))


def test_library_cannot_edit_or_delete_another_users_workflow(app, client, context, enabled):
    from app.auth import register_user
    from app.automation_store import save_runbook, runbooks
    user, error = register_user('other_workflow_owner', 'other-test-password')
    assert error is None
    book = save_runbook(user.id, dict(name='Private workflow', steps=[dict(name='Identity', command='id', timeout=5)]))
    response = client.delete('/api/automation/runbooks/' + book['id'])
    assert response.status_code == 404
    response = client.post('/api/automation/runbooks', json={**book, 'name': 'Changed'})
    assert response.status_code == 404
    assert runbooks(user.id) == [book]
