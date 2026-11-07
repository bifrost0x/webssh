"""Binding a saved password to a destination requires account reauthentication."""
import pytest

from tests.test_automation_service import context  # noqa: F401  (fixture)


SECURE = dict(base_url='https://localhost')


def _prepare(client, mutation):
    response = client.post('/api/credentials/intents', json=dict(operation='native', mutation=mutation), **SECURE)
    assert response.status_code == 200, response.json
    return response.json['intent']


def _step_up(client, token, password='password123'):
    started = client.post('/api/account/step-up/intents', json=dict(action='credentials.vault', target=token), **SECURE)
    assert started.status_code == 200, started.json
    approved = client.post('/api/account/step-up/password', json=dict(intent=started.json['intent'], password=password), **SECURE)
    assert approved.status_code == 200, approved.json
    return {'X-WebSSH-Step-Up': approved.json['grant']}


def _target_body(record_id, host='attacker.example'):
    return dict(credential_id=record_id, confirm_target=True,
                target=dict(host=host, port=2222, username='operator'))


def test_authorize_target_requires_reauthentication_for_the_exact_intent(app, client, context):
    uid, aid, _book, _profile = context
    service = app.extensions['credentials']
    record = service.create_named(uid, dict(name='Saved', password='victim-secret'))
    body = _target_body(record['id'])
    token = _prepare(client, dict(method='authorize_target', **body))

    denied = client.post('/api/credentials/authorize-target', json=dict(intent=token, **body), **SECURE)
    assert denied.status_code == 403
    assert denied.json['code'] == 'step_up_required'
    assert 'credential_target_token' not in denied.json

    # The intent was not consumed by the refused attempt.
    headers = _step_up(client, token)
    allowed = client.post('/api/credentials/authorize-target', json=dict(intent=token, **body), headers=headers, **SECURE)
    assert allowed.status_code == 200
    assert 'victim-secret' not in allowed.get_data(as_text=True)
    target_token = allowed.json['credential_target_token']
    assert service.target_password(uid, aid, record['id'], body['target'], target_token) == 'victim-secret'
    # Single use.
    assert client.post('/api/credentials/authorize-target', json=dict(intent=token, **body), headers=headers, **SECURE).status_code == 409


def test_authorize_target_rejects_legacy_request_without_intent(app, client, context):
    uid, _aid, _book, _profile = context
    record = app.extensions['credentials'].create_named(uid, dict(name='Saved', password='victim-secret'))
    response = client.post('/api/credentials/authorize-target', json=_target_body(record['id']), **SECURE)
    assert response.status_code == 409
    assert response.json['code'] == 'invalid_intent'


def test_grant_for_another_intent_is_refused(app, client, context):
    uid, _aid, _book, _profile = context
    record = app.extensions['credentials'].create_named(uid, dict(name='Saved', password='victim-secret'))
    first = _target_body(record['id'], host='first.example')
    second = _target_body(record['id'], host='second.example')
    first_token = _prepare(client, dict(method='authorize_target', **first))
    second_token = _prepare(client, dict(method='authorize_target', **second))
    headers = _step_up(client, first_token)
    response = client.post('/api/credentials/authorize-target', json=dict(intent=second_token, **second), headers=headers, **SECURE)
    assert response.status_code == 403
    assert response.json['code'] == 'step_up_required'


def test_assign_requires_reauthentication_but_unassign_does_not(app, client, context):
    uid, _aid, _book, profile = context
    service = app.extensions['credentials']
    record = service.create_named(uid, dict(name='Saved', password='assigned-secret'))
    payload = dict(resource_id=profile['id'], credential_id=record['id'], confirm_target=True)
    token = _prepare(client, dict(method='assign', **payload))
    denied = client.post('/api/credentials/assign', json=dict(intent=token, **payload), **SECURE)
    assert denied.status_code == 403
    assert denied.json['code'] == 'step_up_required'
    assert profile['id'] not in service.named.read(uid)['assignments']

    headers = _step_up(client, token)
    assert client.post('/api/credentials/assign', json=dict(intent=token, **payload), headers=headers, **SECURE).status_code == 200
    assert profile['id'] in service.named.read(uid)['assignments']

    service.revoke(uid)  # drop the recent-verification window
    assignment = service.named.read(uid)['assignments'][profile['id']]
    removal = dict(resource_id=profile['id'], credential_id=None, confirm_target=True, expected_assignment=assignment)
    token = _prepare(client, dict(method='assign', **removal))
    assert client.post('/api/credentials/assign', json=dict(intent=token, **removal), **SECURE).status_code == 200
    assert profile['id'] not in service.named.read(uid)['assignments']


def test_one_verification_covers_a_batch_until_revoked(app, client, context):
    from app.profile_manager import add_profile
    uid, aid, _book, _profile = context
    service = app.extensions['credentials']
    record = service.create_named(uid, dict(name='Shared', password='batch-secret'))
    payloads = []
    for index in range(3):
        profile, error = add_profile(uid, f'Batch {index}', f'batch-{index}.example', 22, 'operator', 'password')
        assert error is None
        payloads.append(dict(resource_id=profile['id'], credential_id=record['id'], confirm_target=True))
    token = _prepare(client, dict(method='assign', **payloads[0]))
    headers = _step_up(client, token)
    assert client.post('/api/credentials/assign', json=dict(intent=token, **payloads[0]), headers=headers, **SECURE).status_code == 200
    token = _prepare(client, dict(method='assign', **payloads[1]))
    assert client.post('/api/credentials/assign', json=dict(intent=token, **payloads[1]), **SECURE).status_code == 200
    service.revoke_session(aid)
    token = _prepare(client, dict(method='assign', **payloads[2]))
    denied = client.post('/api/credentials/assign', json=dict(intent=token, **payloads[2]), **SECURE)
    assert denied.status_code == 403
    assert denied.json['code'] == 'step_up_required'


def test_verification_window_expires_and_follows_policy_revision(app, context, monkeypatch):
    from app import credential_service
    from app.app_settings import set_credentials_enabled
    uid, aid, _book, _profile = context
    service = app.extensions['credentials']
    service.assure_binding(uid, aid)
    assert service.binding_assured(uid, aid) is True
    assert service.binding_assured(uid, aid + 1) is False
    now = credential_service.time.monotonic()
    monkeypatch.setattr(credential_service.time, 'monotonic', lambda: now + credential_service.BINDING_ASSURANCE_SECONDS + 1)
    assert service.binding_assured(uid, aid) is False
    monkeypatch.undo()
    service.assure_binding(uid, aid)
    set_credentials_enabled(False)
    set_credentials_enabled(True)
    assert service.binding_assured(uid, aid) is False


def test_legacy_import_requires_reauthentication_and_vault_rate_limit(app, client, context, monkeypatch):
    uid, aid, _book, _profile = context
    service = app.extensions['credentials']
    service.vault.setup(uid, aid, 'separate vault passphrase long enough')
    service.vault.lock(uid)
    payload = dict(passphrase='separate vault passphrase long enough')
    token = _prepare(client, dict(method='import', **payload))
    denied = client.post('/api/credentials/import-legacy', json=dict(intent=token, **payload), **SECURE)
    assert denied.status_code == 403
    assert denied.json['code'] == 'step_up_required'

    calls = []
    import app.credential_routes as routes

    def limited(user_id, remote_addr, bucket, limit):
        calls.append((bucket, limit))
        return False

    monkeypatch.setattr(routes, 'check_reauth_rate_limit', limited)
    _prepare(client, dict(method='import', **payload))
    _prepare(client, dict(method='create', name='Typed', password='typed-secret'))
    assert calls == [('automation_vault', '10 per minute'), ('credential_change', '120 per minute')]


@pytest.mark.parametrize('method,payload', [
    ('create', dict(name='Typed', password='typed-secret')),
])
def test_typing_a_new_password_needs_no_reauthentication(app, client, context, method, payload):
    token = _prepare(client, dict(method=method, **payload))
    assert client.post('/api/credentials', json=dict(intent=token, **payload), **SECURE).status_code == 200
