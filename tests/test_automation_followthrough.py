import pytest
from tests.test_automation_service import context
from tests.test_automation_routes import enabled
from tests.test_automation_schedules import scheduling


def test_notification_opt_in_owner_and_no_url(app, client, context, enabled):
    response = client.post('/api/automation/notifications', json={'enabled': True, 'url': 'https://attacker.invalid'})
    assert response.status_code == 400
    response = client.post('/api/automation/notifications', json={'enabled': True})
    assert response.status_code == 200
    assert response.json['notifications']['enabled'] is True
    assert response.json['notifications']['available'] is False


def test_export_is_owner_only_and_csv_safe(app, client, context, enabled):
    service = app.extensions['automation']
    uid = context[0]
    record = dict(id='retained', name='=HYPERLINK("evil")', created_at='2026-01-01', status='failed', targets=[dict(id='p',name='+host',host='host',port=22,username='u',group=None,status='failed',reason=None,steps=[dict(name='@step',status='failed',exit_code=1,duration=1)])])
    service._persist(uid, record)
    response = client.get('/api/automation/runs/retained/export?format=csv')
    assert response.status_code == 200
    assert "'=HYPERLINK" in response.text and "'+host" in response.text and "'@step" in response.text
    assert client.get('/api/automation/runs/missing/export').status_code == 404
    assert client.get('/api/automation/runs/retained/export?format=exe').status_code == 400


def test_notifications_never_send_without_config_and_opt_in(app, context, monkeypatch):
    from app import automation_notifications as notifications
    calls = []
    monkeypatch.setattr(notifications, '_post', lambda *args: calls.append(args))
    uid = context[0]
    with app.app_context():
        notifications.notify(uid, 'failed')
        app.config['AUTOMATION_NOTIFICATION_WEBHOOK_URL'] = 'https://notify.invalid/hook'
        notifications.notify(uid, 'unknown')
    assert calls == []
    from app.automation_store import notification_preferences
    notification_preferences(uid, True)
    app.config['AUTOMATION_NOTIFICATION_WEBHOOK_URL'] = ''
    notifications.notify(uid, 'failed')
    assert calls == []
    assert notifications.status(uid)['delivery'] == 'unavailable'


def test_notification_payload_is_fixed_and_failure_is_separate(app, context, monkeypatch):
    from app import automation_notifications as notifications
    from app.automation_store import notification_preferences
    uid = context[0]
    calls = []
    import threading
    monkeypatch.setattr(app.extensions['runtime_lifecycle'], 'start_job', lambda name, target, **kwargs: target(threading.Event()))
    with app.app_context():
        notification_preferences(uid, True)
        app.config['AUTOMATION_NOTIFICATION_WEBHOOK_URL'] = 'https://notify.invalid/hook'
        monkeypatch.setattr(notifications, '_post', lambda url, payload: calls.append((url, payload)))
        notifications.notify(uid, 'failed')
        assert calls[0][1] == {'event': 'workflow_attention', 'status': 'failed'}
        def broken(*args):
            raise RuntimeError('secret endpoint diagnostics')
        monkeypatch.setattr(notifications, '_post', broken)
        notifications.notify(uid, 'unknown')
        assert notifications.status(uid)['delivery'] == 'failed'
        assert 'secret' not in str(notifications.status(uid))


@pytest.mark.parametrize('url', ['http://notify.invalid', 'https://u:p@notify.invalid', 'https://notify.invalid/#fragment', 'file:///etc/passwd'])
def test_invalid_notification_endpoints_unavailable(app, context, url):
    from app.automation_notifications import status
    with app.app_context():
        app.config['AUTOMATION_NOTIFICATION_WEBHOOK_URL'] = url
        assert status(context[0])['available'] is False

def test_exports_and_preferences_are_fenced_to_authenticated_account(app, client, context, enabled):
    from app.auth import register_user
    from app.automation_store import notification_preferences
    user, error = register_user('notification_other', 'other-password123')
    assert error is None
    notification_preferences(user.id, True)
    record = dict(id='private-run', name='Private', created_at='2026-01-01', status='failed', targets=[dict(id='p',name='Private target',host='private.invalid',port=22,username='u',group=None,status='failed',reason=None,steps=[dict(name='step',status='failed',exit_code=1,duration=1)])])
    app.extensions['automation']._persist(user.id, record)
    assert client.get('/api/automation/runs/private-run/export').status_code == 404
    response = client.post('/api/automation/notifications', json={'enabled': False})
    assert response.status_code == 200
    assert notification_preferences(user.id)['enabled'] is True
    assert notification_preferences(context[0])['enabled'] is False
    app.config['WTF_CSRF_ENABLED'] = True
    assert client.post('/api/automation/notifications', json={'enabled': True}).status_code == 400


def test_delivery_runs_off_scheduler_and_rechecks_opt_in(app, context, monkeypatch):
    import threading
    from app import automation_notifications as notifications
    from app.automation_store import notification_preferences
    uid = context[0]
    jobs, calls = [], []
    monkeypatch.setattr(app.extensions['runtime_lifecycle'], 'start_job', lambda name, target, **kwargs: jobs.append(target))
    monkeypatch.setattr(notifications, '_post', lambda *args: calls.append(args))
    app.config['AUTOMATION_NOTIFICATION_WEBHOOK_URL'] = 'https://notify.invalid/hook'
    notification_preferences(uid, True)
    notifications.notify(uid, 'unknown')
    assert notifications.status(uid)['delivery'] == 'pending'
    assert calls == [] and len(jobs) == 1
    notification_preferences(uid, False)
    jobs[0](threading.Event())
    assert calls == []
    assert notifications.status(uid)['delivery'] == 'failed'


def test_webhook_transport_rejects_redirect_without_proxy_or_response_body(app, monkeypatch):
    from app import automation_notifications as notifications
    captured = []
    class Connection:
        def __init__(self, host, port, **kwargs):
            captured.append((host, port, kwargs))
        def request(self, method, path, **kwargs):
            captured.append((method, path, kwargs))
        def getresponse(self):
            return type('Response', (), {'status': 302})()
        def close(self):
            captured.append('closed')
    monkeypatch.setenv('HTTPS_PROXY', 'http://attacker.invalid')
    monkeypatch.setattr(notifications.http.client, 'HTTPSConnection', Connection)
    with pytest.raises(ValueError):
        notifications._post('https://controlled.internal:8443/alerts', {'event': 'workflow_attention', 'status': 'failed'})
    assert captured[0][0:2] == ('controlled.internal', 8443)
    assert captured[0][2]['timeout'] == 3
    assert captured[0][2]['context'].check_hostname
    assert captured[1][0:2] == ('POST', '/alerts')
    assert captured[-1] == 'closed' and len(captured) == 3


def test_scheduler_unknown_and_reapproval_notifications_are_transition_only(app, scheduling, monkeypatch):
    from datetime import datetime, timezone
    from app.automation_schedule import AutomationSchedule
    from app.models import db
    from tests.test_automation_schedules import activate
    service, uid, *_ = scheduling
    now = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
    calls = []
    monkeypatch.setattr('app.automation_notifications.notify', lambda owner, event: calls.append((owner, event)))
    schedule = activate(scheduling, now)
    row = db.session.get(AutomationSchedule, schedule['id'])
    row.claim_id = 'stale-claim'
    row.claimed_at = now.timestamp() - 2000
    db.session.commit()
    service.tick(now=now)
    service.tick(now=now)
    assert calls == [(uid, 'unknown')]
    row.enabled = True
    row.claim_id = None
    row.last_status = 'waiting'
    row.next_at = now.timestamp()
    row.grant = {**row.grant, 'policy': 'outdated-policy'}
    db.session.commit()
    service.tick(now=now)
    service.tick(now=now)
    assert calls == [(uid, 'unknown'), (uid, 'needs_review')]



def test_orphaned_notification_attempt_is_unconfirmed_after_restart(app, context):
    from app.automation_store import notification_preferences
    from app.automation_notifications import status
    notification_preferences(context[0], True, delivery='pending')
    assert status(context[0])['delivery'] == 'failed'


def test_transport_admission_has_no_unbounded_thread_queue(app, monkeypatch):
    from app import automation_notifications as notifications
    calls = []
    monkeypatch.setattr(notifications, '_post', lambda *args: calls.append(args))
    assert notifications._network_slot.acquire(blocking=False)
    try:
        with pytest.raises(TimeoutError):
            notifications._deliver('https://notify.invalid', {'event': 'workflow_attention', 'status': 'failed'})
    finally:
        notifications._network_slot.release()
    assert calls == []

@pytest.mark.parametrize('revocation', ['lock', 'generation', 'epoch', 'disable', 'policy'])
def test_queued_delivery_rechecks_account_and_automation_authority(app, context, monkeypatch, revocation):
    import threading
    from app import automation_notifications as notifications
    from app.automation_store import notification_preferences
    from app.models import User, db
    from app.app_settings import set_automation_enabled
    uid = context[0]
    jobs, calls = [], []
    app.config['AUTOMATION_NOTIFICATION_WEBHOOK_URL'] = 'https://notify.invalid/hook'
    notification_preferences(uid, True)
    monkeypatch.setattr(app.extensions['runtime_lifecycle'], 'start_job', lambda name, target, **kwargs: jobs.append(target))
    monkeypatch.setattr(notifications, '_post', lambda *args: calls.append(args))
    notifications.notify(uid, 'unknown')
    assert len(jobs) == 1
    if revocation == 'lock':
        db.session.get(User, uid).is_locked = True
        db.session.commit()
    elif revocation == 'generation':
        user = db.session.get(User, uid)
        user.auth_generation = int(user.auth_generation or 0) + 1
        db.session.commit()
    elif revocation == 'epoch':
        from app.session_epoch import rotate_epoch
        rotate_epoch()
    else:
        set_automation_enabled(False)
        if revocation == 'policy':
            set_automation_enabled(True)
    jobs[0](threading.Event())
    assert calls == []
    assert notifications.status(uid)['delivery'] == 'failed'


def test_manual_orphan_persists_unknown_once_and_never_replays_notification(app, context, monkeypatch):
    from app.automation_service import AutomationService
    service = AutomationService(app)
    uid = context[0]
    record = dict(id='orphan-run', name='Interrupted', created_at='2026-01-01', status='running', targets=[dict(id='p',name='target',host='host.invalid',port=22,username='u',group=None,status='running',reason=None,steps=[dict(name='step',status='running',exit_code=None,duration=0)])])
    service._persist(uid, record)
    calls = []
    monkeypatch.setattr('app.automation_notifications.notify', lambda owner, event: calls.append((owner, event)))
    assert service.history(uid)[0]['status'] == 'unknown'
    assert service.history(uid)[0]['status'] == 'unknown'
    assert calls == [(uid, 'unknown')]
    restarted = AutomationService(app)
    assert restarted.history(uid)[0]['status'] == 'unknown'
    assert calls == [(uid, 'unknown')]
