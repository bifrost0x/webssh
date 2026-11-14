from tests.test_automation_service import context
from tests.test_automation_routes import enabled
from tests.test_automation_schedules import scheduling


def test_external_notification_route_and_settings_are_absent(app, client, context, enabled):
    response = client.get('/api/automation/state')
    assert response.status_code == 200
    assert 'notifications' not in response.json
    assert client.post('/api/automation/notifications', json={'enabled': True}).status_code == 404


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

def test_exports_are_fenced_to_authenticated_account(app, client, context, enabled):
    from app.auth import register_user
    user, error = register_user('export_other', 'other-password123')
    assert error is None
    record = dict(id='private-run', name='Private', created_at='2026-01-01', status='failed', targets=[dict(id='p',name='Private target',host='private.invalid',port=22,username='u',group=None,status='failed',reason=None,steps=[dict(name='step',status='failed',exit_code=1,duration=1)])])
    app.extensions['automation']._persist(user.id, record)
    assert client.get('/api/automation/runs/private-run/export').status_code == 404

def test_scheduler_unknown_and_reapproval_states_persist(app, scheduling):
    from datetime import datetime, timezone
    from app.automation_schedule import AutomationSchedule
    from app.models import db
    from tests.test_automation_schedules import activate
    service, *_ = scheduling
    now = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
    schedule = activate(scheduling, now)
    row = db.session.get(AutomationSchedule, schedule['id'])
    row.claim_id = 'stale-claim'
    row.claimed_at = now.timestamp() - 2000
    db.session.commit()
    service.tick(now=now)
    service.tick(now=now)
    assert row.last_status == 'unknown'
    assert row.enabled is False
    assert row.claim_id is None
    row.enabled = True
    row.claim_id = None
    row.last_status = 'waiting'
    row.next_at = now.timestamp()
    row.grant = {**row.grant, 'policy': 'outdated-policy'}
    db.session.commit()
    service.tick(now=now)
    service.tick(now=now)
    assert row.last_status == 'needs_review'
    assert row.enabled is False

def test_manual_orphan_persists_unknown_across_reads_and_restart(app, context):
    from app.automation_service import AutomationService
    service = AutomationService(app)
    uid = context[0]
    record = dict(id='orphan-run', name='Interrupted', created_at='2026-01-01', status='running', targets=[dict(id='p',name='target',host='host.invalid',port=22,username='u',group=None,status='running',reason=None,steps=[dict(name='step',status='running',exit_code=None,duration=0)])])
    service._persist(uid, record)
    assert service.history(uid)[0]['status'] == 'unknown'
    assert service.history(uid)[0]['status'] == 'unknown'
    restarted = AutomationService(app)
    assert restarted.history(uid)[0]['status'] == 'unknown'
    target = restarted.history(uid)[0]['targets'][0]
    assert target['status'] == 'unknown'
    assert target['steps'][0]['status'] == 'unknown'
