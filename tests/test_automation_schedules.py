from datetime import datetime, timezone
from copy import deepcopy

import pytest

from app.automation_store import AutomationError
from tests.test_automation_service import context


@pytest.fixture
def scheduling(app, context, monkeypatch):
    from app.automation_schedule import ScheduleService
    from app.app_settings import set_automation_enabled
    set_automation_enabled(True)
    uid, aid, book, profile = context
    credentials = app.extensions['credentials']
    monkeypatch.setattr(credentials, 'generations', lambda *args: {'one': 'generation'}, raising=False)
    monkeypatch.setattr(credentials, 'schedule_generations', lambda *args: {'one': 'generation'}, raising=False)
    monkeypatch.setattr(credentials, 'password', lambda *args: 'test-only', raising=False)
    service = ScheduleService(app)
    return service, uid, aid, book, profile


def activate(scheduling, now):
    service, uid, aid, book, profile = scheduling
    preview = service.prepare(uid, aid, dict(runbook_id=book['id'], profile_ids=[profile['id']], cron='* * * * *', timezone='UTC'), now=now)
    return service.apply(uid, aid, preview['intent'], '1', now=now)


def test_schedule_is_scoped_and_claimed_once(scheduling, monkeypatch):
    service, uid, aid, book, profile = scheduling
    now = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
    schedule = activate(scheduling, now)
    assert service.list(uid + 1) == []
    started = []
    monkeypatch.setattr(service.automation, 'start_scheduled', lambda grant: started.append(deepcopy(grant)), raising=False)
    service.tick(now=now.replace(minute=1))
    service.tick(now=now.replace(minute=1, second=5))
    assert len(started) == 1
    assert started[0]['schedule_id'] == schedule['id']
    assert 'test-only' not in str(service.list(uid))


def test_missed_jobs_are_not_replayed_and_pause_revokes_claim(scheduling, monkeypatch):
    service, uid, *_ = scheduling
    now = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
    schedule = activate(scheduling, now)
    started = []
    monkeypatch.setattr(service.automation, 'start_scheduled', lambda grant: started.append(grant), raising=False)
    service.tick(now=now.replace(minute=10))
    assert started == []
    assert service.list(uid)[0]['last_status'] == 'missed'
    service.tick(now=now.replace(minute=11))
    assert len(started) == 1
    service.pause(uid, schedule['id'])
    with pytest.raises(AutomationError):
        service.validate(started[0])


def test_policy_toggle_and_account_generation_require_reapproval(scheduling, monkeypatch):
    from app.app_settings import set_automation_enabled
    service, uid, *_ = scheduling
    now = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
    activate(scheduling, now)
    set_automation_enabled(False)
    set_automation_enabled(True)
    started = []
    monkeypatch.setattr(service.automation, 'start_scheduled', lambda grant: started.append(grant), raising=False)
    service.tick(now=now.replace(minute=1))
    assert started == []
    assert service.list(uid)[0]['last_status'] == 'needs_review'


def test_changed_runbook_cannot_run_approved_schedule(scheduling, monkeypatch):
    from app.automation_store import save_runbook
    service, uid, _, book, _ = scheduling
    now = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
    activate(scheduling, now)
    changed = deepcopy(book)
    changed['steps'][0]['command'] = 'changed'
    save_runbook(uid, changed)
    started = []
    monkeypatch.setattr(service.automation, 'start_scheduled', lambda grant: started.append(grant), raising=False)
    service.tick(now=now.replace(minute=1))
    assert not started
    assert service.list(uid)[0]['last_status'] == 'needs_review'


def test_restore_epoch_invalidates_durable_grants(scheduling, monkeypatch):
    from app.session_epoch import rotate_epoch
    service, uid, *_ = scheduling
    now = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
    activate(scheduling, now)
    rotate_epoch()
    started = []
    monkeypatch.setattr(service.automation, 'start_scheduled', lambda grant: started.append(grant))
    service.tick(now=now.replace(minute=1))
    assert started == []
    assert service.list(uid)[0]['last_status'] == 'needs_review'


def test_overlapping_slot_does_not_cancel_current_claim(scheduling, monkeypatch):
    service, uid, *_ = scheduling
    now = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
    activate(scheduling, now)
    started = []
    monkeypatch.setattr(service.automation, 'start_scheduled', lambda grant: started.append(grant))
    service.tick(now=now.replace(minute=1))
    service.tick(now=now.replace(minute=2))
    assert len(started) == 1
    service.validate(started[0])
    assert service.list(uid)[0]['last_status'] == 'overlap'
    service.finish(started[0], 'succeeded')
    assert service.list(uid)[0]['running'] is False


def test_crash_claim_pauses_unknown_without_replay(scheduling, monkeypatch):
    service, uid, *_ = scheduling
    now = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
    activate(scheduling, now)
    started = []
    monkeypatch.setattr(service.automation, 'start_scheduled', lambda grant: started.append(grant))
    service.tick(now=now.replace(minute=1))
    service.tick(now=now.replace(minute=34))
    assert len(started) == 1
    record = service.list(uid)[0]
    assert record['enabled'] is False
    assert record['last_status'] == 'unknown'


def test_real_engine_schedule_does_not_require_browser_session(scheduling, monkeypatch):
    import time
    from contextlib import contextmanager
    from app.models import AuthenticationSession, db
    service, uid, aid, *_ = scheduling
    now = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
    activate(scheduling, now)
    db.session.delete(db.session.get(AuthenticationSession, aid))
    db.session.commit()
    monkeypatch.setattr(service.automation.credentials, 'schedule_password', lambda *args: 'test-only')
    @contextmanager
    def connect(*args, **kwargs):
        assert args[2] == 'test-only'
        assert not args[3]()
        yield object()
    monkeypatch.setattr('app.automation_service.connect_profile', connect)
    monkeypatch.setattr('app.automation_service.execute_step', lambda *args: dict(status='succeeded',exit_code=0,duration=.1))
    service.tick(now=now.replace(minute=1))
    deadline = time.monotonic() + 5
    while uid in service.automation._active and time.monotonic() < deadline:
        time.sleep(.01)
    assert uid not in service.automation._active
    assert service.list(uid)[0]['last_status'] == 'succeeded'
    assert service.automation.history(uid)[0]['status'] == 'succeeded'

@pytest.mark.parametrize('dispatch_error', [False, True])
def test_monthly_stale_claim_requires_explicit_reapproval(scheduling, monkeypatch, dispatch_error):
    from app.automation_schedule import AutomationSchedule
    from app.models import db
    service, uid, aid, book, profile = scheduling
    now = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
    schedule = activate(scheduling, now)
    started = []
    def dispatch(grant):
        started.append(deepcopy(grant))
        if dispatch_error:
            raise RuntimeError('ambiguous dispatch')
    monkeypatch.setattr(service.automation, 'start_scheduled', dispatch)
    service.tick(now=now.replace(minute=1))
    row = db.session.get(AutomationSchedule, schedule['id'])
    row.next_at = datetime(2026, 12, 1, tzinfo=timezone.utc).timestamp()
    db.session.commit()
    with pytest.raises(AutomationError, match='preview_changed'):
        preview = service.prepare(uid, aid, dict(runbook_id=book['id'], profile_ids=[profile['id']], cron='* * * * *', timezone='UTC', schedule_id=schedule['id']), now=now)
        service.apply(uid, aid, preview['intent'], '1', now=now)
    service.tick(now=now.replace(minute=33))
    record = service.list(uid)[0]
    assert not record['enabled'] and not record['running'] and record['last_status'] == 'unknown'
    service.finish(started[0], 'succeeded')
    assert service.list(uid)[0]['last_status'] == 'unknown'
    service.tick(now=now.replace(minute=34))
    assert len(started) == 1
    preview = service.prepare(uid, aid, dict(runbook_id=book['id'], profile_ids=[profile['id']], cron='* * * * *', timezone='UTC', schedule_id=schedule['id']), now=now.replace(minute=34))
    record = service.apply(uid, aid, preview['intent'], '1', now=now.replace(minute=34))
    assert record['enabled'] and record['last_status'] == 'unknown'
    assert len(started) == 1


def test_account_delete_removes_schedules_and_incarnation_blocks_orphans(scheduling):
    from app.models import User, db
    from app.automation_schedule import AutomationSchedule
    from app.user_lifecycle import delete_user_account
    service, uid, aid, book, profile = scheduling
    now = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
    schedule = activate(scheduling, now)
    orphan_values = {c.name: deepcopy(getattr(db.session.get(AutomationSchedule, schedule['id']), c.name)) for c in AutomationSchedule.__table__.columns}
    delete_user_account(db.session.get(User, uid))
    assert db.session.get(AutomationSchedule, schedule['id']) is None
    replacement = User(id=uid, username='replacement', password_hash='unused')
    db.session.add(replacement)
    db.session.commit()
    # Simulate a legacy orphan surviving a pre-fix deletion or restored DB.
    db.session.add(AutomationSchedule(**orphan_values))
    db.session.commit()
    assert service.list(uid) == []
    for operation in (lambda: service._owned(uid, schedule['id']),
                      lambda: service.pause(uid, schedule['id']),
                      lambda: service.pause(uid, schedule['id'], delete=True),
                      lambda: service.prepare(uid, aid, dict(schedule_id=schedule['id'], cron='* * * * *', timezone='UTC'), now=now)):
        with pytest.raises(AutomationError, match='not_found'):
            operation()


def _concurrent(app, *operations):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from app.models import db
    barrier = Barrier(len(operations))
    def worker(operation):
        with app.app_context():
            barrier.wait(timeout=5)
            try:
                return operation()
            finally:
                db.session.remove()
    with ThreadPoolExecutor(max_workers=len(operations)) as pool:
        futures = [pool.submit(worker, operation) for operation in operations]
        return [future.result(timeout=15) for future in futures]


def test_concurrent_sessions_claim_exactly_once_and_finish_pause_preserves_state(app, scheduling, monkeypatch):
    from contextlib import nullcontext
    from threading import Barrier
    from app.models import db
    service, uid, *_ = scheduling
    now = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
    schedule = activate(scheduling, now)
    started = []
    monkeypatch.setattr(service.automation, 'start_scheduled', lambda grant: started.append(deepcopy(grant)))
    # Separate processes do not share the in-process user lock. Force both DB
    # sessions to validate the same due row before either can claim it.
    gate = Barrier(2)
    validate = service._validate_snapshot
    def simultaneous_snapshot(*args):
        validate(*args)
        gate.wait(timeout=5)
    monkeypatch.setattr('app.automation_schedule.user_data_access', lambda *args: nullcontext())
    monkeypatch.setattr(service, '_validate_snapshot', simultaneous_snapshot)
    _concurrent(app, lambda: service.tick(now=now.replace(minute=1)), lambda: service.tick(now=now.replace(minute=1)))
    monkeypatch.setattr(service, '_validate_snapshot', validate)
    assert len(started) == 1
    _concurrent(app, lambda: service.finish(started[0], 'succeeded'), lambda: service.pause(uid, schedule['id']))
    db.session.expire_all()
    record = service.list(uid)[0]
    assert not record['enabled'] and not record['running'] and record['last_status'] == 'paused'
    service.tick(now=now.replace(minute=2))
    assert len(started) == 1


def test_native_named_password_real_engine_without_browser_session(app, context, monkeypatch):
    import time
    from contextlib import contextmanager
    from app.automation_schedule import ScheduleService
    from app.app_settings import set_automation_enabled, set_credentials_enabled
    from app.models import AuthenticationSession, db
    set_automation_enabled(True)
    set_credentials_enabled(True)
    uid, aid, book, profile = context
    service = ScheduleService(app)
    credentials = service.automation.credentials
    record = credentials.create_named(uid, dict(name='Scheduled password', username=profile['username'], password='native-scheduled-secret'))
    credentials.assign_named(uid, profile['id'], record['id'], True)
    now = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
    activate((service, uid, aid, book, profile), now)
    db.session.delete(db.session.get(AuthenticationSession, aid))
    db.session.commit()
    seen = []
    @contextmanager
    def connect(*args, **kwargs):
        assert args[2] == 'native-scheduled-secret'
        assert not args[3]()
        seen.append(args[1]['id'])
        yield object()
    monkeypatch.setattr('app.automation_service.connect_profile', connect)
    monkeypatch.setattr('app.automation_service.execute_step', lambda *args: dict(status='succeeded', exit_code=0, duration=.1))
    service.tick(now=now.replace(minute=1))
    deadline = time.monotonic() + 5
    while uid in service.automation._active and time.monotonic() < deadline:
        time.sleep(.01)
    assert uid not in service.automation._active
    assert seen == [profile['id']]
    assert service.list(uid)[0]['last_status'] == 'succeeded'
    assert service.automation.history(uid)[0]['status'] == 'succeeded'
    assert 'native-scheduled-secret' not in str(service.list(uid)) + str(service.automation.history(uid))


def test_persisted_stop_fences_exact_claim_but_keeps_future_slots(scheduling, monkeypatch):
    service, uid, *_ = scheduling
    now = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
    schedule = activate(scheduling, now)
    started = []
    monkeypatch.setattr(service.automation, 'start_scheduled', lambda grant: started.append(deepcopy(grant)))
    service.tick(now=now.replace(minute=1))
    assert not service.cancel_run(uid, schedule['id'], 'foreign-claim')
    service.validate(started[0])
    assert service.cancel_run(uid, schedule['id'], started[0]['claim_id'])
    with pytest.raises(AutomationError, match='preview_changed'):
        service.validate(started[0])
    service.finish(started[0], 'cancelled')
    assert service.list(uid)[0]['enabled']
    service.tick(now=now.replace(minute=2))
    assert len(started) == 2
    service.validate(started[1])


def test_account_delete_schedule_cleanup_rolls_back_with_account(scheduling, monkeypatch):
    from app.models import User, db
    from app.automation_schedule import AutomationSchedule
    from app.user_lifecycle import delete_user_account
    service, uid, *_ = scheduling
    schedule = activate(scheduling, datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc))
    def fail_commit():
        raise RuntimeError('simulated database failure')
    # Avoid unrelated best-effort revocation commits: the transaction tested is
    # the account-and-schedule deletion after quarantine.
    monkeypatch.setattr('app.user_lifecycle.revoke_user_access', lambda *args: None)
    monkeypatch.setattr(db.session, 'commit', fail_commit)
    with pytest.raises(RuntimeError, match='simulated database failure'):
        delete_user_account(db.session.get(User, uid))
    assert db.session.get(User, uid) is not None
    assert db.session.get(AutomationSchedule, schedule['id']) is not None
    assert service.list(uid)[0]['id'] == schedule['id']


def test_pause_wins_against_concurrent_validated_claim(app, scheduling, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from contextlib import nullcontext
    from threading import Event
    from app.models import db
    service, uid, *_ = scheduling
    now = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
    schedule = activate(scheduling, now)
    validated, paused = Event(), Event()
    validate = service._validate_snapshot
    def blocked_validation(*args):
        validate(*args)
        validated.set()
        assert paused.wait(timeout=5)
    monkeypatch.setattr(service, '_validate_snapshot', blocked_validation)
    monkeypatch.setattr('app.automation_schedule.user_data_access', lambda *args: nullcontext())
    started = []
    monkeypatch.setattr(service.automation, 'start_scheduled', lambda grant: started.append(grant))
    def tick():
        with app.app_context():
            try:
                service.tick(now=now.replace(minute=1))
            finally:
                db.session.remove()
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(tick)
        assert validated.wait(timeout=5)
        service.pause(uid, schedule['id'])
        paused.set()
        future.result(timeout=10)
    db.session.expire_all()
    assert started == []
    assert not service.list(uid)[0]['enabled']
    assert service.list(uid)[0]['last_status'] == 'paused'


def test_run_now_uses_saved_snapshot_without_mutating_schedule(scheduling):
    from app.automation_store import save_runbook
    service, uid, aid, book, _ = scheduling
    schedule = activate(scheduling, datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc))
    changed = deepcopy(book)
    changed['steps'][0]['command'] = 'changed'
    save_runbook(uid, changed)
    preview = service.prepare_run(uid, aid, schedule['id'])
    assert preview['runbook'] == book
    intent = service.automation.intent(preview['intent'], uid, aid)
    assert intent['kind'] == 'run'
    service.automation.validate_run(intent)
    assert service.list(uid) == [schedule]


@pytest.mark.parametrize('mutation', ['pause', 'delete', 'edit', 'target', 'credentials'])
def test_run_now_revalidates_saved_schedule_and_live_access(scheduling, monkeypatch, mutation):
    from app.automation_schedule import AutomationSchedule
    from app.models import db
    from app.profile_manager import upsert_profile
    service, uid, aid, book, profile = scheduling
    schedule = activate(scheduling, datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc))
    preview = service.prepare_run(uid, aid, schedule['id'])
    intent = service.automation.intent(preview['intent'], uid, aid)
    if mutation in {'pause', 'delete'}:
        service.pause(uid, schedule['id'], delete=mutation == 'delete')
    elif mutation == 'edit':
        row = db.session.get(AutomationSchedule, schedule['id'])
        row.revision += 1
        db.session.commit()
    elif mutation == 'target':
        upsert_profile(uid, dict(profile, host='changed.example'))
    else:
        monkeypatch.setattr(service.automation.credentials, 'generations', lambda *args: {'one': 'revoked'})
    with pytest.raises(AutomationError):
        service.automation.validate_run(intent)


def test_run_now_is_owned_and_bound_to_session(scheduling):
    service, uid, aid, *_ = scheduling
    schedule = activate(scheduling, datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc))
    with pytest.raises(AutomationError, match='not_found'):
        service.prepare_run(uid + 1, aid, schedule['id'])
    preview = service.prepare_run(uid, aid, schedule['id'])
    with pytest.raises(AutomationError):
        service.automation.intent(preview['intent'], uid, aid + 1)
    service.automation.intent(preview['intent'], uid, aid, consume=True)
    with pytest.raises(AutomationError):
        service.automation.intent(preview['intent'], uid, aid)


def test_run_now_stops_after_schedule_revision_changes(scheduling, monkeypatch):
    import time
    from contextlib import contextmanager
    from app.automation_store import save_runbook
    service, uid, aid, book, profile = scheduling
    book = save_runbook(uid, dict(book, steps=book['steps'] + [dict(name='Second', command='whoami', timeout=5, sudo=False)]))
    schedule = activate((service, uid, aid, book, profile), datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc))
    @contextmanager
    def connect(*args, **kwargs):
        yield object()
    seen = []
    def execute(transport, step, cancelled, output_secrets, output_budget):
        seen.append(step['command'])
        service.pause(uid, schedule['id'])
        assert cancelled()
        return dict(status='succeeded', exit_code=0, duration=.1)
    monkeypatch.setattr('app.automation_service.connect_profile', connect)
    monkeypatch.setattr('app.automation_service.execute_step', execute)
    preview = service.prepare_run(uid, aid, schedule['id'])
    service.automation.start(preview['intent'], uid, aid, '1')
    deadline = time.monotonic() + 5
    while uid in service.automation._active and time.monotonic() < deadline:
        time.sleep(.01)
    assert uid not in service.automation._active
    assert seen == ['id']
    assert service.automation.history(uid)[0]['targets'][0]['steps'][1]['status'] == 'skipped'
    assert service.list(uid)[0]['last_status'] == 'paused'
