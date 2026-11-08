"""Regression tests for scheduler dispatch, revalidation cost and network policy."""
from contextlib import contextmanager
from datetime import datetime, timezone
import threading
import time

import pytest

from tests.test_automation_service import context  # noqa: F401  (fixture)
from tests.test_automation_schedules import scheduling, activate  # noqa: F401


NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)


def test_busy_rejection_skips_the_slot_and_keeps_the_schedule(scheduling):
    service, uid, aid, book, profile = scheduling
    activate(scheduling, NOW)
    # A concurrent manual run occupies this user's run slot.
    service.automation._active[int(uid)] = dict(record=dict(id='other'), cancel=threading.Event(), resources=[], auth_id=1)
    try:
        service.tick(now=NOW.replace(minute=1))
    finally:
        service.automation._active.pop(int(uid))
    row = service.list(uid)[0]
    assert row['enabled'] is True
    assert row['last_status'] == 'skipped'
    assert row['running'] is False
    # The schedule stays editable and runs at the next slot.
    started = []
    original = service.automation.start_scheduled
    service.automation.start_scheduled = lambda grant: started.append(grant)
    try:
        service.tick(now=NOW.replace(minute=2))
    finally:
        service.automation.start_scheduled = original
    assert len(started) == 1


def test_global_capacity_rejection_is_not_an_ambiguous_dispatch(scheduling):
    service, uid, *_ = scheduling
    activate(scheduling, NOW)
    for other in range(4):
        service.automation._active[10_000 + other] = dict(record=dict(id=str(other)), cancel=threading.Event(), resources=[], auth_id=1)
    try:
        service.tick(now=NOW.replace(minute=1))
    finally:
        for other in range(4):
            service.automation._active.pop(10_000 + other)
    row = service.list(uid)[0]
    assert (row['enabled'], row['last_status'], row['running']) == (True, 'skipped', False)


def test_invalid_grant_at_dispatch_requires_review(scheduling, monkeypatch):
    from app.automation_store import AutomationError
    service, uid, *_ = scheduling
    activate(scheduling, NOW)

    def changed(intent):
        raise AutomationError('preview_changed')

    monkeypatch.setattr(service.automation, 'validate_run', changed)
    service.tick(now=NOW.replace(minute=1))
    row = service.list(uid)[0]
    assert (row['enabled'], row['last_status'], row['running']) == (False, 'needs_review', False)


def test_unexpected_dispatch_failure_stays_ambiguous(scheduling, monkeypatch):
    service, uid, *_ = scheduling
    activate(scheduling, NOW)

    def ambiguous(grant):
        raise RuntimeError('lost reply')

    monkeypatch.setattr(service.automation, 'start_scheduled', ambiguous)
    service.tick(now=NOW.replace(minute=1))
    row = service.list(uid)[0]
    assert (row['enabled'], row['last_status']) == (False, 'unknown')


def test_shutdown_rejection_marks_the_queued_record_skipped(app, scheduling, monkeypatch):
    from app.runtime_lifecycle import RuntimeShuttingDown
    from app.automation_store import AutomationNotDispatched
    from app.automation_store import user_path
    service, uid, *_ = scheduling
    activate(scheduling, NOW)

    def reject(*args, **kwargs):
        raise RuntimeShuttingDown('stopping')

    monkeypatch.setattr(app.extensions['runtime_lifecycle'], 'start_job', reject)
    service.tick(now=NOW.replace(minute=1))
    # The stored history passes its validator and shows the run as skipped.
    history = service.automation._read_history(user_path(uid, 'automation-runs.json'))
    assert history['runs'][0]['status'] == 'skipped'
    assert {target['status'] for target in history['runs'][0]['targets']} == {'skipped'}
    assert service.list(uid)[0]['last_status'] == 'skipped'
    assert int(uid) not in service.automation._active
    assert issubclass(AutomationNotDispatched, Exception)


def test_cancel_polling_revalidates_at_most_every_quarter_second(app, scheduling, monkeypatch):
    service, uid, *_ = scheduling
    activate(scheduling, NOW)
    monkeypatch.setattr(service.automation.credentials, 'schedule_password', lambda *args: 'test-only')
    schedules = app.extensions['automation_schedules']
    calls = []
    original = type(schedules)._validate_snapshot

    def counting(self, *args, **kwargs):
        calls.append(1)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(type(schedules), '_validate_snapshot', counting)
    app.extensions['automation_schedules'] = service

    @contextmanager
    def connect(*args, **kwargs):
        yield object()

    def execute(_target, _step, cancelled, *args):
        for _ in range(200):
            assert cancelled() is False
        return dict(status='succeeded', exit_code=0, duration=.1)

    monkeypatch.setattr('app.automation_service.connect_profile', connect)
    monkeypatch.setattr('app.automation_service.execute_step', execute)
    started = time.monotonic()
    service.tick(now=NOW.replace(minute=1))
    deadline = time.monotonic() + 20
    while int(uid) in service.automation._active and time.monotonic() < deadline:
        time.sleep(.01)
    elapsed = time.monotonic() - started
    # Dispatch, connect and authentication validate a fixed number of times;
    # the 200 cancellation polls add at most one per 250 ms window. Before the
    # throttle every poll revalidated (more than 200 validations).
    assert len(calls) <= 8 + int(elapsed / .25)


def test_key_digest_decrypts_once_until_the_stored_key_changes(app, context, monkeypatch, tmp_path):
    from app import automation_service
    uid, _aid, _book, _profile = context
    service = app.extensions['automation']
    key_file = tmp_path / 'key.pem'
    key_file.write_text('encrypted-v1')
    reads = []
    monkeypatch.setattr('app.key_manager.get_key_path', lambda user_id, key_id: str(key_file))

    def read(user_id, key_id):
        reads.append(key_id)
        return key_file.read_text(), None

    monkeypatch.setattr(automation_service, 'read_key_content', read)
    target = dict(id='p1', auth_type='key', key_id='k1')
    first = service._key_digests(uid, [target])
    for _ in range(20):
        assert service._key_digests(uid, [target]) == first
    assert reads == ['k1']
    key_file.write_text('encrypted-v2-replaced')
    assert service._key_digests(uid, [target]) != first
    assert reads == ['k1', 'k1']
    key_file.unlink()
    with pytest.raises(automation_service.AutomationError):
        service._key_digests(uid, [target])


def test_automation_transport_honors_the_private_network_allowlist(monkeypatch):
    import config
    from app import automation_transport
    seen = {}

    class Stop(Exception):
        pass

    def resolve(host, port, **kwargs):
        seen.update(kwargs)
        raise Stop()

    monkeypatch.setattr(automation_transport, 'resolve_allowed_target', resolve)
    monkeypatch.setattr(config, 'SSH_ALLOWED_INTERNAL_NETWORKS', ('10.20.0.0/16',))
    with pytest.raises(Exception):
        with automation_transport.connect_profile(1, dict(host='10.20.1.5', port=22, username='op', auth_type='password'),
                                                  'pw', lambda: False, lambda resource: None):
            pass
    assert seen['allowed_internal_networks'] == ('10.20.0.0/16',)
