import threading
from types import SimpleNamespace

from tests.test_automation_service import context


def test_corrupt_history_does_not_prevent_local_stop(app, context, monkeypatch):
    service = app.extensions['automation']
    uid = context[0]
    closed = []
    state = dict(record={'id': 'active'}, cancel=threading.Event(),
                 resources=[SimpleNamespace(close=lambda: closed.append(True))])
    service._active[uid] = state
    def broken(*args):
        raise OSError('unreadable history')
    monkeypatch.setattr(service, '_read_history', broken)
    service.cancel(uid, 'active')
    assert state['cancel'].is_set()
    assert closed == [True]
    service._active.clear()


def test_account_deletion_cancels_active_scheduled_run_without_reentering_retired_gate(app, context):
    from app.models import User, db
    from app.user_lifecycle import delete_user_account
    service = app.extensions['automation']
    uid = context[0]
    closed = []
    state = dict(record={'id':'active','schedule_id':'schedule','claim_id':'claim'},
                 auth_id=0,cancel=threading.Event(),resources=[SimpleNamespace(close=lambda:closed.append(True))])
    service._active[uid] = state
    try:
        delete_user_account(db.session.get(User, uid))
        assert db.session.get(User, uid) is None
        assert state['cancel'].is_set()
        assert closed == [True]
    finally:
        service._active.clear()
