"""Real disposable SSH/SFTP acceptance for server-managed named credentials."""
import os
import time
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from tests.integration.test_automation_openssh import peer, trust, PASSWORD

pytestmark = pytest.mark.skipif(os.environ.get('PARAMIKO5_INTEGRATION') != '1', reason='requires disposable OpenSSH lab')


def test_named_password_sftp_and_unattended_schedule(app, client, peer):
    from app.app_settings import set_credentials_enabled, set_automation_enabled
    from app.models import AuthenticationSession, db
    from app.profile_manager import add_profile
    from app.automation_store import AutomationError, save_runbook
    from app.connection_pool import TemporaryConnectionPool
    uid, target = peer
    set_credentials_enabled(True)
    set_automation_enabled(True)
    profile, error = add_profile(uid, 'Named credential lab', target['host'], target['port'], target['username'], 'password')
    assert error is None
    assert client.post('/login', data={'username':'automation_integration','password':'integration-password'}).status_code == 302
    auth = AuthenticationSession.query.filter_by(user_id=uid).first()
    aid = auth.id
    credentials = app.extensions['credentials']
    record = credentials.create_named(uid, dict(name='Disposable SSH', username=target['username'], password=PASSWORD))
    credentials.assign_named(uid, profile['id'], record['id'], True)
    token = credentials.connection_generation(uid, aid, 'ssh', profile['id'], profile)
    def check():
        if credentials.connection_generation(uid, aid, 'ssh', profile['id'], profile) != token:
            raise AutomationError('credential_target_changed')
    trust(uid)
    pool = TemporaryConnectionPool()
    pool.bind_lifecycle(app.extensions['runtime_lifecycle'])
    connection_id, error = pool.create_connection(host=profile['host'], port=profile['port'], username=profile['username'],
        password=credentials.connection_password(uid, aid, 'ssh', profile['id'], profile), user_id=uid,
        credential_guard=SimpleNamespace(check=check))
    assert error is None and connection_id
    try:
        sftp, error = pool.get_sftp_client(connection_id)
        assert error is None and sftp.stat('.').st_mode
        book = save_runbook(uid, dict(name='Disposable scheduled identity', steps=[dict(name='Identity',command='id',timeout=5,sudo=False)]))
        schedules = app.extensions['automation_schedules']
        now = datetime.now(timezone.utc)
        preview = schedules.prepare(uid, aid, dict(runbook_id=book['id'],profile_ids=[profile['id']],cron='* * * * *',timezone='UTC'), now=now)
        scheduled = schedules.apply(uid, aid, preview['intent'], '1', now=now)
        db.session.delete(auth)
        db.session.commit()
        schedules.tick(now=datetime.fromisoformat(scheduled['next_due']))
        engine = app.extensions['automation']
        deadline = time.monotonic() + 20
        while uid in engine._active and time.monotonic() < deadline:
            time.sleep(.05)
        assert uid not in engine._active
        runs = engine.history(uid)
        assert runs[0]['status'] == 'succeeded'
        assert runs[0]['targets'][0]['steps'][0]['exit_code'] == 0
        assert PASSWORD not in str(runs)
        set_credentials_enabled(False)
        assert sftp.stat('.').st_mode
        with pytest.raises(AutomationError):
            credentials.schedule_password(uid, profile)
    finally:
        pool.close_connection(connection_id)
