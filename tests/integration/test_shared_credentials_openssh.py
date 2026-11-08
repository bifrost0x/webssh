"""Shared credentials authenticate real disposable SSH/SFTP peers."""
import os
from types import SimpleNamespace

import pytest

from tests.integration.test_automation_openssh import peer, trust, PASSWORD

pytestmark = pytest.mark.skipif(os.environ.get('PARAMIKO5_INTEGRATION') != '1',
                                reason='requires disposable OpenSSH lab')


def test_saved_password_sftp_survives_lock_but_new_authentication_does_not(app, client, peer):
    from app.app_settings import set_credentials_enabled
    from app.models import AuthenticationSession
    from app.profile_manager import add_profile
    from app.automation_store import AutomationError
    from app import connection_pool
    uid, target = peer
    set_credentials_enabled(True)
    profile, error = add_profile(uid, 'Shared vault target', target['host'], target['port'],
                                 target['username'], 'password')
    assert error is None
    assert client.post('/login', data={'username': 'automation_integration',
                                     'password': 'integration-password'}).status_code == 302
    aid = AuthenticationSession.query.filter_by(user_id=uid).first().id
    service = app.extensions['credentials']
    service.vault.setup(uid, aid, 'a separate integration vault passphrase')
    service.vault.put(uid, aid, service.resolve_resource(uid, profile['id']), PASSWORD)
    token = service.connection_generation(uid, aid, 'ssh', profile['id'], profile)
    def check():
        if service.connection_generation(uid, aid, 'ssh', profile['id'], profile) != token:
            raise AutomationError('vault_locked')
    guard = SimpleNamespace(check=check)
    secret = service.connection_password(uid, aid, 'ssh', profile['id'], profile)
    trust(uid)
    pool = connection_pool.TemporaryConnectionPool()
    pool.bind_lifecycle(app.extensions['runtime_lifecycle'])
    connection_id, error = pool.create_connection(host=profile['host'], port=profile['port'],
        username=profile['username'], password=secret, user_id=uid, credential_guard=guard)
    assert error is None and connection_id
    try:
        sftp, error = pool.get_sftp_client(connection_id)
        assert error is None
        assert sftp.stat('.').st_mode
        service.revoke(uid)
        assert sftp.stat('.').st_mode, 'Lock must not close an already authenticated SFTP connection'
        with pytest.raises(AutomationError, match='vault_locked'):
            service.connection_password(uid, aid, 'ssh', profile['id'], profile)
        new_id, error = pool.create_connection(host=profile['host'], port=profile['port'],
            username=profile['username'], password=secret, user_id=uid, credential_guard=guard)
        assert new_id is None and error
    finally:
        secret = None
        pool.close_connection(connection_id)
