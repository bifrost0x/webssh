"""Saved SMB credentials against the disposable encrypted Samba lab."""
import os
import threading
import pytest

pytestmark = pytest.mark.skipif(os.environ.get('SMB_INTEGRATION') != '1',
                                reason='requires disposable SMB lab')


def test_saved_smb_credential_is_bound_and_existing_source_survives_lock(app, client):
    from app.auth import register_user
    from app.models import AuthenticationSession
    from app.smb_share_manager import upsert_smb_share
    from app.smb_pool import SMBConnectionPool
    from app.automation_store import AutomationError
    with app.app_context():
        user, error = register_user('shared_smb_test', 'test-account-password')
        assert error is None
        uid = user.id
        share, error = upsert_smb_share(uid, dict(name='Samba lab', host=os.environ['SMB_INTEGRATION_HOST'],
            share='Docs', domain='', username=os.environ['SMB_INTEGRATION_USER']))
        assert error is None
        assert client.post('/login', data=dict(username='shared_smb_test', password='test-account-password')).status_code == 302
        aid = AuthenticationSession.query.filter_by(user_id=uid).first().id
        service = app.extensions['credentials']
        resource = service.resolve_resource(uid, 'smb:' + share['id'])
        service.vault.setup(uid, aid, 'a separate samba integration passphrase')
        service.vault.put(uid, aid, resource, os.environ['SMB_INTEGRATION_PASSWORD'])
        with pytest.raises(AutomationError):
            service.connection_password(uid, aid, 'smb', resource['id'], dict(resource, share='Other'))
        password = service.connection_password(uid, aid, 'smb', resource['id'], resource)
        pool = SMBConnectionPool(allowed_targets=(resource['host'],))
        try:
            source = pool.create_source(host=resource['host'], share=resource['share'], domain='',
                username=resource['username'], password=password, user_id=str(uid), cancel_event=threading.Event())
            assert source.access['list'] == 'granted'
            service.revoke(uid)
            assert pool.get_source(source.source_id, str(uid)) is not None
            with pytest.raises(AutomationError, match='vault_locked'):
                service.connection_password(uid, aid, 'smb', resource['id'], resource)
        finally:
            password = None
            pool.close_all_sources()
