"""Actual encrypted SMB source using a named credential assignment."""
import os
import threading
import pytest

pytestmark = pytest.mark.skipif(os.environ.get('SMB_INTEGRATION') != '1', reason='requires disposable Samba lab')


def test_named_smb_credentials_preserve_source_on_policy_disable(app, client):
    from app.auth import register_user
    from app.models import AuthenticationSession
    from app.app_settings import set_credentials_enabled
    from app.smb_share_manager import upsert_smb_share
    from app.smb_pool import SMBConnectionPool
    from app.automation_store import AutomationError
    set_credentials_enabled(True)
    user, error = register_user('native_smb', 'lab-account-password')
    assert error is None
    uid = user.id
    share, error = upsert_smb_share(uid, dict(name='Native Samba lab', host=os.environ['SMB_INTEGRATION_HOST'],
        share='Docs', domain='', username=os.environ['SMB_INTEGRATION_USER']))
    assert error is None
    assert client.post('/login', data={'username':'native_smb','password':'lab-account-password'}).status_code == 302
    aid = AuthenticationSession.query.filter_by(user_id=uid).first().id
    service = app.extensions['credentials']
    resource = service.resolve_resource(uid, 'smb:' + share['id'])
    credential = service.create_named(uid, dict(name='SMB lab',password=os.environ['SMB_INTEGRATION_PASSWORD']))
    service.assign_named(uid, resource['id'], credential['id'], True)
    with pytest.raises(AutomationError):
        service.connection_password(uid, aid, 'smb', resource['id'], dict(resource, share='Other'))
    pool = SMBConnectionPool(allowed_targets=(resource['host'],))
    try:
        source = pool.create_source(host=resource['host'],share=resource['share'],domain='',username=resource['username'],
            password=service.connection_password(uid, aid, 'smb', resource['id'], resource),user_id=str(uid),cancel_event=threading.Event())
        assert source.access['list'] == 'granted'
        set_credentials_enabled(False)
        assert pool.get_source(source.source_id, str(uid)) is not None
        with pytest.raises(AutomationError, match='credentials_disabled'):
            service.connection_password(uid, aid, 'smb', resource['id'], resource)
    finally:
        pool.close_all_sources()
