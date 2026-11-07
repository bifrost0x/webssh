"""Automation transport against the disposable OpenSSH integration lab."""
import os
import socket
import threading
from pathlib import Path
import paramiko
import pytest
import config
from app.automation_transport import connect_profile, execute_step
from app.host_key_store import HostKeyStore, HostKeyNotAccepted

pytestmark = pytest.mark.skipif(os.environ.get('PARAMIKO5_INTEGRATION') != '1', reason='requires disposable OpenSSH lab')
HOST = os.environ.get('PARAMIKO5_TARGET_HOST','127.0.0.1')
PORT = int(os.environ.get('PARAMIKO5_TARGET_PORT','2223'))
PASSWORD = 'Paramiko5-Test-Only!'

@pytest.fixture
def peer(app, monkeypatch):
    from app.auth import register_user
    monkeypatch.setattr(config,'BLOCK_INTERNAL_SSH',False)
    with app.app_context():
        user, error = register_user('automation_integration','integration-password')
        assert error is None
        profile = dict(id='integration-host',name='Disposable OpenSSH',host=HOST,port=PORT,username='testuser',auth_type='password')
        yield user.id, profile

def trust(uid):
    transport = paramiko.Transport(socket.create_connection((HOST,PORT),timeout=5))
    try:
        transport.start_client(timeout=5)
        HostKeyStore(uid,config.KNOWN_HOSTS_FILE,config.USERS_DIR).record(f'[{HOST}]:{PORT}',transport.get_remote_server_key())
    finally:
        transport.close()

def test_real_openssh_requires_prior_trust_and_confirms_exit(peer):
    uid, profile = peer
    with pytest.raises(HostKeyNotAccepted):
        with connect_profile(uid,profile,PASSWORD,lambda:False):
            pytest.fail('unknown host key was accepted')
    trust(uid)
    with connect_profile(uid,profile,PASSWORD,lambda:False) as transport:
        result = execute_step(transport,dict(command="printf '%s' 'remote-secret'",timeout=5,sudo=False),lambda:False, ('remote-secret',))
        assert result['status'] == 'succeeded' and result['exit_code'] == 0
        assert 'remote-secret' not in str(result)
        assert result['stdout'] == '[redacted]' and not result['output_truncated']
        result = execute_step(transport,dict(command="printf 'failure detail' >&2; exit 7",timeout=5,sudo=False),lambda:False)
        assert result['status'] == 'failed' and result['exit_code'] == 7
        assert result['reason'] == 'nonzero_exit' and result['stderr'] == 'failure detail'

def test_real_openssh_timeout_and_cancel_are_uncertain(peer):
    uid, profile = peer
    trust(uid)
    with connect_profile(uid,profile,PASSWORD,lambda:False) as transport:
        result = execute_step(transport,dict(command="printf 'started'; sleep 3",timeout=1,sudo=False),lambda:False)
        assert result['status'] == 'unknown' and result['reason'] == 'timeout'
        assert result['stdout'] == 'started'
        cancelled = threading.Event()
        timer = threading.Timer(.3,cancelled.set);timer.start()
        try:
            assert execute_step(transport,dict(command='sleep 5',timeout=5,sudo=False),cancelled.is_set)['status'] == 'unknown'
        finally:
            timer.cancel()

def test_real_openssh_stored_key_authentication(peer):
    from app.key_manager import save_key
    uid, profile = peer
    trust(uid)
    key, error = save_key(uid,'Automation integration key',(Path(__file__).parent/'paramiko5/runtime/ed25519.pem').read_text())
    assert error is None
    profile.update(auth_type='key',key_id=key['id'])
    from app.automation_store import AutomationError
    with pytest.raises(AutomationError,match='preview_changed'):
        with connect_profile(uid,profile,None,lambda:False,expected_key_digest='0'*64):
            pytest.fail('a key different from the preview was used')
    with connect_profile(uid,profile,None,lambda:False) as transport:
        assert execute_step(transport,dict(command='id -u',timeout=5,sudo=False),lambda:False)['status'] == 'succeeded'
