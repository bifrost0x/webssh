import threading
import pytest
from app.automation_transport import execute_step, command_for

class Channel:
    closed = False
    eof_received = True
    def __init__(self, chunks=(), status=0):
        self.chunks = list(chunks)
        self.status = status
    def recv_ready(self): return bool(self.chunks)
    def recv_stderr_ready(self): return False
    def recv_stderr(self, size): return b""
    def recv(self, size): return self.chunks.pop(0)
    def exit_status_ready(self): return not self.chunks
    def recv_exit_status(self): return self.status
    def close(self): self.closed = True
    def shutdown_write(self): pass

@pytest.mark.parametrize('status,expected', [(0,'succeeded'),(2,'failed'),(-1,'unknown')])
def test_confirmed_exit_status_only(monkeypatch, status, expected):
    channel = Channel([b'never retain remote-secret'], status)
    monkeypatch.setattr('app.automation_transport.paramiko_channels.open_exec_channel', lambda *a, **kw: (kw['before_exec'](), channel)[1])
    result = execute_step(object(), dict(command='id', timeout=2, sudo=False), lambda: False, ('remote-secret',))
    assert result['status'] == expected
    assert 'remote-secret' not in str(result)
    assert channel.closed

def test_cancel_after_dispatch_unknown(monkeypatch):
    cancelled = [False]
    def open_channel(*args, **kwargs):
        kwargs['before_exec']()
        cancelled[0] = True
        return Channel()
    monkeypatch.setattr('app.automation_transport.paramiko_channels.open_exec_channel', open_channel)
    assert execute_step(object(), dict(command='id', timeout=2, sudo=False), lambda: cancelled[0])['status'] == 'unknown'

def test_continuous_output_remains_bounded_by_timeout(monkeypatch):
    class Flood(Channel):
        def recv_ready(self): return True
        def recv(self, size): return b'x' * size
        def exit_status_ready(self): return False
    channel = Flood()
    ticks = iter(range(100))
    monkeypatch.setattr('app.automation_transport.time.monotonic', lambda: next(ticks) / 10)
    monkeypatch.setattr('app.automation_transport.paramiko_channels.open_exec_channel', lambda *a, **kw: (kw['before_exec'](), channel)[1])
    result = execute_step(object(), dict(command='yes', timeout=2, sudo=False), lambda: False)
    assert result['status'] == 'unknown' and result['reason'] == 'timeout'
    assert len(result['stdout'].encode()) <= 8192 and result['output_truncated']
    assert channel.closed


def test_lost_ack_unknown(monkeypatch):
    def lost(*args, **kwargs):
        kwargs['before_exec']()
        raise TimeoutError()
    monkeypatch.setattr('app.automation_transport.paramiko_channels.open_exec_channel', lost)
    assert execute_step(object(), dict(command='id', timeout=2, sudo=False), lambda: False)['status'] == 'unknown'

def test_sudo_quotes_whole_pipeline():
    assert command_for(dict(command='id; uname -a', sudo=True)) == "sudo -n -- sh -c 'id; uname -a'"


@pytest.mark.parametrize('status', [0, 7, -1])
def test_closed_channel_drains_buffered_output_before_deciding_outcome(monkeypatch, status):
    channel = Channel([b'packages\n' * 4096, b'last package\n'], status)
    channel.closed = True
    monkeypatch.setattr('app.automation_transport.paramiko_channels.open_exec_channel',
                        lambda *a, **kw: (kw['before_exec'](), channel)[1])
    result = execute_step(object(), dict(command='inventory', timeout=2, sudo=False), lambda: False)
    assert not channel.chunks
    assert result['exit_code'] == (status if status >= 0 else None)
    assert result['status'] == ('succeeded' if status == 0 else 'failed' if status > 0 else 'unknown')
    assert result['output_truncated']


@pytest.mark.parametrize('status', [0, 7])
def test_large_finite_output_is_drained_without_aborting_command(monkeypatch, status):
    channel = Channel([b'x' * 32768 for _ in range(40)], status)
    monkeypatch.setattr('app.automation_transport.paramiko_channels.open_exec_channel',
                        lambda *a, **kw: (kw['before_exec'](), channel)[1])
    result = execute_step(object(), dict(command='inventory', timeout=3, sudo=False), lambda: False)
    assert not channel.chunks
    assert result['exit_code'] == status
    assert result['status'] == ('succeeded' if status == 0 else 'failed')
    assert result['output_truncated']
    assert len(result['stdout'].encode()) <= 8192


def test_exit_status_before_eof_does_not_drop_late_stderr(monkeypatch):
    class EarlyStatus(Channel):
        eof_received = False
        error = []
        def exit_status_ready(self): return True
        def recv_stderr_ready(self): return bool(self.error)
        def recv_stderr(self, size): return self.error.pop()
    channel = EarlyStatus(status=7)
    def finish(_delay):
        channel.error.append(b'late diagnostic')
        channel.eof_received = True
    monkeypatch.setattr('app.automation_transport.time.sleep', finish)
    monkeypatch.setattr('app.automation_transport.paramiko_channels.open_exec_channel',
                        lambda *a, **kw: (kw['before_exec'](), channel)[1])
    result = execute_step(object(), dict(command='inventory', timeout=2, sudo=False), lambda: False)
    assert result['exit_code'] == 7 and result['stderr'] == 'late diagnostic'

def test_internal_network_policy_blocks_before_opening_socket(monkeypatch):
    import config
    from app.automation_transport import connect_profile
    monkeypatch.setattr(config,'BLOCK_INTERNAL_SSH',True)
    def forbidden(*args,**kwargs):pytest.fail('network socket opened before policy admission')
    monkeypatch.setattr('app.automation_transport.open_validated_socket',forbidden)
    with pytest.raises(ValueError,match='not allowed'):
        with connect_profile(1,dict(host='127.0.0.1',port=22,username='u',auth_type='password'),'secret',lambda:False):
            pytest.fail('blocked destination connected')

def test_fast_confirmed_remote_exit_is_not_rejected_as_lost_ack(monkeypatch):
    from app.paramiko_channels import open_exec_channel
    class FastExit(Channel):
        def settimeout(self, timeout):pass
        def exec_command(self, command):self.closed=True
    channel=FastExit(status=0)
    class Transport:
        def open_session(self,timeout):return channel
    assert open_exec_channel(Transport(),'true',timeout=2) is channel
    assert channel.recv_exit_status()==0


@pytest.mark.parametrize('revoke_during_handshake', [False, True])
@pytest.mark.parametrize('auth_type', ['password', 'key'])
@pytest.mark.parametrize('destination_changed', [False, True])
def test_authentication_rechecks_cancellation_after_handshake(monkeypatch, revoke_during_handshake, auth_type, destination_changed):
    from types import SimpleNamespace
    from app.automation_store import AutomationError
    from app.automation_transport import connect_profile
    cancelled = threading.Event()
    authentications = []
    closed = []
    transport = SimpleNamespace(auth_password=lambda *args, **kwargs: authentications.append((args, kwargs)))
    class Client:
        def set_missing_host_key_policy(self, policy):
            pass
        def connect(self, **kwargs):
            if revoke_during_handshake:
                cancelled.set()
            # Paramiko selects/authenticates the source after host-key verification.
            source = next(kwargs['auth_strategy'].get_sources())
            source.authenticate(transport)
        def get_transport(self):
            return transport
        def close(self):
            closed.append('client')
    store = SimpleNamespace(load_into=lambda _client: None, missing_key_policy=lambda: object())
    monkeypatch.setattr('app.automation_transport.HostKeyStore', lambda *_args: store)
    monkeypatch.setattr('app.automation_transport.paramiko.SSHClient', Client)
    monkeypatch.setattr('app.automation_transport.resolve_allowed_target', lambda *args, **kwargs:
                        SimpleNamespace(hostname='server.example', port=22))
    monkeypatch.setattr('app.automation_transport.open_validated_socket', lambda *_args:
                        SimpleNamespace(close=lambda: closed.append('socket')))
    key = object()
    if auth_type == 'key':
        monkeypatch.setattr('app.automation_transport.read_key_content', lambda *_: ('test-key', None))
        monkeypatch.setattr('app.automation_transport.load_private_key', lambda *_: key)
        transport.auth_publickey = lambda *args, **kwargs: authentications.append((args, kwargs)) or []
    profile = dict(host='server.example', port=22, username='operator', auth_type=auth_type)
    def validate():
        if destination_changed:
            raise AutomationError('preview_changed')
    if revoke_during_handshake or destination_changed:
        with pytest.raises(AutomationError, match='cancelled|preview_changed'):
            with connect_profile(1, profile, 'remote-secret', cancelled.is_set, validate_auth=validate):
                pytest.fail('revoked credential authenticated')
        assert authentications == []
    else:
        with connect_profile(1, profile, 'remote-secret', cancelled.is_set, validate_auth=validate) as connected:
            assert connected is transport
        assert authentications == ([(('operator', 'remote-secret'), {'fallback': False})] if auth_type == 'password'
                                   else [(('operator', key), {})])
    assert closed == ['client', 'socket']

def test_output_capture_redacts_chunk_boundaries_and_drains(monkeypatch):
    channel = Channel([b'\x1b[31mhello sec', b'ret\x1b[0m\x00\n', ('\U0001f600'*3000).encode()], 7)
    monkeypatch.setattr('app.automation_transport.paramiko_channels.open_exec_channel', lambda *a, **kw: (kw['before_exec'](), channel)[1])
    result = execute_step(object(), dict(command='id', timeout=2, sudo=False), lambda: False, ('secret',))
    assert result['status'] == 'failed'
    assert result['reason'] == 'nonzero_exit'
    assert result['exit_code'] == 7
    assert result['stdout'].startswith('hello [redacted]\n')
    assert 'secret' not in result['stdout'] and '\x1b' not in result['stdout']
    assert len(result['stdout'].encode()) <= 8192
    assert result['output_truncated'] is True
    assert not channel.chunks

@pytest.mark.parametrize('budget', [0, 7, 8192])
def test_output_budget_preserves_stderr_and_confirmed_exit(monkeypatch, budget):
    class Both(Channel):
        error = [b'failure detail']
        def recv_stderr_ready(self): return bool(self.error)
        def recv_stderr(self, size): return self.error.pop()
    channel = Both([b'x'*20000], 9)
    monkeypatch.setattr('app.automation_transport.paramiko_channels.open_exec_channel', lambda *a, **kw: (kw['before_exec'](), channel)[1])
    result = execute_step(object(), dict(command='id', timeout=2, sudo=False), lambda: False, (), budget)
    assert result['status'] == 'failed' and result['exit_code'] == 9
    assert len(result['stdout'].encode()) + len(result['stderr'].encode()) <= budget
    assert result['output_truncated'] is True
    if budget == 8192:
        assert result['stderr'] == 'failure detail'
    assert not channel.chunks and not channel.error

@pytest.mark.parametrize('sent,reason,status', [(False,'dispatch_failed','failed'), (True,'acknowledgement_lost','unknown')])
def test_dispatch_reason(monkeypatch, sent, reason, status):
    def fail(*args, **kwargs):
        if sent: kwargs['before_exec']()
        raise OSError('private internal failure')
    monkeypatch.setattr('app.automation_transport.paramiko_channels.open_exec_channel', fail)
    result = execute_step(object(), dict(command='id', timeout=2, sudo=False), lambda: False)
    assert result['reason'] == reason and result['status'] == status
    assert 'private' not in str(result)

@pytest.mark.parametrize('exit_status,expected', [(0,'help'), (-1,'hel[redacted]')])
def test_partial_secret_suffix_only_redacted_on_interruption(monkeypatch, exit_status, expected):
    channel = Channel([b'help'], exit_status)
    monkeypatch.setattr('app.automation_transport.paramiko_channels.open_exec_channel', lambda *a, **kw: (kw['before_exec'](), channel)[1])
    result = execute_step(object(), dict(command='id', timeout=2, sudo=False), lambda: False, ('password',))
    assert result['stdout'] == expected

@pytest.mark.parametrize('capture_limit', [False, True])
def test_interrupted_utf8_secret_suffix_redacted_before_replacement(monkeypatch, capture_limit):
    from app.automation_transport import STREAM_OUTPUT_BYTES
    secret = 'password\U0001f511'
    encoded = secret.encode()
    if capture_limit:
        # Capture cuts two bytes into the emoji; control padding is removed for display.
        raw = b'\xff' + b'\x00'*(STREAM_OUTPUT_BYTES-len(encoded)+1) + encoded
    else:
        raw = b'\xff' + encoded[:-2]
    channel = Channel([raw], -1)
    monkeypatch.setattr('app.automation_transport.paramiko_channels.open_exec_channel', lambda *a, **kw: (kw['before_exec'](), channel)[1])
    result = execute_step(object(), dict(command='id', timeout=2, sudo=False), lambda: False, (secret,))
    assert result['status'] == 'unknown'
    assert result['reason'] == 'channel_lost'
    assert result['stdout'] == '\ufffd[redacted]'
    assert 'password' not in str(result)
    if capture_limit: assert result['output_truncated'] is True


@pytest.mark.parametrize('status', [0, 7])
def test_capture_truncation_redacts_partial_secret_even_with_confirmed_exit(monkeypatch, status):
    from app.automation_transport import STREAM_OUTPUT_BYTES
    secret = 'password\U0001f511'
    raw = b'\x00' * (STREAM_OUTPUT_BYTES - len(secret.encode()) + 2) + secret.encode()
    channel = Channel([raw], status)
    monkeypatch.setattr('app.automation_transport.paramiko_channels.open_exec_channel',
                        lambda *a, **kw: (kw['before_exec'](), channel)[1])
    result = execute_step(object(), dict(command='inventory', timeout=2, sudo=False), lambda: False, (secret,))
    assert result['exit_code'] == status and result['output_truncated']
    assert result['stdout'] == '[redacted]'
    assert 'password' not in str(result)
