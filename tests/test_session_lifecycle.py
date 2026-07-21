import threading

import pytest

from app import ssh_manager


class FakeChannel:
    def __init__(self, exec_error=None):
        self.exec_error = exec_error
        self.closed = False
        self.command = None
        self.timeout = None
        self.events = []

    def settimeout(self, timeout):
        self.timeout = timeout
        self.events.append(('settimeout', timeout))

    def exec_command(self, command):
        self.command = command
        self.events.append(('exec_command', command))
        if self.exec_error:
            raise self.exec_error

    def recv(self, _size):
        return b''

    def close(self):
        self.closed = True


class FakeTransport:
    def __init__(self, kill_channel=None):
        self.keepalive = None
        self.kill_channel = kill_channel
        self.open_timeout = None

    def set_keepalive(self, seconds):
        self.keepalive = seconds

    def is_active(self):
        return True

    def open_session(self, timeout=None):
        self.open_timeout = timeout
        return self.kill_channel


class FakeSSHClient:
    def __init__(self, connect_started=None, connect_release=None,
                 close_started=None, close_release=None, transport=None):
        self.connect_started = connect_started
        self.connect_release = connect_release
        self.close_started = close_started
        self.close_release = close_release
        self.transport = transport or FakeTransport()
        self.channel = FakeChannel()
        self.closed = False

    def load_host_keys(self, _path):
        pass

    def set_missing_host_key_policy(self, _policy):
        pass

    def connect(self, **_kwargs):
        if self.connect_started:
            self.connect_started.set()
        if self.connect_release:
            assert self.connect_release.wait(2)

    def get_transport(self):
        return self.transport

    def invoke_shell(self, **_kwargs):
        return self.channel

    def close(self):
        self.closed = True
        if self.close_started:
            self.close_started.set()
        if self.close_release:
            assert self.close_release.wait(2)


@pytest.fixture(autouse=True)
def clean_session_state():
    with ssh_manager.sessions_lock:
        ssh_manager.sessions.clear()
        ssh_manager._pending_connections = 0
    yield
    with ssh_manager.sessions_lock:
        ssh_manager.sessions.clear()
        ssh_manager._pending_connections = 0


def _connect(**overrides):
    kwargs = {
        'host': 'target.example',
        'port': 22,
        'username': 'alice',
        'password': 'secret',
        'user_id': 7,
    }
    kwargs.update(overrides)
    return ssh_manager.create_ssh_connection(**kwargs)


def _session(client, channel=None, **overrides):
    session = {
        'client': client,
        'channel': channel or client.channel,
        'connected': True,
        'use_tmux': False,
        'tmux_session_name': None,
        'bastion_client': None,
    }
    session.update(overrides)
    return session


def test_pending_connection_reserves_capacity(monkeypatch):
    connect_started = threading.Event()
    connect_release = threading.Event()
    first_client = FakeSSHClient(connect_started, connect_release)
    created_clients = []

    def client_factory():
        client = first_client if not created_clients else FakeSSHClient()
        created_clients.append(client)
        return client

    monkeypatch.setattr(ssh_manager.config, 'MAX_SESSIONS', 1)
    monkeypatch.setattr(ssh_manager.paramiko, 'SSHClient', client_factory)
    monkeypatch.setattr(ssh_manager.time, 'sleep', lambda _seconds: None)

    first_result = []
    first_thread = threading.Thread(
        target=lambda: first_result.append(_connect()), daemon=True)
    first_thread.start()
    assert connect_started.wait(2)

    second_session_id, second_error = _connect()

    assert second_session_id is None
    assert second_error == 'Maximum number of sessions reached'
    assert len(created_clients) == 1
    with ssh_manager.sessions_lock:
        assert ssh_manager._pending_connections == 1
        assert ssh_manager.sessions == {}

    connect_release.set()
    first_thread.join(2)
    assert not first_thread.is_alive()
    assert first_result[0][1] is None
    assert first_result[0][0] in ssh_manager.sessions
    with ssh_manager.sessions_lock:
        assert ssh_manager._pending_connections == 0


def test_failed_connection_releases_reserved_capacity(monkeypatch):
    client = FakeSSHClient()

    def fail_connect(**_kwargs):
        raise ssh_manager.paramiko.SSHException('boom')

    client.connect = fail_connect
    monkeypatch.setattr(ssh_manager.config, 'MAX_SESSIONS', 1)
    monkeypatch.setattr(ssh_manager.paramiko, 'SSHClient', lambda: client)

    session_id, error = _connect()

    assert session_id is None
    assert error == 'SSH connection failed'
    with ssh_manager.sessions_lock:
        assert ssh_manager._pending_connections == 0


def test_close_session_does_not_hold_registry_lock_during_io(monkeypatch):
    close_started = threading.Event()
    close_release = threading.Event()
    client = FakeSSHClient(
        close_started=close_started, close_release=close_release)
    with ssh_manager.sessions_lock:
        ssh_manager.sessions['session-1'] = _session(client)

    monkeypatch.setattr(
        'app.sftp_handler.close_sftp_cache', lambda _session_id: None)
    result = []
    close_thread = threading.Thread(
        target=lambda: result.append(ssh_manager.close_session('session-1')),
        daemon=True,
    )
    close_thread.start()
    assert close_started.wait(2)

    acquired = ssh_manager.sessions_lock.acquire(timeout=0.5)
    try:
        assert acquired is True
        assert 'session-1' not in ssh_manager.sessions
    finally:
        if acquired:
            ssh_manager.sessions_lock.release()

    close_release.set()
    close_thread.join(2)
    assert not close_thread.is_alive()
    assert result == [True]


def test_close_session_quotes_tmux_target_and_sets_timeout_first(monkeypatch):
    kill_channel = FakeChannel()
    transport = FakeTransport(kill_channel)
    client = FakeSSHClient(transport=transport)
    with ssh_manager.sessions_lock:
        ssh_manager.sessions['session-1'] = _session(
            client,
            use_tmux=True,
            tmux_session_name='name; touch /tmp/marker',
        )

    monkeypatch.setattr(
        'app.sftp_handler.close_sftp_cache', lambda _session_id: None)

    assert ssh_manager.close_session('session-1', kill_tmux=True) is True
    assert transport.open_timeout == 2.0
    assert kill_channel.command == (
        "tmux kill-session -t 'name; touch /tmp/marker'")
    assert kill_channel.events[0] == ('settimeout', 2.0)
    assert kill_channel.events[1][0] == 'exec_command'
    assert kill_channel.closed is True


def test_close_session_closes_everything_when_tmux_exec_fails(monkeypatch):
    kill_channel = FakeChannel(exec_error=RuntimeError('boom'))
    transport = FakeTransport(kill_channel)
    client = FakeSSHClient(transport=transport)
    interactive_channel = FakeChannel()
    bastion_client = FakeSSHClient()
    with ssh_manager.sessions_lock:
        ssh_manager.sessions['session-1'] = _session(
            client,
            channel=interactive_channel,
            use_tmux=True,
            tmux_session_name='tmux-session',
            bastion_client=bastion_client,
        )

    monkeypatch.setattr(
        'app.sftp_handler.close_sftp_cache', lambda _session_id: None)

    assert ssh_manager.close_session('session-1', kill_tmux=True) is True
    assert kill_channel.closed is True
    assert interactive_channel.closed is True
    assert client.closed is True
    assert bastion_client.closed is True
    assert 'session-1' not in ssh_manager.sessions
