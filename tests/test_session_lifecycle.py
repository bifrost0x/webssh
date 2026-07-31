import threading

import paramiko
import pytest

from app import ssh_manager
from app.network_policy import ResolvedTarget
from app.quota_manager import QuotaExceeded, QuotaKind, QuotaManager


class FakeChannel:
    def __init__(self, exec_error=None):
        self.exec_error = exec_error
        self.closed = False
        self.command = None
        self.timeout = None
        self.events = []
        self.pty = None
        self.shell_invoked = False

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

    def get_pty(self, term, width, height):
        self.pty = (term, width, height)

    def invoke_shell(self):
        self.shell_invoked = True

    def close(self):
        self.closed = True


class FakeTransport:
    def __init__(self, kill_channel=None, shell_channel=None):
        self.keepalive = None
        self.kill_channel = kill_channel
        self.shell_channel = shell_channel
        self.open_timeout = None

    def set_keepalive(self, seconds):
        self.keepalive = seconds

    def is_active(self):
        return True

    def open_session(self, timeout=None):
        self.open_timeout = timeout
        return self.kill_channel or self.shell_channel

    def _send_user_message(self, _message):
        pass

    def get_exception(self):
        return None


class FakeSSHClient:
    def __init__(self, connect_started=None, connect_release=None,
                 close_started=None, close_release=None, transport=None):
        self.connect_started = connect_started
        self.connect_release = connect_release
        self.close_started = close_started
        self.close_release = close_release
        self.channel = FakeChannel()
        self.transport = transport or FakeTransport(shell_channel=self.channel)
        self.host_keys = paramiko.HostKeys()
        self.closed = False

    def load_host_keys(self, _path):
        pass

    def set_missing_host_key_policy(self, _policy):
        pass

    def get_host_keys(self):
        return self.host_keys

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


class FakeValidatedSocket:
    def close(self):
        pass


class FailingReservation:
    def release(self):
        raise RuntimeError('release failed')


@pytest.fixture(autouse=True)
def clean_session_state(monkeypatch):
    limits = {
        kind: {'global': 100, 'per_user': 50}
        for kind in QuotaKind
    }
    limits[QuotaKind.SSH_SESSION] = {'global': 2, 'per_user': 1}
    monkeypatch.setattr(
        ssh_manager, 'quota_manager', QuotaManager(limits)
    )
    monkeypatch.setattr(
        ssh_manager,
        'resolve_allowed_target',
        lambda host, port, allow_internal=False: ResolvedTarget(
            host, port, '1.1.1.1', 2
        ),
    )
    monkeypatch.setattr(
        ssh_manager,
        'open_validated_socket',
        lambda target, timeout: FakeValidatedSocket(),
    )
    with ssh_manager.sessions_lock:
        ssh_manager.sessions.clear()
    yield
    with ssh_manager.sessions_lock:
        ssh_manager.sessions.clear()


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
        assert ssh_manager.sessions == {}

    connect_release.set()
    first_thread.join(2)
    assert not first_thread.is_alive()
    assert first_result[0][1] is None
    assert first_result[0][0] in ssh_manager.sessions
    with ssh_manager.sessions_lock:
        reservation = ssh_manager.sessions[first_result[0][0]][
            'quota_reservation'
        ]
    assert reservation.released is False


def test_failed_connection_releases_reserved_capacity(monkeypatch):
    client = FakeSSHClient()

    def fail_connect(**_kwargs):
        raise ssh_manager.paramiko.SSHException('boom')

    client.connect = fail_connect
    monkeypatch.setattr(ssh_manager.paramiko, 'SSHClient', lambda: client)

    session_id, error = _connect()

    assert session_id is None
    assert error == 'SSH connection failed'
    replacement = ssh_manager.quota_manager.reserve(
        QuotaKind.SSH_SESSION, user_id=7
    )
    replacement.release()


def test_ssh_reader_is_a_lifecycle_job_and_close_cancels_it(monkeypatch):
    """A raw reader Thread cannot be cancelled or joined during session close."""
    from app.runtime_lifecycle import RuntimeLifecycle

    lifecycle = RuntimeLifecycle(max_workers=1)
    reader_started = threading.Event()

    class App:
        extensions = {'runtime_lifecycle': lifecycle}

    def reader(_session_id, _socketio, _app, cancel_event):
        reader_started.set()
        cancel_event.wait(1)

    monkeypatch.setattr(ssh_manager, 'read_ssh_output', reader)
    monkeypatch.setattr(ssh_manager.paramiko, 'SSHClient', FakeSSHClient)
    monkeypatch.setattr(ssh_manager.time, 'sleep', lambda _seconds: None)
    monkeypatch.setattr(
        'app.sftp_handler.close_sftp_cache', lambda _session_id: None)

    try:
        session_id, error = _connect(
            socketio_instance=object(), app=App(),
        )
        assert error is None
        assert reader_started.wait(1)
        with ssh_manager.sessions_lock:
            handle = ssh_manager.sessions[session_id]['reader_handle']

        assert ssh_manager.close_session(session_id) is True
        assert handle.cancel_event.is_set()
        assert handle.join(1) is True
    finally:
        lifecycle.begin_shutdown(1)


def test_reader_closing_its_own_session_never_joins_itself(monkeypatch):
    """Joining the current reader from its final cleanup deadlocks the worker."""
    from app.runtime_lifecycle import RuntimeLifecycle

    lifecycle = RuntimeLifecycle(max_workers=1)
    allow_close = threading.Event()
    reader_finished = threading.Event()

    class App:
        extensions = {'runtime_lifecycle': lifecycle}

    def reader(session_id, _socketio, _app, _cancel_event):
        assert allow_close.wait(1)
        ssh_manager.close_session(session_id)
        reader_finished.set()

    monkeypatch.setattr(ssh_manager, 'read_ssh_output', reader)
    monkeypatch.setattr(ssh_manager.paramiko, 'SSHClient', FakeSSHClient)
    monkeypatch.setattr(ssh_manager.time, 'sleep', lambda _seconds: None)
    monkeypatch.setattr(
        'app.sftp_handler.close_sftp_cache', lambda _session_id: None)

    try:
        session_id, error = _connect(
            socketio_instance=object(), app=App(),
        )
        assert error is None
        allow_close.set()
        assert reader_finished.wait(1)
        with ssh_manager.sessions_lock:
            assert session_id not in ssh_manager.sessions
    finally:
        lifecycle.begin_shutdown(1)


def test_close_session_releases_quota_exactly_once(monkeypatch):
    reservation = ssh_manager.quota_manager.reserve(
        QuotaKind.SSH_SESSION, user_id=7
    )
    client = FakeSSHClient()
    with ssh_manager.sessions_lock:
        ssh_manager.sessions['session-1'] = _session(
            client, quota_reservation=reservation
        )
    monkeypatch.setattr(
        'app.sftp_handler.close_sftp_cache', lambda _session_id: None
    )

    assert ssh_manager.close_session('session-1') is True
    assert ssh_manager.close_session('session-1') is False
    assert reservation.released is True

    replacement = ssh_manager.quota_manager.reserve(
        QuotaKind.SSH_SESSION, user_id=7
    )
    replacement.release()


def test_close_session_still_cleans_up_when_quota_release_fails(monkeypatch):
    client = FakeSSHClient()
    channel = FakeChannel()
    with ssh_manager.sessions_lock:
        ssh_manager.sessions['session-1'] = _session(
            client,
            channel=channel,
            quota_reservation=FailingReservation(),
        )
    monkeypatch.setattr(
        'app.sftp_handler.close_sftp_cache', lambda _session_id: None
    )

    assert ssh_manager.close_session('session-1') is True
    assert channel.closed is True
    assert client.closed is True


def test_close_session_does_not_hold_registry_lock_during_io(monkeypatch):
    close_started = threading.Event()
    close_release = threading.Event()
    client = FakeSSHClient(
        close_started=close_started, close_release=close_release)
    reservation = ssh_manager.quota_manager.reserve(
        QuotaKind.SSH_SESSION, user_id=7
    )
    with ssh_manager.sessions_lock:
        ssh_manager.sessions['session-1'] = _session(
            client, quota_reservation=reservation
        )

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

    with pytest.raises(QuotaExceeded):
        ssh_manager.quota_manager.reserve(
            QuotaKind.SSH_SESSION, user_id=7
        )

    close_release.set()
    close_thread.join(2)
    assert not close_thread.is_alive()
    assert result == [True]
    replacement = ssh_manager.quota_manager.reserve(
        QuotaKind.SSH_SESSION, user_id=7
    )
    replacement.release()


def test_close_session_removes_registry_entry_before_sftp_cleanup(monkeypatch):
    cleanup_started = threading.Event()
    cleanup_release = threading.Event()
    client = FakeSSHClient()
    with ssh_manager.sessions_lock:
        ssh_manager.sessions['session-1'] = _session(client)

    def blocking_sftp_cleanup(_session_id):
        cleanup_started.set()
        assert cleanup_release.wait(2)

    monkeypatch.setattr(
        'app.sftp_handler.close_sftp_cache', blocking_sftp_cleanup)
    result = []
    close_thread = threading.Thread(
        target=lambda: result.append(ssh_manager.close_session('session-1')),
        daemon=True,
    )
    close_thread.start()
    assert cleanup_started.wait(2)

    try:
        with ssh_manager.sessions_lock:
            assert 'session-1' not in ssh_manager.sessions
    finally:
        cleanup_release.set()
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


def test_close_session_bounds_paramiko_tmux_exec_handshake(monkeypatch):
    transport = FakeTransport()
    kill_channel = ssh_manager.paramiko.Channel(1)
    kill_channel.active = True
    kill_channel.remote_chanid = 1
    kill_channel.transport = transport
    transport.kill_channel = kill_channel

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
    monkeypatch.setattr(
        ssh_manager, 'TMUX_KILL_TIMEOUT', 0.05, raising=False)

    finished = threading.Event()
    result = []

    def close():
        result.append(ssh_manager.close_session('session-1', kill_tmux=True))
        finished.set()

    close_thread = threading.Thread(target=close, daemon=True)
    close_thread.start()
    completed_within_deadline = finished.wait(0.5)

    if not completed_within_deadline:
        kill_channel.close()
    close_thread.join(2)

    assert completed_within_deadline, 'tmux exec handshake exceeded its deadline'
    assert not close_thread.is_alive()
    assert result == [True]
    assert transport.open_timeout == 0.05
    assert interactive_channel.closed is True
    assert client.closed is True
    assert bastion_client.closed is True
