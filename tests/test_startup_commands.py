"""Tests for post-connect command normalization and terminal input."""

from pathlib import Path
import threading

import paramiko
import pytest


@pytest.fixture(autouse=True)
def _clean_ssh_sessions(monkeypatch):
    from app import ssh_manager
    from app.network_policy import ResolvedTarget

    class FakeValidatedSocket:
        def close(self):
            pass

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
    for session_id in list(ssh_manager.sessions):
        ssh_manager.close_session(session_id)


class _StartupCommandChannel:
    def __init__(self, fail_on_send=False, max_send_size=None):
        self.closed = False
        self.close_calls = 0
        self.command = None
        self.fail_on_send = fail_on_send
        self.max_send_size = max_send_size
        self.pty = None
        self.sent = []

    def settimeout(self, _timeout):
        pass

    def send(self, data):
        if self.fail_on_send:
            raise OSError('channel write failed')
        data = data.encode('utf-8') if isinstance(data, str) else data
        sent_size = min(len(data), self.max_send_size or len(data))
        self.sent.append(data[:sent_size])
        return sent_size

    def exec_command(self, command):
        self.command = command

    def get_pty(self, term, width, height):
        self.pty = (term, width, height)

    def recv(self, _size):
        return b'/usr/bin/tmux\n'

    def recv_exit_status(self):
        return 0

    def exit_status_ready(self):
        return True

    def invoke_shell(self):
        pass

    def close(self):
        self.closed = True
        self.close_calls += 1


class _StartupCommandTransport:
    def __init__(self, session_channel_factory=None):
        self.session_channel_factory = session_channel_factory
        self.session_channels = []
        self.open_timeouts = []

    def set_keepalive(self, _seconds):
        pass

    def open_session(self, timeout=None):
        self.open_timeouts.append(timeout)
        index = len(self.session_channels)
        channel = (
            self.session_channel_factory(index)
            if self.session_channel_factory
            else _StartupCommandChannel()
        )
        self.session_channels.append(channel)
        return channel

    def is_active(self):
        return True


class _StartupCommandClient:
    def __init__(self, channel, transport=None):
        self.channel = channel
        self.transport = transport or _StartupCommandTransport(
            lambda _index: channel
        )
        self.host_keys = paramiko.HostKeys()
        self.closed = False
        self.close_calls = 0

    def set_missing_host_key_policy(self, _policy):
        pass

    def get_host_keys(self):
        return self.host_keys

    def connect(self, **_kwargs):
        pass

    def get_transport(self):
        return self.transport

    def invoke_shell(self, **_kwargs):
        return self.channel

    def close(self):
        self.closed = True
        self.close_calls += 1


class _FixedUuid:
    hex = 'deadbeef0123456789abcdef'

    def __str__(self):
        return 'fixed-session-id'


def test_normalize_startup_commands_accepts_blank_input():
    from app.startup_commands import normalize_startup_commands

    commands, error = normalize_startup_commands('')

    assert commands == ''
    assert error is None


def test_normalize_startup_commands_converts_all_line_endings_to_lf():
    from app.startup_commands import normalize_startup_commands

    commands, error = normalize_startup_commands('echo first\r\necho second\recho third')

    assert commands == 'echo first\necho second\necho third'
    assert error is None


@pytest.mark.parametrize('value', [None, 42, ['echo test']])
def test_normalize_startup_commands_rejects_non_string_values(value):
    from app.startup_commands import normalize_startup_commands

    commands, error = normalize_startup_commands(value)

    assert commands == ''
    assert error == 'Startup commands must be text'


def test_normalize_startup_commands_rejects_nul_bytes():
    from app.startup_commands import normalize_startup_commands

    commands, error = normalize_startup_commands('echo safe\x00echo unsafe')

    assert commands == ''
    assert error == 'Startup commands must not contain NUL bytes'


def test_normalize_startup_commands_rejects_too_long_text():
    from app.startup_commands import normalize_startup_commands

    commands, error = normalize_startup_commands('x' * 4097)

    assert commands == ''
    assert error == 'Startup commands must not exceed 4096 characters'


def test_normalize_startup_commands_rejects_raw_crlf_payload_over_limit():
    from app.startup_commands import normalize_startup_commands

    commands, error = normalize_startup_commands('\r\n' * 2049)

    assert commands == ''
    assert error == 'Startup commands must not exceed 4096 characters'


def test_normalize_startup_commands_accepts_raw_crlf_payload_at_limit():
    from app.startup_commands import normalize_startup_commands

    commands, error = normalize_startup_commands('\r\n' * 2048)

    assert commands == '\n' * 2048
    assert error is None


def test_to_terminal_input_converts_normalized_linefeeds_to_carriage_returns():
    from app.startup_commands import to_terminal_input

    assert to_terminal_input('echo first\necho second') == 'echo first\recho second'


@pytest.mark.parametrize(
    ('startup_commands', 'expected_input'),
    [
        ('echo first\necho second', 'echo first\recho second\r'),
        ('echo first\n', 'echo first\r'),
        ('echo first\n\n', 'echo first\r'),
    ],
)
def test_create_ssh_connection_delivers_startup_commands_once(
        monkeypatch, startup_commands, expected_input):
    from app import ssh_manager

    channel = _StartupCommandChannel()
    client = _StartupCommandClient(channel)
    monkeypatch.setattr(ssh_manager.paramiko, 'SSHClient', lambda: client)
    monkeypatch.setattr(ssh_manager.time, 'sleep', lambda _seconds: None)

    session_id, error = ssh_manager.create_ssh_connection(
        host='target.example',
        port=22,
        username='alice',
        password='secret',
        user_id=1,
        startup_commands=startup_commands,
    )

    assert error is None
    assert session_id in ssh_manager.sessions
    assert channel.sent == [expected_input.encode('utf-8')]

    ssh_manager.close_session(session_id)


def test_cancelled_connection_never_delivers_startup_commands(monkeypatch):
    from app import ssh_manager

    cancel_event = threading.Event()

    class CancelWhenShellIsReady(_StartupCommandChannel):
        def settimeout(self, _timeout):
            cancel_event.set()

    channel = CancelWhenShellIsReady()
    client = _StartupCommandClient(channel)
    monkeypatch.setattr(ssh_manager.paramiko, 'SSHClient', lambda: client)
    monkeypatch.setattr(ssh_manager.time, 'sleep', lambda _seconds: None)

    session_id, error = ssh_manager.create_ssh_connection(
        host='target.example',
        port=22,
        username='alice',
        password='secret',
        user_id=1,
        startup_commands='touch should-not-run',
        cancel_event=cancel_event,
    )

    assert session_id is None
    assert error == 'Connection cancelled'
    assert channel.sent == []
    assert channel.closed
    assert client.closed
    assert ssh_manager.sessions == {}


def test_cancellation_while_formatting_startup_commands_sends_nothing(monkeypatch):
    from app import ssh_manager

    cancel_event = threading.Event()
    channel = _StartupCommandChannel()
    client = _StartupCommandClient(channel)
    original_to_terminal_input = ssh_manager.to_terminal_input

    def cancel_during_formatting(commands):
        cancel_event.set()
        return original_to_terminal_input(commands)

    monkeypatch.setattr(ssh_manager.paramiko, 'SSHClient', lambda: client)
    monkeypatch.setattr(ssh_manager.time, 'sleep', lambda _seconds: None)
    monkeypatch.setattr(
        ssh_manager,
        'to_terminal_input',
        cancel_during_formatting,
    )

    session_id, error = ssh_manager.create_ssh_connection(
        host='target.example',
        port=22,
        username='alice',
        password='secret',
        user_id=1,
        startup_commands='touch should-not-run',
        cancel_event=cancel_event,
    )

    assert session_id is None
    assert error == 'Connection cancelled'
    assert channel.sent == []
    assert channel.closed
    assert client.closed
    assert ssh_manager.sessions == {}


def test_cancellation_stops_partial_startup_command_delivery(monkeypatch):
    from app import ssh_manager

    cancel_event = threading.Event()

    class CancelAfterFirstChunk(_StartupCommandChannel):
        def send(self, data):
            sent = super().send(data)
            cancel_event.set()
            return sent

    channel = CancelAfterFirstChunk(max_send_size=4)
    client = _StartupCommandClient(channel)
    monkeypatch.setattr(ssh_manager.paramiko, 'SSHClient', lambda: client)
    monkeypatch.setattr(ssh_manager.time, 'sleep', lambda _seconds: None)

    session_id, error = ssh_manager.create_ssh_connection(
        host='target.example',
        port=22,
        username='alice',
        password='secret',
        user_id=1,
        startup_commands='touch should-not-run',
        cancel_event=cancel_event,
    )

    assert session_id is None
    assert error == 'Connection cancelled'
    assert channel.sent == [b'touc']
    assert channel.closed
    assert client.closed
    assert ssh_manager.sessions == {}


def test_user_cancel_is_rejected_after_startup_delivery_commits(monkeypatch):
    from app import ssh_manager
    import app.socket_events as socket_events

    send_started = threading.Event()
    release_send = threading.Event()

    class BlockingFullSend(_StartupCommandChannel):
        def send(self, data):
            send_started.set()
            assert release_send.wait(2)
            return super().send(data)

    channel = BlockingFullSend()
    client = _StartupCommandClient(channel)
    user_cancel = threading.Event()
    lifecycle_cancel = threading.Event()
    attempt = {
        'cancel_event': user_cancel,
        'commit_lock': threading.Lock(),
        'state': 'pending',
    }
    cancellation = socket_events._CombinedCancellation(
        user_cancel,
        lifecycle_cancel,
        attempt['commit_lock'],
        attempt,
    )
    result = {}

    monkeypatch.setattr(ssh_manager.paramiko, 'SSHClient', lambda: client)
    monkeypatch.setattr(ssh_manager.time, 'sleep', lambda _seconds: None)

    def connect():
        result['value'] = ssh_manager.create_ssh_connection(
            host='target.example',
            port=22,
            username='alice',
            password='secret',
            user_id=1,
            startup_commands='touch committed-command',
            cancel_event=cancellation,
        )

    worker = threading.Thread(target=connect)
    worker.start()
    try:
        assert send_started.wait(2)
        assert attempt['state'] == 'committed'
        assert socket_events._try_cancel_ssh_attempt(attempt) is False
        assert not user_cancel.is_set()
    finally:
        release_send.set()
        worker.join(2)

    assert not worker.is_alive()
    session_id, error = result['value']
    assert error is None
    assert b''.join(channel.sent) == b'touch committed-command\r'
    assert session_id in ssh_manager.sessions
    ssh_manager.close_session(session_id)


def test_user_cancel_before_startup_commit_sends_nothing(monkeypatch):
    from app import ssh_manager
    import app.socket_events as socket_events

    channel = _StartupCommandChannel()
    client = _StartupCommandClient(channel)
    user_cancel = threading.Event()
    attempt = {
        'cancel_event': user_cancel,
        'commit_lock': threading.Lock(),
        'state': 'pending',
    }
    cancellation = socket_events._CombinedCancellation(
        user_cancel,
        threading.Event(),
        attempt['commit_lock'],
        attempt,
    )
    assert socket_events._try_cancel_ssh_attempt(attempt) is True

    monkeypatch.setattr(ssh_manager.paramiko, 'SSHClient', lambda: client)
    monkeypatch.setattr(ssh_manager.time, 'sleep', lambda _seconds: None)

    session_id, error = ssh_manager.create_ssh_connection(
        host='target.example',
        port=22,
        username='alice',
        password='secret',
        user_id=1,
        startup_commands='touch should-not-run',
        cancel_event=cancellation,
    )

    assert session_id is None
    assert error == 'Connection cancelled'
    assert channel.sent == []
    assert channel.closed is False
    assert client.closed is False
    assert ssh_manager.sessions == {}


def test_create_ssh_connection_delivers_all_startup_commands_after_partial_send(monkeypatch):
    from app import ssh_manager

    channel = _StartupCommandChannel(max_send_size=4)
    client = _StartupCommandClient(channel)
    monkeypatch.setattr(ssh_manager.paramiko, 'SSHClient', lambda: client)
    monkeypatch.setattr(ssh_manager.time, 'sleep', lambda _seconds: None)

    session_id, error = ssh_manager.create_ssh_connection(
        host='target.example',
        port=22,
        username='alice',
        password='secret',
        user_id=1,
        startup_commands='echo first\necho second',
    )

    assert error is None
    assert b''.join(channel.sent) == b'echo first\recho second\r'
    assert len(channel.sent) > 1

    ssh_manager.close_session(session_id)


def test_create_ssh_connection_delivers_unicode_startup_commands_after_partial_send(monkeypatch):
    from app import ssh_manager

    channel = _StartupCommandChannel(max_send_size=6)
    client = _StartupCommandClient(channel)
    monkeypatch.setattr(ssh_manager.paramiko, 'SSHClient', lambda: client)
    monkeypatch.setattr(ssh_manager.time, 'sleep', lambda _seconds: None)

    session_id, error = ssh_manager.create_ssh_connection(
        host='target.example',
        port=22,
        username='alice',
        password='secret',
        user_id=1,
        startup_commands='echo €\necho done',
    )

    assert error is None
    assert b''.join(channel.sent) == 'echo €\recho done\r'.encode('utf-8')
    assert len(channel.sent) > 1

    ssh_manager.close_session(session_id)


def test_create_ssh_connection_closes_session_when_startup_delivery_fails(monkeypatch):
    from app import ssh_manager

    channel = _StartupCommandChannel(fail_on_send=True)
    client = _StartupCommandClient(channel)
    monkeypatch.setattr(ssh_manager.paramiko, 'SSHClient', lambda: client)
    monkeypatch.setattr(ssh_manager.time, 'sleep', lambda _seconds: None)

    session_id, error = ssh_manager.create_ssh_connection(
        host='target.example',
        port=22,
        username='alice',
        password='secret',
        user_id=1,
        startup_commands='echo first',
    )

    assert session_id is None
    assert error == 'Connection failed'
    assert ssh_manager.sessions == {}
    assert channel.closed
    assert client.closed


def test_create_ssh_connection_kills_new_tmux_when_startup_delivery_fails(monkeypatch):
    from app import ssh_manager

    transport = _StartupCommandTransport(
        lambda index: _StartupCommandChannel(fail_on_send=index == 1)
    )
    client = _StartupCommandClient(_StartupCommandChannel(), transport=transport)
    monkeypatch.setattr(ssh_manager.paramiko, 'SSHClient', lambda: client)
    monkeypatch.setattr(ssh_manager.time, 'sleep', lambda _seconds: None)
    monkeypatch.setattr(ssh_manager.uuid, 'uuid4', lambda: _FixedUuid())

    session_id, error = ssh_manager.create_ssh_connection(
        host='target.example',
        port=22,
        username='alice',
        password='secret',
        user_id=1,
        use_tmux=True,
        startup_commands='echo first',
    )

    assert session_id is None
    assert error == 'Connection failed'
    assert ssh_manager.sessions == {}
    probe_channel, tmux_channel, kill_channel = transport.session_channels
    tmux_session_name = (
        f'{ssh_manager.config.TMUX_SESSION_PREFIX}_alice_target_example_22_deadbeef'
    )
    assert tmux_channel.command == f'tmux new-session -s {tmux_session_name}'
    assert kill_channel.command == f'tmux kill-session -t {tmux_session_name}'
    assert probe_channel.close_calls == 1
    assert tmux_channel.close_calls == 1
    assert kill_channel.close_calls == 1
    assert client.close_calls == 1


def test_output_reader_start_failure_detaches_existing_tmux(monkeypatch):
    from app import ssh_manager

    class RejectingLifecycle:
        def start_job(self, *_args, **_kwargs):
            raise RuntimeError('reader unavailable')

    class FakeApp:
        extensions = {'runtime_lifecycle': RejectingLifecycle()}

    transport = _StartupCommandTransport()
    client = _StartupCommandClient(_StartupCommandChannel(), transport=transport)
    monkeypatch.setattr(ssh_manager.paramiko, 'SSHClient', lambda: client)
    monkeypatch.setattr(ssh_manager.time, 'sleep', lambda _seconds: None)

    session_id, error = ssh_manager.create_ssh_connection(
        host='target.example',
        port=22,
        username='alice',
        password='secret',
        user_id=1,
        use_tmux=True,
        reconnect_tmux_name='existing_session',
        socketio_instance=object(),
        app=FakeApp(),
    )

    assert session_id is None
    assert error == 'Connection failed'
    assert ssh_manager.sessions == {}
    probe_channel, tmux_channel = transport.session_channels
    assert probe_channel.command == 'command -v tmux'
    assert tmux_channel.command == 'tmux new-session -A -s existing_session'
    assert tmux_channel.closed
    assert client.closed


def test_connection_form_offers_free_text_command_and_named_set_modes():
    template = Path('templates/index.html').read_text(encoding='utf-8')

    assert 'id="startupCommandsInput"' in template
    assert 'id="connectionCommandSelect"' in template
    assert 'id="commandSetSelect"' in template
    assert 'id="manageCommandSetsBtn"' in template
    assert 'id="connectionCommandPreview"' in template


def test_connection_payload_uses_the_selected_post_connect_mode():
    source = Path('static/js/app.js').read_text(encoding='utf-8')

    assert 'ConnectionCommandManager.getPayload()' in source
    assert "window.socket.emit('save_profile'" not in source


def test_profile_selection_restores_command_set_and_supports_legacy_conversion():
    source = Path('static/js/profile-manager.js').read_text(encoding='utf-8')

    assert 'ConnectionCommandManager?.applyProfile(profile)' in source
    assert 'profile.startup_commands' in source
    assert 'CommandSetManager.openLegacyConversion(profile)' in source
    assert 'getLegacyStartupCommands()' in source
