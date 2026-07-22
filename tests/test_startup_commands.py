"""Tests for post-connect command normalization and terminal input."""

import re
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _clean_ssh_sessions():
    from app import ssh_manager

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
        self.transport = transport or _StartupCommandTransport()
        self.closed = False
        self.close_calls = 0

    def set_missing_host_key_policy(self, _policy):
        pass

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
        startup_commands=startup_commands,
    )

    assert error is None
    assert session_id in ssh_manager.sessions
    assert channel.sent == [expected_input.encode('utf-8')]

    ssh_manager.close_session(session_id)


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


def test_connection_form_replaces_raw_startup_commands_with_named_set_selector():
    template = Path('templates/index.html').read_text(encoding='utf-8')

    assert 'id="startupCommandsInput"' not in template
    assert 'id="commandSetSelect"' in template
    assert 'id="createCommandSetBtn"' in template
    assert 'id="commandSetPreview"' in template


def test_connection_and_saved_profile_payloads_include_command_set_reference():
    source = Path('static/js/app.js').read_text(encoding='utf-8')

    assert "CommandSetManager.getSelectedId()" in source
    assert re.search(r'profilePayload\.command_set_id\s*=\s*commandSetId', source)
    assert re.search(r'connectionData\.command_set_id\s*=\s*commandSetId', source)
    assert re.search(
        r'connectionData\.startup_commands\s*=\s*legacyStartupCommands', source
    )


def test_profile_selection_restores_command_set_and_supports_legacy_conversion():
    source = Path('static/js/profile-manager.js').read_text(encoding='utf-8')

    assert 'CommandSetManager.selectForConnection(profile.command_set_id)' in source
    assert 'profile.startup_commands' in source
    assert 'CommandSetManager.openLegacyConversion(profile)' in source
    assert 'getLegacyStartupCommands()' in source
