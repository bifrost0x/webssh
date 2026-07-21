"""Tests for post-connect command normalization and terminal input."""

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
        self.fail_on_send = fail_on_send
        self.max_send_size = max_send_size
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

    def close(self):
        self.closed = True


class _StartupCommandTransport:
    def set_keepalive(self, _seconds):
        pass


class _StartupCommandClient:
    def __init__(self, channel):
        self.channel = channel
        self.transport = _StartupCommandTransport()
        self.closed = False

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
