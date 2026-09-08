import logging
import socket
import threading
import time

import paramiko
import pytest


def _invoke_channel_open_failure(channel_id, reason_code, description):
    transport = object.__new__(paramiko.Transport)
    transport.logger = logging.getLogger('paramiko.transport')
    transport.lock = threading.Lock()
    transport.channel_events = {}
    transport.saved_exception = None

    message = paramiko.Message()
    message.add_int(channel_id)
    message.add_int(reason_code)
    message.add_string(description)
    message.add_string('en')
    message.rewind()
    transport._parse_channel_open_failure(message)
    return transport.saved_exception


@pytest.mark.parametrize(
    ('reason_code', 'reason_text'),
    [
        (1, 'Administratively prohibited'),
        (2, 'Connect failed'),
        (3, 'Unknown channel type'),
        (4, 'Resource shortage'),
        (99, '(unknown code)'),
    ],
)
def test_paramiko_channel_open_failure_log_omits_remote_description(
        caplog, reason_code, reason_text):
    from app import paramiko_channels  # noqa: F401

    caplog.set_level(logging.ERROR, logger='paramiko.transport')
    remote_description = 'attacker-line\nFORGED\r\x1b[31m\x00'

    error = _invoke_channel_open_failure(27, reason_code, remote_description)

    assert caplog.messages == [
        'Secsh channel 27 open FAILED: '
        f'{reason_text} (server description omitted)'
    ]
    assert remote_description not in caplog.text
    assert 'FORGED' not in caplog.text
    assert '\x1b' not in caplog.text
    assert '\x00' not in caplog.text
    assert error.code == reason_code
    assert error.text == reason_text


def test_paramiko_channel_log_filter_preserves_unrelated_records(caplog):
    from app import paramiko_channels  # noqa: F401

    caplog.set_level(logging.ERROR, logger='paramiko.transport')
    logger = logging.getLogger('paramiko.transport')

    logger.error('Unrelated Paramiko error: %s', 'connection reset')

    assert caplog.messages == [
        'Unrelated Paramiko error: connection reset'
    ]


def test_paramiko_channel_log_filter_installation_is_idempotent():
    from app import paramiko_channels

    logger = logging.getLogger('paramiko.transport')
    paramiko_channels._install_channel_open_failure_log_filter()
    paramiko_channels._install_channel_open_failure_log_filter()

    assert sum(
        bool(getattr(
            log_filter,
            paramiko_channels._CHANNEL_OPEN_FAILURE_FILTER_MARKER,
            False,
        ))
        for log_filter in logger.filters
    ) == 1


def test_optional_channel_rejection_fields_accepts_only_remote_resource_shortage():
    from app import paramiko_channels

    assert paramiko_channels.optional_channel_rejection_fields(
        paramiko.ChannelException(4, 'server-controlled text')
    ) == {
        'ssh_channel_code': 4,
        'ssh_channel_reason': 'remote_resource_shortage',
    }
    assert paramiko_channels.optional_channel_rejection_fields(
        paramiko.ChannelException(1, 'Administratively prohibited')
    ) is None
    assert paramiko_channels.optional_channel_rejection_fields(
        paramiko.SSHException('transport race')
    ) is None


def test_primary_shell_keeps_remote_resource_shortage_fatal():
    from app import paramiko_channels

    class RejectingTransport:
        def open_session(self, timeout=None):
            raise paramiko.ChannelException(4, 'Resource shortage')

    with pytest.raises(paramiko.ChannelException) as error:
        paramiko_channels.open_shell_channel(
            RejectingTransport(),
            timeout=1,
            term='xterm-256color',
            width=80,
            height=24,
        )

    assert error.value.code == 4


class BlockingTransport:
    def __init__(self):
        self.open_timeout = None
        self.channel = paramiko.Channel(1)
        self.channel.active = True
        self.channel.remote_chanid = 1
        self.channel.transport = self

    def open_session(self, timeout=None):
        self.open_timeout = timeout
        return self.channel

    def _send_user_message(self, _message):
        pass

    def get_exception(self):
        return None


@pytest.mark.parametrize('operation', ['shell', 'sftp'])
def test_channel_request_handshakes_obey_the_connection_deadline(operation):
    """A silent server cannot hold a worker in PTY, shell, or SFTP setup."""
    from app import paramiko_channels

    transport = BlockingTransport()
    finished = threading.Event()
    errors = []

    def execute():
        try:
            if operation == 'shell':
                paramiko_channels.open_shell_channel(
                    transport,
                    timeout=0.05,
                    term='xterm-256color',
                    width=80,
                    height=24,
                )
            else:
                paramiko_channels.open_sftp_client(
                    transport,
                    timeout=0.05,
                    operation_timeout=1,
                )
        except Exception as error:
            errors.append(error)
        finally:
            finished.set()

    worker = threading.Thread(target=execute, daemon=True)
    worker.start()
    completed = finished.wait(0.5)
    if not completed:
        transport.channel.close()
    worker.join(2)

    assert completed, f'Paramiko {operation} request exceeded its deadline'
    assert transport.open_timeout == 0.05
    assert transport.channel.closed is True
    assert errors


def test_exit_status_wait_closes_a_silent_channel_at_deadline():
    """tmux availability probing cannot wait indefinitely for exit status."""
    from app import paramiko_channels

    class SilentChannel:
        closed = False

        def exit_status_ready(self):
            return False

        def close(self):
            self.closed = True

    channel = SilentChannel()
    started = time.monotonic()

    with pytest.raises(socket.timeout, match='exit status'):
        paramiko_channels.wait_for_exit_status(channel, timeout=0.02)

    assert time.monotonic() - started < 0.5
    assert channel.closed is True


def test_open_sftp_sets_bounded_normal_operation_timeout(monkeypatch):
    """Cached SFTP operations must not inherit Paramiko's unbounded default."""
    from app import paramiko_channels

    class Channel:
        def __init__(self):
            self.timeouts = []
            self.closed = False

        def settimeout(self, timeout):
            self.timeouts.append(timeout)

        def invoke_subsystem(self, name):
            assert name == 'sftp'

        def close(self):
            self.closed = True

    class Transport:
        def __init__(self):
            self.channel = Channel()

        def open_session(self, timeout=None):
            assert timeout == 3
            return self.channel

    transport = Transport()
    marker = object()
    monkeypatch.setattr(
        paramiko_channels,
        'BoundedSFTPClient',
        lambda channel: marker,
    )

    result = paramiko_channels.open_sftp_client(
        transport,
        timeout=3,
        operation_timeout=17,
    )

    assert result is marker
    assert transport.channel.timeouts == [3, 17]
    assert transport.channel.closed is False


def test_open_sftp_uses_one_shared_absolute_deadline(monkeypatch):
    from app import paramiko_channels

    now = iter([10.0, 10.4, 10.8])
    monkeypatch.setattr(paramiko_channels.time, 'monotonic', lambda: next(now))

    class Channel:
        closed = False

        def __init__(self):
            self.timeouts = []

        def settimeout(self, timeout):
            self.timeouts.append(timeout)

        def invoke_subsystem(self, _name):
            pass

        def close(self):
            self.closed = True

    channel = Channel()

    class Transport:
        def open_session(self, timeout=None):
            assert timeout == pytest.approx(2.0)
            return channel

    guard = type('Guard', (), {'cancel': lambda self: None})()
    monkeypatch.setattr(paramiko_channels, '_request_guard', lambda *_args: guard)
    monkeypatch.setattr(
        paramiko_channels,
        'BoundedSFTPClient',
        lambda _channel: object(),
    )

    paramiko_channels.open_sftp_client(
        Transport(), timeout=5, operation_timeout=5, deadline=12.0
    )

    assert channel.timeouts == pytest.approx([1.6, 1.2])


def test_sftp_packet_limit_closes_channel_before_declared_body_read(
    monkeypatch,
):
    import struct
    import config
    from app import paramiko_channels
    from paramiko.sftp import SFTPError

    monkeypatch.setattr(config, 'SFTP_MAX_PACKET_BYTES', 1024)

    class Socket:
        def __init__(self):
            self.closed = False
            self.reads = []

        def recv(self, size):
            self.reads.append(size)
            if len(self.reads) == 1:
                return struct.pack('>I', 1025)
            raise AssertionError('oversized SFTP packet body was read')

        def close(self):
            self.closed = True

    client = object.__new__(paramiko_channels.BoundedSFTPClient)
    client.sock = Socket()

    with pytest.raises(SFTPError, match='packet exceeds'):
        client._read_packet()

    assert client.sock.reads == [4]
    assert client.sock.closed is True
