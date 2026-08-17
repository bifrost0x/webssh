import socket
import threading
import time

import paramiko
import pytest


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
        paramiko_channels.paramiko,
        'SFTPClient',
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
    monkeypatch.setattr(paramiko_channels.paramiko, 'SFTPClient', lambda _channel: object())

    paramiko_channels.open_sftp_client(
        Transport(), timeout=5, operation_timeout=5, deadline=12.0
    )

    assert channel.timeouts == pytest.approx([1.6, 1.2])
