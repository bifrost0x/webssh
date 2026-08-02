"""Bound Paramiko channel handshakes and long-lived channel operations."""

import socket
import time
from threading import Timer

import paramiko


def _request_guard(channel, timeout):
    guard = Timer(timeout, channel.close)
    guard.daemon = True
    guard.start()
    return guard


def open_shell_channel(transport, *, timeout, term, width, height):
    """Open a PTY shell without Paramiko's unbounded request waits."""
    channel = transport.open_session(timeout=timeout)
    channel.settimeout(timeout)
    timeout_guard = _request_guard(channel, timeout)
    try:
        channel.get_pty(term=term, width=width, height=height)
        channel.invoke_shell()
        if channel.closed:
            raise socket.timeout('SSH shell request exceeded its deadline')
    except Exception:
        channel.close()
        raise
    finally:
        timeout_guard.cancel()
    return channel


def open_sftp_client(transport, *, timeout, operation_timeout):
    """Open SFTP with a handshake deadline and bounded later operations."""
    channel = transport.open_session(timeout=timeout)
    channel.settimeout(timeout)
    timeout_guard = _request_guard(channel, timeout)
    try:
        channel.invoke_subsystem('sftp')
        sftp = paramiko.SFTPClient(channel)
        if channel.closed:
            raise socket.timeout('SFTP request exceeded its deadline')
        channel.settimeout(operation_timeout)
        return sftp
    except Exception:
        channel.close()
        raise
    finally:
        timeout_guard.cancel()


def wait_for_exit_status(channel, *, timeout, poll_interval=0.05):
    """Return an exec exit status or close the channel at the deadline."""
    deadline = time.monotonic() + timeout
    while not channel.exit_status_ready():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            channel.close()
            raise socket.timeout('SSH command exit status exceeded its deadline')
        time.sleep(min(poll_interval, remaining))
    return channel.recv_exit_status()
