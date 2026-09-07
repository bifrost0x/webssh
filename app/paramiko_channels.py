"""Bound Paramiko channel handshakes and long-lived channel operations."""

import socket
import struct
import time
from threading import Timer

import paramiko
from paramiko.sftp import SFTPError

import config


SSH_OPEN_FAILED_RESOURCE_SHORTAGE = 4


def optional_channel_rejection_fields(error):
    """Describe a remote capacity rejection for an optional SSH channel.

    RFC 4254 reason code 4 is supplied by the remote SSH server.  Keep the
    server-provided text out of application logs because it is untrusted, and
    leave retry policy to the caller because this condition can be temporary.
    Do not classify other channel failures here: callers may need to retry or
    fail a primary SSH operation for those errors.
    """
    if not isinstance(error, paramiko.ChannelException):
        return None
    code = getattr(error, 'code', None)
    if type(code) is not int or code != SSH_OPEN_FAILED_RESOURCE_SHORTAGE:
        return None
    return {
        'ssh_channel_code': SSH_OPEN_FAILED_RESOURCE_SHORTAGE,
        'ssh_channel_reason': 'remote_resource_shortage',
    }


class BoundedSFTPClient(paramiko.SFTPClient):
    """Reject attacker-declared SFTP packets before allocating their body."""

    def _read_packet(self):
        header = self._read_all(4)
        size = struct.unpack('>I', header)[0]
        if size > config.SFTP_MAX_PACKET_BYTES:
            try:
                self.sock.close()
            finally:
                raise SFTPError('SFTP packet exceeds configured byte limit')
        data = self._read_all(size)
        if self.ultra_debug:
            self._log(
                paramiko.common.DEBUG,
                paramiko.util.format_binary(data, 'IN: '),
            )
        if size > 0:
            return data[0], data[1:]
        return 0, bytes()


def _request_guard(channel, timeout):
    guard = Timer(timeout, channel.close)
    guard.daemon = True
    guard.start()
    return guard


def _remaining_timeout(deadline, maximum):
    if deadline is None:
        return maximum
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise socket.timeout('SSH channel operation exceeded its deadline')
    return min(maximum, remaining)


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


def open_sftp_client(transport, *, timeout, operation_timeout, deadline=None):
    """Open SFTP with a handshake deadline and bounded later operations."""
    channel = transport.open_session(
        timeout=_remaining_timeout(deadline, timeout)
    )
    handshake_timeout = _remaining_timeout(deadline, timeout)
    channel.settimeout(handshake_timeout)
    timeout_guard = _request_guard(channel, handshake_timeout)
    try:
        channel.invoke_subsystem('sftp')
        sftp = BoundedSFTPClient(channel)
        if channel.closed:
            raise socket.timeout('SFTP request exceeded its deadline')
        channel.settimeout(_remaining_timeout(deadline, operation_timeout))
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
