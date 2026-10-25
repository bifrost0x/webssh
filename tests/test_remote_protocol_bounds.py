"""Reject hostile framing before dependency parsers can allocate or iterate."""

import struct
from types import SimpleNamespace

import pytest
from paramiko import SFTPFile
from paramiko.sftp import CMD_ATTRS, CMD_NAME, CMD_VERSION, SFTPError

from app.paramiko_channels import BoundedSFTPClient


def _packet(command, payload):
    body = bytes([command]) + payload
    return struct.pack('>I', len(body)) + body


class _Channel:
    def __init__(self, response):
        self.data = bytearray(_packet(CMD_VERSION, struct.pack('>I', 3)) + response)
        self.closed = False

    def send(self, data):
        return len(data)

    def get_name(self):
        return 'synthetic'

    def recv(self, count):
        result = bytes(self.data[:count])
        del self.data[:count]
        return result

    def close(self):
        self.closed = True


@pytest.mark.parametrize('operation', ['stat', 'lstat', 'fstat'])
def test_sftp_public_metadata_rejects_unbacked_extension_count(operation):
    # Seventeen iterations remain harmless even against the old parser.
    payload = struct.pack('>III', 1, 0x80000000, 17)
    channel = _Channel(_packet(CMD_ATTRS, payload))
    client = BoundedSFTPClient(channel)
    remote_file = SFTPFile(client, b'handle', 'r')
    try:
        with pytest.raises(SFTPError):
            remote_file.stat() if operation == 'fstat' else getattr(client, operation)('/file')
        assert channel.closed
    finally:
        remote_file._closed = True


@pytest.mark.parametrize(('command', 'payload'), [
    (CMD_ATTRS, struct.pack('>III', 1, 0x80000000, 0xFFFFFFFF)),
    (CMD_ATTRS, struct.pack('>II', 1, 1)),  # Missing uint64 size.
    (CMD_ATTRS, struct.pack('>II', 1, 0x10)),  # Unknown attribute flag.
    (CMD_NAME, struct.pack('>II', 1, 0xFFFFFFFF)),
    (CMD_NAME, struct.pack('>III', 1, 1, 0xFFFFFFFF)),
])
def test_sftp_packet_rejects_malformed_metadata_before_dependency_parsing(command, payload):
    channel = _Channel(_packet(command, payload))
    client = BoundedSFTPClient(channel)
    with pytest.raises(SFTPError):
        client._read_packet()
    assert channel.closed


def test_sftp_stat_preserves_valid_binary_extensions():
    attributes = struct.pack('>IQII', 0x80000005, 42, 0o100640, 1)
    attributes += struct.pack('>I', 2) + b'\xff\x00' + struct.pack('>I', 2) + b'\xff\x00'
    client = BoundedSFTPClient(_Channel(_packet(CMD_ATTRS, struct.pack('>I', 1) + attributes)))
    result = client.stat('/file')
    assert (result.st_size, result.st_mode) == (42, 0o100640)
    assert result.attr == {b'\xff\x00': b'\xff\x00'}


def _string(value):
    return struct.pack('>I', len(value)) + value


def test_sftp_name_rejects_nested_attribute_extensions():
    payload = struct.pack('>II', 1, 1) + _string(b'file') + _string(b'listing')
    payload += struct.pack('>II', 0x80000000, 17)
    channel = _Channel(_packet(CMD_NAME, payload))
    client = BoundedSFTPClient(channel)
    with pytest.raises(SFTPError):
        client._read_packet()
    assert channel.closed


def test_sftp_name_preserves_valid_metadata_and_empty_listing():
    payload = struct.pack('>II', 1, 1) + _string(b'/home/user') + _string(b'') + struct.pack('>I', 0)
    client = BoundedSFTPClient(_Channel(_packet(CMD_NAME, payload)))
    assert client.normalize('.') == '/home/user'
    client = BoundedSFTPClient(_Channel(_packet(CMD_NAME, struct.pack('>II', 1, 0))))
    command, data = client._read_packet()
    assert command == CMD_NAME
    assert data == struct.pack('>II', 1, 0)


def test_sftp_status_retains_permission_error_contract():
    from paramiko.sftp import CMD_STATUS
    payload = struct.pack('>II', 1, 3) + _string(b'denied') + _string(b'')
    client = BoundedSFTPClient(_Channel(_packet(CMD_STATUS, payload)))
    with pytest.raises(PermissionError):
        client.stat('/file')


@pytest.mark.parametrize('declared_size', [0x01000000, 0xFFFFFFFF])
def test_smb_negotiate_rejects_frame_before_body_allocation(monkeypatch, declared_size):
    from smbprotocol.connection import Connection
    from smbprotocol.transport import Tcp
    from app.smb_protocol import _RealSMBProtocol

    body_reads = []

    def receive(_transport, length, timeout):
        if length == 4:
            return struct.pack('>I', declared_size), timeout
        body_reads.append(length)
        raise AssertionError('dependency body allocation was reached')

    def negotiate(connection, *_args):
        connection._t_worker.join(2)
        assert not connection._t_worker.is_alive()
        raise connection._t_exc

    monkeypatch.setattr(Tcp, '_recv', receive)
    monkeypatch.setattr(Connection, '_send_smb2_negotiate', negotiate)
    monkeypatch.setattr('smbprotocol.transport.socket.create_connection', lambda *_a, **_k: SimpleNamespace(
        settimeout=lambda _timeout: None, shutdown=lambda _how: None, close=lambda: None,
    ))
    with pytest.raises(ValueError, match='frame'):
        _RealSMBProtocol().new_connection(
            server='192.0.2.1', port=445, require_signing=True,
            dialect=0x0311, timeout=1, io_idle_timeout=1,
        )
    assert body_reads == []


def test_smb_receive_keeps_fragmented_frames_timeout_and_eof(monkeypatch):
    import socket
    import uuid
    from smbprotocol.connection import Connection
    from smbprotocol.transport import Tcp
    from app.smb_protocol import _BoundedSMBConnection

    local, peer = socket.socketpair()

    class FragmentedSocket:
        def fileno(self):
            return local.fileno()

        def recv(self, count):
            return local.recv(min(count, 1))

        def shutdown(self, how):
            local.shutdown(how)

        def close(self):
            local.close()

    transport = Tcp('synthetic', 445)
    transport._sock = FragmentedSocket()
    transport.connected = True
    connection = _BoundedSMBConnection(uuid.uuid4(), 'synthetic')
    connection.transport = transport

    def receiver(self):
        assert self.transport.recv(1) == b'hello'
        assert self.transport.recv(1) == b''

    monkeypatch.setattr(Connection, '_process_message_thread', receiver)
    try:
        peer.sendall(struct.pack('>I', 5) + b'hello')
        peer.shutdown(socket.SHUT_WR)
        connection._process_message_thread()
        assert not transport.connected
    finally:
        peer.close()
        local.close()


def test_smb_frame_guard_is_per_connection_and_accepts_protocol_maximum(monkeypatch):
    import uuid
    from smbprotocol.connection import Connection
    from app.smb_protocol import _BoundedSMBConnection

    monkeypatch.setattr(Connection, '_process_message_thread', lambda _self: None)
    connections = []
    for marker in (b'first', b'second'):
        connection = _BoundedSMBConnection(uuid.uuid4(), 'synthetic')
        connection.transport = SimpleNamespace(_recv=lambda _length, timeout, value=marker: (value, timeout))
        connection._process_message_thread()
        connections.append(connection)
    assert connections[0].transport._recv(0xFFFFFF, 7) == (b'first', 7)
    assert connections[1].transport._recv(4, 3) == (b'second', 3)
    with pytest.raises(ValueError, match='frame'):
        connections[0].transport._recv(0x1000000, 7)
