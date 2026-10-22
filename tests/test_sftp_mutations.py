"""Exercise wire flags and no-follow operations without a live server."""

import struct
import stat
import threading
from contextlib import contextmanager
from types import SimpleNamespace

import paramiko
import pytest
from paramiko.message import Message
from paramiko.sftp import CMD_ATTRS, CMD_CLOSE, CMD_EXTENDED, CMD_FSTAT, CMD_HANDLE, CMD_OPEN, CMD_SETSTAT, CMD_VERSION, SFTP_FLAG_CREATE, SFTP_FLAG_EXCL, SFTP_FLAG_WRITE


class WireClient:
    def __init__(self, *, close_error=None):
        self.requests = []
        self.close_error = close_error
        self.server_extensions = {'lsetstat@openssh.com': '1'}

    def _adjust_cwd(self, path):
        return path

    def _log(self, *_):
        pass

    def _request(self, command, *args):
        self.requests.append((command, args))
        message = Message()
        if command == CMD_OPEN:
            message.add_string(b'owned-handle')
            return CMD_HANDLE, Message(message.asbytes())
        if command == CMD_CLOSE and self.close_error:
            raise self.close_error
        if command == CMD_FSTAT:
            info = paramiko.SFTPAttributes()
            info.st_mode = stat.S_IFREG | 0o600
            info.st_size = 0
            info._pack(message)
            return CMD_ATTRS, Message(message.asbytes())
        return None, message


def test_exclusive_open_sets_permissions_in_open_without_truncate():
    from app.sftp_handler import open_exclusive_file
    client = WireClient()
    with open_exclusive_file(client, '/new') as handle:
        assert handle.stat().st_size == 0
    command, args = client.requests[0]
    assert command == CMD_OPEN
    assert args[1] == SFTP_FLAG_WRITE | SFTP_FLAG_CREATE | SFTP_FLAG_EXCL
    assert args[2].st_mode == 0o600
    assert [command for command, _ in client.requests].count(CMD_CLOSE) == 1


def test_exclusive_close_does_not_swallow_real_protocol_failure():
    from app.sftp_handler import open_exclusive_file
    client = WireClient(close_error=EOFError('private'))
    with pytest.raises(EOFError):
        with open_exclusive_file(client, '/new'):
            pass
    assert [command for command, _ in client.requests].count(CMD_CLOSE) == 1


def test_lsetstat_sends_only_permissions_and_never_general_setstat():
    from app.paramiko_channels import BoundedSFTPClient
    client = WireClient()
    BoundedSFTPClient.set_permissions_no_follow(client, '/file', 0o640)
    assert len(client.requests) == 1
    command, args = client.requests[0]
    assert command == CMD_EXTENDED
    assert args[:2] == ('lsetstat@openssh.com', '/file')
    attributes = args[2]
    assert attributes.st_mode == 0o640
    assert attributes.st_uid is None and attributes.st_gid is None
    assert attributes.st_size is None and attributes.st_mtime is None
    assert command != CMD_SETSTAT


@pytest.mark.parametrize('extensions', [{}, {'lsetstat@openssh.com': '2'}])
def test_missing_extension_never_sends_a_mutation(extensions):
    from app.paramiko_channels import BoundedSFTPClient
    from app.file_mutations import FileMutationError
    client = WireClient()
    client.server_extensions = extensions
    with pytest.raises(FileMutationError):
        BoundedSFTPClient.set_permissions_no_follow(client, '/file', 0o600)
    assert client.requests == []


def handshake(data):
    from app.paramiko_channels import BoundedSFTPClient
    client = object.__new__(BoundedSFTPClient)
    client._send_packet = lambda *_: None
    client._read_packet = lambda: (CMD_VERSION, data)
    def invoke():
        import config
        previous = config.SFTP_CHMOD_ENABLED
        config.SFTP_CHMOD_ENABLED = True
        try:
            return client._send_version()
        finally:
            config.SFTP_CHMOD_ENABLED = previous
    return client, invoke


def test_extensions_are_captured_from_bounded_handshake():
    client, invoke = handshake(struct.pack('>I', 3) + MessageBytes('lsetstat@openssh.com', '1'))
    assert invoke() == 3
    assert client.server_extensions == {'lsetstat@openssh.com': '1'}


def MessageBytes(*values):
    message = Message()
    for value in values:
        message.add_string(value)
    return message.asbytes()


@pytest.mark.parametrize('data', [b'', b'\x00\x00\x00'])
def test_invalid_version_header_is_rejected(data):
    _, invoke = handshake(data)
    with pytest.raises(paramiko.SFTPError):
        invoke()


@pytest.mark.parametrize('suffix', [b'\x00', MessageBytes('x' * 257, '1'), MessageBytes(*(['x', '1'] * 65)), MessageBytes('x', '1', 'x', '2')])
def test_invalid_extensions_disable_only_chmod(suffix):
    client, invoke = handshake(struct.pack('>I', 3) + MessageBytes('lsetstat@openssh.com', '1') + suffix)
    assert invoke() == 3
    assert client.server_extensions == {}


def test_mutation_lock_deadline_does_not_touch_another_requests_channel(monkeypatch):
    from app import sftp_handler
    from app.file_mutations import FileMutationError
    lock = threading.Lock()
    lock.acquire()
    monkeypatch.setattr(sftp_handler, '_get_sftp_lock', lambda _: lock)
    monkeypatch.setattr(sftp_handler, 'get_any_sftp_client', lambda _: pytest.fail('busy lock accessed channel'))
    with pytest.raises(FileMutationError) as failure:
        with sftp_handler.mutation_session('a', timeout=0.01):
            pytest.fail('busy session entered')
    assert failure.value.code == 'TIMEOUT'
    assert lock.locked()
    lock.release()


@pytest.mark.parametrize('payload', [struct.pack('>I', 2**32 - 1), struct.pack('>I', 0), MessageBytes('x') + b'trailing'])
def test_exclusive_open_rejects_unbounded_empty_or_trailing_handles(payload):
    from app.sftp_handler import open_exclusive_file, RemoteMetadataLimitExceeded
    client = WireClient()
    request = client._request
    client._request = lambda command, *args: (CMD_HANDLE, Message(payload)) if command == CMD_OPEN else request(command, *args)
    with pytest.raises(RemoteMetadataLimitExceeded):
        with open_exclusive_file(client, '/new'):
            pytest.fail('invalid handle reached caller')


def test_new_metadata_reader_rejects_attacker_declared_attribute_count():
    from app.sftp_handler import mutation_lstat, RemoteMetadataLimitExceeded
    client = WireClient()
    client._request = lambda *_: (CMD_ATTRS, Message(struct.pack('>II', 0x80000000, 2**32 - 1)))
    with pytest.raises(RemoteMetadataLimitExceeded):
        mutation_lstat(client, '/file')


@pytest.mark.parametrize('payload', [struct.pack('>II', 0x80000000, 2**32 - 1), b'\0', struct.pack('>I', 0) + b'trailing', struct.pack('>I', 0x40000000)])
def test_handle_metadata_reader_rejects_excessive_truncated_trailing_and_unknown_attributes(payload):
    from app.sftp_handler import mutation_fstat, RemoteMetadataLimitExceeded
    client = WireClient()
    client._request = lambda *_: (CMD_ATTRS, Message(payload))
    with pytest.raises(RemoteMetadataLimitExceeded):
        mutation_fstat(client, SimpleNamespace(handle=b'original'))


def test_revoked_authorization_after_lock_prevents_any_channel_open(monkeypatch):
    from app import sftp_handler
    from app.file_mutations import FileMutationError
    lock = threading.Lock()
    monkeypatch.setattr(sftp_handler, '_get_sftp_lock', lambda _: lock)
    monkeypatch.setattr(sftp_handler, 'get_ssh_client', lambda _: pytest.fail('unauthorized channel access'))

    def revoked():
        assert lock.locked()
        raise FileMutationError('PERMISSION_DENIED')

    with pytest.raises(FileMutationError, match='Permission denied'):
        with sftp_handler.mutation_session('a', authorize=revoked):
            pytest.fail('revoked mutation entered')
    assert not lock.locked()
