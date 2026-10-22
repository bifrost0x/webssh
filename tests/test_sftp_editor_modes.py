"""The editor must not widen permissions while replacing file content."""

import hashlib
import io
import stat
import struct
from contextlib import contextmanager
from types import SimpleNamespace

import pytest


def fixture(monkeypatch, mode=0o600, *, fail_chmod=False, fail_rename=False, changed=False, malformed_at=None):
    from app import sftp_handler
    state = {'data': b'old', 'mode': mode, 'renamed': False, 'removed': []}

    def info(value):
        return SimpleNamespace(st_mode=stat.S_IFREG | value, st_size=3, st_mtime=10, st_uid=1000, st_gid=1000)

    class Reader(io.BytesIO):
        handle = b'original'

        def stat(self):
            from paramiko.sftp_attr import SFTPAttributes
            from paramiko.sftp import CMD_FSTAT
            return SFTPAttributes._from_msg(client._request(CMD_FSTAT, self.handle)[1])

    class Staged(io.BytesIO):
        new_mode = 0o600

        def stat(self):
            result = info(self.new_mode)
            result.st_size = len(self.getvalue())
            return result

        def chmod(self, value):
            if fail_chmod:
                raise PermissionError('private')
            self.new_mode = value

    staged = Staged()

    class Client:
        calls = {}

        def _adjust_cwd(self, path):
            return path

        def _request(self, command, *_args):
            from paramiko.message import Message
            from paramiko.sftp import CMD_ATTRS, CMD_FSTAT, CMD_LSTAT
            from paramiko.sftp_attr import SFTPAttributes
            assert command in {CMD_FSTAT, CMD_LSTAT}
            self.calls[command] = self.calls.get(command, 0) + 1
            value = info(0o644 if changed and command == CMD_LSTAT else mode)
            attributes = SFTPAttributes()
            attributes.__dict__.update(value.__dict__)
            attributes.st_atime = 10
            message = Message()
            attributes._pack(message)
            payload = message.asbytes()
            if malformed_at == (command, self.calls[command]):
                flags = struct.unpack('>I', payload[:4])[0] | SFTPAttributes.FLAG_EXTENDED
                payload = struct.pack('>I', flags) + payload[4:] + struct.pack('>I', 32)
            return CMD_ATTRS, Message(payload)

        def file(self, path, mode):
            assert mode == 'rb', 'editor must not use a truncating path open'
            return Reader(b'old')

        def lstat(self, _path):
            from paramiko.sftp_attr import SFTPAttributes
            from paramiko.sftp import CMD_LSTAT
            return SFTPAttributes._from_msg(self._request(CMD_LSTAT, _path)[1])

        def posix_rename(self, _old, _new):
            if fail_rename:
                raise EOFError('lost acknowledgement')
            state.update(data=staged.getvalue(), mode=staged.new_mode, renamed=True)

        def remove(self, path):
            state['removed'].append(path)

    client = Client()

    @contextmanager
    def session(*_args, **_kwargs):
        yield client

    @contextmanager
    def exclusive(_client, _path, *, mode=0o600):
        assert mode == 0o600
        yield staged

    monkeypatch.setattr(sftp_handler, 'mutation_session', session)
    monkeypatch.setattr(sftp_handler, 'open_exclusive_file', exclusive)
    return state


@pytest.mark.parametrize('operation,index', [('FSTAT', 1), ('FSTAT', 2), ('FSTAT', 3), ('LSTAT', 1), ('LSTAT', 2)])
def test_save_rejects_excessive_extensions_at_every_reader_and_path_check(monkeypatch, operation, index):
    from paramiko.sftp import CMD_FSTAT, CMD_LSTAT
    from app.sftp_handler import write_file_text
    command = CMD_FSTAT if operation == 'FSTAT' else CMD_LSTAT
    state = fixture(monkeypatch, malformed_at=(command, index))
    result = write_file_text('a', '/file', 'new', expected_revision=hashlib.sha256(b'old').hexdigest())
    assert not result.success
    assert state['data'] == b'old'
    assert not state['renamed']


def test_save_metadata_never_uses_paramikos_unbounded_attribute_parser(monkeypatch):
    from paramiko.sftp_attr import SFTPAttributes
    from app.sftp_handler import write_file_text
    state = fixture(monkeypatch, 0o750)
    monkeypatch.setattr(SFTPAttributes, '_from_msg', lambda *_args, **_kwargs: pytest.fail('unbounded parser reached'))
    result = write_file_text('a', '/file', 'new', expected_revision=hashlib.sha256(b'old').hexdigest())
    assert result.success, result.error
    assert state['renamed'] and state['mode'] == 0o750


@pytest.mark.parametrize('mode', [0o600, 0o750])
def test_save_preserves_private_and_executable_modes(monkeypatch, mode):
    from app.sftp_handler import write_file_text
    state = fixture(monkeypatch, mode)
    outcome = write_file_text('a', '/file', 'new', expected_revision=hashlib.sha256(b'old').hexdigest())
    assert outcome.success, outcome.error
    assert state['mode'] == mode
    assert state['data'] == b'new'


@pytest.mark.parametrize('options', [{'fail_chmod': True}, {'mode': 0o4600}, {'changed': True}])
def test_save_does_not_replace_on_permission_or_metadata_failure(monkeypatch, options):
    from app.sftp_handler import write_file_text
    state = fixture(monkeypatch, **options)
    outcome = write_file_text('a', '/file', 'new', expected_revision=hashlib.sha256(b'old').hexdigest())
    assert not outcome.success
    assert state['data'] == b'old'
    assert not state['renamed']


def test_unconfirmed_rename_never_claims_original_is_unchanged_or_deletes_by_path(monkeypatch):
    from app.sftp_handler import write_file_text
    state = fixture(monkeypatch, fail_rename=True)
    outcome = write_file_text('a', '/file', 'new', expected_revision=hashlib.sha256(b'old').hexdigest())
    assert not outcome.success
    assert outcome.code == 'SAVE_OUTCOME_UNKNOWN'
    assert state['removed'] == []
