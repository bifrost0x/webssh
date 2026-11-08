from contextlib import contextmanager
from types import SimpleNamespace
import io
import stat

import pytest

from app import sftp_handler


class Remote:
    def __init__(self, mode=0o600):
        self.original = SimpleNamespace(st_mode=stat.S_IFREG | mode, st_size=3,
                                        st_mtime=1, st_uid=1000, st_gid=1000)
        self.staged = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_size=0,
                                      st_mtime=2, st_uid=1000, st_gid=1000)
        self.removed = []
        self.published = []
        self.collision = False
        self.rename_error = None
        self.requested_modes = []
        # None models a server that applies its umask or forced create mode.
        self.default_mode = 0o644
        self.chown_error = None
        self.chmod_error = None

    def lstat(self, path):
        if self.original is None:
            raise FileNotFoundError(path)
        return self.original

    def rename(self, old, new):
        if self.rename_error:
            raise self.rename_error
        self.published.append((old, new))

    posix_rename = rename

    def remove(self, path):
        self.removed.append(path)


@pytest.fixture
def remote(monkeypatch):
    remote = Remote()

    @contextmanager
    def exclusive(client, path, *, mode=0o600):
        client.requested_modes.append(mode)
        if client.collision:
            raise FileExistsError(path)
        if mode is None:
            client.staged.st_mode = stat.S_IFREG | client.default_mode
        class Writer(io.BytesIO):
            def stat(self):
                return client.staged

            def chmod(self, mode):
                if client.chmod_error:
                    raise client.chmod_error
                client.staged.st_mode = stat.S_IFREG | mode

            def chown(self, uid, gid):
                if client.chown_error:
                    raise client.chown_error
                client.staged.st_uid, client.staged.st_gid = uid, gid
        with Writer() as writer:
            yield writer
    monkeypatch.setattr(sftp_handler, 'open_exclusive_file', exclusive)
    return remote


@pytest.mark.parametrize('mode', [0o600, 0o640, 0o750, 0o400, 0o444, 0o440, 0o500, 0o555])
def test_transfer_stays_private_until_payload_complete_and_retains_mode(remote, mode):
    remote.original.st_mode = stat.S_IFREG | mode
    with sftp_handler.atomic_transfer_writer(remote, '/target', '/stage', replace=True) as writer:
        writer.write(b'secret')
        assert stat.S_IMODE(remote.staged.st_mode) == 0o600
        assert remote.published == []
    assert stat.S_IMODE(remote.staged.st_mode) == mode
    assert remote.published == [('/stage', '/target')]


def test_transfer_restores_the_original_group_in_shared_directories(remote):
    remote.original.st_gid = 33
    with sftp_handler.atomic_transfer_writer(remote, '/target', '/stage', replace=True):
        pass
    assert remote.staged.st_gid == 33
    assert remote.published == [('/stage', '/target')]


@pytest.mark.parametrize('setup', [
    lambda remote: setattr(remote.staged, 'st_uid', 1001),
    lambda remote: (setattr(remote.staged, 'st_gid', 1001), setattr(remote, 'chown_error', PermissionError('not a member'))),
    lambda remote: setattr(remote, 'chmod_error', OSError('setstat unsupported')),
])
def test_transfer_refuses_to_change_owner_or_group(remote, setup):
    setup(remote)
    with pytest.raises(sftp_handler.AtomicOverwriteUnavailable):
        with sftp_handler.atomic_transfer_writer(remote, '/target', '/stage', replace=True):
            pass
    assert remote.published == []
    assert remote.removed == ['/stage']


def test_exclusive_collision_never_deletes_unowned_staging_path(remote):
    remote.collision = True
    with pytest.raises(FileExistsError):
        with sftp_handler.atomic_transfer_writer(remote, '/target', '/stage', replace=True):
            pytest.fail('collided staging must never be writable')
    assert remote.removed == []
    assert remote.published == []


def test_new_destination_appearing_during_replace_is_not_overwritten(remote):
    original = remote.original
    remote.original = None
    with pytest.raises(sftp_handler.UploadConflict):
        with sftp_handler.atomic_transfer_writer(remote, '/target', '/stage', replace=True):
            remote.original = original
    assert remote.published == []
    assert remote.removed == ['/stage']


def test_ambiguous_rename_never_deletes_a_path_of_unknown_ownership(remote):
    remote.rename_error = OSError('connection lost')
    with pytest.raises(sftp_handler.AtomicOverwriteUnavailable):
        with sftp_handler.atomic_transfer_writer(remote, '/target', '/stage', replace=True):
            pass
    assert remote.removed == []


@pytest.mark.parametrize('mode', [stat.S_IFLNK | 0o777, stat.S_IFREG | 0o4600])
def test_replacement_refuses_symlinks_and_special_permissions(remote, mode):
    remote.original.st_mode = mode
    with pytest.raises((sftp_handler.FileMutationError, sftp_handler.AtomicOverwriteUnavailable)):
        with sftp_handler.atomic_transfer_writer(remote, '/target', '/stage', replace=True):
            pytest.fail('unsupported destination must not be replaced')
    assert remote.published == []


def test_server_cannot_supply_public_staging_permissions(remote):
    remote.staged.st_mode = stat.S_IFREG | 0o644
    with pytest.raises(sftp_handler.SFTPOperationError):
        with sftp_handler.atomic_transfer_writer(remote, '/target', '/stage', replace=True):
            pytest.fail('payload must not be written to public staging')
    assert remote.published == []


def test_tightened_destination_permissions_abort_before_staging_is_made_readable(remote):
    remote.original.st_mode = stat.S_IFREG | 0o644
    with pytest.raises(sftp_handler.UploadConflict):
        with sftp_handler.atomic_transfer_writer(remote, '/target', '/stage', replace=True) as writer:
            writer.write(b'new private contents')
            remote.original.st_mode = stat.S_IFREG | 0o600
    assert stat.S_IMODE(remote.staged.st_mode) == 0o600
    assert remote.published == []


def test_definitive_new_file_rename_rejection_cleans_staging(remote):
    remote.original = None
    remote.rename_error = OSError('permission denied')
    remote.rename_error.sftp_status = 3
    with pytest.raises(OSError):
        with sftp_handler.atomic_transfer_writer(remote, '/target', '/stage', replace=False):
            pass
    assert remote.removed == ['/stage']


@pytest.mark.parametrize('mode', [stat.S_IFDIR | 0o755, stat.S_IFLNK | 0o777])
def test_no_replace_reports_conflict_for_every_existing_object(remote, mode):
    remote.original.st_mode = mode
    with pytest.raises(sftp_handler.UploadConflict):
        with sftp_handler.atomic_transfer_writer(remote, '/target', '/stage', replace=False):
            pass
    assert remote.published == []


def test_new_file_uses_the_server_default_mode(remote):
    remote.original = None
    with sftp_handler.atomic_transfer_writer(remote, '/target', '/stage', replace=False) as writer:
        writer.write(b'index')
    assert remote.requested_modes == [None]
    assert stat.S_IMODE(remote.staged.st_mode) == 0o644
    assert remote.published == [('/stage', '/target')]


def test_new_file_accepts_a_forced_server_create_mode(remote):
    remote.original = None
    remote.default_mode = 0o664
    with sftp_handler.atomic_transfer_writer(remote, '/target', '/stage', replace=True):
        pass
    assert remote.requested_modes == [None]
    assert remote.published == [('/stage', '/target')]


def test_forced_create_mode_may_replace_an_equally_readable_file(remote):
    remote.original.st_mode = stat.S_IFREG | 0o644
    remote.staged.st_mode = stat.S_IFREG | 0o644
    with sftp_handler.atomic_transfer_writer(remote, '/target', '/stage', replace=True):
        pass
    assert remote.requested_modes == [0o600]
    assert stat.S_IMODE(remote.staged.st_mode) == 0o644
    assert remote.published == [('/stage', '/target')]
