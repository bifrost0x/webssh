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
        assert mode == 0o600
        if client.collision:
            raise FileExistsError(path)
        class Writer(io.BytesIO):
            def stat(self):
                return client.staged

            def chmod(self, mode):
                client.staged.st_mode = stat.S_IFREG | mode
        with Writer() as writer:
            yield writer
    monkeypatch.setattr(sftp_handler, 'open_exclusive_file', exclusive)
    return remote


@pytest.mark.parametrize('mode', [0o600, 0o640, 0o750])
def test_transfer_stays_private_until_payload_complete_and_retains_mode(remote, mode):
    remote.original.st_mode = stat.S_IFREG | mode
    with sftp_handler.atomic_transfer_writer(remote, '/target', '/stage', replace=True) as writer:
        writer.write(b'secret')
        assert stat.S_IMODE(remote.staged.st_mode) == 0o600
        assert remote.published == []
    assert stat.S_IMODE(remote.staged.st_mode) == mode
    assert remote.published == [('/stage', '/target')]


@pytest.mark.parametrize('field,value', [('st_uid', 1001), ('st_gid', 1001)])
def test_transfer_refuses_to_change_owner_or_group(remote, field, value):
    setattr(remote.staged, field, value)
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
