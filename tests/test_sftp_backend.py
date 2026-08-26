from contextlib import contextmanager
import io
import stat
import threading
from types import SimpleNamespace

import pytest

from app import sftp_handler
from app import sftp_backend
from app.file_backend import FileBackend, FileWriteOutcome
from app.file_sources import (
    FileCapability,
    FileSourceDescriptor,
    FileSourceKind,
    ResolvedFileSource,
)
from app.sftp_backend import SFTPBackend


def source(handle_id='session-a'):
    return ResolvedFileSource(
        descriptor=FileSourceDescriptor(
            source_id=f'sftp-session:{handle_id}',
            kind='sftp',
            label='operator@example.test',
            endpoint='example.test:22',
            protocol='SFTP',
            capabilities=tuple(FileCapability),
            ephemeral=False,
            security={},
        ),
        user_id='7',
        handle_id=handle_id,
        backend=SimpleNamespace(),
    )


def test_sftp_backend_implements_the_common_file_contract():
    assert isinstance(SFTPBackend(), FileBackend)


def test_stat_or_raise_preserves_sftp_permission_failure(monkeypatch):
    class DeniedSFTP:
        def lstat(self, _path):
            raise PermissionError('private server detail')

    @contextmanager
    def denied_session(_handle_id, *, io_lane='control'):
        assert io_lane == 'control'
        yield DeniedSFTP(), 'session'

    monkeypatch.setattr(sftp_handler, 'sftp_session', denied_session)

    with pytest.raises(PermissionError, match='private server detail'):
        SFTPBackend().stat_or_raise(
            source(), '/restricted.txt', follow_links=False
        )


def test_mkdir_or_raise_preserves_sftp_permission_failure(monkeypatch):
    class DeniedSFTP:
        def mkdir(self, _path):
            raise PermissionError('private server detail')

    @contextmanager
    def denied_session(_handle_id, *, io_lane='control'):
        assert io_lane == 'control'
        yield DeniedSFTP(), 'session'

    monkeypatch.setattr(sftp_handler, 'sftp_session', denied_session)

    with pytest.raises(PermissionError, match='private server detail'):
        SFTPBackend().mkdir_or_raise(source(), '/restricted')


def test_sftp_backend_delegates_listing_without_changing_path_semantics(monkeypatch):
    calls = []
    monkeypatch.setattr(
        sftp_handler,
        'list_directory',
        lambda session_id, path: calls.append((session_id, path)) or ([], None),
    )

    files, error = SFTPBackend().list_directory(source(), '/home/user')

    assert (files, error) == ([], None)
    assert calls == [('session-a', '/home/user')]


def test_sftp_backend_preserves_preview_limits_and_offsets(monkeypatch):
    calls = []

    def preview(**kwargs):
        calls.append(kwargs)
        return {'content': 'tail'}, None

    monkeypatch.setattr(sftp_handler, 'read_file_preview', preview)

    result = SFTPBackend().read_file_preview(
        source(),
        '/var/log/app.log',
        max_bytes=4096,
        offset=128,
        tail_lines=20,
    )

    assert result == ({'content': 'tail'}, None)
    assert calls == [{
        'session_id': 'session-a',
        'path': '/var/log/app.log',
        'max_bytes': 4096,
        'offset': 128,
        'tail_lines': 20,
    }]


def test_sftp_backend_preserves_editor_encoding_and_newline(monkeypatch):
    calls = []

    def write(**kwargs):
        calls.append(kwargs)
        return FileWriteOutcome(success=True, revision='a' * 64)

    monkeypatch.setattr(sftp_handler, 'write_file_text', write)

    result = SFTPBackend().write_file_text(
        source(),
        '/etc/app.conf',
        'first\nsecond',
        encoding='latin-1',
        newline='crlf',
        expected_revision='b' * 64,
    )

    assert result == FileWriteOutcome(success=True, revision='a' * 64)
    assert calls == [{
        'session_id': 'session-a',
        'path': '/etc/app.conf',
        'content_str': 'first\nsecond',
        'encoding': 'latin-1',
        'newline': 'crlf',
        'expected_revision': 'b' * 64,
    }]


def test_sftp_backend_delegates_existing_mutations(monkeypatch):
    calls = []
    monkeypatch.setattr(
        sftp_handler,
        'create_directory',
        lambda handle, path: calls.append(('mkdir', handle, path)) or (True, None),
    )
    monkeypatch.setattr(
        sftp_handler,
        'rename_item',
        lambda handle, old, new: calls.append(('rename', handle, old, new))
        or (True, None),
    )
    monkeypatch.setattr(
        sftp_handler,
        'delete_directory_recursive',
        lambda handle, path, **options: calls.append(
            ('delete', handle, path, options)
        ) or (True, None),
    )
    backend = SFTPBackend()
    resolved = source()

    assert backend.mkdir(resolved, '/new') == (True, None)
    assert backend.rename(resolved, '/old', '/new') == (True, None)
    assert backend.delete(
        resolved,
        '/old-tree',
        recursive=True,
        budget=None,
        cancel_event=None,
    ) == (True, None)
    assert calls == [
        ('mkdir', 'session-a', '/new'),
        ('rename', 'session-a', '/old', '/new'),
        ('delete', 'session-a', '/old-tree', {
            'member_budget': None,
            'cancel_event': None,
        }),
    ]


def test_sftp_backend_rejects_unsupported_replace_without_touching_sftp(monkeypatch):
    monkeypatch.setattr(
        sftp_handler,
        'rename_item',
        lambda *_args: (_ for _ in ()).throw(
            AssertionError('replace must fail before SFTP')
        ),
    )

    assert SFTPBackend().rename(
        source(),
        '/old',
        '/new',
        replace=True,
    ) == (False, 'Atomic replacement is unavailable')


def test_sftp_backend_normalizes_through_existing_sanitizer(monkeypatch):
    calls = []
    monkeypatch.setattr(
        sftp_handler,
        'sanitize_path',
        lambda path: calls.append(path) or '/normalized',
    )

    assert SFTPBackend().normalize_path('/a/./b') == '/normalized'
    assert calls == ['/a/./b']


class AtomicSFTP:
    def __init__(
        self,
        *,
        destination_exists=True,
        destination_error=None,
        replace_error=None,
    ):
        self.destination_exists = destination_exists
        self.destination_error = destination_error
        self.replace_error = replace_error
        self.opened = []
        self.replaced = []
        self.renamed = []
        self.removed = []

    def file(self, path, mode):
        self.opened.append((path, mode))
        return io.BytesIO()

    def lstat(self, _path):
        if self.destination_error is not None:
            raise self.destination_error
        if not self.destination_exists:
            raise FileNotFoundError()
        return SimpleNamespace(st_mode=stat.S_IFREG)

    def posix_rename(self, old_path, new_path):
        if self.replace_error is not None:
            raise self.replace_error
        self.replaced.append((old_path, new_path))

    def rename(self, old_path, new_path):
        self.renamed.append((old_path, new_path))

    def remove(self, path):
        self.removed.append(path)


def install_sftp_session(monkeypatch, sftp, calls=None):
    @contextmanager
    def fake_session(_handle_id, *, io_lane='control'):
        if calls is not None:
            calls.append((_handle_id, io_lane))
        yield sftp, 'session'

    monkeypatch.setattr(sftp_handler, 'sftp_session', fake_session)


def test_transfer_reader_uses_a_separate_io_lane(monkeypatch):
    calls = []
    sftp = AtomicSFTP()
    install_sftp_session(monkeypatch, sftp, calls)

    with SFTPBackend().open_reader(
        source(), '/source.txt', io_lane='transfer'
    ) as reader:
        assert reader.read() == b''

    assert calls == [('session-a', 'transfer')]


def test_atomic_writer_commits_replace_only_through_posix_rename(monkeypatch):
    sftp = AtomicSFTP()
    install_sftp_session(monkeypatch, sftp)
    monkeypatch.setattr(sftp_backend.secrets, 'token_hex', lambda _size: 'token')

    with SFTPBackend().open_atomic_writer(
        source(),
        '/target.txt',
        replace=True,
        cancel_event=threading.Event(),
    ) as writer:
        writer.write(b'replacement')

    assert sftp.opened == [('/target.txt.webssh-write-token.tmp', 'wb')]
    assert sftp.replaced == [
        ('/target.txt.webssh-write-token.tmp', '/target.txt')
    ]
    assert sftp.renamed == []
    assert sftp.removed == []


def test_atomic_writer_cancellation_removes_only_its_temporary_file(monkeypatch):
    sftp = AtomicSFTP()
    install_sftp_session(monkeypatch, sftp)
    monkeypatch.setattr(sftp_backend.secrets, 'token_hex', lambda _size: 'token')
    cancelled = threading.Event()

    with pytest.raises(sftp_handler.TransferCancelled):
        with SFTPBackend().open_atomic_writer(
            source(),
            '/target.txt',
            replace=True,
            cancel_event=cancelled,
        ) as writer:
            writer.write(b'partial')
            cancelled.set()

    assert sftp.replaced == []
    assert sftp.renamed == []
    assert sftp.removed == ['/target.txt.webssh-write-token.tmp']


def test_atomic_writer_does_not_treat_permission_error_as_missing(monkeypatch):
    sftp = AtomicSFTP(destination_error=PermissionError('denied'))
    install_sftp_session(monkeypatch, sftp)
    monkeypatch.setattr(sftp_backend.secrets, 'token_hex', lambda _size: 'token')

    with pytest.raises(PermissionError):
        with SFTPBackend().open_atomic_writer(
            source(),
            '/target.txt',
            replace=False,
            cancel_event=threading.Event(),
        ) as writer:
            writer.write(b'new')

    assert sftp.renamed == []
    assert sftp.removed == ['/target.txt.webssh-write-token.tmp']


class TreeSFTP:
    def __init__(self):
        self.listed = []
        self.entries = {
            '/root': [
                SimpleNamespace(filename='folder'),
                SimpleNamespace(filename='link'),
            ],
            '/root/folder': [SimpleNamespace(filename='file.txt')],
        }
        self.stats = {
            '/root/folder': SimpleNamespace(st_mode=stat.S_IFDIR, st_size=0),
            '/root/link': SimpleNamespace(st_mode=stat.S_IFLNK, st_size=0),
            '/root/folder/file.txt': SimpleNamespace(
                st_mode=stat.S_IFREG,
                st_size=7,
            ),
        }

    def listdir_iter(self, path):
        self.listed.append(path)
        return iter(self.entries[path])

    def lstat(self, path):
        return self.stats[path]


class MemberBudget:
    def __init__(self, limit):
        self.limit = limit
        self.used = 0

    def consume(self):
        self.used += 1
        if self.used > self.limit:
            raise sftp_handler.TransferMemberLimitExceeded()


def test_iter_tree_is_bounded_and_never_follows_symlinks(monkeypatch):
    sftp = TreeSFTP()
    install_sftp_session(monkeypatch, sftp)
    budget = MemberBudget(3)

    entries = list(SFTPBackend().iter_tree(
        source(),
        '/root',
        budget=budget,
        cancel_event=threading.Event(),
    ))

    assert [entry['path'] for entry in entries] == [
        '/root/folder',
        '/root/folder/file.txt',
        '/root/link',
    ]
    assert entries[-1]['is_symlink'] is True
    assert sftp.listed == ['/root', '/root/folder']
    assert budget.used == 3


def test_iter_tree_rejects_limit_plus_one(monkeypatch):
    sftp = TreeSFTP()
    install_sftp_session(monkeypatch, sftp)

    with pytest.raises(sftp_handler.TransferMemberLimitExceeded):
        list(SFTPBackend().iter_tree(
            source(),
            '/root',
            budget=MemberBudget(2),
            cancel_event=threading.Event(),
        ))


def test_iter_tree_checks_cancellation_before_remote_listing(monkeypatch):
    sftp = TreeSFTP()
    install_sftp_session(monkeypatch, sftp)
    cancelled = threading.Event()
    cancelled.set()

    with pytest.raises(sftp_handler.TransferCancelled):
        list(SFTPBackend().iter_tree(
            source(),
            '/root',
            budget=MemberBudget(3),
            cancel_event=cancelled,
        ))
    assert sftp.listed == []
