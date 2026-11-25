import os
import stat
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture(autouse=True)
def exclusive_transfer_file_stub(monkeypatch):
    from app import sftp_handler

    @contextmanager
    def exclusive_file(client, path, *, mode=0o600):
        assert mode in (0o600, None)
        with client.open(path, 'wb') as remote:
            yield remote
    monkeypatch.setattr(sftp_handler, 'open_exclusive_file', exclusive_file)


class BoundedReader:
    def __init__(self, payload):
        self.payload = payload
        self.offset = 0
        self.read_sizes = []

    def read(self, size=-1):
        if size is None or size < 0:
            raise AssertionError('unbounded read')
        self.read_sizes.append(size)
        chunk = self.payload[self.offset:self.offset + size]
        self.offset += len(chunk)
        return chunk

    def stat(self):
        return SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_size=len(self.payload),
            st_mtime=1,
        )

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class FallbackSFTP:
    def __init__(self, files):
        self.files = files
        self.readers = []

    def listdir_attr(self, path):
        prefix = path.rstrip('/') + '/'
        result = []
        for name, payload in self.files.items():
            if name.startswith(prefix) and '/' not in name[len(prefix):]:
                result.append(SimpleNamespace(
                    filename=name[len(prefix):],
                    st_mode=stat.S_IFREG,
                    st_size=len(payload),
                ))
        return result

    def lstat(self, path):
        return SimpleNamespace(st_mode=stat.S_IFREG, st_size=len(self.files[path]))

    def file(self, path, _mode):
        reader = BoundedReader(self.files[path])
        self.readers.append(reader)
        return reader


def test_socket_cancel_returns_authoritative_state_and_emits_terminal_once(
    app, monkeypatch,
):
    import app.socket_events as socket_events
    from app.transfer_manager import TransferManager

    manager = TransferManager()
    record = manager.create(7, 'sftp-session:owned', 'download', {})
    emitted = []
    monkeypatch.setattr(socket_events, 'transfer_manager', manager)
    monkeypatch.setattr(
        socket_events.socketio,
        'emit',
        lambda event, payload, **kwargs: emitted.append(
            (event, payload, kwargs)
        ),
    )
    user = SimpleNamespace(id=7)

    with app.test_request_context('/socket.io'):
        first = socket_events.handle_cancel_transfer.__wrapped__(
            {'transfer_id': record.transfer_id}, current_user=user
        )
        second = socket_events.handle_cancel_transfer.__wrapped__(
            {'transfer_id': record.transfer_id}, current_user=user
        )

    assert first == {'success': True, 'state': 'cancelled'}
    assert second == {'success': True, 'state': 'cancelled'}
    assert emitted == [(
        'transfer_finished',
        {'transfer_id': record.transfer_id, 'status': 'cancelled'},
        {'room': 'user_7'},
    )]

    completed = manager.create(7, 'sftp-session:owned', 'download', {})
    manager.consume_token(completed.token, 7)
    manager.complete(completed.transfer_id, 7)
    with app.test_request_context('/socket.io'):
        terminal = socket_events.handle_cancel_transfer.__wrapped__(
            {'transfer_id': completed.transfer_id}, current_user=user
        )
        foreign = socket_events.handle_cancel_transfer.__wrapped__(
            {'transfer_id': record.transfer_id},
            current_user=SimpleNamespace(id=8),
        )

    assert terminal == {'success': True, 'state': 'completed'}
    assert foreign == {'success': False, 'state': 'unavailable'}
    assert len(emitted) == 1

    running = manager.create(7, 'sftp-session:owned', 'download', {})
    manager.consume_token(running.token, 7)
    with app.test_request_context('/socket.io'):
        first_running = socket_events.handle_cancel_transfer.__wrapped__(
            {'transfer_id': running.transfer_id}, current_user=user
        )
        second_running = socket_events.handle_cancel_transfer.__wrapped__(
            {'transfer_id': running.transfer_id}, current_user=user
        )

    assert first_running == {'success': True, 'state': 'cancelling'}
    assert second_running == {'success': True, 'state': 'cancelling'}
    assert len(emitted) == 1

    from app.transfer_routes import _terminalize
    assert _terminalize(
        running, 7, 'cancelled', manager=manager
    ) is True
    assert emitted[-1] == (
        'transfer_finished',
        {
            'transfer_id': running.transfer_id,
            'direction': 'download',
            'status': 'cancelled',
        },
        {'room': 'user_7'},
    )


class EmptyDirectorySFTP:
    def listdir_attr(self, path):
        if path == '/reports':
            return [
                SimpleNamespace(
                    filename=f'directory-{index}', st_mode=stat.S_IFDIR,
                    st_size=0,
                )
                for index in range(20)
            ]
        return []

    def lstat(self, _path):
        return SimpleNamespace(st_mode=stat.S_IFDIR, st_size=0)


class ManyZeroFilesSFTP:
    def __init__(self, count):
        self.count = count

    def listdir_attr(self, path):
        if path != '/reports':
            return []
        return [
            SimpleNamespace(
                filename=f'empty-{index}.txt',
                st_mode=stat.S_IFREG,
                st_size=0,
            )
            for index in range(self.count)
        ]

    def lstat(self, _path):
        return SimpleNamespace(st_mode=stat.S_IFREG, st_size=0)

    def file(self, _path, _mode):
        return BoundedReader(b'')


class CleanupDirectoryIterator:
    """Iterator that makes eager or over-budget cleanup observable."""

    def __init__(self, entries, *, fail_after=None):
        self._entries = iter(entries)
        self.fail_after = fail_after
        self.consumed = 0
        self.closed = False

    def __iter__(self):
        return self

    def __next__(self):
        if self.fail_after is not None and self.consumed >= self.fail_after:
            raise AssertionError('cleanup consumed an entry beyond its budget')
        entry = next(self._entries)
        self.consumed += 1
        return entry

    def close(self):
        self.closed = True


class CleanupSFTP:
    """Minimal remote tree whose listings are streamed and inspectable."""

    def __init__(self, listings, modes):
        self.listings = listings
        self.modes = modes
        self.iterators = []
        self.removed = []
        self.removed_dirs = []
        self.listed = []
        self.lstat_calls = []

    def listdir_iter(self, path):
        self.listed.append(path)
        iterator = self.listings[path]
        self.iterators.append(iterator)
        return iterator

    def lstat(self, path):
        self.lstat_calls.append(path)
        return SimpleNamespace(st_mode=self.modes[path])

    def remove(self, path):
        self.removed.append(path)

    def rmdir(self, path):
        self.removed_dirs.append(path)


def cleanup_entry(name, mode):
    return SimpleNamespace(filename=name, st_mode=mode, st_size=0, st_mtime=0)


@contextmanager
def cleanup_sftp_session(sftp):
    yield sftp, 'session'


def test_directory_listing_allows_exact_configured_member_limit(monkeypatch):
    import app.sftp_handler as sftp_handler

    iterator = CleanupDirectoryIterator([cleanup_entry('visible.txt', stat.S_IFREG)])
    sftp = CleanupSFTP(
        {'/remote': iterator},
        {'/remote/visible.txt': stat.S_IFREG},
    )
    monkeypatch.setattr(sftp_handler.config, 'MAX_TRANSFER_MEMBERS', 1)
    monkeypatch.setattr(
        sftp_handler,
        'sftp_session',
        lambda _session_id, **_kwargs: cleanup_sftp_session(sftp),
    )

    listing, error = sftp_handler.open_directory_listing('session', '/remote')
    assert error is None
    files, error, has_more = listing.read_page(10)

    assert error is None
    assert has_more is False
    assert [file['name'] for file in files] == ['visible.txt']
    assert iterator.consumed == 1
    assert iterator.closed is True


def test_directory_listing_rejects_limit_plus_one_without_appending_probe(monkeypatch):
    import app.sftp_handler as sftp_handler

    iterator = CleanupDirectoryIterator([
        cleanup_entry('visible.txt', stat.S_IFREG),
        cleanup_entry('probe.txt', stat.S_IFREG),
    ])
    sftp = CleanupSFTP(
        {'/remote': iterator},
        {
            '/remote/visible.txt': stat.S_IFREG,
            '/remote/probe.txt': stat.S_IFREG,
        },
    )
    monkeypatch.setattr(sftp_handler.config, 'MAX_TRANSFER_MEMBERS', 1)
    monkeypatch.setattr(
        sftp_handler,
        'sftp_session',
        lambda _session_id, **_kwargs: cleanup_sftp_session(sftp),
    )

    listing, error = sftp_handler.open_directory_listing('session', '/remote')
    assert error is None
    files, error, has_more = listing.read_page(10)

    assert files is None
    assert has_more is False
    assert error == 'Directory exceeds configured member limit'
    assert iterator.consumed == 2
    assert iterator.closed is True


def test_recursive_delete_allows_exact_configured_member_limit(monkeypatch):
    import app.sftp_handler as sftp_handler

    root_iterator = CleanupDirectoryIterator([cleanup_entry('first.txt', stat.S_IFREG)])
    sftp = CleanupSFTP(
        {'/remote': root_iterator},
        {
            '/remote': stat.S_IFDIR,
            '/remote/first.txt': stat.S_IFREG,
        },
    )
    monkeypatch.setattr(sftp_handler.config, 'MAX_TRANSFER_MEMBERS', 1)
    monkeypatch.setattr(
        sftp_handler, 'sftp_session', lambda _session_id: cleanup_sftp_session(sftp)
    )

    success, error = sftp_handler.delete_directory_recursive('session', '/remote')

    assert success is True
    assert error is None
    assert root_iterator.consumed == 1
    assert root_iterator.closed is True
    assert sftp.removed == ['/remote/first.txt']
    assert sftp.removed_dirs == ['/remote']


def test_recursive_delete_rejects_limit_plus_one_without_processing_probe(monkeypatch):
    import app.sftp_handler as sftp_handler

    root_iterator = CleanupDirectoryIterator([
        cleanup_entry('first.txt', stat.S_IFREG),
        cleanup_entry('probe.txt', stat.S_IFREG),
    ])
    sftp = CleanupSFTP(
        {'/remote': root_iterator},
        {
            '/remote': stat.S_IFDIR,
            '/remote/first.txt': stat.S_IFREG,
            '/remote/probe.txt': stat.S_IFREG,
        },
    )
    monkeypatch.setattr(sftp_handler.config, 'MAX_TRANSFER_MEMBERS', 1)
    monkeypatch.setattr(
        sftp_handler, 'sftp_session', lambda _session_id: cleanup_sftp_session(sftp)
    )

    success, error = sftp_handler.delete_directory_recursive('session', '/remote')

    assert success is False
    assert error == 'Directory exceeds configured member limit'
    assert root_iterator.consumed == 2
    assert root_iterator.closed is True
    assert sftp.removed == ['/remote/first.txt']
    assert sftp.lstat_calls == ['/remote', '/remote/first.txt']
    assert sftp.removed_dirs == []


def test_recursive_delete_stops_before_remote_mutation_when_cancelled(monkeypatch):
    import app.sftp_handler as sftp_handler

    root_iterator = CleanupDirectoryIterator([
        cleanup_entry('first.txt', stat.S_IFREG),
    ])
    sftp = CleanupSFTP(
        {'/remote': root_iterator},
        {
            '/remote': stat.S_IFDIR,
            '/remote/first.txt': stat.S_IFREG,
        },
    )
    cancelled = threading.Event()
    cancelled.set()
    monkeypatch.setattr(
        sftp_handler,
        'sftp_session',
        lambda _session_id: cleanup_sftp_session(sftp),
    )

    success, error = sftp_handler.delete_directory_recursive(
        'session',
        '/remote',
        cancel_event=cancelled,
    )

    assert success is False
    assert error == 'Operation cancelled'
    assert root_iterator.consumed == 0
    assert sftp.removed == []
    assert sftp.removed_dirs == []


def _zip_source(monkeypatch, sftp):
    """Resolved SFTP source whose sessions are served by ``sftp``."""
    from app import sftp_handler
    from app.sftp_backend import SFTPBackend

    @contextmanager
    def fake_session(_session_id, io_lane='control'):
        yield sftp, 'session'

    monkeypatch.setattr(sftp_handler, 'sftp_session', fake_session)
    return SimpleNamespace(handle_id='session', backend=SFTPBackend())


def test_folder_zip_uses_disk_and_bounded_remote_reads(tmp_path, monkeypatch):
    from app.transfer_routes import _build_backend_zip_to_disk

    sftp = FallbackSFTP({'/reports/a.txt': b'a' * 9})
    archive = _build_backend_zip_to_disk(
        _zip_source(monkeypatch, sftp),
        '/reports',
        'reports',
        cancel_event=threading.Event(),
        max_bytes=1024,
        chunk_size=4,
        temp_dir=tmp_path,
    )

    try:
        assert isinstance(archive, Path)
        assert archive.parent == tmp_path
        assert archive.is_file()
        assert max(sftp.readers[0].read_sizes) == 4
    finally:
        os.unlink(archive)


def test_folder_zip_cancellation_removes_temporary_archive(tmp_path, monkeypatch):
    from app.remote_transfer import RemoteTransferCancelled
    from app.transfer_routes import _build_backend_zip_to_disk

    cancelled = threading.Event()

    class CancellingReader(BoundedReader):
        def read(self, size=-1):
            chunk = super().read(size)
            cancelled.set()
            return chunk

    class CancellingSFTP(FallbackSFTP):
        def file(self, path, _mode):
            reader = CancellingReader(self.files[path])
            self.readers.append(reader)
            return reader

    sftp = CancellingSFTP({'/reports/a.txt': b'a' * 9})

    with pytest.raises(RemoteTransferCancelled):
        _build_backend_zip_to_disk(
            _zip_source(monkeypatch, sftp),
            '/reports',
            'reports',
            cancel_event=cancelled,
            max_bytes=1024,
            chunk_size=4,
            temp_dir=tmp_path,
        )

    assert sftp.readers[0].read_sizes == [4]
    assert list(tmp_path.iterdir()) == []


def test_empty_directory_entries_cannot_exceed_reserved_zip_bytes(
        tmp_path, monkeypatch):
    from app.remote_transfer import RemoteTransferLimitExceeded
    from app.transfer_routes import _build_backend_zip_to_disk

    with pytest.raises(RemoteTransferLimitExceeded):
        _build_backend_zip_to_disk(
            _zip_source(monkeypatch, EmptyDirectorySFTP()),
            '/reports',
            'reports',
            cancel_event=threading.Event(),
            max_bytes=64,
            chunk_size=4,
            temp_dir=tmp_path,
        )

    assert list(tmp_path.iterdir()) == []


def test_remote_tree_counts_zero_byte_members(monkeypatch):
    from app import sftp_handler
    from app.remote_transfer import TransferBudget

    monkeypatch.setattr(sftp_handler.config, 'MAX_TRANSFER_MEMBERS', 3)
    source = _zip_source(monkeypatch, ManyZeroFilesSFTP(4))

    with pytest.raises(sftp_handler.TransferMemberLimitExceeded):
        list(source.backend.iter_tree(
            source,
            '/reports',
            budget=TransferBudget(max_bytes=1, max_members=3),
            cancel_event=threading.Event(),
        ))


def test_remote_tree_closes_paramiko_directory_handle_on_member_rejection(
        monkeypatch):
    import paramiko
    from paramiko.message import Message
    from paramiko.sftp import CMD_CLOSE, CMD_HANDLE, CMD_NAME, CMD_OPENDIR, CMD_READDIR
    from paramiko.sftp_attr import SFTPAttributes
    from app import sftp_handler
    from app.remote_transfer import TransferBudget

    class ProtocolSFTP(paramiko.SFTPClient):
        def __init__(self):
            self.requests = []

        def _adjust_cwd(self, path):
            return path

        def _log(self, *_args):
            pass

        def _request(self, command, *args):
            self.requests.append((command, args))
            message = Message()
            if command == CMD_OPENDIR:
                message.add_string(b'directory-handle')
                message.rewind()
                return CMD_HANDLE, message
            if command == CMD_READDIR:
                message.add_int(2)
                for filename in ('first.txt', 'second.txt'):
                    message.add_string(filename)
                    message.add_string(filename)
                    attributes = SFTPAttributes()
                    attributes.st_mode = stat.S_IFREG
                    attributes.st_size = 0
                    attributes._pack(message)
                message.rewind()
                return CMD_NAME, message
            if command == CMD_CLOSE:
                return 0, message
            raise AssertionError(f'unexpected SFTP command {command}')

        def lstat(self, _path):
            return SimpleNamespace(st_mode=stat.S_IFREG, st_size=0)

    sftp = ProtocolSFTP()
    monkeypatch.setattr(sftp_handler.config, 'MAX_TRANSFER_MEMBERS', 1)
    source = _zip_source(monkeypatch, sftp)

    with pytest.raises(sftp_handler.TransferMemberLimitExceeded):
        list(source.backend.iter_tree(
            source,
            '/reports',
            budget=TransferBudget(max_bytes=1, max_members=1),
            cancel_event=threading.Event(),
        ))

    assert [command for command, _args in sftp.requests].count(CMD_CLOSE) == 1


def test_folder_zip_counts_zero_byte_members(tmp_path, monkeypatch):
    from app import sftp_handler
    from app.transfer_routes import _build_backend_zip_to_disk

    monkeypatch.setattr(sftp_handler.config, 'MAX_TRANSFER_MEMBERS', 3)

    with pytest.raises(sftp_handler.TransferMemberLimitExceeded):
        _build_backend_zip_to_disk(
            _zip_source(monkeypatch, ManyZeroFilesSFTP(4)),
            '/reports',
            'reports',
            cancel_event=threading.Event(),
            max_bytes=1024,
            chunk_size=4,
            temp_dir=tmp_path,
        )

    assert list(tmp_path.iterdir()) == []


class _PathBackend:
    @staticmethod
    def normalize_path(path):
        if isinstance(path, str) and path.startswith('/') and '..' not in path:
            return path
        return None


def _allow_s2s_sources(monkeypatch, socket_events, calls=None):
    from app.file_sources import SourceHoldSet

    backend = _PathBackend()
    monkeypatch.setattr(
        socket_events.file_service,
        'resolve',
        lambda source_id, _user_id, capability: (
            calls.append((source_id, capability.value)) if calls is not None else None
        ) or SimpleNamespace(
            source_id=source_id,
            handle_id=source_id.split(':', 1)[1],
            backend=backend,
        ),
    )
    monkeypatch.setattr(
        socket_events.file_source_resolver,
        'acquire_transfer_holds',
        lambda _user_id, source_ids: SourceHoldSet(tuple(source_ids)),
    )


def test_server_copy_socket_lifecycle_releases_job_and_transfer(
        app, monkeypatch):
    import app.socket_events as socket_events
    from app.transfer_manager import TransferManager

    class Reservation:
        released = False

        def release(self):
            self.released = True

    reservation = Reservation()
    quota = SimpleNamespace(reserve=lambda *_args, **_kwargs: reservation)
    manager = TransferManager()

    class ImmediateLifecycle:
        def start_job(self, _name, target, *, owner_id=None):
            del owner_id
            cancel_event = threading.Event()
            target(cancel_event)
            return SimpleNamespace(cancel_event=cancel_event)

    observed = {}

    def copy(*_args, **kwargs):
        observed.update(kwargs)
        return SimpleNamespace(bytes_transferred=0)

    resolve_calls = []
    _allow_s2s_sources(monkeypatch, socket_events, resolve_calls)
    monkeypatch.setattr(socket_events, 'transfer_manager', manager)
    monkeypatch.setattr(socket_events, 'quota_manager', quota)
    monkeypatch.setattr(socket_events, 'copy_remote_entry', copy)
    monkeypatch.setitem(
        app.extensions, 'runtime_lifecycle', ImmediateLifecycle()
    )

    user = SimpleNamespace(id=7, username='copy-user')
    with app.test_request_context('/socket.io'):
        result = socket_events.handle_transfer_server_to_server.__wrapped__({
            'source_id': 'sftp-session:source',
            'request_id': 's2s:test',
            'source_path': '/from.bin',
            'destination_source_id': 'sftp-session:destination',
            'dest_path': '/to.bin',
            'is_dir': False,
        }, current_user=user)

    assert result['success'] is True
    assert observed['cancel_event'] is not None
    assert observed['chunk_size'] > 0
    assert reservation.released is True
    assert manager._records == {}
    assert resolve_calls == [
        ('sftp-session:source', 'read'),
        ('sftp-session:source', 'remote-transfer'),
        ('sftp-session:destination', 'write'),
        ('sftp-session:destination', 'remote-transfer'),
        ('sftp-session:source', 'read'),
        ('sftp-session:source', 'remote-transfer'),
        ('sftp-session:destination', 'write'),
        ('sftp-session:destination', 'remote-transfer'),
    ]


def test_server_copy_completion_identifies_transferred_item(app, monkeypatch):
    import app.socket_events as socket_events
    from app.transfer_manager import TransferManager

    class Reservation:
        def release(self):
            pass

    class ImmediateLifecycle:
        def start_job(self, _name, target, *, owner_id=None):
            del owner_id
            target(threading.Event())
            return SimpleNamespace()

    emitted = []
    _allow_s2s_sources(monkeypatch, socket_events)
    monkeypatch.setattr(socket_events, 'transfer_manager', TransferManager())
    monkeypatch.setattr(
        socket_events, 'quota_manager',
        SimpleNamespace(reserve=lambda *_args, **_kwargs: Reservation()),
    )
    monkeypatch.setattr(
        socket_events, 'copy_remote_entry',
        lambda *_args, **_kwargs: SimpleNamespace(bytes_transferred=0),
    )
    monkeypatch.setattr(
        socket_events.socketio, 'emit',
        lambda event, payload, room=None: emitted.append((event, payload, room)),
    )
    monkeypatch.setitem(app.extensions, 'runtime_lifecycle', ImmediateLifecycle())

    user = SimpleNamespace(id=7, username='copy-user')
    with app.test_request_context('/socket.io'):
        result = socket_events.handle_transfer_server_to_server.__wrapped__({
            'source_id': 'sftp-session:source',
            'request_id': 's2s:test',
            'source_path': '/reports/report.txt',
            'destination_source_id': 'sftp-session:destination',
            'dest_path': '/archive/report.txt',
            'is_dir': False,
        }, current_user=user)

    assert result['success'] is True
    complete = next(
        payload for event, payload, _room in emitted
        if event == 's2s_transfer_complete'
    )
    assert complete['filename'] == 'report.txt'


def test_backend_copy_cancellation_audits_progressed_bytes(app, monkeypatch):
    import app.socket_events as socket_events
    from app.file_sources import SourceHoldSet
    from app.remote_transfer import RemoteTransferCancelled
    from app.transfer_manager import TransferManager

    class Reservation:
        def release(self):
            pass

    class ImmediateLifecycle:
        def start_job(self, _name, target, *, owner_id=None):
            del owner_id
            target(threading.Event())
            return SimpleNamespace()

    class Backend:
        @staticmethod
        def normalize_path(path):
            return path

    backend = Backend()
    sources = {
        'smb-quick:source': SimpleNamespace(
            source_id='smb-quick:source',
            handle_id='source',
            backend=backend,
        ),
        'smb-quick:destination': SimpleNamespace(
            source_id='smb-quick:destination',
            handle_id='destination',
            backend=backend,
        ),
    }
    audits = []

    monkeypatch.setattr(
        socket_events.file_service,
        'resolve',
        lambda source_id, _user_id, _capability: sources[source_id],
    )
    monkeypatch.setattr(
        socket_events.file_source_resolver,
        'acquire_transfer_holds',
        lambda _user_id, source_ids: SourceHoldSet(tuple(source_ids)),
    )
    monkeypatch.setattr(socket_events, 'transfer_manager', TransferManager())
    monkeypatch.setattr(
        socket_events,
        'quota_manager',
        SimpleNamespace(reserve=lambda *_args, **_kwargs: Reservation()),
    )
    monkeypatch.setattr(
        socket_events,
        'file_source_audit_identity',
        lambda source: {
            'source_kind': 'smb',
            'target_host': f'{source.handle_id}.example.test',
            'share': 'Docs',
        },
    )
    monkeypatch.setattr(
        socket_events,
        'log_file_source_operation',
        lambda **fields: audits.append(fields),
    )

    def cancel_after_progress(*_args, progress, **_kwargs):
        progress({
            'transferred': 37,
            'file_size': 100,
            'path': '/from.bin',
        })
        raise RemoteTransferCancelled('cancelled')

    monkeypatch.setattr(socket_events, 'copy_remote_entry', cancel_after_progress)
    monkeypatch.setattr(socket_events.socketio, 'emit', lambda *_args, **_kwargs: None)
    monkeypatch.setitem(app.extensions, 'runtime_lifecycle', ImmediateLifecycle())

    user = SimpleNamespace(id=7, username='copy-user')
    with app.test_request_context('/socket.io'):
        result = socket_events.handle_transfer_server_to_server.__wrapped__({
            'source_id': 'smb-quick:source',
            'request_id': 's2s:test',
            'source_path': '/from.bin',
            'destination_source_id': 'smb-quick:destination',
            'dest_path': '/to.bin',
            'is_dir': False,
        }, current_user=user)

    assert result['success'] is True
    assert [(entry['result'], entry['size']) for entry in audits] == [
        ('CANCELLED', 37),
    ]


def test_backend_copy_permission_failure_keeps_structured_terminal_reason(
        app, monkeypatch):
    import app.socket_events as socket_events
    from app.file_sources import SourceHoldSet
    from app.transfer_manager import TransferManager

    class Reservation:
        def release(self):
            pass

    class ImmediateLifecycle:
        def start_job(self, _name, target, *, owner_id=None):
            del owner_id
            target(threading.Event())
            return SimpleNamespace()

    class Backend:
        @staticmethod
        def normalize_path(path):
            return path

    backend = Backend()
    sources = {
        source_id: SimpleNamespace(
            source_id=source_id,
            handle_id=source_id.rsplit(':', 1)[-1],
            backend=backend,
        )
        for source_id in ('smb-quick:source', 'smb-quick:destination')
    }
    monkeypatch.setattr(
        socket_events.file_service,
        'resolve',
        lambda source_id, _user_id, _capability: sources[source_id],
    )
    monkeypatch.setattr(
        socket_events.file_source_resolver,
        'acquire_transfer_holds',
        lambda _user_id, source_ids: SourceHoldSet(tuple(source_ids)),
    )
    monkeypatch.setattr(socket_events, 'transfer_manager', TransferManager())
    monkeypatch.setattr(
        socket_events,
        'quota_manager',
        SimpleNamespace(reserve=lambda *_args, **_kwargs: Reservation()),
    )
    observed = {}

    def denied_copy(*_args, **kwargs):
        observed.update(kwargs)
        raise PermissionError(r'private \\server\share')

    monkeypatch.setattr(socket_events, 'copy_remote_entry', denied_copy)
    monkeypatch.setattr(
        socket_events, 'file_source_audit_identity',
        lambda source: {
            'source_kind': 'smb',
            'target_host': f'{source.handle_id}.example.test',
            'share': 'Docs',
        },
    )
    emitted = []
    monkeypatch.setattr(
        socket_events.socketio,
        'emit',
        lambda event, payload, room=None: emitted.append((event, payload, room)),
    )
    monkeypatch.setitem(app.extensions, 'runtime_lifecycle', ImmediateLifecycle())

    user = SimpleNamespace(id=7, username='copy-user')
    with app.test_request_context('/socket.io'):
        result = socket_events.handle_transfer_server_to_server.__wrapped__({
            'source_id': 'smb-quick:source',
            'request_id': 's2s:permission',
            'source_path': '/from.bin',
            'destination_source_id': 'smb-quick:destination',
            'dest_path': '/to.bin',
            'is_dir': False,
        }, current_user=user)

    assert result['success'] is True
    expected = {
        'error_code': 'PERMISSION_DENIED',
        'error': 'Permission denied for this file operation.',
        'retryable': False,
    }
    terminal = next(
        payload for event, payload, _room in emitted
        if event == 'transfer_finished'
    )
    visible = next(
        payload for event, payload, _room in emitted
        if event == 's2s_transfer_error'
    )
    assert terminal['status'] == 'failed'
    assert {key: terminal[key] for key in expected} == expected
    assert {key: visible[key] for key in expected} == expected
    assert observed['conflict_policy'] == 'error'
    assert 'private' not in repr(emitted)


def test_combined_cancellation_wait_observes_runtime_shutdown():
    """Waiting only on user cancellation hides an app lifecycle shutdown."""
    import app.socket_events as socket_events

    user_cancel = threading.Event()
    lifecycle_cancel = threading.Event()
    combined = socket_events._CombinedCancellation(
        user_cancel, lifecycle_cancel
    )
    trigger = threading.Timer(0.02, lifecycle_cancel.set)
    trigger.start()
    try:
        assert combined.wait(0.5) is True
    finally:
        trigger.cancel()


def test_server_copy_observes_lifecycle_shutdown_cancellation(app, monkeypatch):
    """Lifecycle shutdown must reach an in-flight S2S copy beside user cancellation."""
    import app.socket_events as socket_events
    from app.remote_transfer import RemoteTransferCancelled
    from app.transfer_manager import TransferManager

    class Reservation:
        release_calls = 0

        def release(self):
            self.release_calls += 1

    class ImmediateLifecycle:
        def start_job(self, _name, target, *, owner_id=None):
            del owner_id
            cancelled = threading.Event()
            cancelled.set()
            target(cancelled)
            return SimpleNamespace(cancel_event=cancelled)

    reservation = Reservation()
    observed = {}
    manager = TransferManager()
    _allow_s2s_sources(monkeypatch, socket_events)
    monkeypatch.setattr(socket_events, 'transfer_manager', manager)
    monkeypatch.setattr(
        socket_events, 'quota_manager',
        SimpleNamespace(reserve=lambda *_args, **_kwargs: reservation),
    )
    def cancelled_copy(*_args, **kwargs):
        observed.update(kwargs)
        raise RemoteTransferCancelled('Transfer cancelled')

    monkeypatch.setattr(socket_events, 'copy_remote_entry', cancelled_copy)
    monkeypatch.setitem(app.extensions, 'runtime_lifecycle', ImmediateLifecycle())

    user = SimpleNamespace(id=7, username='copy-user')
    with app.test_request_context('/socket.io'):
        result = socket_events.handle_transfer_server_to_server.__wrapped__({
            'source_id': 'sftp-session:source',
            'request_id': 's2s:test',
            'source_path': '/from.bin',
            'destination_source_id': 'sftp-session:destination',
            'dest_path': '/to.bin',
        }, current_user=user)

    assert result['success'] is True
    assert observed['cancel_event'].is_set()
    assert reservation.release_calls == 1
    assert manager._records == {}


def test_active_server_copy_finishes_as_cancelled(app, monkeypatch):
    """A running copy worker must preserve cancellation after the ack."""
    import app.socket_events as socket_events
    from app.remote_transfer import RemoteTransferCancelled
    from app.transfer_manager import TransferManager

    class Reservation:
        release_calls = 0

        def release(self):
            self.release_calls += 1

    class ThreadLifecycle:
        def __init__(self):
            self.thread = None

        def start_job(self, _name, target, *, owner_id=None):
            del owner_id
            lifecycle_cancel = threading.Event()
            self.thread = threading.Thread(
                target=target,
                args=(lifecycle_cancel,),
            )
            self.thread.start()
            return SimpleNamespace(cancel_event=lifecycle_cancel)

    reservation = Reservation()
    lifecycle = ThreadLifecycle()
    manager = TransferManager()
    started = threading.Event()
    emitted = []

    def cancelled_copy(*_args, **kwargs):
        started.set()
        assert kwargs['cancel_event'].wait(1)
        raise RemoteTransferCancelled('Transfer cancelled')

    _allow_s2s_sources(monkeypatch, socket_events)
    monkeypatch.setattr(socket_events, 'transfer_manager', manager)
    monkeypatch.setattr(
        socket_events,
        'quota_manager',
        SimpleNamespace(reserve=lambda *_args, **_kwargs: reservation),
    )
    monkeypatch.setattr(socket_events, 'copy_remote_entry', cancelled_copy)
    monkeypatch.setattr(
        socket_events.socketio,
        'emit',
        lambda event, payload, room=None: emitted.append(
            (event, payload, room)
        ),
    )
    monkeypatch.setitem(app.extensions, 'runtime_lifecycle', lifecycle)

    user = SimpleNamespace(id=7, username='copy-user')
    with app.test_request_context('/socket.io'):
        result = socket_events.handle_transfer_server_to_server.__wrapped__({
            'source_id': 'sftp-session:source',
            'request_id': 's2s:cancel',
            'source_path': '/from.bin',
            'destination_source_id': 'sftp-session:destination',
            'dest_path': '/to.bin',
            'is_dir': False,
        }, current_user=user)

    assert result['success'] is True
    assert started.wait(1)
    cancellation = manager.cancel_with_result(result['transfer_id'], user.id)
    assert cancellation.accepted is True
    assert cancellation.state == 'cancelling'
    lifecycle.thread.join(timeout=1)
    assert lifecycle.thread.is_alive() is False

    terminal = next(
        payload for event, payload, _room in emitted
        if event == 'transfer_finished'
    )
    visible = next(
        payload for event, payload, _room in emitted
        if event == 's2s_transfer_error'
    )
    assert terminal['status'] == 'cancelled'
    assert terminal['error_code'] == 'CANCELLED'
    assert visible['error_code'] == 'CANCELLED'
    assert manager.cancel_with_result(
        result['transfer_id'], user.id
    ).state == 'cancelled'
    assert reservation.release_calls == 1


def test_server_copy_runs_on_the_app_lifecycle_executor(app, monkeypatch):
    """Replacing lifecycle submission with a request-thread copy blocks Socket.IO."""
    import app.socket_events as socket_events
    from app.transfer_manager import TransferManager

    class Reservation:
        release_calls = 0

        def release(self):
            self.release_calls += 1

    reservation = Reservation()
    manager = TransferManager()
    started = threading.Event()
    release = threading.Event()
    observed = {}

    def copy(*_args, **kwargs):
        observed.update(kwargs)
        observed['thread_name'] = threading.current_thread().name
        started.set()
        assert release.wait(1)
        return SimpleNamespace(bytes_transferred=0)

    _allow_s2s_sources(monkeypatch, socket_events)
    monkeypatch.setattr(socket_events, 'transfer_manager', manager)
    monkeypatch.setattr(
        socket_events, 'quota_manager',
        SimpleNamespace(reserve=lambda *_args, **_kwargs: reservation),
    )
    monkeypatch.setattr(socket_events, 'copy_remote_entry', copy)

    user = SimpleNamespace(id=7, username='copy-user')
    with app.test_request_context('/socket.io'):
        result = socket_events.handle_transfer_server_to_server.__wrapped__({
            'source_id': 'sftp-session:source',
            'request_id': 's2s:test',
            'source_path': '/from.bin',
            'destination_source_id': 'sftp-session:destination',
            'dest_path': '/to.bin',
        }, current_user=user)

    try:
        assert result['success'] is True
        assert started.wait(1)
        assert observed['thread_name'].startswith('webssh-runtime')
    finally:
        release.set()

    deadline = time.monotonic() + 1
    while manager._records and time.monotonic() < deadline:
        time.sleep(0.01)
    assert reservation.release_calls == 1
    assert manager._records == {}


def test_server_copy_lifecycle_rejection_releases_each_reservation_once(
        app, monkeypatch):
    """A rejected executor submission must not double-release the job quota."""
    import app.socket_events as socket_events
    from app.runtime_lifecycle import RuntimeShuttingDown
    from app.transfer_manager import TransferManager

    class Reservation:
        release_calls = 0

        def release(self):
            self.release_calls += 1

    class RejectingLifecycle:
        def start_job(self, _name, _target, *, owner_id=None):
            del owner_id
            raise RuntimeShuttingDown('stopping')

    reservation = Reservation()
    manager = TransferManager()
    _allow_s2s_sources(monkeypatch, socket_events)
    monkeypatch.setattr(socket_events, 'transfer_manager', manager)
    monkeypatch.setattr(
        socket_events, 'quota_manager',
        SimpleNamespace(reserve=lambda *_args, **_kwargs: reservation),
    )
    monkeypatch.setattr(
        socket_events, 'copy_remote_entry',
        lambda *_args, **_kwargs: SimpleNamespace(bytes_transferred=0),
    )
    monkeypatch.setattr(socket_events, 'emit', lambda *_args, **_kwargs: None)
    monkeypatch.setitem(app.extensions, 'runtime_lifecycle', RejectingLifecycle())

    user = SimpleNamespace(id=7, username='copy-user')
    with app.test_request_context('/socket.io'):
        result = socket_events.handle_transfer_server_to_server.__wrapped__({
            'source_id': 'sftp-session:source',
            'request_id': 's2s:test',
            'source_path': '/from.bin',
            'destination_source_id': 'sftp-session:destination',
            'dest_path': '/to.bin',
        }, current_user=user)

    assert result['success'] is False
    assert result['error_code'] == 'TRANSFER_UNAVAILABLE'
    assert result['error'] == 'The transfer could not be completed.'
    assert result['retryable'] is False
    assert result['source_id'] == 'sftp-session:source'
    assert result['destination_source_id'] == 'sftp-session:destination'
    assert result['request_id'] == 's2s:test'
    assert reservation.release_calls == 1
    assert manager._records == {}


def test_server_copy_rejects_invalid_paths_before_allocating(app, monkeypatch):
    import app.socket_events as socket_events

    emitted = []
    _allow_s2s_sources(monkeypatch, socket_events)
    monkeypatch.setattr(
        socket_events.file_source_resolver,
        'acquire_transfer_holds',
        lambda *_args: pytest.fail('holds allocated for an invalid path'),
    )
    monkeypatch.setattr(
        socket_events, 'emit',
        lambda event, payload=None, **_kwargs: emitted.append((event, payload)),
    )
    user = SimpleNamespace(id=7, username='copy-user')

    with app.test_request_context('/socket.io'):
        result = socket_events.handle_transfer_server_to_server.__wrapped__({
            'source_id': 'sftp-session:source',
            'request_id': 's2s:test',
            'source_path': '../from.bin',
            'destination_source_id': 'sftp-session:destination',
            'dest_path': '/to.bin',
        }, current_user=user)

    assert result['success'] is False
    assert result['error'] == 'Invalid path'
    assert emitted[0][0] == 's2s_transfer_error'
    assert emitted[0][1]['transfer_id'] is None


def test_server_copy_reports_missing_capability_before_path_errors(
        app, monkeypatch):
    import app.socket_events as socket_events
    from app.file_sources import FileSourceUnavailable

    emitted = []

    def unavailable(*_args, **_kwargs):
        raise FileSourceUnavailable()

    monkeypatch.setattr(socket_events.file_service, 'resolve', unavailable)
    monkeypatch.setattr(
        socket_events, 'emit',
        lambda event, payload=None, **_kwargs: emitted.append((event, payload)),
    )
    user = SimpleNamespace(id=7, username='copy-user')

    with app.test_request_context('/socket.io'):
        result = socket_events.handle_transfer_server_to_server.__wrapped__({
            'source_id': 'sftp-session:source',
            'request_id': 's2s:test',
            'source_path': '../from.bin',
            'destination_source_id': 'sftp-session:destination',
            'dest_path': '/to.bin',
        }, current_user=user)

    assert result['success'] is False
    assert result['error_code'] == 'SOURCE_UNAVAILABLE'
    assert result['error'] != 'Invalid path'
    assert emitted[0][0] == 's2s_transfer_error'
    assert emitted[0][1]['transfer_id'] is None


def test_backend_server_copy_progress_is_throttled(app, monkeypatch):
    import app.socket_events as socket_events
    from app import transfer_progress
    from app.file_sources import SourceHoldSet
    from app.transfer_manager import TransferManager

    monkeypatch.setattr(
        transfer_progress.ProgressThrottle.__init__,
        '__defaults__',
        (transfer_progress.PROGRESS_INTERVAL_SECONDS, lambda: 100.0),
    )

    class Reservation:
        def release(self):
            pass

    class ImmediateLifecycle:
        def start_job(self, _name, target, *, owner_id=None):
            del owner_id
            target(threading.Event())
            return SimpleNamespace()

    class Backend:
        @staticmethod
        def normalize_path(path):
            return path

    def copy(_source, path, _destination, _dest_path, *, progress, **_kwargs):
        for count in range(1, 11):
            progress({'transferred': count * 4, 'file_size': 40, 'path': path})
        return SimpleNamespace(bytes_transferred=40)

    emitted = []
    monkeypatch.setattr(
        socket_events.file_service,
        'resolve',
        lambda source_id, _user_id, _capability: SimpleNamespace(
            handle_id=source_id.split(':', 1)[1], backend=Backend(),
        ),
    )
    monkeypatch.setattr(
        socket_events.file_source_resolver,
        'acquire_transfer_holds',
        lambda _user_id, source_ids: SourceHoldSet(tuple(source_ids)),
    )
    monkeypatch.setattr(socket_events, 'transfer_manager', TransferManager())
    monkeypatch.setattr(
        socket_events, 'quota_manager',
        SimpleNamespace(reserve=lambda *_args, **_kwargs: Reservation()),
    )
    monkeypatch.setattr(socket_events, 'copy_remote_entry', copy)
    monkeypatch.setattr(
        socket_events.socketio, 'emit',
        lambda event, payload, room=None: emitted.append((event, payload)),
    )
    monkeypatch.setitem(app.extensions, 'runtime_lifecycle', ImmediateLifecycle())

    user = SimpleNamespace(id=7, username='copy-user')
    with app.test_request_context('/socket.io'):
        result = socket_events.handle_transfer_server_to_server.__wrapped__({
            'source_id': 'smb-quick:source',
            'request_id': 's2s:test',
            'source_path': '/reports/report.txt',
            'destination_source_id': 'smb-quick:destination',
            'dest_path': '/archive/report.txt',
            'is_dir': False,
        }, current_user=user)

    assert result['success'] is True
    progress = [
        payload['transferred']
        for event, payload in emitted
        if event == 's2s_transfer_progress'
    ]
    assert progress == [4]
    assert [event for event, _payload in emitted][-1] == 's2s_transfer_complete'
