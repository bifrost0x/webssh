import io
import os
import stat
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest


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

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class MemoryWriter(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class StoredWriter(MemoryWriter):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def __exit__(self, *_args):
        self.callback(self.getvalue())
        return False


class S2SSFTP:
    def __init__(self, payload=b'', destination=False):
        self.payload = payload
        self.destination = destination
        self.files = {}
        self.dirs = set()
        self.removed = []
        self.renamed = []
        self.closed = False
        self.close_calls = 0

    def stat(self, path):
        if self.destination:
            if path in self.dirs:
                return SimpleNamespace(st_mode=stat.S_IFDIR, st_size=0)
            if path not in self.files:
                raise FileNotFoundError(path)
            return SimpleNamespace(st_mode=stat.S_IFREG, st_size=len(self.files[path]))
        return SimpleNamespace(st_mode=stat.S_IFREG, st_size=len(self.payload))

    def open(self, path, mode):
        if not self.destination:
            return BoundedReader(self.payload)
        return StoredWriter(lambda payload: self.files.__setitem__(path, payload))

    def remove(self, path):
        self.removed.append(path)
        self.files.pop(path, None)

    def mkdir(self, path):
        self.dirs.add(path)

    def rmdir(self, path):
        self.dirs.discard(path)

    def listdir_attr(self, path):
        if not self.destination:
            return [SimpleNamespace(
                filename='file.bin', st_mode=stat.S_IFREG,
                st_size=len(self.payload),
            )]
        prefix = path.rstrip('/') + '/'
        names = {}
        for candidate in self.files:
            if candidate.startswith(prefix):
                remainder = candidate[len(prefix):]
                if '/' not in remainder:
                    names[remainder] = SimpleNamespace(
                        filename=remainder, st_mode=stat.S_IFREG,
                        st_size=len(self.files[candidate]),
                    )
        for candidate in self.dirs:
            if candidate.startswith(prefix):
                remainder = candidate[len(prefix):]
                if remainder and '/' not in remainder:
                    names[remainder] = SimpleNamespace(
                        filename=remainder, st_mode=stat.S_IFDIR, st_size=0,
                    )
        return list(names.values())

    def lstat(self, path):
        if not self.destination:
            return SimpleNamespace(st_mode=stat.S_IFREG, st_size=len(self.payload))
        return self.stat(path)

    def rename(self, source, destination):
        self.renamed.append((source, destination))
        if source in self.files:
            self.files[destination] = self.files.pop(source)
            return
        moved_files = {
            destination + path[len(source):]: payload
            for path, payload in list(self.files.items())
            if path.startswith(source + '/')
        }
        for path in list(self.files):
            if path.startswith(source + '/'):
                del self.files[path]
        self.files.update(moved_files)
        moved_dirs = {
            destination + path[len(source):]
            for path in self.dirs if path == source or path.startswith(source + '/')
        }
        self.dirs = {
            path for path in self.dirs
            if path != source and not path.startswith(source + '/')
        }
        self.dirs.update(moved_dirs)

    def close(self):
        self.closed = True
        self.close_calls += 1


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


def test_server_transfer_closes_fresh_pool_channels_on_success(monkeypatch):
    """Quick-connection SFTP channels are per-operation and must be closed."""
    import app.sftp_handler as sftp_handler

    source = S2SSFTP(b'payload')
    destination = S2SSFTP(destination=True)
    monkeypatch.setattr(
        sftp_handler,
        'get_sftp_client_fresh',
        lambda _identifier: (None, 'not an SSH session'),
    )
    monkeypatch.setattr(
        sftp_handler,
        'get_sftp_client_from_pool',
        lambda identifier: (
            (source, None) if identifier == 'source' else (destination, None)
        ),
    )

    success, error = sftp_handler.transfer_server_to_server(
        'source', '/from.bin', 'destination', '/to.bin', 'pool-success',
        cancel_event=threading.Event(), max_bytes=100, chunk_size=4,
    )

    assert success is True
    assert error is None
    assert source.close_calls == 1
    assert destination.close_calls == 1


def test_server_transfer_closes_pool_source_once_if_destination_fails(monkeypatch):
    """Opening the destination must not leak or double-close the pool source."""
    import app.sftp_handler as sftp_handler

    source = S2SSFTP(b'payload')
    monkeypatch.setattr(
        sftp_handler,
        'get_sftp_client_fresh',
        lambda _identifier: (None, 'not an SSH session'),
    )
    monkeypatch.setattr(
        sftp_handler,
        'get_sftp_client_from_pool',
        lambda identifier: (
            (source, None)
            if identifier == 'source'
            else (None, 'destination unavailable')
        ),
    )

    success, error = sftp_handler.transfer_server_to_server(
        'source', '/from.bin', 'destination', '/to.bin', 'pool-error',
    )

    assert success is False
    assert error == 'Destination connection error: destination unavailable'
    assert source.close_calls == 1


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


def test_copy_sftp_stream_uses_bounded_reads_and_checks_cancellation():
    from app.sftp_handler import TransferCancelled, copy_sftp_stream

    source = BoundedReader(b'abcdefgh')
    destination = MemoryWriter()
    cancelled = threading.Event()

    def progress(transferred):
        if transferred == 4:
            cancelled.set()

    with pytest.raises(TransferCancelled):
        copy_sftp_stream(
            source,
            destination,
            cancel_event=cancelled,
            max_bytes=8,
            chunk_size=4,
            progress=progress,
        )

    assert destination.getvalue() == b'abcd'
    assert source.read_sizes == [4]


def test_stream_remote_zip_is_bounded_and_cancellable():
    from app.sftp_handler import TransferCancelled, stream_remote_zip

    remote = BoundedReader(b'abcdefgh')
    cancelled = threading.Event()
    chunks = stream_remote_zip(
        remote,
        cancel_event=cancelled,
        max_bytes=8,
        chunk_size=4,
    )

    assert next(chunks) == b'abcd'
    cancelled.set()
    with pytest.raises(TransferCancelled):
        next(chunks)
    assert remote.read_sizes == [4]


def test_fallback_zip_uses_disk_and_bounded_remote_reads(tmp_path):
    from app.sftp_handler import build_fallback_zip_to_disk

    sftp = FallbackSFTP({'/reports/a.txt': b'a' * 9})
    archive = build_fallback_zip_to_disk(
        sftp,
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


def test_fallback_zip_cancellation_removes_temporary_archive(tmp_path):
    from app.sftp_handler import TransferCancelled, build_fallback_zip_to_disk

    cancelled = threading.Event()
    sftp = FallbackSFTP({'/reports/a.txt': b'a' * 9})

    def progress(transferred):
        if transferred == 4:
            cancelled.set()

    with pytest.raises(TransferCancelled):
        build_fallback_zip_to_disk(
            sftp,
            '/reports',
            'reports',
            cancel_event=cancelled,
            max_bytes=1024,
            chunk_size=4,
            temp_dir=tmp_path,
            progress=progress,
        )

    assert list(tmp_path.iterdir()) == []


def test_empty_directory_entries_cannot_exceed_reserved_zip_bytes(tmp_path):
    from app.sftp_handler import TransferSizeExceeded, build_fallback_zip_to_disk

    with pytest.raises(TransferSizeExceeded):
        build_fallback_zip_to_disk(
            EmptyDirectorySFTP(),
            '/reports',
            'reports',
            cancel_event=threading.Event(),
            max_bytes=64,
            chunk_size=4,
            temp_dir=tmp_path,
        )

    assert list(tmp_path.iterdir()) == []


def test_remote_tree_counts_zero_byte_members():
    from app.sftp_handler import (
        TransferMemberLimitExceeded,
        inspect_remote_tree,
    )

    with pytest.raises(TransferMemberLimitExceeded):
        inspect_remote_tree(
            ManyZeroFilesSFTP(4),
            '/reports',
            cancel_event=threading.Event(),
            max_bytes=1,
            max_members=3,
        )


def test_remote_tree_closes_paramiko_directory_handle_on_member_rejection():
    import paramiko
    from paramiko.message import Message
    from paramiko.sftp import CMD_CLOSE, CMD_HANDLE, CMD_NAME, CMD_OPENDIR, CMD_READDIR
    from paramiko.sftp_attr import SFTPAttributes
    from app.sftp_handler import (
        TransferMemberLimitExceeded,
        inspect_remote_tree,
    )

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

    with pytest.raises(TransferMemberLimitExceeded):
        inspect_remote_tree(
            sftp,
            '/reports',
            cancel_event=threading.Event(),
            max_bytes=1,
            max_members=1,
        )

    assert [command for command, _args in sftp.requests].count(CMD_CLOSE) == 1


def test_fallback_zip_counts_zero_byte_members(tmp_path):
    from app.sftp_handler import (
        TransferMemberLimitExceeded,
        build_fallback_zip_to_disk,
    )

    with pytest.raises(TransferMemberLimitExceeded):
        build_fallback_zip_to_disk(
            ManyZeroFilesSFTP(4),
            '/reports',
            'reports',
            cancel_event=threading.Event(),
            max_bytes=1024,
            max_members=3,
            chunk_size=4,
            temp_dir=tmp_path,
        )

    assert list(tmp_path.iterdir()) == []


def test_server_directory_copy_rejects_excess_members(monkeypatch):
    import app.sftp_handler as sftp_handler

    source = ManyZeroFilesSFTP(4)
    source.close = lambda: None
    destination = S2SSFTP(destination=True)
    monkeypatch.setattr(
        sftp_handler,
        'get_sftp_client_fresh',
        lambda session_id: (
            (source, None) if session_id == 'source' else (destination, None)
        ),
    )

    success, error = sftp_handler.transfer_server_to_server(
        'source', '/reports', 'destination', '/copy', 'transfer-members',
        is_dir=True,
        cancel_event=threading.Event(),
        max_bytes=1,
        max_members=3,
        chunk_size=4,
    )

    assert success is False
    assert error == 'Transfer exceeds configured member limit'
    assert destination.files == {}
    assert destination.dirs == set()


def test_server_copy_cancellation_removes_partial_destination(monkeypatch):
    import app.sftp_handler as sftp_handler

    source = S2SSFTP(b'a' * 12)
    destination = S2SSFTP(destination=True)
    cancelled = threading.Event()

    def fresh(session_id):
        return (source, None) if session_id == 'source' else (destination, None)

    class Socket:
        def emit(self, event, payload, room=None):
            if event == 's2s_transfer_progress':
                cancelled.set()

    monkeypatch.setattr(sftp_handler, 'get_sftp_client_fresh', fresh)

    success, error = sftp_handler.transfer_server_to_server(
        'source', '/from.txt', 'destination', '/to.txt', 'transfer-1',
        socketio_instance=Socket(), user_room='user_1',
        cancel_event=cancelled, max_bytes=100, chunk_size=4,
    )

    assert success is False
    assert error == 'Transfer cancelled'
    assert '/to.txt' not in destination.files
    assert len(destination.removed) == 1
    assert destination.removed[0].startswith('/to.txt.webssh-transfer-')


def test_server_directory_cancellation_removes_temporary_tree(monkeypatch):
    import app.sftp_handler as sftp_handler

    source = S2SSFTP(b'a' * 12)
    destination = S2SSFTP(destination=True)
    cancelled = threading.Event()

    monkeypatch.setattr(
        sftp_handler, 'get_sftp_client_fresh',
        lambda session_id: (
            (source, None) if session_id == 'source' else (destination, None)
        ),
    )

    class Socket:
        def emit(self, event, payload, room=None):
            if event == 's2s_transfer_progress':
                cancelled.set()

    success, error = sftp_handler.transfer_server_to_server(
        'source', '/folder', 'destination', '/copy', 'transfer-dir',
        socketio_instance=Socket(), user_room='user_1', is_dir=True,
        cancel_event=cancelled, max_bytes=100, chunk_size=4,
    )

    assert success is False
    assert error == 'Transfer cancelled'
    assert destination.files == {}
    assert destination.dirs == set()
    assert destination.renamed == []


def test_server_directory_progress_is_cumulative(monkeypatch):
    import app.sftp_handler as sftp_handler

    class DirectorySource(S2SSFTP):
        def __init__(self):
            super().__init__()
            self.files = {
                '/folder/first.bin': b'a' * 5,
                '/folder/second.bin': b'b' * 7,
            }

        def listdir_attr(self, path):
            assert path == '/folder'
            return [
                SimpleNamespace(
                    filename=os.path.basename(file_path),
                    st_mode=stat.S_IFREG,
                    st_size=len(payload),
                )
                for file_path, payload in self.files.items()
            ]

        def lstat(self, path):
            return SimpleNamespace(
                st_mode=stat.S_IFREG,
                st_size=len(self.files[path]),
            )

        def stat(self, path):
            return self.lstat(path)

        def open(self, path, mode):
            del mode
            return BoundedReader(self.files[path])

    source = DirectorySource()
    destination = S2SSFTP(destination=True)
    progress = []

    monkeypatch.setattr(
        sftp_handler, 'get_sftp_client_fresh',
        lambda session_id: (
            (source, None) if session_id == 'source' else (destination, None)
        ),
    )

    class Socket:
        def emit(self, event, payload, room=None):
            if event == 's2s_transfer_progress':
                progress.append(payload)

    success, error = sftp_handler.transfer_server_to_server(
        'source', '/folder', 'destination', '/copy', 'transfer-dir',
        socketio_instance=Socket(), user_room='user_1', is_dir=True,
        cancel_event=threading.Event(), max_bytes=100, chunk_size=4,
    )

    assert success is True
    assert error is None
    assert progress
    assert [item['transferred'] for item in progress] == sorted(
        item['transferred'] for item in progress
    )
    assert progress[-1]['transferred'] == 12
    assert progress[-1]['total'] == 12
    assert progress[-1]['percent'] == 100


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

    def copy(**kwargs):
        observed.update(kwargs)
        return True, None

    monkeypatch.setattr(socket_events, 'verify_session_ownership', lambda *_: True)
    monkeypatch.setattr(socket_events, 'transfer_manager', manager)
    monkeypatch.setattr(socket_events, 'quota_manager', quota)
    monkeypatch.setattr(socket_events.sftp_handler, 'transfer_server_to_server', copy)
    monkeypatch.setitem(
        app.extensions, 'runtime_lifecycle', ImmediateLifecycle()
    )

    user = SimpleNamespace(id=7, username='copy-user')
    with app.test_request_context('/socket.io'):
        result = socket_events.handle_transfer_server_to_server.__wrapped__({
            'source_session_id': 'source',
            'source_path': '/from.bin',
            'dest_session_id': 'destination',
            'dest_path': '/to.bin',
            'is_dir': False,
        }, current_user=user)

    assert result['success'] is True
    assert observed['cancel_event'] is not None
    assert observed['chunk_size'] > 0
    assert reservation.released is True
    assert manager._records == {}


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
    monkeypatch.setattr(socket_events, 'verify_session_ownership', lambda *_: True)
    monkeypatch.setattr(socket_events, 'transfer_manager', TransferManager())
    monkeypatch.setattr(
        socket_events, 'quota_manager',
        SimpleNamespace(reserve=lambda *_args, **_kwargs: Reservation()),
    )
    monkeypatch.setattr(
        socket_events.sftp_handler, 'transfer_server_to_server',
        lambda **_kwargs: (True, None),
    )
    monkeypatch.setattr(
        socket_events.socketio, 'emit',
        lambda event, payload, room=None: emitted.append((event, payload, room)),
    )
    monkeypatch.setitem(app.extensions, 'runtime_lifecycle', ImmediateLifecycle())

    user = SimpleNamespace(id=7, username='copy-user')
    with app.test_request_context('/socket.io'):
        result = socket_events.handle_transfer_server_to_server.__wrapped__({
            'source_session_id': 'source',
            'source_path': '/reports/report.txt',
            'dest_session_id': 'destination',
            'dest_path': '/archive/report.txt',
            'is_dir': False,
        }, current_user=user)

    assert result['success'] is True
    complete = next(
        payload for event, payload, _room in emitted
        if event == 's2s_transfer_complete'
    )
    assert complete['filename'] == 'report.txt'


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
    monkeypatch.setattr(socket_events, 'verify_session_ownership', lambda *_: True)
    monkeypatch.setattr(socket_events, 'transfer_manager', manager)
    monkeypatch.setattr(
        socket_events, 'quota_manager',
        SimpleNamespace(reserve=lambda *_args, **_kwargs: reservation),
    )
    monkeypatch.setattr(
        socket_events.sftp_handler,
        'transfer_server_to_server',
        lambda **kwargs: (observed.update(kwargs) or (False, 'Transfer cancelled')),
    )
    monkeypatch.setitem(app.extensions, 'runtime_lifecycle', ImmediateLifecycle())

    user = SimpleNamespace(id=7, username='copy-user')
    with app.test_request_context('/socket.io'):
        result = socket_events.handle_transfer_server_to_server.__wrapped__({
            'source_session_id': 'source',
            'source_path': '/from.bin',
            'dest_session_id': 'destination',
            'dest_path': '/to.bin',
        }, current_user=user)

    assert result['success'] is True
    assert observed['cancel_event'].is_set()
    assert reservation.release_calls == 1
    assert manager._records == {}


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

    def copy(**kwargs):
        observed.update(kwargs)
        observed['thread_name'] = threading.current_thread().name
        started.set()
        assert release.wait(1)
        return True, None

    monkeypatch.setattr(socket_events, 'verify_session_ownership', lambda *_: True)
    monkeypatch.setattr(socket_events, 'transfer_manager', manager)
    monkeypatch.setattr(
        socket_events, 'quota_manager',
        SimpleNamespace(reserve=lambda *_args, **_kwargs: reservation),
    )
    monkeypatch.setattr(socket_events.sftp_handler, 'transfer_server_to_server', copy)

    user = SimpleNamespace(id=7, username='copy-user')
    with app.test_request_context('/socket.io'):
        result = socket_events.handle_transfer_server_to_server.__wrapped__({
            'source_session_id': 'source',
            'source_path': '/from.bin',
            'dest_session_id': 'destination',
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
    monkeypatch.setattr(socket_events, 'verify_session_ownership', lambda *_: True)
    monkeypatch.setattr(socket_events, 'transfer_manager', manager)
    monkeypatch.setattr(
        socket_events, 'quota_manager',
        SimpleNamespace(reserve=lambda *_args, **_kwargs: reservation),
    )
    monkeypatch.setattr(
        socket_events.sftp_handler,
        'transfer_server_to_server', lambda **_kwargs: (True, None),
    )
    monkeypatch.setattr(socket_events, 'emit', lambda *_args, **_kwargs: None)
    monkeypatch.setitem(app.extensions, 'runtime_lifecycle', RejectingLifecycle())

    user = SimpleNamespace(id=7, username='copy-user')
    with app.test_request_context('/socket.io'):
        result = socket_events.handle_transfer_server_to_server.__wrapped__({
            'source_session_id': 'source',
            'source_path': '/from.bin',
            'dest_session_id': 'destination',
            'dest_path': '/to.bin',
        }, current_user=user)

    assert result == {'success': False, 'error': 'Transfer unavailable'}
    assert reservation.release_calls == 1
    assert manager._records == {}


def test_remote_zip_command_can_be_cancelled_before_exit():
    from app import sftp_handler, transfer_routes

    cancelled = threading.Event()
    cancelled.set()

    class Channel:
        def settimeout(self, _timeout): pass
        def exec_command(self, _command): pass
        def exit_status_ready(self): return False
        def close(self): pass

    class Transport:
        def open_session(self, timeout=None):
            return Channel()

    class SFTP:
        def __init__(self):
            self._client = SimpleNamespace(
                get_transport=lambda: Transport(),
            )
            self.removed = []

        def remove(self, path):
            self.removed.append(path)

    sftp = SFTP()
    with pytest.raises(sftp_handler.TransferCancelled):
        transfer_routes._remote_zip_path(
            sftp, sftp._client, '/reports', cancelled
        )

    assert len(sftp.removed) == 1


def test_server_copy_rejects_invalid_paths_before_allocating(app, monkeypatch):
    import app.socket_events as socket_events

    emitted = []
    monkeypatch.setattr(socket_events.sftp_handler, 'sanitize_path', lambda _path: None)
    monkeypatch.setattr(
        socket_events, 'emit',
        lambda event, payload=None, **_kwargs: emitted.append((event, payload)),
    )
    user = SimpleNamespace(id=7, username='copy-user')

    with app.test_request_context('/socket.io'):
        result = socket_events.handle_transfer_server_to_server.__wrapped__({
            'source_session_id': 'source',
            'source_path': '../from.bin',
            'dest_session_id': 'destination',
            'dest_path': '/to.bin',
        }, current_user=user)

    assert result['success'] is False
    assert emitted[0][1]['transfer_id'] is None
