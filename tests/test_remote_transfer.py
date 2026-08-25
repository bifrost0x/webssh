from contextlib import contextmanager
from io import BytesIO
from types import SimpleNamespace
from threading import Barrier, BrokenBarrierError, Event, Lock, Thread
import hashlib

import pytest


class _BoundedReader(BytesIO):
    def __init__(self, payload):
        super().__init__(payload)
        self.read_sizes = []

    def read(self, size=-1):
        if size is None or size < 0:
            raise AssertionError('remote reads must be bounded')
        self.read_sizes.append(size)
        return super().read(size)


class _PartialWriter(BytesIO):
    def write(self, data):
        chunk = data[:max(1, len(data) // 2)]
        super().write(chunk)
        return len(chunk)


class _Backend:
    def __init__(self, files=None, tree=None):
        self.files = dict(files or {})
        self.tree = list(tree or [])
        self.readers = []
        self.commits = []
        self.created = []

    def normalize_path(self, path):
        return path if isinstance(path, str) and path.startswith('/') else None

    def stat(self, _source, path, *, follow_links=False):
        assert follow_links is False
        if path in self.files:
            return {
                'path': path, 'size': len(self.files[path]),
                'is_dir': False, 'is_symlink': False,
            }, None
        if path == '/folder':
            return {
                'path': path, 'size': 0,
                'is_dir': True, 'is_symlink': False,
            }, None
        return None, 'File or directory not found'

    @contextmanager
    def open_reader(self, _source, path, *, io_lane='control'):
        assert io_lane == 'transfer'
        reader = _BoundedReader(self.files[path])
        self.readers.append(reader)
        with reader:
            yield reader

    @contextmanager
    def open_atomic_writer(
        self, _source, path, *, replace, cancel_event, io_lane='control'
    ):
        assert io_lane == 'transfer'
        writer = _PartialWriter()
        try:
            yield writer
            if cancel_event.is_set():
                raise RuntimeError('cancelled before commit')
            if not replace and path in self.files:
                raise FileExistsError(path)
            payload = writer.getvalue()
            self.files[path] = payload
            self.commits.append((path, payload))
        finally:
            writer.close()

    def iter_tree(
        self, _source, _path, *, budget, cancel_event,
        follow_links=False, io_lane='control',
    ):
        assert follow_links is False
        assert io_lane == 'transfer'
        for entry in self.tree:
            budget.consume()
            if cancel_event.is_set():
                raise RuntimeError('cancelled')
            yield dict(entry)

    def check_exists(self, _source, path):
        exists = path in self.files or path in self.created
        return {'exists': exists, 'is_dir': path in self.created, 'size': 0}, None

    def mkdir(self, _source, path):
        self.created.append(path)
        return True, None


def _source(kind, backend):
    return SimpleNamespace(
        source_id=f'{kind}-quick:owned',
        backend=backend,
    )


@pytest.mark.parametrize(('source_kind', 'destination_kind'), [
    ('sftp', 'sftp'),
    ('sftp', 'smb'),
    ('smb', 'sftp'),
    ('smb', 'smb'),
])
def test_remote_copy_streams_through_one_atomic_commit(
    source_kind, destination_kind,
):
    from app.remote_transfer import TransferBudget, copy_remote_entry

    payload = b'0123456789' * 30
    source_backend = _Backend({'/source.bin': payload})
    destination_backend = _Backend()

    result = copy_remote_entry(
        _source(source_kind, source_backend),
        '/source.bin',
        _source(destination_kind, destination_backend),
        '/target.bin',
        conflict_policy='replace',
        budget=TransferBudget(max_bytes=len(payload), max_members=10),
        cancel_event=Event(),
        progress=lambda *_args, **_kwargs: None,
        chunk_size=31,
    )

    assert destination_backend.files['/target.bin'] == payload
    assert len(destination_backend.commits) == 1
    assert result.sha256 == hashlib.sha256(payload).hexdigest()
    assert max(source_backend.readers[0].read_sizes) == 31


def test_limit_plus_one_never_commits_destination():
    from app.remote_transfer import (
        RemoteTransferLimitExceeded,
        TransferBudget,
        copy_remote_entry,
    )

    source_backend = _Backend({'/source.bin': b'12345'})
    destination_backend = _Backend()

    with pytest.raises(RemoteTransferLimitExceeded):
        copy_remote_entry(
            _source('smb', source_backend), '/source.bin',
            _source('sftp', destination_backend), '/target.bin',
            conflict_policy='replace',
            budget=TransferBudget(max_bytes=4, max_members=1),
            cancel_event=Event(), progress=None, chunk_size=2,
        )

    assert destination_backend.commits == []


def test_cancelled_copy_leaves_no_visible_destination():
    from app.remote_transfer import (
        RemoteTransferCancelled,
        TransferBudget,
        copy_remote_entry,
    )

    source_backend = _Backend({'/source.bin': b'12345'})
    destination_backend = _Backend()
    cancelled = Event()
    cancelled.set()

    with pytest.raises(RemoteTransferCancelled):
        copy_remote_entry(
            _source('sftp', source_backend), '/source.bin',
            _source('smb', destination_backend), '/target.bin',
            conflict_policy='replace',
            budget=TransferBudget(max_bytes=10, max_members=1),
            cancel_event=cancelled, progress=None, chunk_size=2,
        )

    assert destination_backend.commits == []


def test_directory_reparse_is_rejected_before_destination_mutation():
    from app.remote_transfer import (
        RemoteTransferError,
        TransferBudget,
        copy_remote_entry,
    )

    source_backend = _Backend(tree=[{
        'name': 'link', 'path': '/folder/link', 'size': 0,
        'is_dir': False, 'is_symlink': True,
    }])
    destination_backend = _Backend()

    with pytest.raises(RemoteTransferError, match='Reparse'):
        copy_remote_entry(
            _source('smb', source_backend), '/folder',
            _source('smb', destination_backend), '/copy',
            conflict_policy='replace',
            budget=TransferBudget(max_bytes=10, max_members=1),
            cancel_event=Event(), progress=None, chunk_size=2,
        )

    assert destination_backend.created == []
    assert destination_backend.commits == []


def test_directory_total_size_is_rejected_before_destination_mutation():
    from app.remote_transfer import (
        RemoteTransferLimitExceeded,
        TransferBudget,
        copy_remote_entry,
    )

    source_backend = _Backend(
        files={'/folder/a.bin': b'123', '/folder/b.bin': b'456'},
        tree=[
            {
                'name': 'a.bin', 'path': '/folder/a.bin', 'size': 3,
                'is_dir': False, 'is_symlink': False,
            },
            {
                'name': 'b.bin', 'path': '/folder/b.bin', 'size': 3,
                'is_dir': False, 'is_symlink': False,
            },
        ],
    )
    destination_backend = _Backend()

    with pytest.raises(RemoteTransferLimitExceeded):
        copy_remote_entry(
            _source('smb', source_backend), '/folder',
            _source('sftp', destination_backend), '/copy',
            conflict_policy='replace',
            budget=TransferBudget(max_bytes=5, max_members=2),
            cancel_event=Event(), progress=None, chunk_size=2,
        )

    assert destination_backend.created == []
    assert destination_backend.commits == []


def test_same_source_and_path_is_rejected_as_a_noop_conflict():
    from app.remote_transfer import (
        RemoteTransferConflict,
        TransferBudget,
        copy_remote_entry,
    )

    backend = _Backend({'/same': b'value'})
    source = _source('smb', backend)

    with pytest.raises(RemoteTransferConflict):
        copy_remote_entry(
            source, '/same', source, '/same',
            conflict_policy='replace',
            budget=TransferBudget(max_bytes=10, max_members=1),
            cancel_event=Event(), progress=None, chunk_size=2,
        )


def test_typed_source_stat_permission_failure_is_not_collapsed():
    from app.remote_transfer import TransferBudget, copy_remote_entry

    class DeniedBackend(_Backend):
        def stat_or_raise(self, _source, _path, *, follow_links=False):
            assert follow_links is False
            raise PermissionError('private backend detail')

    with pytest.raises(PermissionError, match='private backend detail'):
        copy_remote_entry(
            _source('smb', DeniedBackend()), '/restricted.bin',
            _source('smb', _Backend()), '/target.bin',
            conflict_policy='error',
            budget=TransferBudget(max_bytes=10, max_members=1),
            cancel_event=Event(), progress=None, chunk_size=2,
        )


def test_typed_destination_directory_permission_failure_is_not_collapsed():
    from app.remote_transfer import TransferBudget, copy_remote_entry

    source_backend = _Backend(
        files={'/folder/a.bin': b'a'},
        tree=[{
            'name': 'a.bin', 'path': '/folder/a.bin', 'size': 1,
            'is_dir': False, 'is_symlink': False,
        }],
    )

    class DeniedDestination(_Backend):
        def check_exists_or_raise(self, _source, _path):
            return {'exists': False, 'is_dir': False, 'size': 0}

        def mkdir_or_raise(self, _source, _path):
            raise PermissionError('private backend detail')

    with pytest.raises(PermissionError, match='private backend detail'):
        copy_remote_entry(
            _source('smb', source_backend), '/folder',
            _source('smb', DeniedDestination()), '/copy',
            conflict_policy='error',
            budget=TransferBudget(max_bytes=10, max_members=2),
            cancel_event=Event(), progress=None, chunk_size=2,
        )


def test_opposite_direction_transfers_use_one_canonical_source_lock_order():
    from app.remote_transfer import TransferBudget, copy_remote_entry

    rendezvous = Barrier(2)
    source_locks = {'source-a': Lock(), 'source-b': Lock()}
    payloads = {'source-a': b'a', 'source-b': b'b'}
    completed = []

    class LockingBackend:
        def normalize_path(self, path):
            return path

        def stat(self, source, _path, *, follow_links=False):
            assert follow_links is False
            return {
                'size': len(payloads[source.handle_id]),
                'is_dir': False,
                'is_symlink': False,
            }, None

        @contextmanager
        def open_reader(self, source, _path, *, io_lane='control'):
            assert io_lane == 'transfer'
            with source_locks[source.handle_id]:
                try:
                    rendezvous.wait(timeout=0.2)
                except BrokenBarrierError:
                    pass
                yield _BoundedReader(payloads[source.handle_id])

        @contextmanager
        def open_atomic_writer(
            self, source, _path, *, replace, cancel_event,
            io_lane='control',
        ):
            assert io_lane == 'transfer'
            assert replace is True
            with source_locks[source.handle_id]:
                yield _PartialWriter()

    backend = LockingBackend()
    source_a = SimpleNamespace(
        source_id='smb-quick:source-a', handle_id='source-a', backend=backend,
    )
    source_b = SimpleNamespace(
        source_id='smb-quick:source-b', handle_id='source-b', backend=backend,
    )

    def run(source, destination):
        copy_remote_entry(
            source,
            '/source.bin',
            destination,
            '/target.bin',
            conflict_policy='replace',
            budget=TransferBudget(max_bytes=10, max_members=1),
            cancel_event=Event(),
            progress=None,
            chunk_size=2,
        )
        completed.append((source.source_id, destination.source_id))

    threads = [
        Thread(target=run, args=(source_a, source_b), daemon=True),
        Thread(target=run, args=(source_b, source_a), daemon=True),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=1)

    assert not any(thread.is_alive() for thread in threads)
    assert len(completed) == 2
