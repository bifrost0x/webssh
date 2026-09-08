from contextlib import contextmanager
from io import BytesIO
from types import SimpleNamespace
from threading import Barrier, BrokenBarrierError, Event, Lock, Thread
import hashlib

import pytest

from app.file_backend import FileReaderLease


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
    def __init__(self, files=None, tree=None, root_identities=None):
        self.files = dict(files or {})
        self.tree = list(tree or [])
        self.readers = []
        self.reader_identities = []
        self.commits = []
        self.created = []
        self.writer_opens = 0
        self.stat_paths = []
        self.root_identities = root_identities
        self.tree_identities = []

    def normalize_path(self, path):
        return path if isinstance(path, str) and path.startswith('/') else None

    def stat(self, _source, path, *, follow_links=False):
        assert follow_links is False
        self.stat_paths.append(path)
        if path in self.files:
            result = {
                'path': path, 'size': len(self.files[path]),
                'is_dir': False, 'is_symlink': False,
            }
            if self.root_identities is not None:
                result['_smb_identity_chain'] = self.root_identities
            return result, None
        if path == '/folder':
            result = {
                'path': path, 'size': 0,
                'is_dir': True, 'is_symlink': False,
            }
            if self.root_identities is not None:
                result['_smb_identity_chain'] = self.root_identities
            return result, None
        return None, 'File or directory not found'

    @contextmanager
    def open_reader(
        self,
        _source,
        path,
        *,
        io_lane='control',
        _expected_identities=None,
    ):
        assert io_lane == 'transfer'
        self.reader_identities.append(_expected_identities)
        reader = _BoundedReader(self.files[path])
        self.readers.append(reader)
        with reader:
            yield FileReaderLease(reader=reader, size=len(self.files[path]))

    @contextmanager
    def open_atomic_writer(
        self, _source, path, *, replace, cancel_event, io_lane='control'
    ):
        assert io_lane == 'transfer'
        self.writer_opens += 1
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
        follow_links=False, io_lane='control', _expected_identities=None,
    ):
        assert follow_links is False
        assert io_lane == 'transfer'
        self.tree_identities.append(_expected_identities)
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


def test_single_file_copy_binds_reader_to_classified_smb_root():
    from app.remote_transfer import TransferBudget, copy_remote_entry

    identity_chain = (71, 73)
    source_backend = _Backend(
        {'/source.bin': b'bound'},
        root_identities=identity_chain,
    )
    destination_backend = _Backend()

    copy_remote_entry(
        _source('smb', source_backend),
        '/source.bin',
        _source('sftp', destination_backend),
        '/target.bin',
        conflict_policy='replace',
        budget=TransferBudget(max_bytes=10, max_members=1),
        cancel_event=Event(),
        progress=None,
        chunk_size=2,
    )

    assert source_backend.reader_identities == [identity_chain]
    assert destination_backend.files['/target.bin'] == b'bound'


def test_directory_copy_binds_traversal_to_classified_smb_root():
    from app.remote_transfer import TransferBudget, copy_remote_entry

    root_chain = (41,)
    leaf_chain = (41, 73)
    source_backend = _Backend(
        files={'/folder/a.bin': b'bound'},
        tree=[{
            'name': 'a.bin',
            'path': '/folder/a.bin',
            'size': 5,
            'is_dir': False,
            'is_symlink': False,
            '_smb_identity_chain': leaf_chain,
        }],
        root_identities=root_chain,
    )
    destination_backend = _Backend()

    copy_remote_entry(
        _source('smb', source_backend),
        '/folder',
        _source('sftp', destination_backend),
        '/copy',
        conflict_policy='replace',
        budget=TransferBudget(max_bytes=10, max_members=2),
        cancel_event=Event(),
        progress=None,
        chunk_size=2,
    )

    assert source_backend.tree_identities == [root_chain]
    assert source_backend.reader_identities == [leaf_chain]


def test_remote_copy_rejects_opened_object_before_destination_writer():
    """A small path stat must not authorize a larger substituted object."""
    from app.remote_transfer import (
        RemoteTransferLimitExceeded,
        TransferBudget,
        copy_remote_entry,
    )

    class StaleStatBackend(_Backend):
        def stat(self, _source, path, *, follow_links=False):
            assert follow_links is False
            assert path == '/source.bin'
            return {
                'path': path,
                'size': 1,
                'is_dir': False,
                'is_symlink': False,
            }, None

    source_backend = StaleStatBackend({'/source.bin': b'123456789'})
    destination_backend = _Backend()

    with pytest.raises(
        RemoteTransferLimitExceeded,
        match='Transfer size limit exceeded',
    ):
        copy_remote_entry(
            _source('sftp', source_backend),
            '/source.bin',
            _source('smb', destination_backend),
            '/target.bin',
            conflict_policy='replace',
            budget=TransferBudget(max_bytes=5, max_members=1),
            cancel_event=Event(),
            progress=None,
            chunk_size=2,
        )

    assert destination_backend.writer_opens == 0
    assert destination_backend.commits == []


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


def test_directory_copy_binds_reader_to_enumerated_smb_identity_chain():
    from app.remote_transfer import TransferBudget, copy_remote_entry

    identity_chain = (41, 73)
    source_backend = _Backend(
        files={'/folder/a.bin': b'bound'},
        tree=[{
            'name': 'a.bin',
            'path': '/folder/a.bin',
            'size': 5,
            'is_dir': False,
            'is_symlink': False,
            '_smb_identity_chain': identity_chain,
        }],
    )
    destination_backend = _Backend()

    copy_remote_entry(
        _source('smb', source_backend),
        '/folder',
        _source('sftp', destination_backend),
        '/copy',
        conflict_policy='replace',
        budget=TransferBudget(max_bytes=10, max_members=2),
        cancel_event=Event(),
        progress=None,
        chunk_size=2,
    )

    assert source_backend.reader_identities == [identity_chain]
    assert source_backend.stat_paths == ['/folder']
    assert destination_backend.files['/copy/a.bin'] == b'bound'


@pytest.mark.parametrize('race', ['missing', 'reparse', 'directory'])
def test_directory_copy_preserves_bound_smb_source_change(race):
    from app.file_backend import FileSourceChanged
    from app.remote_transfer import TransferBudget, copy_remote_entry

    identity_chain = (41, 73)

    class ChangedBackend(_Backend):
        @contextmanager
        def open_reader(
            self,
            _source,
            path,
            *,
            io_lane='control',
            _expected_identities=None,
        ):
            assert path == '/folder/a.bin'
            assert io_lane == 'transfer'
            assert _expected_identities == identity_chain
            raise FileSourceChanged(f'enumerated source became {race}')
            yield  # pragma: no cover - contextmanager contract

    source_backend = ChangedBackend(
        files={'/folder/a.bin': b'old'},
        tree=[{
            'name': 'a.bin',
            'path': '/folder/a.bin',
            'size': 3,
            'is_dir': False,
            'is_symlink': False,
            '_smb_identity_chain': identity_chain,
        }],
    )

    with pytest.raises(FileSourceChanged) as error:
        copy_remote_entry(
            _source('smb', source_backend),
            '/folder',
            _source('sftp', _Backend()),
            '/copy',
            conflict_policy='replace',
            budget=TransferBudget(max_bytes=10, max_members=2),
            cancel_event=Event(),
            progress=None,
            chunk_size=2,
        )

    assert error.value.public_code == 'SOURCE_CHANGED'
    # Only the root classification is unbound. The enumerated leaf goes
    # directly through its expected-ID reader instead of a pathname re-stat.
    assert source_backend.stat_paths == ['/folder']


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


def test_remote_copy_preserves_source_identity_change_classification():
    from app.file_backend import FileSourceChanged
    from app.remote_transfer import TransferBudget, copy_remote_entry
    from app.transfer_errors import classify_transfer_failure

    class ChangedSourceBackend(_Backend):
        @contextmanager
        def open_reader(
            self,
            _source,
            _path,
            *,
            io_lane='control',
            _expected_identities=None,
        ):
            assert io_lane == 'transfer'
            raise FileSourceChanged('private source path')
            yield  # pragma: no cover - required by contextmanager semantics

    with pytest.raises(FileSourceChanged) as failure:
        copy_remote_entry(
            _source('smb', ChangedSourceBackend({'/source.bin': b'value'})),
            '/source.bin',
            _source('smb', _Backend()),
            '/target.bin',
            conflict_policy='error',
            budget=TransferBudget(max_bytes=10, max_members=1),
            cancel_event=Event(), progress=None, chunk_size=2,
        )

    assert classify_transfer_failure(
        failure.value, operation='remote_transfer'
    ).code == 'SOURCE_CHANGED'


def test_remote_copy_preserves_backend_enumeration_cancellation():
    from app.file_backend import FileOperationCancelled
    from app.remote_transfer import TransferBudget, copy_remote_entry
    from app.transfer_errors import classify_transfer_failure

    class CancelledTreeBackend(_Backend):
        def iter_tree(
            self, _source, _path, *, budget, cancel_event,
            follow_links=False, io_lane='control',
        ):
            assert follow_links is False
            assert io_lane == 'transfer'
            raise FileOperationCancelled('private backend detail')
            yield  # pragma: no cover - generator contract

    with pytest.raises(FileOperationCancelled) as failure:
        copy_remote_entry(
            _source('smb', CancelledTreeBackend()),
            '/folder',
            _source('smb', _Backend()),
            '/copy',
            conflict_policy='error',
            budget=TransferBudget(max_bytes=10, max_members=2),
            cancel_event=Event(),
            progress=None,
            chunk_size=2,
        )

    assert classify_transfer_failure(
        failure.value,
        operation='remote_transfer',
    ).code == 'CANCELLED'


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


@pytest.mark.parametrize(
    ('writer_error', 'expected_type', 'expected_code'),
    [
        pytest.param(
            lambda: __import__(
                'app.smb_protocol', fromlist=['SMBProtocolError']
            ).SMBProtocolError('CONFLICT'),
            'SMBProtocolError',
            'CONFLICT',
            id='smb-protocol-conflict',
        ),
        pytest.param(
            lambda: __import__(
                'app.smb_backend', fromlist=['FileConflict']
            ).FileConflict('private destination'),
            'FileConflict',
            'CONFLICT',
            id='smb-file-conflict',
        ),
        pytest.param(
            lambda: __import__(
                'app.smb_backend', fromlist=['NonAtomicOverwriteRequired']
            ).NonAtomicOverwriteRequired('private destination'),
            'NonAtomicOverwriteRequired',
            'ATOMIC_REPLACE_UNAVAILABLE',
            id='smb-non-atomic-replace',
        ),
        pytest.param(
            lambda: PermissionError('private destination'),
            'PermissionError',
            'PERMISSION_DENIED',
            id='destination-permission',
        ),
    ],
)
def test_remote_copy_preserves_typed_writer_failures(
    writer_error, expected_type, expected_code,
):
    from app.remote_transfer import TransferBudget, copy_remote_entry
    from app.transfer_errors import classify_transfer_failure

    class FailingWriterBackend(_Backend):
        @contextmanager
        def open_atomic_writer(
            self, _source, _path, *, replace, cancel_event,
            io_lane='control',
        ):
            assert io_lane == 'transfer'
            yield _PartialWriter()
            raise writer_error()

    with pytest.raises(Exception) as failure:
        copy_remote_entry(
            _source('smb', _Backend({'/source.bin': b'value'})),
            '/source.bin',
            _source('smb', FailingWriterBackend()),
            '/target.bin',
            conflict_policy='error',
            budget=TransferBudget(max_bytes=10, max_members=1),
            cancel_event=Event(), progress=None, chunk_size=2,
        )

    assert type(failure.value).__name__ == expected_type
    assert classify_transfer_failure(
        failure.value, operation='remote_transfer'
    ).code == expected_code


def test_directory_copy_rejects_existing_root_before_mutation():
    from app.remote_transfer import (
        RemoteTransferConflict,
        TransferBudget,
        copy_remote_entry,
    )

    source_backend = _Backend(
        files={'/folder/a.bin': b'a'},
        tree=[{
            'name': 'a.bin', 'path': '/folder/a.bin', 'size': 1,
            'is_dir': False, 'is_symlink': False,
        }],
    )
    destination_backend = _Backend()
    destination_backend.created.append('/copy')

    with pytest.raises(RemoteTransferConflict):
        copy_remote_entry(
            _source('smb', source_backend), '/folder',
            _source('smb', destination_backend), '/copy',
            conflict_policy='error',
            budget=TransferBudget(max_bytes=10, max_members=2),
            cancel_event=Event(), progress=None, chunk_size=2,
        )

    assert destination_backend.created == ['/copy']
    assert destination_backend.commits == []


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
                reader = _BoundedReader(payloads[source.handle_id])
                yield FileReaderLease(
                    reader=reader,
                    size=len(payloads[source.handle_id]),
                )

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
