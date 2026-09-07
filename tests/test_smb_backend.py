from contextlib import contextmanager
import hashlib
from io import BytesIO
from types import SimpleNamespace
from threading import Event, RLock, Thread

import pytest

from app.file_sources import (
    FileSourceDescriptor,
    FileSourceKind,
    ResolvedFileSource,
    make_source_id,
)
from app.file_backend import (
    FileOperationCancelled,
    FileReaderLease,
    FileSourceChanged,
    FileWriteOutcome,
)
from app.smb_backend import (
    FileConflict,
    NonAtomicOverwriteRequired,
    SMBBackend,
    SMBBackendError,
)
from app.smb_paths import SMBShareName
from app.smb_protocol import SMBProtocolError


class _Stat:
    def __init__(
        self,
        *,
        size=0,
        mode=0o100644,
        attributes=0,
        modified=10,
        identity=1,
        links=1,
    ):
        self.st_size = size
        self.st_mode = mode
        self.st_file_attributes = attributes
        self.st_mtime = modified
        self.st_ino = identity
        self.st_nlink = links


class _Entry:
    def __init__(
        self,
        name,
        *,
        directory=False,
        reparse=False,
        size=0,
        identity=1,
    ):
        self.name = name
        self._directory = directory
        self._reparse = reparse
        attributes = (0x10 if directory else 0) | (0x400 if reparse else 0)
        self._stat = _Stat(
            size=size,
            mode=0o040755 if directory else 0o100644,
            attributes=attributes,
            identity=identity,
        )
        self.smb_info = SimpleNamespace(
            file_id=identity,
            file_attributes=attributes,
            end_of_file=size,
            last_write_time=10,
        )

    def stat(self, follow_symlinks=True):
        assert follow_symlinks is False
        return self._stat

    def is_dir(self, follow_symlinks=True):
        assert follow_symlinks is False
        return self._directory

    def is_symlink(self):
        return self._reparse


class _Iterator:
    def __init__(
        self,
        entries,
        *,
        identity_chain=(),
        children=None,
        child_identities=None,
    ):
        self._entries = iter(entries)
        self.closed = False
        self.identity_chain = identity_chain
        self.children = dict(children or {})
        self.child_identities = dict(child_identities or {})
        self.child_open_calls = []

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._entries)

    def open_child_directory(self, entry):
        self.child_open_calls.append(entry.name)
        expected = entry.smb_info.file_id
        actual = self.child_identities.get(entry.name, expected)
        if actual != expected:
            raise SMBProtocolError('CONFLICT')
        child = self.children.get(entry.name)
        if child is None:
            raise AssertionError(f'unexpected child traversal: {entry.name}')
        if callable(child):
            child = child(entry)
        child.identity_chain = (*self.identity_chain, actual)
        return child

    def close(self):
        self.closed = True


class _Writable(BytesIO):
    def close(self):
        self.saved = self.getvalue()
        super().close()


class _Readable(BytesIO):
    def __init__(self, data, *, attributes=0, declared_size=None):
        super().__init__(data)
        self.fd = SimpleNamespace(
            end_of_file=(len(data) if declared_size is None else declared_size),
            file_attributes=attributes,
        )


class _PartialWritable(_Writable):
    def write(self, data):
        return super().write(data[:2])


class _Session:
    def __init__(self):
        self.calls = []
        self.responses = {}

    def invoke(self, name, *args, **kwargs):
        self.calls.append((name, args, kwargs))
        if name == 'open_handle_matches_path_verified':
            handle, candidate = args
            return getattr(handle, 'path', None) == candidate
        if name in {
            'scandir_verified',
            'open_file_move_verified',
            'open_file_verified',
            'stat_verified',
            'delete_verified',
        }:
            expected = kwargs.get('expected_identities')
            if expected is not None and tuple(expected) != self._identity_chain(
                args[0]
            ):
                raise SMBProtocolError('CONFLICT')
        response = self.responses.get(name)
        if response is None and name == 'rename_open_handle_verified':
            response = self.responses.get(
                'replace' if kwargs.get('replace') else 'rename'
            )
        if response is None:
            aliases = {
                'open_file_no_follow': ('open_file',),
                'open_file_verified': (
                    'open_file_no_follow',
                    'open_file',
                ),
                'create_file_move_verified': (
                    'open_file_no_follow',
                    'open_file',
                ),
                'open_file_move_verified': (
                    'open_file_verified',
                    'open_file_no_follow',
                    'open_file',
                ),
                'scandir_no_follow': ('scandir',),
                'scandir_verified': ('scandir',),
                'stat_verified': ('stat',),
                'mkdir_no_follow': ('mkdir',),
            }.get(name, ())
            for alias in aliases:
                response = self.responses.get(alias)
                if response is not None:
                    break
        if isinstance(response, Exception):
            raise response
        if callable(response):
            if name == 'stat_verified' and 'stat_verified' not in self.responses:
                kwargs.setdefault('follow_symlinks', False)
            response = response(*args, **kwargs)
        if name == 'stat_verified' and response is not None:
            if hasattr(response, 'identity_chain'):
                return response
            chain = self._identity_chain(args[0])
            if chain:
                chain = (*chain[:-1], response.st_ino)
            return SimpleNamespace(
                file_id=response.st_ino,
                file_attributes=response.st_file_attributes,
                end_of_file=response.st_size,
                last_write_time=response.st_mtime,
                number_of_links=response.st_nlink,
                identity_chain=chain,
            )
        if name == 'scandir_verified' and response is not None:
            response.identity_chain = self._identity_chain(args[0])
        if name in {'delete_verified', 'delete_open_handle_verified'}:
            return response
        if name == 'create_file_move_verified' and response is not None:
            response.path = args[0]
        if (
            name == 'rename_open_handle_verified'
            and response is None
            and hasattr(args[0], 'path')
        ):
            args[0].path = args[1]
        return response

    def _identity_chain(self, path):
        parts = path[2:].split('\\')[2:]
        configured = self.responses.get('pinned_identities', {})
        root = '\\\\' + '\\'.join(path[2:].split('\\')[:2])
        return tuple(
            configured.get(root + '\\' + '\\'.join(parts[:index]), 1)
            for index in range(1, len(parts) + 1)
        )

    def inspect_directory_access(self, path):
        self.calls.append(('inspect_directory_access', (path,), {}))
        response = self.responses.get('inspect_directory_access')
        if isinstance(response, Exception):
            raise response
        return response

    def _pinned_identities(self, paths, expected_identities):
        configured = self.responses.get('pinned_identities', {})
        identities = {
            path: configured.get(path, 1)
            for path in paths
        }
        for path, expected in (expected_identities or {}).items():
            if identities.get(path) != expected:
                raise SMBProtocolError('CONFLICT')
        return identities

    @contextmanager
    def pin_directories(self, paths, *, expected_identities=None):
        paths = tuple(paths)
        self.calls.append((
            'pin_directories',
            (paths,),
            {'expected_identities': expected_identities or {}},
        ))
        yield self._pinned_identities(paths, expected_identities)

    @contextmanager
    def pin_mutation_ancestors(self, paths, *, expected_identities=None):
        paths = tuple(paths)
        self.calls.append((
            'pin_mutation_ancestors',
            (paths,),
            {'expected_identities': expected_identities or {}},
        ))
        yield self._pinned_identities(paths, expected_identities)


def _fixture():
    session = _Session()
    descriptor = FileSourceDescriptor(
        source_id=make_source_id(FileSourceKind.SMB_QUICK, 'abc'),
        kind='smb',
        label='Docs on nas.example',
        endpoint='nas.example/Docs',
        protocol='SMB 3.1.1',
        capabilities=(),
        ephemeral=True,
        security={},
    )
    smb_source = SimpleNamespace(
        source_id=descriptor.source_id,
        user_id='7',
        target_ip='10.0.0.8',
        share=SMBShareName.parse('Docs'),
        session=session,
        lock=RLock(),
    )

    class _Pool:
        def get_source(self, source_id, user_id):
            if source_id in {'abc', descriptor.source_id} and str(user_id) == '7':
                return smb_source
            return None

    backend = SMBBackend(_Pool())
    resolved = ResolvedFileSource(descriptor, '7', 'abc', backend)
    return backend, resolved, session


class _StatefulSMBSession(_Session):
    """Small in-memory SMB surface for editor replacement tests."""

    def __init__(self, original=b'old'):
        super().__init__()
        self.destination = r'\\10.0.0.8\Docs\report.txt'
        self.files = {self.destination: original}
        self.failures = {}
        self.open_modes = []

    def invoke(self, name, *args, **kwargs):
        self.calls.append((name, args, kwargs))
        subject = args[0] if args else None
        path = subject if isinstance(subject, str) else getattr(
            subject, 'path', None
        )
        failure = self.failures.get((name, path), self.failures.get(name))
        if failure is not None:
            raise failure
        if name in {'stat', 'stat_verified'}:
            if path not in self.files:
                raise FileNotFoundError(path)
            result = _Stat(size=len(self.files[path]))
            if name == 'stat':
                return result
            return SimpleNamespace(
                file_id=1,
                file_attributes=0,
                end_of_file=result.st_size,
                last_write_time=result.st_mtime,
                number_of_links=1,
                identity_chain=self._identity_chain(path),
            )
        if name in {
            'open_file_no_follow',
            'open_file_verified',
            'open_file_move_verified',
            'create_file_move_verified',
        }:
            mode = kwargs.get('mode', 'rb')
            if name == 'create_file_move_verified':
                mode = 'xb'
            self.open_modes.append((path, mode))
            if mode == 'rb':
                if path not in self.files:
                    raise FileNotFoundError(path)
                if name == 'open_file_move_verified':
                    handle = self._Handle(self, path, writable=False)
                    return handle, SimpleNamespace(
                        file_id=1,
                        file_attributes=0,
                        end_of_file=len(self.files[path]),
                        last_write_time=10,
                        number_of_links=1,
                        identity_chain=self._identity_chain(path),
                    )
                return _Readable(self.files[path])
            if mode != 'xb':
                raise AssertionError(f'unsafe editor mode: {mode}')
            if path in self.files:
                raise FileExistsError(path)
            self.files[path] = b''
            return self._Handle(self, path, writable=True)
        if name in {'rename', 'replace', 'rename_verified'}:
            old_path, new_path = args
            if old_path not in self.files:
                raise FileNotFoundError(old_path)
            replacing = name == 'replace' or kwargs.get('replace') is True
            if not replacing and new_path in self.files:
                raise FileExistsError(new_path)
            self.files[new_path] = self.files.pop(old_path)
            return None
        if name == 'rename_open_handle_verified':
            handle, new_path = args
            if handle.closed:
                raise AssertionError('closed handle was renamed')
            if handle.path not in self.files:
                raise FileNotFoundError(handle.path)
            if not kwargs.get('replace') and new_path in self.files:
                raise FileExistsError(new_path)
            data = (
                handle.getvalue()
                if handle.writable
                else self.files[handle.path]
            )
            self.files.pop(handle.path)
            self.files[new_path] = data
            handle.path = new_path
            return None
        if name == 'open_handle_matches_path_verified':
            handle, candidate = args
            if handle.closed:
                raise AssertionError('closed handle was queried')
            return handle.path == candidate
        if name == 'delete_open_handle_verified':
            handle = args[0]
            if handle.closed:
                raise AssertionError('closed handle was deleted')
            if handle.path not in self.files:
                raise FileNotFoundError(handle.path)
            handle.delete_pending = True
            self.files.pop(handle.path)
            return None
        if name == 'remove':
            if path not in self.files:
                raise FileNotFoundError(path)
            del self.files[path]
            return None
        raise AssertionError(f'unexpected SMB operation: {name}')

    class _Handle(BytesIO):
        def __init__(self, session, path, *, writable):
            super().__init__(session.files[path])
            self.session = session
            self.path = path
            self.writable = writable
            self.delete_pending = False

        def close(self):
            if not self.closed and self.writable and not self.delete_pending:
                self.session.files[self.path] = self.getvalue()
            super().close()


def _stateful_fixture(original=b'old'):
    backend, source, _session = _fixture()
    session = _StatefulSMBSession(original)
    actual = backend._pool().get_source(source.source_id, source.user_id)
    actual.session = session
    return backend, source, session


def test_listing_closes_iterator_and_marks_reparse_entries_unfollowable():
    backend, source, session = _fixture()
    iterator = _Iterator([
        _Entry('folder', directory=True),
        _Entry('link', directory=True, reparse=True),
    ])
    session.responses['scandir'] = iterator

    listing, error = backend.list_directory(source, '/')

    assert error is None
    assert iterator.closed is True
    assert listing[0]['is_dir'] is True
    assert listing[1]['is_dir'] is False
    assert listing[1]['is_symlink'] is True


def test_listing_preserves_valid_dollar_in_path_component():
    backend, source, session = _fixture()
    iterator = _Iterator([_Entry('budget$.xlsx', identity=17)])
    session.responses['scandir'] = iterator

    listing, error = backend.list_directory(source, '/reports')

    assert error is None
    assert listing == [{
        'name': 'budget$.xlsx',
        'path': '/reports/budget$.xlsx',
        'size': 0,
        'mode': 0o100666,
        'is_dir': False,
        'is_symlink': False,
        'modified': 10,
    }]
    assert iterator.closed is True


def test_overdeep_path_is_rejected_before_any_smb_operation():
    backend, source, session = _fixture()
    overdeep = '/' + '/'.join('a' for _ in range(129))

    listing, error = backend.list_directory(source, overdeep)

    assert listing is None
    assert error == 'Invalid path'
    assert session.calls == []


def test_paged_listing_reuses_one_bounded_scandir_iterator():
    backend, source, session = _fixture()
    iterator = _Iterator([
        _Entry('one'),
        _Entry('two'),
        _Entry('three'),
    ])
    session.responses['scandir'] = iterator

    listing, error = backend.open_directory_listing(source, '/')
    assert error is None
    first, error, has_more = listing.read_page(2)
    assert error is None
    assert [item['name'] for item in first] == ['one', 'two']
    assert has_more is True
    second, error, has_more = listing.read_page(2)

    assert error is None
    assert [item['name'] for item in second] == ['three']
    assert has_more is False
    assert iterator.closed is True
    assert [call[0] for call in session.calls].count('scandir_verified') == 1


def test_paged_listing_keeps_verified_scanner_open_until_exhausted():
    backend, source, session = _fixture()
    observed = []

    class LazyIterator(_Iterator):
        def __next__(self):
            observed.append(not self.closed)
            return super().__next__()

    session.responses['scandir'] = LazyIterator([_Entry('one', identity=31)])

    listing, error = backend.open_directory_listing(source, '/safe')

    assert error is None
    assert observed == []
    page, error, has_more = listing.read_page(10)
    assert error is None
    assert [item['name'] for item in page] == ['one']
    assert has_more is False
    assert observed == [True, True]
    assert listing._iterator is None


@pytest.mark.parametrize('missing_identity', [False, True])
def test_listing_fails_closed_when_server_identity_is_unavailable(
    missing_identity,
):
    backend, source, session = _fixture()
    entry = _Entry('unknown.txt', identity=0)
    if missing_identity:
        del entry.smb_info.file_id
    iterator = _Iterator([entry])
    session.responses['scandir'] = iterator

    listing, error = backend.list_directory(source, '/')

    assert listing is None
    assert error == 'SMB object identity is unavailable'
    assert iterator.closed is True


def test_paged_listing_member_budget_is_cumulative(monkeypatch):
    import config

    backend, source, session = _fixture()
    iterator = _Iterator([_Entry(str(index)) for index in range(4)])
    session.responses['scandir'] = iterator
    monkeypatch.setattr(config, 'MAX_TRANSFER_MEMBERS', 3)

    listing, error = backend.open_directory_listing(source, '/')
    assert error is None
    first, error, has_more = listing.read_page(2)
    assert error is None
    assert len(first) == 2
    assert has_more is True

    second, error, has_more = listing.read_page(2)

    assert second is None
    assert error == 'Directory exceeds configured member limit'
    assert has_more is False
    assert iterator.closed is True


def test_directory_access_inspection_uses_the_owned_share_confined_source():
    backend, source, session = _fixture()
    session.responses['inspect_directory_access'] = {
        'list': 'granted',
        'create_file': 'denied',
        'create_directory': 'unknown',
        'delete_children': 'granted',
    }

    access = backend.inspect_directory_access(source, '/')

    assert access == session.responses['inspect_directory_access']
    assert session.calls[-1] == (
        'inspect_directory_access',
        (r'\\10.0.0.8\Docs',),
        {},
    )


def test_directory_access_inspection_preserves_protocol_failure():
    backend, source, session = _fixture()
    session.responses['inspect_directory_access'] = SMBProtocolError(
        'PERMISSION_DENIED'
    )

    with pytest.raises(SMBProtocolError) as exc:
        backend.inspect_directory_access(source, '/')

    assert exc.value.public_code == 'PERMISSION_DENIED'


def test_non_root_access_inspection_uses_verified_session_boundary():
    backend, source, session = _fixture()

    def inspect(path):
        assert path == r'\\10.0.0.8\Docs\safe\nested'
        return {'list': 'granted'}

    session.inspect_directory_access = inspect

    assert backend.inspect_directory_access(source, '/safe/nested') == {
        'list': 'granted'
    }


def test_stat_or_raise_preserves_protocol_failure_for_transfer_boundaries():
    backend, source, session = _fixture()
    session.responses['stat'] = SMBProtocolError('PERMISSION_DENIED')

    with pytest.raises(SMBProtocolError) as exc:
        backend.stat_or_raise(source, '/restricted.txt', follow_links=False)

    assert exc.value.public_code == 'PERMISSION_DENIED'


def test_stat_uses_verified_protocol_metadata():
    backend, source, session = _fixture()

    def stat(path, *, follow_symlinks):
        assert follow_symlinks is False
        assert path == r'\\10.0.0.8\Docs\safe\file.txt'
        return _Stat(size=4)

    session.responses['stat'] = stat

    result = backend.stat_or_raise(source, '/safe/file.txt')

    assert result['size'] == 4
    assert result['_smb_identity_chain'] == (1, 1)
    assert session.calls[0][0] == 'stat_verified'


def test_typed_directory_mutations_preserve_protocol_failure():
    backend, source, session = _fixture()
    session.responses['stat'] = _Stat(mode=0o040755, attributes=0x10)
    session.responses['mkdir'] = SMBProtocolError('PERMISSION_DENIED')

    assert backend.check_exists_or_raise(source, '/folder')['exists'] is True
    with pytest.raises(SMBProtocolError) as exc:
        backend.mkdir_or_raise(source, '/folder/new')

    assert exc.value.public_code == 'PERMISSION_DENIED'


def test_listing_and_recursive_traversal_use_verified_directory_handles():
    backend, source, session = _fixture()
    session.responses['scandir'] = _Iterator([])
    session.responses['scandir_no_follow'] = _Iterator([])

    listing, error = backend.list_directory(source, '/')

    assert error is None
    assert listing == []
    assert any(call[0] == 'scandir_verified' for call in session.calls)

    session.calls.clear()
    list(backend.iter_tree(
        source,
        '/',
        budget=_MemberBudget(1),
        cancel_event=Event(),
    ))
    assert any(call[0] == 'scandir_verified' for call in session.calls)


def test_listing_rejects_unsafe_server_supplied_name_and_closes_iterator():
    backend, source, session = _fixture()
    iterator = _Iterator([_Entry('../escape')])
    session.responses['scandir'] = iterator

    listing, error = backend.list_directory(source, '/')

    assert listing is None
    assert error == 'Unsafe directory response'
    assert iterator.closed is True


def test_stat_never_follows_or_accepts_reparse_points():
    backend, source, session = _fixture()
    session.responses['stat'] = _Stat(attributes=0x400)

    result, error = backend.stat(source, '/link', follow_links=False)

    assert result is None
    assert error == 'Reparse points are not supported'
    assert session.calls[0][0] == 'stat_verified'


def test_mutations_reject_reparse_ancestors_before_side_effects():
    mutating_names = {
        'create_file_move_verified',
        'delete_open_handle_verified',
        'mkdir',
        'remove',
        'rename',
        'rename_open_handle_verified',
        'rename_verified',
        'replace',
        'rmdir',
    }

    def fixture_with_reparse_ancestor():
        backend, source, session = _fixture()

        def path_stat(path, *, follow_symlinks):
            assert follow_symlinks is False
            if path.endswith(r'\link'):
                return _Stat(mode=0o040755, attributes=0x410)
            return _Stat()

        session.responses['stat'] = path_stat
        return backend, source, session

    backend, source, session = fixture_with_reparse_ancestor()
    success, error = backend.mkdir(source, '/link/new')
    assert success is False
    assert error == 'Reparse points are not supported'
    assert not any(call[0] in mutating_names for call in session.calls)

    backend, source, session = fixture_with_reparse_ancestor()
    session.responses['stat_verified'] = SMBProtocolError(
        'REPARSE_POINT_REJECTED'
    )
    success, error = backend.delete(
        source,
        '/link/file',
        recursive=False,
        budget=_MemberBudget(1),
        cancel_event=Event(),
    )
    assert success is False
    assert error == 'Reparse points are not supported'
    assert not any(call[0] in mutating_names for call in session.calls)

    backend, source, session = fixture_with_reparse_ancestor()
    success, error = backend.rename(source, '/link/old', '/safe/new')
    assert success is False
    assert error == 'Reparse points are not supported'
    assert not any(call[0] in mutating_names for call in session.calls)


def test_rename_uses_verified_source_handle_operation():
    backend, source, session = _fixture()
    session.responses['stat'] = _Stat()

    success, error = backend.rename(
        source,
        '/old.txt',
        '/renamed.txt',
    )

    assert success is True
    assert error is None
    rename_call = next(
        call for call in session.calls if call[0] == 'rename_verified'
    )
    assert rename_call[1] == (
        r'\\10.0.0.8\Docs\old.txt',
        r'\\10.0.0.8\Docs\renamed.txt',
    )
    assert rename_call[2] == {'replace': False}


def test_atomic_writer_rejects_reparse_parent_before_creating_temp_file():
    backend, source, session = _fixture()

    def path_stat(path, *, follow_symlinks):
        assert follow_symlinks is False
        if path.endswith(r'\link'):
            return _Stat(mode=0o040755, attributes=0x410)
        return _Stat()

    session.responses['stat'] = path_stat
    session.responses['open_file'] = _Writable()
    session.responses['open_file_no_follow'] = _Writable()

    with pytest.raises(SMBBackendError, match='Reparse points'):
        with backend.open_atomic_writer(
            source,
            '/link/report.txt',
            replace=True,
            cancel_event=Event(),
        ) as remote:
            remote.write(b'new')

    assert all(
        name not in {
            'create_file_move_verified',
            'open_file',
            'open_file_no_follow',
        }
        for name, _args, _kwargs in session.calls
    )


def test_atomic_replace_never_predeletes_existing_target():
    backend, source, session = _fixture()
    writer = _Writable()
    session.responses['open_file'] = writer
    session.responses['replace'] = SMBProtocolError('CONFLICT')

    with pytest.raises(FileConflict):
        with backend.open_atomic_writer(
            source,
            '/report.txt',
            replace=True,
            cancel_event=Event(),
        ) as remote:
            remote.write(b'new')

    names = [name for name, _args, _kwargs in session.calls]
    assert 'delete_open_handle_verified' in names
    assert names.index('rename_open_handle_verified') < names.index(
        'delete_open_handle_verified'
    )
    deleted = next(
        args[0]
        for name, args, _kwargs in session.calls
        if name == 'delete_open_handle_verified'
    )
    assert deleted is writer


def test_editor_read_returns_revision_of_exact_remote_bytes():
    backend, source, session = _stateful_fixture(b'old\r\ntext')

    result, error = backend.read_file_for_edit(source, '/report.txt')

    assert error is None
    assert result['content'] == 'old\ntext'
    assert result['revision'] == hashlib.sha256(b'old\r\ntext').hexdigest()


def test_editor_save_rejects_missing_or_changed_revision_before_staging():
    backend, source, session = _stateful_fixture()

    missing = backend.write_file_text(
        source,
        '/report.txt',
        'new',
        encoding='utf-8',
        newline='lf',
        expected_revision=None,
    )
    changed = backend.write_file_text(
        source,
        '/report.txt',
        'new',
        encoding='utf-8',
        newline='lf',
        expected_revision='0' * 64,
    )

    assert missing == FileWriteOutcome(
        success=False,
        error='The file changed on the server. Reopen it before saving.',
        code='EDIT_CONFLICT',
    )
    assert changed.code == 'EDIT_CONFLICT'
    assert session.files[session.destination] == b'old'
    assert all(mode != 'xb' for _path, mode in session.open_modes)


def test_recoverable_editor_swap_never_opens_destination_for_write():
    backend, source, session = _stateful_fixture()
    original_revision = hashlib.sha256(b'old').hexdigest()

    outcome = backend.write_file_text(
        source,
        '/report.txt',
        'new',
        encoding='utf-8',
        newline='lf',
        expected_revision=original_revision,
        replace_strategy='recoverable_swap',
    )

    assert outcome == FileWriteOutcome(
        success=True,
        revision=hashlib.sha256(b'new').hexdigest(),
    )
    assert session.files == {session.destination: b'new'}
    assert all(
        path != session.destination or mode == 'rb'
        for path, mode in session.open_modes
    )
    renames = [
        call for call in session.calls
        if call[0] == 'rename_open_handle_verified'
    ]
    deletes = [
        call for call in session.calls
        if call[0] == 'delete_open_handle_verified'
    ]
    assert len(renames) == 2
    destination_handle = renames[0][1][0]
    temporary_handle = renames[1][1][0]
    assert destination_handle is not temporary_handle
    assert deletes[-1][1][0] is destination_handle


def test_recoverable_editor_swap_rolls_back_when_install_fails():
    backend, source, session = _stateful_fixture()
    original_revision = hashlib.sha256(b'old').hexdigest()

    def fail_temp_install(name, *args, **kwargs):
        path = getattr(args[0], 'path', '') if args else ''
        if (
            name == 'rename_open_handle_verified'
            and '.webssh-write-' in path
        ):
            raise SMBProtocolError('PERMISSION_DENIED')
        return _StatefulSMBSession.invoke(session, name, *args, **kwargs)

    session.invoke = fail_temp_install

    outcome = backend.write_file_text(
        source,
        '/report.txt',
        'new',
        encoding='utf-8',
        newline='lf',
        expected_revision=original_revision,
        replace_strategy='recoverable_swap',
    )

    assert outcome.success is False
    assert outcome.code == 'SMB_RECOVERABLE_REPLACE_FAILED'
    assert outcome.recovery_leaves == ()
    assert session.files == {session.destination: b'old'}


def test_recoverable_editor_swap_preserves_safe_artifacts_when_rollback_fails():
    backend, source, session = _stateful_fixture()
    original_revision = hashlib.sha256(b'old').hexdigest()

    def fail_install_and_rollback(name, *args, **kwargs):
        old_path = getattr(args[0], 'path', '') if args else ''
        if name == 'rename_open_handle_verified' and (
            '.webssh-write-' in old_path or '.webssh-recovery-' in old_path
        ):
            raise SMBProtocolError('PERMISSION_DENIED')
        return _StatefulSMBSession.invoke(session, name, *args, **kwargs)

    session.invoke = fail_install_and_rollback

    outcome = backend.write_file_text(
        source,
        '/report.txt',
        'new',
        encoding='utf-8',
        newline='lf',
        expected_revision=original_revision,
        replace_strategy='recoverable_swap',
    )

    assert outcome.success is False
    assert outcome.code == 'SMB_RECOVERY_REQUIRED'
    assert len(outcome.recovery_leaves) == 2
    assert all('/' not in leaf and '\\' not in leaf for leaf in outcome.recovery_leaves)
    assert all(leaf in '\n'.join(session.files) for leaf in outcome.recovery_leaves)
    assert session.destination not in session.files


def test_recoverable_editor_swap_reports_retained_backup_after_cleanup_failure():
    backend, source, session = _stateful_fixture()
    original_revision = hashlib.sha256(b'old').hexdigest()

    original_invoke = session.invoke

    def fail_backup_cleanup(name, *args, **kwargs):
        path = getattr(args[0], 'path', '') if args else ''
        if (
            name == 'delete_open_handle_verified'
            and '.webssh-recovery-' in path
        ):
            raise SMBProtocolError('PERMISSION_DENIED')
        return original_invoke(name, *args, **kwargs)

    session.invoke = fail_backup_cleanup

    outcome = backend.write_file_text(
        source,
        '/report.txt',
        'new',
        encoding='utf-8',
        newline='lf',
        expected_revision=original_revision,
        replace_strategy='recoverable_swap',
    )

    assert outcome.success is True
    assert outcome.warning_code == 'SMB_RECOVERY_BACKUP_RETAINED'
    assert len(outcome.recovery_leaves) == 1
    assert session.files[session.destination] == b'new'


def test_atomic_replace_permission_failure_requires_explicit_non_atomic_consent():
    backend, source, session = _stateful_fixture()
    session.failures['replace'] = SMBProtocolError('PERMISSION_DENIED')

    outcome = backend.write_file_text(
        source,
        '/report.txt',
        'new',
        encoding='utf-8',
        newline='lf',
        expected_revision=hashlib.sha256(b'old').hexdigest(),
    )

    assert outcome.code == 'SMB_RECOVERABLE_REPLACE_REQUIRED'
    assert session.files[session.destination] == b'old'
    assert all(mode != 'wb' for _path, mode in session.open_modes)


def test_legacy_non_atomic_consent_never_truncates_the_destination():
    backend, source, session = _stateful_fixture()
    session.failures['replace'] = SMBProtocolError('PERMISSION_DENIED')

    outcome = backend.write_file_text(
        source,
        '/report.txt',
        'new',
        encoding='utf-8',
        newline='lf',
        allow_non_atomic=True,
        expected_revision=hashlib.sha256(b'old').hexdigest(),
    )

    assert outcome.code == 'SMB_RECOVERABLE_REPLACE_REQUIRED'
    assert all(
        mode != 'wb'
        for _path, mode in session.open_modes
    )


def test_default_editor_requires_recoverable_swap_without_remote_mutation():
    backend, source, session = _stateful_fixture()
    session.failures['replace'] = SMBProtocolError('CONFLICT')

    outcome = backend.write_file_text(
        source,
        '/report.txt',
        'new',
        encoding='utf-8',
        newline='lf',
        allow_non_atomic=True,
        expected_revision=hashlib.sha256(b'old').hexdigest(),
    )

    assert outcome.success is False
    assert outcome.code == 'SMB_RECOVERABLE_REPLACE_REQUIRED'
    assert not any(
        name in {
            'create_file_move_verified',
            'rename_open_handle_verified',
        }
        for name, _args, _kwargs in session.calls
    )
    assert all(
        mode != 'wb'
        for _path, mode in session.open_modes
    )


@pytest.mark.parametrize('public_code', [
    'TIMEOUT',
    'SHARE_UNAVAILABLE',
    'SOURCE_UNAVAILABLE',
    'NOT_FOUND',
])
def test_atomic_replace_preserves_actionable_non_conflict_failure(public_code):
    backend, source, session = _stateful_fixture()
    session.failures['rename_open_handle_verified'] = SMBProtocolError(
        public_code
    )

    with pytest.raises(SMBProtocolError) as caught:
        with backend.open_atomic_writer(
            source,
            '/report.txt',
            replace=True,
            cancel_event=None,
        ) as remote_file:
            remote_file.write(b'new')

    assert caught.value.public_code == public_code
    assert session.files == {session.destination: b'old'}


def test_atomic_replace_reconciles_a_committed_rename_with_lost_response():
    backend, source, session = _stateful_fixture()
    original_invoke = session.invoke

    def commit_then_timeout(name, *args, **kwargs):
        result = original_invoke(name, *args, **kwargs)
        if name == 'rename_open_handle_verified':
            raise SMBProtocolError('TIMEOUT')
        return result

    session.invoke = commit_then_timeout

    with backend.open_atomic_writer(
        source,
        '/report.txt',
        replace=True,
        cancel_event=None,
    ) as remote_file:
        remote_file.write(b'new')

    assert session.files == {session.destination: b'new'}
    assert not any(
        name == 'delete_open_handle_verified'
        for name, _args, _kwargs in session.calls
    )


def test_atomic_replace_does_not_fail_after_committed_close_response_loss(
    monkeypatch,
):
    backend, source, session = _stateful_fixture()
    original_close = session._Handle.close

    def close_then_timeout(remote_file):
        original_close(remote_file)
        raise TimeoutError('close response lost after handle closed')

    monkeypatch.setattr(session._Handle, 'close', close_then_timeout)

    with backend.open_atomic_writer(
        source,
        '/report.txt',
        replace=True,
        cancel_event=None,
    ) as remote_file:
        remote_file.write(b'new')

    assert session.files == {session.destination: b'new'}


def test_atomic_replace_taints_session_when_close_fails_before_send(
    monkeypatch,
):
    backend, source, session = _stateful_fixture()
    original_invoke = session.invoke
    original_close = session._Handle.close
    opened = []

    def capture_handles(name, *args, **kwargs):
        result = original_invoke(name, *args, **kwargs)
        if name == 'create_file_move_verified':
            opened.append(result)
        return result

    def close_session():
        session._closed = True
        for remote_file in opened:
            original_close(remote_file)
        return True

    session.invoke = capture_handles
    session._closed = False
    session.close = close_session
    monkeypatch.setattr(
        session._Handle,
        'close',
        lambda _remote_file: (_ for _ in ()).throw(
            TimeoutError('close request was not sent')
        ),
    )

    with backend.open_atomic_writer(
        source,
        '/report.txt',
        replace=True,
        cancel_event=None,
    ) as remote_file:
        remote_file.write(b'new')

    assert session._closed is True
    assert all(remote_file.closed for remote_file in opened)
    assert session.files == {session.destination: b'new'}


def test_atomic_replace_taints_session_and_propagates_close_interrupt(
    monkeypatch,
):
    backend, source, session = _stateful_fixture()
    original_invoke = session.invoke
    original_close = session._Handle.close
    opened = []

    def capture_handles(name, *args, **kwargs):
        result = original_invoke(name, *args, **kwargs)
        if name == 'create_file_move_verified':
            opened.append(result)
        return result

    def close_session():
        session._closed = True
        for remote_file in opened:
            original_close(remote_file)

    session.invoke = capture_handles
    session._closed = False
    session.close = close_session
    monkeypatch.setattr(
        session._Handle,
        'close',
        lambda _remote_file: (_ for _ in ()).throw(KeyboardInterrupt()),
    )

    with pytest.raises(KeyboardInterrupt):
        with backend.open_atomic_writer(
            source,
            '/report.txt',
            replace=True,
            cancel_event=None,
        ) as remote_file:
            remote_file.write(b'new')

    assert session._closed is True
    assert all(remote_file.closed for remote_file in opened)
    assert session.files == {session.destination: b'new'}


def test_recoverable_editor_taints_session_when_handle_close_is_unsent(
    monkeypatch,
):
    backend, source, session = _stateful_fixture()
    original_invoke = session.invoke
    original_close = session._Handle.close
    opened = []

    def capture_handles(name, *args, **kwargs):
        result = original_invoke(name, *args, **kwargs)
        if name == 'open_file_move_verified':
            opened.append(result[0])
        elif name == 'create_file_move_verified':
            opened.append(result)
        return result

    def close_session():
        session._closed = True
        for remote_file in opened:
            if not remote_file.closed:
                original_close(remote_file)
        return True

    session.invoke = capture_handles
    session._closed = False
    session.close = close_session
    monkeypatch.setattr(
        session._Handle,
        'close',
        lambda _remote_file: (_ for _ in ()).throw(
            TimeoutError('close request was not sent')
        ),
    )

    outcome = backend.write_file_text(
        source,
        '/report.txt',
        'new',
        encoding='utf-8',
        newline='lf',
        expected_revision=hashlib.sha256(b'old').hexdigest(),
        replace_strategy='recoverable_swap',
    )

    assert outcome.success is True
    assert session._closed is True
    assert all(remote_file.closed for remote_file in opened)
    assert session.files == {session.destination: b'new'}


def test_recoverable_editor_taints_session_and_propagates_close_interrupt(
    monkeypatch,
):
    backend, source, session = _stateful_fixture()
    original_invoke = session.invoke
    original_close = session._Handle.close
    opened = []

    def capture_handles(name, *args, **kwargs):
        result = original_invoke(name, *args, **kwargs)
        if name == 'open_file_move_verified':
            opened.append(result[0])
        elif name == 'create_file_move_verified':
            opened.append(result)
        return result

    def close_session():
        session._closed = True
        for remote_file in opened:
            if not remote_file.closed:
                original_close(remote_file)

    session.invoke = capture_handles
    session._closed = False
    session.close = close_session
    monkeypatch.setattr(
        session._Handle,
        'close',
        lambda _remote_file: (_ for _ in ()).throw(KeyboardInterrupt()),
    )

    with pytest.raises(KeyboardInterrupt):
        backend.write_file_text(
            source,
            '/report.txt',
            'new',
            encoding='utf-8',
            newline='lf',
            expected_revision=hashlib.sha256(b'old').hexdigest(),
            replace_strategy='recoverable_swap',
        )

    assert session._closed is True
    assert all(remote_file.closed for remote_file in opened)
    assert session.files == {session.destination: b'new'}


def test_recoverable_editor_closes_remaining_handle_after_close_interrupt(
    monkeypatch,
):
    backend, source, session = _stateful_fixture()
    original_invoke = session.invoke
    original_close = session._Handle.close
    opened = []
    close_count = 0

    def capture_handles(name, *args, **kwargs):
        result = original_invoke(name, *args, **kwargs)
        if name == 'open_file_move_verified':
            opened.append(result[0])
        elif name == 'create_file_move_verified':
            opened.append(result)
        return result

    def close_then_interrupt_first(remote_file):
        nonlocal close_count
        close_count += 1
        original_close(remote_file)
        if close_count == 1:
            raise KeyboardInterrupt

    session.invoke = capture_handles
    monkeypatch.setattr(
        session._Handle,
        'close',
        close_then_interrupt_first,
    )

    with pytest.raises(KeyboardInterrupt):
        backend.write_file_text(
            source,
            '/report.txt',
            'new',
            encoding='utf-8',
            newline='lf',
            expected_revision=hashlib.sha256(b'old').hexdigest(),
            replace_strategy='recoverable_swap',
        )

    assert len(opened) == 2
    assert close_count == 2
    assert all(remote_file.closed for remote_file in opened)
    assert session.files == {session.destination: b'new'}


def test_atomic_replace_never_cleans_an_ambiguous_rename_handle():
    backend, source, session = _stateful_fixture()
    original_invoke = session.invoke

    def commit_then_lose_all_responses(name, *args, **kwargs):
        if name == 'open_handle_matches_path_verified':
            raise SMBProtocolError('TIMEOUT')
        result = original_invoke(name, *args, **kwargs)
        if name == 'rename_open_handle_verified':
            raise SMBProtocolError('TIMEOUT')
        return result

    session.invoke = commit_then_lose_all_responses

    with pytest.raises(SMBProtocolError) as caught:
        with backend.open_atomic_writer(
            source,
            '/report.txt',
            replace=True,
            cancel_event=None,
        ) as remote_file:
            remote_file.write(b'new')

    assert caught.value.public_code == 'TIMEOUT'
    assert session.files == {session.destination: b'new'}
    assert not any(
        name == 'delete_open_handle_verified'
        for name, _args, _kwargs in session.calls
    )


def test_editor_swap_reconciles_committed_recovery_rename_response_loss():
    backend, source, session = _stateful_fixture()
    original_invoke = session.invoke
    response_lost = False

    def commit_first_rename_then_timeout(name, *args, **kwargs):
        nonlocal response_lost
        result = original_invoke(name, *args, **kwargs)
        if name == 'rename_open_handle_verified' and not response_lost:
            response_lost = True
            raise SMBProtocolError('TIMEOUT')
        return result

    session.invoke = commit_first_rename_then_timeout

    outcome = backend.write_file_text(
        source,
        '/report.txt',
        'new',
        encoding='utf-8',
        newline='lf',
        expected_revision=hashlib.sha256(b'old').hexdigest(),
        replace_strategy='recoverable_swap',
    )

    assert outcome.success is True
    assert session.files == {session.destination: b'new'}


def test_editor_swap_reports_artifacts_when_rename_outcome_is_ambiguous():
    backend, source, session = _stateful_fixture()
    original_invoke = session.invoke

    def commit_then_lose_all_responses(name, *args, **kwargs):
        if name == 'open_handle_matches_path_verified':
            raise SMBProtocolError('TIMEOUT')
        result = original_invoke(name, *args, **kwargs)
        if name == 'rename_open_handle_verified':
            raise SMBProtocolError('TIMEOUT')
        return result

    session.invoke = commit_then_lose_all_responses

    outcome = backend.write_file_text(
        source,
        '/report.txt',
        'new',
        encoding='utf-8',
        newline='lf',
        expected_revision=hashlib.sha256(b'old').hexdigest(),
        replace_strategy='recoverable_swap',
    )

    assert outcome.success is False
    assert outcome.code == 'SMB_RECOVERY_REQUIRED'
    assert len(outcome.recovery_leaves) == 2
    assert session.destination not in session.files
    assert any('.webssh-recovery-' in path for path in session.files)
    assert any('.webssh-write-' in path for path in session.files)


def test_recoverable_editor_cleans_staging_file_on_base_exception(
    monkeypatch,
):
    backend, source, session = _stateful_fixture()
    original_write_all = backend._write_all

    def interrupt_after_write(remote_file, data):
        original_write_all(remote_file, data)
        raise KeyboardInterrupt

    monkeypatch.setattr(backend, '_write_all', interrupt_after_write)

    with pytest.raises(KeyboardInterrupt):
        backend.write_file_text(
            source,
            '/report.txt',
            'new',
            encoding='utf-8',
            newline='lf',
            expected_revision=hashlib.sha256(b'old').hexdigest(),
            replace_strategy='recoverable_swap',
        )

    assert session.files == {session.destination: b'old'}


@pytest.mark.parametrize(
    ('target_rename', 'timing'),
    ((1, 'before'), (1, 'after'), (2, 'before'), (2, 'after')),
)
def test_recoverable_editor_rolls_back_base_exception_around_each_rename(
    target_rename,
    timing,
):
    backend, source, session = _stateful_fixture()
    original_invoke = session.invoke
    rename_count = 0
    interrupted = False

    def interrupt_rename(name, *args, **kwargs):
        nonlocal interrupted, rename_count
        if name != 'rename_open_handle_verified' or interrupted:
            return original_invoke(name, *args, **kwargs)
        rename_count += 1
        if rename_count == target_rename and timing == 'before':
            interrupted = True
            raise KeyboardInterrupt
        result = original_invoke(name, *args, **kwargs)
        if rename_count == target_rename and timing == 'after':
            interrupted = True
            raise KeyboardInterrupt
        return result

    session.invoke = interrupt_rename

    with pytest.raises(KeyboardInterrupt):
        backend.write_file_text(
            source,
            '/report.txt',
            'new',
            encoding='utf-8',
            newline='lf',
            expected_revision=hashlib.sha256(b'old').hexdigest(),
            replace_strategy='recoverable_swap',
        )

    assert interrupted is True
    assert session.files == {session.destination: b'old'}


def test_recoverable_editor_preserves_install_if_backup_delete_is_interrupted():
    backend, source, session = _stateful_fixture()
    original_invoke = session.invoke
    interrupted = False

    def delete_then_interrupt(name, *args, **kwargs):
        nonlocal interrupted
        result = original_invoke(name, *args, **kwargs)
        if name == 'delete_open_handle_verified' and not interrupted:
            interrupted = True
            raise KeyboardInterrupt
        return result

    session.invoke = delete_then_interrupt

    with pytest.raises(KeyboardInterrupt):
        backend.write_file_text(
            source,
            '/report.txt',
            'new',
            encoding='utf-8',
            newline='lf',
            expected_revision=hashlib.sha256(b'old').hexdigest(),
            replace_strategy='recoverable_swap',
        )

    assert interrupted is True
    assert session.files == {session.destination: b'new'}


def test_cancelled_atomic_write_cleans_only_generated_temp():
    backend, source, session = _fixture()
    session.responses['open_file'] = _Writable()
    cancelled = Event()

    with pytest.raises(FileOperationCancelled, match='cancelled'):
        with backend.open_atomic_writer(
            source,
            '/report.txt',
            replace=True,
            cancel_event=cancelled,
        ) as remote:
            remote.write(b'partial')
            cancelled.set()

    assert all(
        name != 'rename_open_handle_verified'
        for name, args, _kwargs in session.calls
    )
    assert any(
        name == 'delete_open_handle_verified'
        for name, _args, _kwargs in session.calls
    )


def test_atomic_writer_cleans_exact_temp_on_base_exception():
    backend, source, session = _fixture()
    writer = _Writable()
    session.responses['open_file'] = writer

    with pytest.raises(KeyboardInterrupt):
        with backend.open_atomic_writer(
            source,
            '/report.txt',
            replace=True,
            cancel_event=None,
        ) as remote:
            remote.write(b'partial')
            raise KeyboardInterrupt

    deleted = [
        args[0]
        for name, args, _kwargs in session.calls
        if name == 'delete_open_handle_verified'
    ]
    assert deleted == [writer]


def test_share_root_mutations_are_rejected_before_remote_io():
    backend, source, session = _fixture()

    assert backend.mkdir(source, '/') == (False, 'Share root cannot be modified')
    assert backend.rename(source, '/', '/renamed') == (
        False, 'Share root cannot be modified'
    )
    assert backend.rename(source, '/old', '/') == (
        False, 'Share root cannot be modified'
    )
    assert backend.delete(
        source,
        '/',
        recursive=True,
        budget=_MemberBudget(10),
        cancel_event=Event(),
    ) == (False, 'Share root cannot be modified')

    assert session.calls == []


def test_preview_uses_opened_size_when_path_size_is_stale():
    backend, source, session = _fixture()
    session.responses['stat'] = _Stat(size=3)
    session.responses['open_file'] = _Readable(b'abcd')

    result, error = backend.read_file_preview(
        source,
        '/growing.txt',
        max_bytes=3,
        offset=0,
        tail_lines=None,
    )

    assert error is None
    assert result['content'] == 'abc'
    assert result['size'] == 4
    assert result['truncated'] is True


def test_preview_rejects_growth_after_the_handle_metadata_was_bound():
    backend, source, session = _fixture()
    session.responses['stat'] = _Stat(size=3)
    session.responses['open_file'] = _Readable(
        b'abcd',
        declared_size=3,
    )

    result, error = backend.read_file_preview(
        source,
        '/growing.txt',
        max_bytes=3,
        offset=0,
        tail_lines=None,
    )

    assert result is None
    assert error == 'File exceeds preview limit'


def test_preview_truncates_a_file_that_was_already_over_the_limit():
    backend, source, session = _fixture()
    session.responses['stat'] = _Stat(size=6)
    session.responses['open_file'] = _Readable(b'abcdef')

    result, error = backend.read_file_preview(
        source,
        '/large.txt',
        max_bytes=3,
        offset=0,
        tail_lines=None,
    )

    assert error is None
    assert result['content'] == 'abc'
    assert result['truncated'] is True


def test_open_reader_does_not_retry_when_caller_raises_attribute_error():
    backend, source, session = _fixture()
    session.responses['stat'] = _Stat(size=3)
    session.responses['open_file'] = _Readable(b'abc')
    yielded = 0

    with pytest.raises(AttributeError, match='caller failure'):
        with backend.open_reader(source, '/a.txt'):
            yielded += 1
            raise AttributeError('caller failure')

    assert yielded == 1


def test_transfer_lane_does_not_block_control_lane_navigation():
    backend, source, control_session = _fixture()
    transfer_session = _Session()
    transfer_session.responses['stat'] = _Stat(size=3)
    transfer_session.responses['open_file'] = _Readable(b'abc')
    control_session.responses['scandir'] = _Iterator([])
    actual = backend._pool().get_source(source.source_id, source.user_id)
    actual.control_session = control_session
    actual.transfer_session = transfer_session
    actual.control_lock = RLock()
    actual.transfer_lock = RLock()
    actual.session = control_session
    actual.lock = actual.control_lock
    transfer_entered = Event()
    release_transfer = Event()
    listing_finished = Event()
    listing_result = []

    def hold_transfer_reader():
        with backend.open_reader(
            source, '/large.bin', io_lane='transfer'
        ):
            transfer_entered.set()
            release_transfer.wait(2)

    def list_during_transfer():
        listing_result.append(backend.list_directory(source, '/'))
        listing_finished.set()

    transfer_thread = Thread(target=hold_transfer_reader)
    listing_thread = Thread(target=list_during_transfer)
    transfer_thread.start()
    try:
        assert transfer_entered.wait(1)
        listing_thread.start()
        assert listing_finished.wait(1)
    finally:
        release_transfer.set()
        transfer_thread.join(2)
        if listing_thread.ident is not None:
            listing_thread.join(2)

    assert listing_result == [([], None)]
    assert any(call[0] == 'open_file_verified' for call in transfer_session.calls)
    assert any(call[0] == 'scandir_verified' for call in control_session.calls)


def test_read_paths_open_the_validated_object_without_following_reparse_points():
    backend, source, session = _fixture()
    session.responses['stat'] = _Stat(size=3)
    session.responses['open_file'] = _Readable(b'bad')
    session.responses['open_file_no_follow'] = (
        lambda *_args, **_kwargs: _Readable(b'abc')
    )

    with backend.open_reader(source, '/a.txt') as lease:
        assert isinstance(lease, FileReaderLease)
        assert lease.reader.read() == b'abc'

    assert any(name == 'open_file_verified' for name, _args, _kwargs in session.calls)
    assert all(
        name != 'open_file'
        for name, _args, _kwargs in session.calls
    )

    session.calls.clear()
    result, error = backend.read_file_preview(
        source,
        '/a.txt',
        max_bytes=3,
        offset=0,
        tail_lines=None,
    )
    assert error is None
    assert result['content'] == 'abc'
    assert any(name == 'open_file_verified' for name, _args, _kwargs in session.calls)


def test_reader_uses_the_protocol_verified_leaf_handle():
    backend, source, session = _fixture()
    opened = _Readable(b'bound')

    def open_file(_path, **_kwargs):
        return opened

    session.responses['open_file_verified'] = open_file

    with backend.open_reader(source, '/safe/file.txt') as lease:
        assert lease.reader.read() == b'bound'

    assert opened.closed is True
    assert session.calls[0][0] == 'open_file_verified'


def test_reader_rejects_a_replaced_enumerated_identity_chain():
    backend, source, session = _fixture()
    file_unc = r'\\10.0.0.8\Docs\root\file.txt'
    session.responses['pinned_identities'] = {
        r'\\10.0.0.8\Docs\root': 99,
        file_unc: 30,
    }
    opened = []
    session.responses['open_file_verified'] = (
        lambda *_args, **_kwargs: opened.append(True)
    )

    with pytest.raises(FileSourceChanged) as error:
        with backend.open_reader(
            source,
            '/root/file.txt',
            _expected_identities=(10, 30),
        ):
            pass

    assert error.value.public_code == 'SOURCE_CHANGED'
    assert opened == []


@pytest.mark.parametrize('public_code', [
    'CONFLICT',
    'IDENTITY_UNAVAILABLE',
    'NOT_FOUND',
    'REPARSE_POINT_REJECTED',
])
def test_reader_maps_expected_leaf_open_races_to_source_changed(public_code):
    backend, source, session = _fixture()
    session.responses['open_file_verified'] = SMBProtocolError(public_code)

    with pytest.raises(FileSourceChanged) as error:
        with backend.open_reader(
            source,
            '/file.txt',
            _expected_identities=(1,),
        ):
            pass

    assert error.value.public_code == 'SOURCE_CHANGED'


def test_reader_preserves_conflict_without_an_expected_identity_chain():
    backend, source, session = _fixture()
    session.responses['open_file_verified'] = SMBProtocolError('CONFLICT')

    with pytest.raises(SMBProtocolError) as error:
        with backend.open_reader(source, '/file.txt'):
            pass

    assert error.value.public_code == 'CONFLICT'


def test_open_reader_uses_size_and_attributes_from_the_open_handle():
    """The SMB2 CREATE response, not a pathname stat, binds read policy."""
    backend, source, session = _fixture()
    session.responses['stat'] = _Stat(size=1)
    opened = _Readable(b'replacement', declared_size=11)
    session.responses['open_file'] = opened

    with backend.open_reader(source, '/swapped.txt') as lease:
        assert lease.reader is opened
        assert lease.size == 11
        assert lease.reader.read() == b'replacement'


def test_open_reader_rejects_reparse_attribute_from_the_open_handle():
    """A leaf swapped after component checks must still be rejected."""
    backend, source, session = _fixture()
    session.responses['stat'] = _Stat(size=1)
    session.responses['open_file'] = _Readable(
        b'link-target',
        attributes=0x400,
    )

    with pytest.raises(SMBBackendError, match='File is not readable'):
        with backend.open_reader(source, '/swapped.txt'):
            pass


class _MemberBudget:
    def __init__(self, limit):
        self.limit = limit
        self.used = 0

    def consume(self):
        self.used += 1
        if self.used > self.limit:
            raise SMBBackendError('member limit exceeded')


def test_iter_tree_is_bounded_and_never_enters_reparse_directories():
    backend, source, session = _fixture()
    nested = _Iterator([_Entry('file.txt', size=7)])
    root = _Iterator([
        _Entry('folder', directory=True),
        _Entry('link', directory=True, reparse=True),
    ], children={'folder': nested})

    session.responses['scandir'] = root
    budget = _MemberBudget(3)

    entries = list(backend.iter_tree(
        source,
        '/root',
        budget=budget,
        cancel_event=Event(),
    ))

    assert [entry['path'] for entry in entries] == [
        '/root/folder', '/root/folder/file.txt', '/root/link',
    ]
    assert entries[-1]['is_symlink'] is True
    assert root.closed is True
    assert nested.closed is True
    assert budget.used == 3
    assert [
        call[0] for call in session.calls
        if call[0] == 'scandir_verified'
    ] == ['scandir_verified']
    assert root.child_open_calls == ['folder']


def test_iter_tree_checks_member_limit_before_entering_next_directory():
    backend, source, session = _fixture()
    session.responses['scandir'] = _Iterator([
        _Entry('one'), _Entry('two', directory=True),
    ])

    with pytest.raises(SMBBackendError, match='member limit'):
        list(backend.iter_tree(
            source,
            '/',
            budget=_MemberBudget(1),
            cancel_event=Event(),
        ))

    assert len([
        call for call in session.calls if call[0] == 'scandir_verified'
    ]) == 1


def test_iter_tree_rejects_replaced_child_before_opening_it():
    backend, source, session = _fixture()
    root_unc = r'\\10.0.0.8\Docs\root'
    child_unc = root_unc + r'\child'
    session.responses['pinned_identities'] = {
        root_unc: 10,
        child_unc: 99,
    }
    session.responses['scandir'] = _Iterator(
        [_Entry('child', directory=True, identity=20)],
        child_identities={'child': 99},
    )

    with pytest.raises(FileSourceChanged) as error:
        list(backend.iter_tree(
            source,
            '/root',
            budget=_MemberBudget(2),
            cancel_event=Event(),
        ))

    assert error.value.public_code == 'SOURCE_CHANGED'
    assert [
        args[0] for name, args, _kwargs in session.calls
        if name == 'scandir_verified'
    ] == [root_unc]


@pytest.mark.parametrize('public_code', [
    'CONFLICT',
    'IDENTITY_UNAVAILABLE',
    'NOT_FOUND',
    'REPARSE_POINT_REJECTED',
])
def test_iter_tree_maps_expected_root_races_to_source_changed(public_code):
    backend, source, session = _fixture()
    session.responses['scandir_verified'] = SMBProtocolError(public_code)

    with pytest.raises(FileSourceChanged) as error:
        list(backend.iter_tree(
            source,
            '/root',
            budget=_MemberBudget(1),
            cancel_event=Event(),
            _expected_identities=(1,),
        ))

    assert error.value.public_code == 'SOURCE_CHANGED'


def test_iter_tree_preserves_unbound_root_not_found():
    backend, source, session = _fixture()
    session.responses['scandir_verified'] = SMBProtocolError('NOT_FOUND')

    with pytest.raises(SMBProtocolError) as error:
        list(backend.iter_tree(
            source,
            '/missing',
            budget=_MemberBudget(1),
            cancel_event=Event(),
        ))

    assert error.value.public_code == 'NOT_FOUND'


@pytest.mark.parametrize('public_code', [
    'CONFLICT',
    'IDENTITY_UNAVAILABLE',
    'NOT_FOUND',
    'REPARSE_POINT_REJECTED',
])
def test_iter_tree_maps_enumerated_child_races_without_root_token(
    public_code,
):
    backend, source, session = _fixture()

    class RacingIterator(_Iterator):
        def open_child_directory(self, entry):
            self.child_open_calls.append(entry.name)
            raise SMBProtocolError(public_code)

    root = RacingIterator([_Entry('child', directory=True, identity=20)])
    session.responses['scandir'] = root

    with pytest.raises(FileSourceChanged) as error:
        list(backend.iter_tree(
            source,
            '/root',
            budget=_MemberBudget(2),
            cancel_event=Event(),
        ))

    assert error.value.public_code == 'SOURCE_CHANGED'
    assert root.child_open_calls == ['child']


def test_iter_tree_holds_verified_child_scanner_until_it_is_exhausted():
    backend, source, session = _fixture()
    root_unc = r'\\10.0.0.8\Docs\root'
    child_unc = root_unc + r'\child'
    replacement_attempts = []
    session.responses['pinned_identities'] = {
        root_unc: 10,
        child_unc: 20,
    }

    class RacingChildIterator(_Iterator):
        def __next__(self):
            if getattr(self, '_primed', False):
                replacement_attempts.append(not self.closed)
            self._primed = True
            return super().__next__()

    child = RacingChildIterator([
        _Entry('one.txt', identity=31),
        _Entry('two.txt', identity=32),
    ])
    session.responses['scandir'] = _Iterator(
        [_Entry('child', directory=True, identity=20)],
        children={'child': child},
    )

    entries = list(backend.iter_tree(
        source,
        '/root',
        budget=_MemberBudget(3),
        cancel_event=Event(),
    ))

    assert [entry['path'] for entry in entries] == [
        '/root/child',
        '/root/child/one.txt',
        '/root/child/two.txt',
    ]
    assert replacement_attempts == [True, True]
    assert child.closed is True


@pytest.mark.parametrize('missing_identity', [False, True])
def test_iter_tree_fails_closed_when_entry_identity_is_unavailable(
    missing_identity,
):
    backend, source, session = _fixture()
    entry = _Entry('unknown.txt', identity=0)
    if missing_identity:
        del entry.smb_info.file_id
    iterator = _Iterator([entry])
    session.responses['scandir'] = iterator

    with pytest.raises(SMBBackendError, match='identity is unavailable'):
        list(backend.iter_tree(
            source,
            '/',
            budget=_MemberBudget(1),
            cancel_event=Event(),
        ))

    assert iterator.closed is True


def test_recursive_delete_is_postorder_and_rejects_reparse_points():
    backend, source, session = _fixture()
    root_unc = r'\\10.0.0.8\Docs\folder'
    session.responses['stat'] = _Stat(
        mode=0o040755,
        attributes=0x10,
        identity=90,
    )
    session.responses['pinned_identities'] = {
        root_unc: 90,
        root_unc + r'\file.txt': 91,
        root_unc + r'\sub': 92,
    }
    session.responses['scandir'] = _Iterator(
        [
            _Entry('file.txt', size=3, identity=91),
            _Entry('sub', directory=True, identity=92),
        ],
        children={'sub': _Iterator([])},
    )
    success, error = backend.delete(
        source,
        '/folder',
        recursive=True,
        budget=_MemberBudget(2),
        cancel_event=Event(),
    )

    assert error is None
    assert success is True
    mutations = [
        args[0]
        for name, args, kwargs in session.calls
        if name == 'delete_verified'
    ]
    assert mutations == [
        r'\\10.0.0.8\Docs\folder\file.txt',
        r'\\10.0.0.8\Docs\folder\sub',
        r'\\10.0.0.8\Docs\folder',
    ]
    assert [
        kwargs['expected_identities']
        for name, _args, kwargs in session.calls
        if name == 'delete_verified'
    ] == [(90, 91), (90, 92), (90,)]


def test_recursive_delete_rejects_selected_root_replacement_before_scan():
    backend, source, session = _fixture()
    root_unc = r'\\10.0.0.8\Docs\folder'
    session.responses['stat'] = _Stat(
        mode=0o040755,
        attributes=0x10,
        identity=40,
    )
    session.responses['pinned_identities'] = {root_unc: 41}
    session.responses['scandir'] = lambda *_args, **_kwargs: (
        (_ for _ in ()).throw(
            AssertionError('replacement root was enumerated')
        )
    )

    success, error = backend.delete(
        source,
        '/folder',
        recursive=True,
        budget=_MemberBudget(1),
        cancel_event=Event(),
    )

    assert success is False
    assert error == 'File conflict'
    assert not any(
        name == 'delete_verified'
        for name, _args, _kwargs in session.calls
    )


def test_recursive_delete_rejects_nested_parent_swap_after_traversal():
    backend, source, session = _fixture()
    root_unc = r'\\10.0.0.8\Docs\root'
    child_unc = root_unc + r'\child'
    session.responses['stat'] = _Stat(
        mode=0o040755,
        attributes=0x10,
        identity=10,
    )
    session.responses['pinned_identities'] = {
        root_unc: 10,
        child_unc: 20,
    }
    deleted = []
    session.responses['delete_verified'] = (
        lambda path, **_kwargs: deleted.append(path)
    )

    def swapped_tree(*_args, **_kwargs):
        yield {
            'name': 'child',
            'path': '/root/child',
            'size': 0,
            'mode': 0o040755,
            'is_dir': True,
            'is_symlink': False,
            '_smb_identity': 20,
            '_smb_identity_chain': (10, 20),
        }
        yield {
            'name': 'protected.txt',
            'path': '/root/child/protected.txt',
            'size': 1,
            'mode': 0o100644,
            'is_dir': False,
            'is_symlink': False,
            '_smb_identity': 30,
            '_smb_identity_chain': (10, 20, 30),
        }
        session.responses['pinned_identities'][child_unc] = 99

    backend.iter_tree = swapped_tree

    success, error = backend.delete(
        source,
        '/root',
        recursive=True,
        budget=_MemberBudget(2),
        cancel_event=Event(),
    )

    assert success is False
    assert error == 'File conflict'
    assert deleted == []


def test_binary_preview_is_bounded_even_if_file_grows():
    backend, source, session = _fixture()
    session.responses['stat'] = _Stat(size=2)
    session.responses['open_file'] = _Readable(b'abc')

    value, error = backend.read_binary_preview(source, '/file.bin', max_size=2)

    assert value is None
    assert error == 'File too large for download'


def test_paths_are_built_only_from_share_rooted_values():
    backend, source, session = _fixture()
    session.responses['stat'] = _Stat(size=0)

    assert backend.get_file_stat(source, r'\\other\share\file')[0] is None
    assert session.calls == []


def test_home_and_exists_use_backend_neutral_contract():
    backend, source, session = _fixture()
    session.responses['stat'] = _Stat(size=4)

    assert backend.get_home_directory(source) == ('/', None)
    assert backend.check_exists(source, '/a.txt') == (
        {'exists': True, 'is_dir': False, 'size': 4},
        None,
    )


def test_protocol_errors_have_stable_non_sensitive_messages():
    backend, source, session = _fixture()
    session.responses['scandir'] = SMBProtocolError('PERMISSION_DENIED')

    listing, error = backend.list_directory(source, '/denied')

    assert listing is None
    assert error == 'Permission denied'
