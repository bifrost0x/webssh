from contextlib import contextmanager
from io import BytesIO
from types import SimpleNamespace
from threading import Event, RLock

import pytest

from app.file_sources import (
    FileSourceDescriptor,
    FileSourceKind,
    ResolvedFileSource,
    make_source_id,
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
    def __init__(self, *, size=0, mode=0o100644, attributes=0, modified=10):
        self.st_size = size
        self.st_mode = mode
        self.st_file_attributes = attributes
        self.st_mtime = modified


class _Entry:
    def __init__(self, name, *, directory=False, reparse=False, size=0):
        self.name = name
        self._directory = directory
        self._reparse = reparse
        self._stat = _Stat(
            size=size,
            mode=0o040755 if directory else 0o100644,
            attributes=(0x400 if reparse else 0),
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
    def __init__(self, entries):
        self._entries = iter(entries)
        self.closed = False

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._entries)

    def close(self):
        self.closed = True


class _Writable(BytesIO):
    def close(self):
        self.saved = self.getvalue()
        super().close()


class _PartialWritable(_Writable):
    def write(self, data):
        return super().write(data[:2])


class _Session:
    def __init__(self):
        self.calls = []
        self.responses = {}

    def invoke(self, name, *args, **kwargs):
        self.calls.append((name, args, kwargs))
        response = self.responses.get(name)
        if response is None:
            response = self.responses.get({
                'open_file_no_follow': 'open_file',
                'scandir_no_follow': 'scandir',
                'mkdir_no_follow': 'mkdir',
            }.get(name, ''))
        if isinstance(response, Exception):
            raise response
        if callable(response):
            return response(*args, **kwargs)
        return response


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


def test_listing_and_recursive_traversal_use_no_follow_directory_opens():
    backend, source, session = _fixture()
    session.responses['scandir'] = _Iterator([])
    session.responses['scandir_no_follow'] = _Iterator([])

    listing, error = backend.list_directory(source, '/')

    assert error is None
    assert listing == []
    assert session.calls[0][0] == 'scandir_no_follow'

    session.calls.clear()
    list(backend.iter_tree(
        source,
        '/',
        budget=_MemberBudget(1),
        cancel_event=Event(),
    ))
    assert session.calls[0][0] == 'scandir_no_follow'


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
    assert session.calls[0][2]['follow_symlinks'] is False


def test_mutations_reject_reparse_ancestors_before_side_effects():
    mutating_names = {'mkdir', 'rename', 'replace', 'remove', 'rmdir'}

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
    success, error = backend.rename(source, '/link/old', '/safe/new')
    assert success is False
    assert error == 'Reparse points are not supported'
    assert not any(call[0] in mutating_names for call in session.calls)

    backend, source, session = fixture_with_reparse_ancestor()
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
        name not in {'open_file', 'open_file_no_follow'}
        for name, _args, _kwargs in session.calls
    )


def test_atomic_replace_never_predeletes_existing_target():
    backend, source, session = _fixture()
    writer = _Writable()
    session.responses['open_file'] = writer
    session.responses['replace'] = OSError('replace unsupported')

    with pytest.raises(FileConflict):
        with backend.open_atomic_writer(
            source,
            '/report.txt',
            replace=True,
            cancel_event=Event(),
        ) as remote:
            remote.write(b'new')

    names = [name for name, _args, _kwargs in session.calls]
    assert 'remove' in names  # generated temp only
    assert names.index('replace') < names.index('remove')
    removed = next(args[0] for name, args, _kwargs in session.calls if name == 'remove')
    assert removed != r'\\10.0.0.8\Docs\report.txt'


def test_atomic_replace_permission_failure_requires_explicit_non_atomic_consent():
    backend, source, session = _fixture()
    session.responses['open_file'] = _Writable()
    session.responses['replace'] = SMBProtocolError('PERMISSION_DENIED')

    with pytest.raises(NonAtomicOverwriteRequired):
        backend.write_file_text(
            source,
            '/report.txt',
            'new',
            encoding='utf-8',
            newline='lf',
        )

    open_modes = [
        kwargs['mode']
        for name, _args, kwargs in session.calls
        if name in {'open_file', 'open_file_no_follow'}
    ]
    assert open_modes == ['xb']


def test_explicit_non_atomic_consent_retries_with_direct_overwrite():
    backend, source, session = _fixture()
    atomic_writer = _Writable()
    direct_writer = _PartialWritable()

    def open_file(_path, *, mode, **_kwargs):
        if mode == 'xb':
            return atomic_writer
        if mode == 'wb':
            return direct_writer
        raise AssertionError(f'unexpected mode: {mode}')

    session.responses['open_file'] = open_file
    session.responses['open_file_no_follow'] = open_file
    session.responses['replace'] = SMBProtocolError('PERMISSION_DENIED')

    success, error = backend.write_file_text(
        source,
        '/report.txt',
        'new',
        encoding='utf-8',
        newline='lf',
        allow_non_atomic=True,
    )

    assert success is True
    assert error is None
    assert direct_writer.saved == b'new'
    assert [
        kwargs['mode']
        for name, _args, kwargs in session.calls
        if name in {'open_file', 'open_file_no_follow'}
    ] == ['xb', 'wb']
    assert any(
        name == 'open_file_no_follow' and kwargs['mode'] == 'wb'
        for name, _args, kwargs in session.calls
    )


def test_direct_overwrite_refuses_reparse_target_even_with_consent():
    backend, source, session = _fixture()
    atomic_writer = _Writable()

    def open_file(_path, *, mode, **_kwargs):
        if mode == 'xb':
            return atomic_writer
        raise AssertionError('direct overwrite must not open a reparse point')

    session.responses['open_file'] = open_file
    session.responses['replace'] = SMBProtocolError('PERMISSION_DENIED')
    session.responses['stat'] = _Stat(attributes=0x400)

    success, error = backend.write_file_text(
        source,
        '/report.txt',
        'new',
        encoding='utf-8',
        newline='lf',
        allow_non_atomic=True,
    )

    assert success is False
    assert error == 'Reparse points are not supported'
    assert next(
        kwargs for name, _args, kwargs in session.calls if name == 'stat'
    )['follow_symlinks'] is False


def test_non_permission_replace_failure_never_uses_direct_overwrite():
    backend, source, session = _fixture()
    session.responses['open_file'] = _Writable()
    session.responses['replace'] = SMBProtocolError('CONFLICT')

    success, error = backend.write_file_text(
        source,
        '/report.txt',
        'new',
        encoding='utf-8',
        newline='lf',
        allow_non_atomic=True,
    )

    assert success is False
    assert error == 'Atomic replacement is unavailable'
    assert all(
        kwargs['mode'] != 'wb'
        for name, _args, kwargs in session.calls
        if name == 'open_file'
    )


def test_cancelled_atomic_write_cleans_only_generated_temp():
    backend, source, session = _fixture()
    session.responses['open_file'] = _Writable()
    cancelled = Event()

    with pytest.raises(SMBBackendError, match='cancelled'):
        with backend.open_atomic_writer(
            source,
            '/report.txt',
            replace=True,
            cancel_event=cancelled,
        ) as remote:
            remote.write(b'partial')
            cancelled.set()

    assert all(
        args[0] != r'\\10.0.0.8\Docs\report.txt'
        for name, args, _kwargs in session.calls
        if name == 'remove'
    )


def test_preview_rejects_growth_beyond_limit():
    backend, source, session = _fixture()
    session.responses['stat'] = _Stat(size=3)
    session.responses['open_file'] = BytesIO(b'abcd')

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
    session.responses['open_file'] = BytesIO(b'abcdef')

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
    session.responses['open_file'] = BytesIO(b'abc')
    yielded = 0

    with pytest.raises(AttributeError, match='caller failure'):
        with backend.open_reader(source, '/a.txt'):
            yielded += 1
            raise AttributeError('caller failure')

    assert yielded == 1


def test_read_paths_open_the_validated_object_without_following_reparse_points():
    backend, source, session = _fixture()
    session.responses['stat'] = _Stat(size=3)
    session.responses['open_file'] = BytesIO(b'bad')
    session.responses['open_file_no_follow'] = (
        lambda *_args, **_kwargs: BytesIO(b'abc')
    )

    with backend.open_reader(source, '/a.txt') as remote:
        assert remote.read() == b'abc'

    assert any(
        name == 'open_file_no_follow' and kwargs['mode'] == 'rb'
        for name, _args, kwargs in session.calls
    )
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
    assert any(
        name == 'open_file_no_follow' and kwargs['mode'] == 'rb'
        for name, _args, kwargs in session.calls
    )


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
    root = _Iterator([
        _Entry('folder', directory=True),
        _Entry('link', directory=True, reparse=True),
    ])
    nested = _Iterator([_Entry('file.txt', size=7)])

    def scandir(path, **_kwargs):
        if path == r'\\10.0.0.8\Docs\root':
            return root
        if path == r'\\10.0.0.8\Docs\root\folder':
            return nested
        raise AssertionError(f'unexpected traversal: {path}')

    session.responses['scandir'] = scandir
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
        call for call in session.calls if call[0] == 'scandir_no_follow'
    ]) == 1


def test_recursive_delete_is_postorder_and_rejects_reparse_points():
    backend, source, session = _fixture()
    session.responses['stat'] = _Stat(mode=0o040755, attributes=0x10)
    session.responses['scandir'] = _Iterator([
        _Entry('file.txt', size=3),
        _Entry('sub', directory=True),
    ])

    def scandir(path, **_kwargs):
        if path.endswith(r'\sub'):
            return _Iterator([])
        return _Iterator([_Entry('file.txt', size=3), _Entry('sub', directory=True)])

    session.responses['scandir'] = scandir
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
        (name, args[0]) for name, args, _kwargs in session.calls
        if name in {'remove', 'rmdir'}
    ]
    assert mutations == [
        ('remove', r'\\10.0.0.8\Docs\folder\file.txt'),
        ('rmdir', r'\\10.0.0.8\Docs\folder\sub'),
        ('rmdir', r'\\10.0.0.8\Docs\folder'),
    ]


def test_binary_preview_is_bounded_even_if_file_grows():
    backend, source, session = _fixture()
    session.responses['stat'] = _Stat(size=2)
    session.responses['open_file'] = BytesIO(b'abc')

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
