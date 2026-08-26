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
from app.file_backend import FileWriteOutcome
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

    def inspect_directory_access(self, path):
        self.calls.append(('inspect_directory_access', (path,), {}))
        response = self.responses.get('inspect_directory_access')
        if isinstance(response, Exception):
            raise response
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
        path = args[0] if args else None
        failure = self.failures.get((name, path), self.failures.get(name))
        if failure is not None:
            raise failure
        if name == 'stat':
            if path not in self.files:
                raise FileNotFoundError(path)
            return _Stat(size=len(self.files[path]))
        if name == 'open_file_no_follow':
            mode = kwargs['mode']
            self.open_modes.append((path, mode))
            if mode == 'rb':
                if path not in self.files:
                    raise FileNotFoundError(path)
                return BytesIO(self.files[path])
            if mode != 'xb':
                raise AssertionError(f'unsafe editor mode: {mode}')
            if path in self.files:
                raise FileExistsError(path)
            session = self

            class _StoredWrite(_Writable):
                def close(self):
                    if not self.closed:
                        session.files[path] = self.getvalue()
                    super().close()

            return _StoredWrite()
        if name in {'rename', 'replace'}:
            old_path, new_path = args
            if old_path not in self.files:
                raise FileNotFoundError(old_path)
            if name == 'rename' and new_path in self.files:
                raise FileExistsError(new_path)
            self.files[new_path] = self.files.pop(old_path)
            return None
        if name == 'remove':
            if path not in self.files:
                raise FileNotFoundError(path)
            del self.files[path]
            return None
        raise AssertionError(f'unexpected SMB operation: {name}')


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


def test_stat_or_raise_preserves_protocol_failure_for_transfer_boundaries():
    backend, source, session = _fixture()
    session.responses['stat'] = SMBProtocolError('PERMISSION_DENIED')

    with pytest.raises(SMBProtocolError) as exc:
        backend.stat_or_raise(source, '/restricted.txt', follow_links=False)

    assert exc.value.public_code == 'PERMISSION_DENIED'


def test_typed_directory_mutations_preserve_protocol_failure():
    backend, source, session = _fixture()
    session.responses['stat'] = _Stat(mode=0o040755, attributes=0x10)
    session.responses['mkdir'] = SMBProtocolError('PERMISSION_DENIED')

    assert backend.check_exists_or_raise(source, '/folder')['exists'] is True
    with pytest.raises(SMBProtocolError) as exc:
        backend.mkdir_or_raise(source, '/folder/new')

    assert exc.value.public_code == 'PERMISSION_DENIED'


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
    assert 'remove' in names  # generated temp only
    assert names.index('replace') < names.index('remove')
    removed = next(args[0] for name, args, _kwargs in session.calls if name == 'remove')
    assert removed != r'\\10.0.0.8\Docs\report.txt'


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


def test_recoverable_editor_swap_rolls_back_when_install_fails():
    backend, source, session = _stateful_fixture()
    original_revision = hashlib.sha256(b'old').hexdigest()

    def fail_temp_install(name, *args, **kwargs):
        path = args[0] if args else None
        if name == 'rename' and path and '.webssh-write-' in path:
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
        old_path = args[0] if args else ''
        if name == 'rename' and (
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
        path = args[0] if args else ''
        if name == 'remove' and '.webssh-recovery-' in path:
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


def test_non_permission_replace_failure_never_uses_direct_overwrite():
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
    assert outcome.error == 'Atomic replacement is unavailable'
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
    session.failures['replace'] = SMBProtocolError(public_code)

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


def test_transfer_lane_does_not_block_control_lane_navigation():
    backend, source, control_session = _fixture()
    transfer_session = _Session()
    transfer_session.responses['stat'] = _Stat(size=3)
    transfer_session.responses['open_file'] = BytesIO(b'abc')
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
    assert any(call[0] == 'open_file_no_follow' for call in transfer_session.calls)
    assert any(call[0] == 'scandir_no_follow' for call in control_session.calls)


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
