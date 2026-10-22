"""Tests for SFTP path sanitization and safe error reporting."""

import errno
from contextlib import contextmanager

import pytest


def test_remote_metadata_budget_counts_utf8_bytes_and_aggregate_overhead(
    monkeypatch,
):
    import config
    import app.sftp_handler as sftp_handler

    monkeypatch.setattr(config, 'REMOTE_FILENAME_MAX_BYTES', 4)
    with pytest.raises(sftp_handler.RemoteMetadataLimitExceeded):
        sftp_handler._TransferMemberBudget(10, metadata_limit=100).consume(
            'ééé'
        )

    budget = sftp_handler._TransferMemberBudget(10, metadata_limit=258)
    budget.consume('a')
    budget.consume('b')
    with pytest.raises(sftp_handler.RemoteMetadataLimitExceeded):
        budget.consume('c')


def test_remote_exception_text_is_not_reflected_to_file_control_clients(
    monkeypatch,
):
    from contextlib import contextmanager

    import app.sftp_handler as sftp_handler

    class HostileSFTP:
        def mkdir(self, _path):
            raise OSError('remote-controlled-' + ('x' * 1024 * 1024))

    @contextmanager
    def fake_session(_identifier):
        yield HostileSFTP(), 'session'

    monkeypatch.setattr(sftp_handler, 'sftp_session', fake_session)

    success, error = sftp_handler.create_directory('session', '/safe')

    assert success is False
    assert error == 'Remote file operation failed'
    assert len(error.encode('utf-8')) <= 512
    assert sftp_handler.public_sftp_error(
        sftp_handler.SFTPOperationError('application-authored error')
    ) == 'application-authored error'


@pytest.mark.parametrize('failure, expected', [
    (PermissionError(errno.EACCES, 'Permission denied', '/private/key'),
     'Permission denied'),
    (OSError(errno.EPERM, 'Operation not permitted', '/private/key'),
     'Permission denied'),
    (FileNotFoundError(errno.ENOENT, 'No such file', '/private/key'),
     'File or directory not found'),
    (NotADirectoryError(errno.ENOTDIR, 'Not a directory', '/private/key'),
     'Not a directory'),
    (FileExistsError(errno.EEXIST, 'File exists', '/private/key'),
     'File or directory already exists'),
    (OSError(errno.EROFS, 'Read-only file system', '/private/key'),
     'Remote file system is read-only'),
    (OSError(errno.ENOSPC, 'No space left on device', '/private/key'),
     'Remote file system is full'),
    (TimeoutError(errno.ETIMEDOUT, 'Timed out', '/private/key'),
     'Remote file operation timed out'),
    (OSError('Permission denied: /private/key'), 'Permission denied'),
])
def test_known_remote_file_failures_have_safe_reasons(failure, expected):
    import app.sftp_handler as sftp_handler

    reason = sftp_handler.public_sftp_error(failure)

    assert reason == expected
    assert '/private/key' not in reason


def test_directory_and_editor_save_report_permission_failure(monkeypatch):
    import app.sftp_handler as sftp_handler

    @contextmanager
    def denied_session(_identifier, **_kwargs):
        raise PermissionError(errno.EACCES, 'Permission denied', '/private/key')
        yield

    monkeypatch.setattr(sftp_handler, 'sftp_session', denied_session)
    monkeypatch.setattr(sftp_handler, 'mutation_session', denied_session)

    files, listing_error = sftp_handler.list_directory('session', '/private')
    save = sftp_handler.write_file_text('session', '/private/key', 'updated')

    assert files is None
    assert listing_error == 'Permission denied'
    assert save.success is False
    assert save.error == 'Permission denied'


def test_paramiko_directory_parser_rejects_huge_extended_attribute_count():
    import paramiko
    from paramiko.message import Message
    from paramiko.sftp import (
        CMD_CLOSE,
        CMD_HANDLE,
        CMD_NAME,
        CMD_OPENDIR,
        CMD_READDIR,
    )
    from paramiko.sftp_attr import SFTPAttributes
    import app.sftp_handler as sftp_handler

    class ProtocolSFTP(paramiko.SFTPClient):
        def __init__(self):
            self.requests = []

        def _adjust_cwd(self, path):
            return path

        def _log(self, *_args):
            pass

        def _request(self, command, *args):
            self.requests.append(command)
            message = Message()
            if command == CMD_OPENDIR:
                message.add_string(b'directory-handle')
                message.rewind()
                return CMD_HANDLE, message
            if command == CMD_READDIR:
                message.add_int(1)
                message.add_string('safe.txt')
                message.add_string('safe.txt')
                message.add_int(SFTPAttributes.FLAG_EXTENDED)
                message.add_int(0xffffffff)
                message.rewind()
                return CMD_NAME, message
            if command == CMD_CLOSE:
                return 0, message
            raise AssertionError(f'unexpected SFTP command {command}')

    sftp = ProtocolSFTP()

    with pytest.raises(sftp_handler.RemoteMetadataLimitExceeded):
        list(sftp_handler._iter_paramiko_directory_entries(sftp, '/'))

    assert sftp.requests == [CMD_OPENDIR, CMD_READDIR, CMD_CLOSE]


def test_paramiko_directory_parser_closes_on_oversized_handle(monkeypatch):
    import config
    import paramiko
    from paramiko.message import Message
    from paramiko.sftp import CMD_HANDLE, CMD_OPENDIR, CMD_READDIR
    import app.sftp_handler as sftp_handler

    monkeypatch.setattr(config, 'SFTP_MAX_HANDLE_BYTES', 256)

    class ProtocolSFTP(paramiko.SFTPClient):
        def __init__(self):
            self.requests = []
            self.channel_closed = False

        def _adjust_cwd(self, path):
            return path

        def _log(self, *_args):
            pass

        def _request(self, command, *_args):
            self.requests.append(command)
            if command == CMD_READDIR:
                raise AssertionError('oversized handle must not be reflected')
            if command != CMD_OPENDIR:
                raise AssertionError(f'unexpected SFTP command {command}')
            message = Message()
            message.add_string(b'x' * 257)
            message.rewind()
            return CMD_HANDLE, message

        def close(self):
            self.channel_closed = True

    sftp = ProtocolSFTP()

    with pytest.raises(sftp_handler.RemoteMetadataLimitExceeded):
        list(sftp_handler._iter_paramiko_directory_entries(sftp, '/'))

    assert sftp.requests == [CMD_OPENDIR]
    assert sftp.channel_closed is True


@pytest.mark.parametrize(('responses', 'expected_error'), [
    pytest.param(
        ((),),
        'metadata',
        id='empty-name-response',
    ),
    pytest.param(
        (('.', '..'), ('.', '..')),
        'members',
        id='repeated-dot-entries',
    ),
])
def test_paramiko_directory_parser_bounds_non_yielding_responses(
    monkeypatch,
    responses,
    expected_error,
):
    import paramiko
    import config
    from paramiko.message import Message
    from paramiko.sftp import (
        CMD_CLOSE,
        CMD_HANDLE,
        CMD_NAME,
        CMD_OPENDIR,
        CMD_READDIR,
    )
    import app.sftp_handler as sftp_handler

    monkeypatch.setattr(config, 'MAX_TRANSFER_MEMBERS', 3)

    class ProtocolSFTP(paramiko.SFTPClient):
        def __init__(self):
            self.requests = []
            self.responses = iter(responses)

        def _adjust_cwd(self, path):
            return path

        def _log(self, *_args):
            pass

        def _request(self, command, *args):
            self.requests.append(command)
            message = Message()
            if command == CMD_OPENDIR:
                message.add_string(b'directory-handle')
                message.rewind()
                return CMD_HANDLE, message
            if command == CMD_READDIR:
                names = next(self.responses)
                message.add_int(len(names))
                for name in names:
                    message.add_string(name)
                    message.add_string(name)
                    message.add_int(0)
                message.rewind()
                return CMD_NAME, message
            if command == CMD_CLOSE:
                return 0, message
            raise AssertionError(f'unexpected SFTP command {command}')

    sftp = ProtocolSFTP()

    error_type = (
        sftp_handler.RemoteMetadataLimitExceeded
        if expected_error == 'metadata'
        else sftp_handler.TransferMemberLimitExceeded
    )
    with pytest.raises(error_type):
        list(sftp_handler._iter_paramiko_directory_entries(sftp, '/'))

    assert sftp.requests[-1] == CMD_CLOSE
    assert sftp.requests.count(CMD_READDIR) == len(responses)


def test_recursive_paramiko_listing_shares_raw_dot_metadata_budget(
    monkeypatch,
):
    import stat
    from types import SimpleNamespace

    import config
    import paramiko
    from paramiko.message import Message
    from paramiko.sftp import (
        CMD_CLOSE,
        CMD_HANDLE,
        CMD_NAME,
        CMD_OPENDIR,
        CMD_READDIR,
    )
    from paramiko.sftp_attr import SFTPAttributes
    import app.sftp_handler as sftp_handler

    # Each directory fits this limit independently, but their combined raw
    # dot-entry metadata does not. Recursive traversal must use one budget.
    monkeypatch.setattr(config, 'REMOTE_LISTING_MAX_METADATA_BYTES', 550)

    class ProtocolSFTP(paramiko.SFTPClient):
        def __init__(self):
            self.requests = []
            self.served_handles = set()

        def _adjust_cwd(self, path):
            return path

        def _log(self, *_args):
            pass

        def _request(self, command, *args):
            self.requests.append(command)
            message = Message()
            if command == CMD_OPENDIR:
                message.add_string(args[0].encode('utf-8'))
                message.rewind()
                return CMD_HANDLE, message
            if command == CMD_READDIR:
                handle = bytes(args[0])
                if handle in self.served_handles:
                    raise EOFError()
                self.served_handles.add(handle)
                names = (
                    ('.', '..', 'child')
                    if handle == b'/' else ('.', '..', 'leaf')
                )
                message.add_int(len(names))
                for name in names:
                    message.add_string(name)
                    message.add_string(name)
                    message.add_int(SFTPAttributes.FLAG_PERMISSIONS)
                    mode = (
                        stat.S_IFDIR | 0o700
                        if name == 'child' else stat.S_IFREG | 0o600
                    )
                    message.add_int(mode)
                message.rewind()
                return CMD_NAME, message
            if command == CMD_CLOSE:
                return 0, message
            raise AssertionError(f'unexpected SFTP command {command}')

        def lstat(self, path):
            is_directory = path == '/child'
            return SimpleNamespace(
                st_mode=(
                    stat.S_IFDIR | 0o700
                    if is_directory else stat.S_IFREG | 0o600
                ),
                st_size=0,
            )

    sftp = ProtocolSFTP()

    with pytest.raises(sftp_handler.RemoteMetadataLimitExceeded):
        sftp_handler.inspect_remote_tree(
            sftp,
            '/',
            cancel_event=None,
            max_bytes=1024,
            max_members=20,
        )

    assert sftp.requests.count(CMD_OPENDIR) == 2
    assert sftp.requests.count(CMD_CLOSE) == 2


def test_remote_attribute_extensions_count_toward_aggregate_budget():
    from types import SimpleNamespace
    import app.sftp_handler as sftp_handler

    budget = sftp_handler._TransferMemberBudget(10, metadata_limit=140)
    entry = SimpleNamespace(
        filename='a',
        _webssh_extra_metadata_bytes=12,
    )

    with pytest.raises(sftp_handler.RemoteMetadataLimitExceeded):
        budget.consume_entry(entry)


def test_directory_listing_is_returned_in_bounded_pages(monkeypatch):
    import stat
    from contextlib import contextmanager
    from types import SimpleNamespace

    import config
    import app.sftp_handler as sftp_handler

    entries = [
        SimpleNamespace(
            filename=name,
            st_size=index,
            st_mode=stat.S_IFREG | 0o600,
            st_mtime=index,
        )
        for index, name in enumerate(('one', 'two', 'three'))
    ]

    class EntryIterator:
        def __init__(self, values):
            self.values = iter(values)
            self.pulls = 0
            self.closed = False

        def __iter__(self):
            return self

        def __next__(self):
            value = next(self.values)
            self.pulls += 1
            return value

        def close(self):
            self.closed = True

    iterator = EntryIterator(entries)
    sessions = []

    class FakeSFTP:
        def listdir_iter(self, _path):
            return iterator

    @contextmanager
    def fake_session(identifier, *, io_lane='control'):
        sessions.append((identifier, io_lane, 'open'))
        try:
            yield FakeSFTP(), 'session'
        finally:
            sessions.append((identifier, io_lane, 'close'))

    monkeypatch.setattr(sftp_handler, 'sftp_session', fake_session)
    monkeypatch.setattr(config, 'REMOTE_FILENAME_MAX_BYTES', 64)
    monkeypatch.setattr(config, 'REMOTE_LISTING_MAX_METADATA_BYTES', 4096)

    listing, error = sftp_handler.open_directory_listing('session', '/')
    assert error is None

    first, error, has_more = listing.read_page(2)
    assert error is None
    assert [item['name'] for item in first] == ['one', 'two']
    assert has_more is True
    assert iterator.pulls == 3

    second, error, has_more = listing.read_page(2)
    assert error is None
    assert [item['name'] for item in second] == ['three']
    assert has_more is False
    assert iterator.closed is True
    assert sessions == [
        ('session', 'transfer', 'open'),
        ('session', 'transfer', 'close'),
    ]


def test_directory_page_member_budget_is_cumulative(monkeypatch):
    import stat
    from contextlib import contextmanager
    from types import SimpleNamespace

    import config
    import app.sftp_handler as sftp_handler

    entries = [
        SimpleNamespace(
            filename=f'item-{index}',
            st_size=index,
            st_mode=stat.S_IFREG | 0o600,
            st_mtime=index,
        )
        for index in range(4)
    ]

    class FakeSFTP:
        def listdir_iter(self, _path):
            return iter(entries)

    @contextmanager
    def fake_session(_identifier, *, io_lane='control'):
        assert io_lane == 'transfer'
        yield FakeSFTP(), 'session'

    monkeypatch.setattr(sftp_handler, 'sftp_session', fake_session)
    monkeypatch.setattr(config, 'MAX_TRANSFER_MEMBERS', 3)
    monkeypatch.setattr(config, 'REMOTE_FILENAME_MAX_BYTES', 64)
    monkeypatch.setattr(config, 'REMOTE_LISTING_MAX_METADATA_BYTES', 4096)

    listing, error = sftp_handler.open_directory_listing('session', '/')
    assert error is None
    first, error, has_more = listing.read_page(2)
    assert error is None
    assert len(first) == 2
    assert has_more is True

    second, error, has_more = listing.read_page(2)

    assert second is None
    assert error == 'Directory exceeds configured member limit'
    assert has_more is False


def test_transfer_lane_owns_and_closes_a_fresh_sftp_channel(monkeypatch):
    import app.sftp_handler as sftp_handler

    class FreshSFTP:
        closed = False

        def close(self):
            self.closed = True

    fresh = FreshSFTP()
    monkeypatch.setattr(
        sftp_handler,
        'get_sftp_client_fresh',
        lambda identifier: (
            (fresh, None) if identifier == 'session-a'
            else (None, 'missing')
        ),
    )
    monkeypatch.setattr(
        sftp_handler,
        '_get_sftp_lock',
        lambda _identifier: (_ for _ in ()).throw(
            AssertionError('transfer lane must not acquire the control lock')
        ),
    )

    with sftp_handler.sftp_session(
        'session-a', io_lane='transfer'
    ) as (client, source_type):
        assert client is fresh
        assert source_type == 'transfer'
        assert fresh.closed is False

    assert fresh.closed is True


@pytest.mark.parametrize('filename', ['probe.txt', r'report\draft.txt'])
def test_probe_sftp_capability_verifies_directory_access(monkeypatch, filename):
    from types import SimpleNamespace
    import app.sftp_handler as sftp_handler

    class ClosingIterator:
        def __init__(self):
            self.closed = False
            self.used = False

        def __iter__(self):
            return self

        def __next__(self):
            if self.used:
                raise StopIteration
            self.used = True
            return SimpleNamespace(filename=filename)

        def close(self):
            self.closed = True

    entries = ClosingIterator()
    fake_sftp = type('FakeSFTP', (), {
        'listdir_iter': lambda self, path: entries,
        'close': lambda self: None,
    })()
    transport = type('Transport', (), {'is_active': lambda self: True})()
    client = type('Client', (), {'get_transport': lambda self: transport})()
    monkeypatch.setitem(sftp_handler.ssh_manager.sessions, 'session-a', {
        'connected': True,
        'client': client,
    })
    monkeypatch.setattr(
        sftp_handler,
        'open_sftp_client',
        lambda *_args, **_kwargs: fake_sftp,
    )

    assert sftp_handler.probe_sftp_capability('session-a') is True
    assert entries.closed is True


def test_probe_sftp_capability_hides_remote_failure(monkeypatch):
    import app.sftp_handler as sftp_handler

    transport = type('Transport', (), {'is_active': lambda self: True})()
    client = type('Client', (), {'get_transport': lambda self: transport})()
    monkeypatch.setitem(sftp_handler.ssh_manager.sessions, 'session-a', {
        'connected': True,
        'client': client,
    })
    monkeypatch.setattr(
        sftp_handler,
        'open_sftp_client',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError('device-specific secret failure')
        ),
    )

    assert sftp_handler.probe_sftp_capability('session-a') is False


def test_probe_sftp_capability_explains_remote_channel_resource_shortage(
        monkeypatch):
    import paramiko
    import app.sftp_handler as sftp_handler

    transport = type('Transport', (), {'is_active': lambda self: True})()
    client = type('Client', (), {'get_transport': lambda self: transport})()
    monkeypatch.setitem(sftp_handler.ssh_manager.sessions, 'session-a', {
        'connected': True,
        'client': client,
    })
    monkeypatch.setattr(
        sftp_handler,
        'open_sftp_client',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            paramiko.ChannelException(4, 'server-controlled text')
        ),
    )
    logged = []
    monkeypatch.setattr(
        sftp_handler,
        'log_info',
        lambda message, **fields: logged.append((message, fields)),
    )

    assert (
        sftp_handler.probe_sftp_capability('session-a')
        == sftp_handler.CAPABILITY_RESOURCE_SHORTAGE
    )
    assert logged == [(
        'SFTP temporarily unavailable because the remote SSH server reported '
        'insufficient capacity for an additional channel',
        {
            'session_id': 'session-a',
            'ssh_channel_code': 4,
            'ssh_channel_reason': 'remote_resource_shortage',
        },
    )]


def test_probe_sftp_capability_uses_a_fresh_bounded_client(monkeypatch):
    from types import SimpleNamespace
    import app.sftp_handler as sftp_handler

    class FakeSFTP:
        def __init__(self):
            self.closed = False

        def listdir_iter(self, _path):
            return iter([SimpleNamespace(filename='probe.txt')])

        def close(self):
            self.closed = True

    class FakeClient:
        def get_transport(self):
            return type('Transport', (), {'is_active': lambda self: True})()

    fake_sftp = FakeSFTP()
    monkeypatch.setitem(sftp_handler.ssh_manager.sessions, 'session-a', {
        'connected': True,
        'client': FakeClient(),
    })
    observed = {}

    def open_client(transport, *, timeout, operation_timeout, deadline):
        observed.update(
            transport=transport,
            timeout=timeout,
            operation_timeout=operation_timeout,
            deadline=deadline,
        )
        return fake_sftp

    monkeypatch.setattr(sftp_handler, 'open_sftp_client', open_client)
    monkeypatch.setattr(
        sftp_handler,
        'sftp_session',
        lambda _session_id: pytest.fail('capability probe used cached SFTP'),
    )

    assert sftp_handler.probe_sftp_capability('session-a') is True
    assert observed['timeout'] <= 3
    assert observed['operation_timeout'] <= 3
    assert observed['deadline'] > 0
    assert fake_sftp.closed is True


def test_probe_sftp_capability_returns_retryable_busy_without_waiting(monkeypatch):
    import app.sftp_handler as sftp_handler

    held_lock = sftp_handler._acquire_capability_probe('session-a')
    assert held_lock is not None
    try:
        assert sftp_handler.probe_sftp_capability('session-a') is None
    finally:
        sftp_handler._release_capability_probe('session-a', held_lock)


def test_probe_sftp_capability_treats_deadline_closed_channel_as_retryable(monkeypatch):
    import app.sftp_handler as sftp_handler

    transport = type('Transport', (), {'is_active': lambda self: True})()
    client = type('Client', (), {'get_transport': lambda self: transport})()
    monkeypatch.setitem(sftp_handler.ssh_manager.sessions, 'session-a', {
        'connected': True,
        'client': client,
    })

    class DeadlineClosedSFTP:
        def listdir_iter(self, _path):
            raise EOFError('channel closed by deadline guard')

        def close(self):
            pass

    clock = iter([10.0, 10.1, 13.1])
    monkeypatch.setattr(sftp_handler.time, 'monotonic', lambda: next(clock))
    monkeypatch.setattr(
        sftp_handler,
        'open_sftp_client',
        lambda *_args, **_kwargs: DeadlineClosedSFTP(),
    )
    monkeypatch.setattr(
        sftp_handler,
        'Timer',
        lambda *_args, **_kwargs: type('Guard', (), {
            'daemon': True,
            'start': lambda self: None,
            'cancel': lambda self: None,
        })(),
    )

    assert sftp_handler.probe_sftp_capability('session-a') is None


class TestSanitizePath:
    """Tests for the sanitize_path function."""

    def test_normal_path(self):
        from app.sftp_handler import sanitize_path
        assert sanitize_path('/home/user/file.txt') == '/home/user/file.txt'

    def test_empty_path(self):
        from app.sftp_handler import sanitize_path
        assert sanitize_path('') == '.'
        assert sanitize_path('   ') == '.'

    def test_null_byte_blocked(self):
        from app.sftp_handler import sanitize_path
        assert sanitize_path('/home/user\x00/file') is None

    def test_path_traversal_blocked(self):
        from app.sftp_handler import sanitize_path
        assert sanitize_path('../../etc/passwd') is None
        assert sanitize_path('../secret') is None

    def test_relative_path(self):
        from app.sftp_handler import sanitize_path
        result = sanitize_path('documents/report.txt')
        assert result == 'documents/report.txt'

    def test_dot_path(self):
        from app.sftp_handler import sanitize_path
        assert sanitize_path('.') == '.'

    def test_none_path(self):
        from app.sftp_handler import sanitize_path
        assert sanitize_path(None) == '.'

    def test_absolute_path_allowed(self):
        from app.sftp_handler import sanitize_path
        assert sanitize_path('/var/log/syslog') == '/var/log/syslog'

    def test_normalized_double_slashes(self):
        from app.sftp_handler import sanitize_path
        result = sanitize_path('/home//user///file.txt')
        assert '//' not in result

    def test_trailing_slash_normalized(self):
        from app.sftp_handler import sanitize_path
        result = sanitize_path('/home/user/')
        assert result == '/home/user'

    def test_relative_escape_blocked(self):
        # A relative path that escapes upward keeps a '..' after normalization
        # and must be blocked.
        from app.sftp_handler import sanitize_path
        assert sanitize_path('foo/../../etc') is None

    def test_embedded_dotdot_filename_blocked(self):
        # Current contract is deliberately strict: any surviving '..' substring
        # is rejected, even inside a filename. Pinned so the behavior is explicit.
        from app.sftp_handler import sanitize_path
        assert sanitize_path('file..txt') is None

    def test_current_dir_segment_collapsed(self):
        from app.sftp_handler import sanitize_path
        assert sanitize_path('a/./b') == 'a/b'

    def test_absolute_dotdot_is_collapsed_and_allowed(self):
        # Documented design (docstring): absolute paths are allowed. normpath
        # collapses '..' against the root, so no traversal token survives.
        from app.sftp_handler import sanitize_path
        assert sanitize_path('/home/../etc') == '/etc'
        assert sanitize_path('/a/b/../../../../etc') == '/etc'

    def test_backslash_treated_as_literal_posix(self):
        # Regression lock for the posixpath fix: a backslash is a normal
        # filename character on remote (POSIX) servers, NOT a separator.
        # os.path on Windows would have split/converted this incorrectly.
        from app.sftp_handler import sanitize_path
        assert sanitize_path('folder\\file.txt') == 'folder\\file.txt'


@pytest.mark.parametrize(
    ('options', 'field'),
    [
        ({'max_bytes': -1}, 'max_bytes'),
        ({'max_bytes': 0}, 'max_bytes'),
        ({'max_bytes': True}, 'max_bytes'),
        ({'max_bytes': '1024'}, 'max_bytes'),
        ({'offset': -1}, 'offset'),
        ({'offset': False}, 'offset'),
        ({'tail_lines': 0}, 'tail_lines'),
        ({'tail_lines': True}, 'tail_lines'),
        ({'tail_lines': '10'}, 'tail_lines'),
    ],
)
def test_preview_options_reject_invalid_client_limits(options, field):
    """Malformed limits must fail before Paramiko can interpret them."""
    from app.sftp_handler import normalize_file_preview_options

    defaults = {'max_bytes': 512000, 'offset': 0, 'tail_lines': None}
    defaults.update(options)

    with pytest.raises(ValueError, match=field):
        normalize_file_preview_options(**defaults)


def test_preview_options_enforce_server_side_caps(monkeypatch):
    """A client cannot raise preview memory, seek, or tail-line limits."""
    import config
    from app.sftp_handler import normalize_file_preview_options

    monkeypatch.setattr(config, 'MAX_PREVIEW_SIZE', 4096)
    monkeypatch.setattr(config, 'MAX_SUPPORTED_FILE_SIZE', 8192)
    monkeypatch.setattr(config, 'MAX_PREVIEW_TAIL_LINES', 50)

    assert normalize_file_preview_options(
        max_bytes=10_000,
        offset=8192,
        tail_lines=50,
    ) == (4096, 8192, 50)

    with pytest.raises(ValueError, match='offset'):
        normalize_file_preview_options(
            max_bytes=1024,
            offset=8193,
            tail_lines=None,
        )
    with pytest.raises(ValueError, match='tail_lines'):
        normalize_file_preview_options(
            max_bytes=1024,
            offset=0,
            tail_lines=51,
        )


def test_preview_rejects_negative_read_before_opening_sftp(monkeypatch):
    """A negative Paramiko read size can never reach the remote file."""
    import app.sftp_handler as sftp_handler

    monkeypatch.setattr(
        sftp_handler,
        'sftp_session',
        lambda _session_id: pytest.fail('invalid options opened SFTP'),
    )

    result, error = sftp_handler.read_file_preview(
        'session', '/large.log', max_bytes=-1
    )

    assert result is None
    assert error == 'max_bytes must be a positive integer'


def test_preview_limit_uses_fstat_from_the_open_object(monkeypatch):
    """A rename between path stat and open must not bypass preview limits."""
    import io
    import stat
    from contextlib import contextmanager
    from types import SimpleNamespace

    import app.sftp_handler as sftp_handler
    import config

    class Replacement(io.BytesIO):
        def __init__(self):
            super().__init__(b'replacement')
            self.read_called = False

        def stat(self):
            return SimpleNamespace(
                st_size=11,
                st_mode=stat.S_IFREG | 0o600,
                st_mtime=1,
            )

        def read(self, size=-1):
            self.read_called = True
            return super().read(size)

    replacement = Replacement()
    sftp = SimpleNamespace(
        stat=lambda _path: SimpleNamespace(st_size=1),
        file=lambda *_args: replacement,
    )

    @contextmanager
    def fake_session(_session_id):
        yield sftp, 'session'

    monkeypatch.setattr(sftp_handler, 'sftp_session', fake_session)
    monkeypatch.setattr(config, 'MAX_SUPPORTED_FILE_SIZE', 8)

    result, error = sftp_handler.read_file_preview(
        'session', '/allowed/link.txt', max_bytes=8
    )

    assert result is None
    assert error == 'File too large (11 bytes). Maximum supported size is 8 bytes.'
    assert replacement.read_called is False


def test_editor_original_backup_preserves_mixed_newlines_and_encoding(monkeypatch):
    import base64
    import hashlib
    import io
    import stat
    from types import SimpleNamespace
    import app.sftp_handler as sftp_handler

    raw = b'caf\xe9\r\nsecond\nthird\r\n'

    class RemoteFile(io.BytesIO):
        def stat(self):
            return SimpleNamespace(st_size=len(raw), st_mode=stat.S_IFREG | 0o600)

    @contextmanager
    def fake_session(_session_id):
        yield SimpleNamespace(file=lambda *_args: RemoteFile(raw)), 'session'

    monkeypatch.setattr(sftp_handler, 'sftp_session', fake_session)
    result, error = sftp_handler.read_file_for_edit('session', '/report.txt')

    assert error is None
    assert result['content'] == 'caf\xe9\nsecond\nthird\n'
    assert result['revision'] == hashlib.sha256(raw).hexdigest()
    assert base64.b64decode(result['original_bytes']) == raw


def test_editor_limit_uses_fstat_from_the_open_object(monkeypatch):
    """Editor authorization must describe the object that supplies bytes."""
    import io
    import stat
    from contextlib import contextmanager
    from types import SimpleNamespace

    import app.sftp_handler as sftp_handler

    class Replacement(io.BytesIO):
        def stat(self):
            return SimpleNamespace(
                st_size=9,
                st_mode=stat.S_IFREG | 0o600,
                st_mtime=1,
            )

    sftp = SimpleNamespace(
        stat=lambda _path: SimpleNamespace(st_size=1),
        file=lambda *_args: Replacement(b'123456789'),
    )

    @contextmanager
    def fake_session(_session_id):
        yield sftp, 'session'

    monkeypatch.setattr(sftp_handler, 'sftp_session', fake_session)

    result, error = sftp_handler.read_file_for_edit(
        'session', '/allowed/link.txt', max_bytes=8
    )

    assert result is None
    assert error == 'File too large to edit (0MB). Maximum: 0MB'

@pytest.mark.parametrize('name', ['../outside', '/absolute', 'nested/file', r'nested\file', 'bad\x00name', '', 'résumé 日本語.txt', 'space name', '.hidden'])
@pytest.mark.parametrize('backend', ['wire', 'iter', 'attr'])
@pytest.mark.parametrize('with_budget', [False, True])
def test_directory_entry_boundary_rejects_untrusted_names(name, backend, with_budget):
    from types import SimpleNamespace
    import paramiko
    from paramiko.message import Message
    from paramiko.sftp import CMD_CLOSE, CMD_HANDLE, CMD_NAME, CMD_OPENDIR, CMD_READDIR
    import app.sftp_handler as handler

    closed = []

    def entries():
        try:
            yield SimpleNamespace(filename=name)
        finally:
            closed.append(True)

    class WireSFTP(paramiko.SFTPClient):
        def __init__(self):
            self.requests = []
            self.served = False
        def _adjust_cwd(self, path):
            return path
        def _log(self, *_args):
            pass
        def _request(self, command, *_args):
            self.requests.append(command)
            message = Message()
            if command == CMD_OPENDIR:
                message.add_string('handle')
                response = CMD_HANDLE
            elif command == CMD_READDIR:
                if self.served:
                    raise EOFError()
                self.served = True
                message.add_int(1)
                message.add_string(name)
                message.add_string(name)
                message.add_int(0)
                response = CMD_NAME
            else:
                assert command == CMD_CLOSE
                closed.append(True)
                response = 0
            message.rewind()
            return response, message

    sftp = WireSFTP() if backend == 'wire' else (
        SimpleNamespace(listdir_iter=lambda _path: entries()) if backend == 'iter'
        else SimpleNamespace(listdir_attr=lambda _path: entries())
    )
    budget = handler._TransferMemberBudget(10) if with_budget else None
    if name in ['résumé 日本語.txt', 'space name', '.hidden', r'nested\file']:
        with handler._directory_entries(sftp, '/selected', member_budget=budget) as listing:
            assert [entry.filename for entry in listing] == [name]
    else:
        with pytest.raises(handler.SFTPOperationError, match='unsafe directory entry name'):
            with handler._directory_entries(sftp, '/selected', member_budget=budget) as listing:
                list(listing)
    assert closed == [True]
    if budget:
        assert budget.used == 1


@pytest.mark.parametrize('backend', ['iter', 'attr'])
def test_directory_entry_boundary_preserves_safe_names_and_counts_dot_entries(backend):
    from types import SimpleNamespace
    import app.sftp_handler as handler
    names = ['.', '..', 'résumé 日本語.txt', 'space name', '.hidden']
    originals = [SimpleNamespace(filename=name) for name in names]
    sftp = SimpleNamespace(**{f'listdir_{backend}': lambda _path: iter(originals)})
    budget = handler._TransferMemberBudget(10)
    with handler._directory_entries(sftp, '/selected', member_budget=budget) as listing:
        assert list(listing) == originals[2:]
    assert budget.used == len(names)

@pytest.mark.parametrize('unsafe_name', ['../outside', '/absolute', 'bad\x00name'])
def test_directory_pagination_rejects_unsafe_continuation_and_closes(monkeypatch, unsafe_name):
    import stat
    from contextlib import contextmanager
    from types import SimpleNamespace
    import app.sftp_handler as handler
    closed = []
    def entries():
        try:
            for name in ['résumé.txt', '.hidden', unsafe_name]:
                yield SimpleNamespace(filename=name, st_mode=stat.S_IFREG | 0o600, st_size=1, st_mtime=0)
        finally:
            closed.append('iterator')
    @contextmanager
    def session(*_args, **_kwargs):
        try:
            yield SimpleNamespace(listdir_iter=lambda _path: entries()), 'session'
        finally:
            closed.append('session')
    monkeypatch.setattr(handler, 'sftp_session', session)
    listing, error = handler.open_directory_listing('session', '/selected')
    assert error is None
    page, error, more = listing.read_page(1)
    assert [item['name'] for item in page] == ['résumé.txt']
    assert error is None and more is True
    assert listing.read_page(1) == (None, 'unsafe directory entry name', False)
    assert closed == ['iterator', 'session']

@pytest.mark.parametrize('name', [r'report\draft.txt', r'folder\report.txt'])
def test_posix_backslash_listing_does_not_relax_transfer_destinations(name):
    from threading import Event
    from types import SimpleNamespace
    from app.remote_transfer import RemoteTransferError, TransferBudget, copy_remote_entry
    from app.smb_backend import SMBBackend
    import app.sftp_handler as handler

    assert handler.sanitize_path('/source/' + name) == '/source/' + name
    assert handler._is_safe_transfer_entry_name(name) is False
    smb = object.__new__(SMBBackend)
    assert smb.normalize_path('/target/' + name) is None
    source = SimpleNamespace(
        source_id='sftp-session:source',
        backend=SimpleNamespace(normalize_path=handler.sanitize_path),
    )
    destination = SimpleNamespace(source_id='smb-quick:target', backend=smb)
    # Invalid SMB targets are rejected before any source stat/read or write.
    with pytest.raises(RemoteTransferError, match='Invalid remote path'):
        copy_remote_entry(
            source, '/source/' + name, destination, '/target/' + name,
            conflict_policy='error', budget=TransferBudget(max_bytes=1024, max_members=10),
            cancel_event=Event(), progress=lambda *_args: None,
        )
