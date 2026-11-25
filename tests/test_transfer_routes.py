"""HTTP streaming transfer boundary tests.

These tests deliberately use streams that reject unbounded reads.  A future
regression back to buffering the request or a remote file must therefore fail
at the route boundary, rather than merely consume more memory in production.
"""

from contextlib import contextmanager
import errno
import stat
from types import SimpleNamespace

import pytest

from app.file_backend import FileReaderLease
from app.sftp_backend import SFTPBackend


class BoundedRequestStream:
    """A WSGI input stream that treats ``read()`` without a size as a bug."""

    def __init__(self, payload):
        self._payload = payload
        self._offset = 0
        self.requested_sizes = []

    def read(self, size=-1):
        if size is None or size < 0:
            raise AssertionError('request stream must be read with a bound')
        self.requested_sizes.append(size)
        chunk = self._payload[self._offset:self._offset + size]
        self._offset += len(chunk)
        return chunk

    def tell(self):
        return self._offset

    def seek(self, offset, whence=0):
        if whence == 2:
            self._offset = len(self._payload) + offset
        elif whence == 0:
            self._offset = offset
        else:
            raise ValueError('test stream only supports absolute or end seeks')
        return self._offset


class TrackingRemoteFile:
    def __init__(self, payload=b'', *, declared_size=None):
        self.payload = payload
        self.declared_size = (
            len(payload) if declared_size is None else declared_size
        )
        self.offset = 0
        self.read_sizes = []
        self.written = bytearray()
        self.closed = False

    def read(self, size=-1):
        if size is None or size < 0:
            raise AssertionError('remote file must be read with a bound')
        self.read_sizes.append(size)
        chunk = self.payload[self.offset:self.offset + size]
        self.offset += len(chunk)
        return chunk

    def write(self, chunk):
        self.written.extend(chunk)

    def chmod(self, mode):
        self.permissions = mode

    def stat(self):
        return SimpleNamespace(
            st_size=self.declared_size,
            st_mode=stat.S_IFREG | getattr(self, 'permissions', 0o600),
            st_mtime=1,
        )

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class FakeSFTP:
    def __init__(self, download_payload=b''):
        self.download_file = TrackingRemoteFile(download_payload)
        self.upload_file = TrackingRemoteFile()
        self.opened = []
        self.renamed = []
        self.removed = []
        self.reported_size = len(download_payload)
        self.destination_exists = True

    def stat(self, _path):
        if not self.destination_exists:
            raise FileNotFoundError(_path)
        return SimpleNamespace(st_size=self.reported_size, st_mode=stat.S_IFREG | 0o600, st_mtime=1)

    def lstat(self, path):
        return self.stat(path)

    def file(self, path, mode):
        self.opened.append((path, mode))
        return self.download_file if mode == 'rb' else self.upload_file

    def rename(self, source, destination):
        self.renamed.append((source, destination))

    def remove(self, path):
        self.removed.append(path)


class PosixRenameSFTP(FakeSFTP):
    def __init__(self, *, supports_posix_rename):
        super().__init__()
        self.supports_posix_rename = supports_posix_rename
        self.posix_renamed = []

    def posix_rename(self, source, destination):
        if not self.supports_posix_rename:
            raise AttributeError('extension unavailable')
        self.posix_renamed.append((source, destination))


@pytest.fixture(autouse=True)
def exclusive_transfer_file_stub(monkeypatch):
    from app import sftp_handler

    @contextmanager
    def exclusive_file(client, path, *, mode=0o600):
        assert mode in (0o600, None)
        with client.file(path, 'wb') as remote:
            yield remote
    monkeypatch.setattr(sftp_handler, 'open_exclusive_file', exclusive_file)


@pytest.fixture
def transfer_components(monkeypatch):
    from app import transfer_routes
    from app.file_sources import SourceHoldSet
    from app.transfer_manager import TransferManager

    manager = TransferManager(token_ttl=60)
    monkeypatch.setattr(transfer_routes, 'transfer_manager', manager)
    monkeypatch.setattr(
        transfer_routes.file_service,
        'resolve',
        lambda *_args, **_kwargs: SimpleNamespace(
            handle_id='owned-session',
            backend=SFTPBackend(),
        ),
    )
    monkeypatch.setattr(
        transfer_routes.file_source_resolver,
        'acquire_transfer_holds',
        lambda _user_id, source_ids: SourceHoldSet(tuple(source_ids)),
    )
    return transfer_routes, manager


def _token(manager, user_id, direction, path='/remote/report.bin'):
    return manager.create(
        user_id=user_id,
        source_id='sftp-session:owned-session',
        direction=direction,
        metadata={'remote_path': path, 'filename': 'report.bin'},
    ).token


def _login(client, app, username):
    from app.auth import register_user

    with app.app_context():
        user, error = register_user(username, 'transfer-password-123')
        assert error is None
        user_id = str(user.id)
    response = client.post('/login', data={
        'username': username,
        'password': 'transfer-password-123',
    })
    assert response.status_code == 302
    return user_id


def test_download_reads_remote_file_in_bounded_chunks(app, client, monkeypatch,
                                                       transfer_components):
    """Replacing ``remote_file.read(chunk_size)`` with ``read()`` is a bug."""
    transfer_routes, manager = transfer_components
    payload = b'x' * (app.config['CHUNK_SIZE'] * 3 + 17)
    sftp = FakeSFTP(payload)

    @contextmanager
    def fake_session(_session_id, io_lane='control'):
        yield sftp, 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    user_id = _login(client, app, 'download_user')
    token = _token(manager, user_id, 'download')

    response = client.get(f'/api/transfers/{token}/download')

    assert response.status_code == 200
    assert response.data == payload
    assert sftp.download_file.read_sizes
    assert max(sftp.download_file.read_sizes) <= app.config['CHUNK_SIZE']
    assert sftp.download_file.closed is True


def test_smb_download_streams_only_through_resolved_backend(
        app, client, monkeypatch, transfer_components):
    transfer_routes, manager = transfer_components
    payload = b'smb-download-' * 100
    remote = TrackingRemoteFile(payload)

    class Backend:
        def stat(self, _source, path, *, follow_links=False):
            assert path == '/report.bin'
            assert follow_links is False
            return {'size': len(payload), 'is_dir': False}, None

        @contextmanager
        def open_reader(self, _source, path, *, io_lane='control'):
            assert path == '/report.bin'
            assert io_lane == 'transfer'
            with remote:
                yield FileReaderLease(reader=remote, size=len(payload))

    resolved = SimpleNamespace(
        handle_id='smb-handle',
        backend=Backend(),
        source_id='smb-quick:owned',
        descriptor=SimpleNamespace(kind='smb', endpoint='nas.example/Docs'),
    )
    audit_calls = []
    monkeypatch.setattr(
        transfer_routes,
        'log_file_source_operation',
        lambda **details: audit_calls.append(details),
    )
    monkeypatch.setattr(
        transfer_routes.file_service, 'resolve',
        lambda *_args, **_kwargs: resolved,
    )
    monkeypatch.setattr(
        transfer_routes.sftp_handler, 'sftp_session',
        lambda *_args: (_ for _ in ()).throw(
            AssertionError('SMB download must not enter SFTP')
        ),
    )
    user_id = _login(client, app, 'smb_download_user')
    record = manager.create(
        user_id=user_id,
        source_id='smb-quick:owned',
        direction='download',
        metadata={'remote_path': '/report.bin', 'filename': 'report.bin'},
    )

    response = client.get(f'/api/transfers/{record.token}/download')

    assert response.status_code == 200
    assert response.data == payload
    assert max(remote.read_sizes) <= app.config['CHUNK_SIZE']
    assert manager._records == {}
    assert audit_calls == [{
        'username': 'smb_download_user',
        'operation': 'download',
        'result': 'COMPLETED',
        'filename': 'report.bin',
        'size': len(payload),
        'ip_address': '127.0.0.1',
        'source_kind': 'smb',
        'target_host': 'nas.example',
        'share': 'Docs',
    }]


def test_download_rejects_oversized_opened_object_before_first_byte(
        app, client, monkeypatch, transfer_components):
    """A stale small preflight must not authorize a larger opened object."""
    transfer_routes, manager = transfer_components
    remote = TrackingRemoteFile(b'123456789', declared_size=9)

    class Backend:
        def stat(self, *_args, **_kwargs):
            raise AssertionError('path stat must not authorize the download')

        @contextmanager
        def open_reader(self, _source, _path, *, io_lane='control'):
            assert io_lane == 'transfer'
            with remote:
                yield FileReaderLease(reader=remote, size=9)

    resolved = SimpleNamespace(
        handle_id='smb-handle',
        backend=Backend(),
        source_id='smb-quick:owned',
        descriptor=SimpleNamespace(kind='smb', endpoint='nas.example/Docs'),
    )
    monkeypatch.setattr(
        transfer_routes.file_service,
        'resolve',
        lambda *_args, **_kwargs: resolved,
    )
    monkeypatch.setattr(transfer_routes.config, 'MAX_DOWNLOAD_SIZE', 5)
    user_id = _login(client, app, 'opened_download_limit_user')
    record = manager.create(
        user_id=user_id,
        source_id='smb-quick:owned',
        direction='download',
        metadata={'remote_path': '/report.bin', 'filename': 'report.bin'},
    )

    response = client.get(f'/api/transfers/{record.token}/download')

    assert response.status_code == 413
    assert response.get_json() == {
        'error_code': 'LIMIT_EXCEEDED',
        'error': 'The transfer exceeds the configured limit.',
        'retryable': False,
        'limit_kind': 'download',
        'limit_bytes': 5,
        'actual_bytes': 9,
    }
    assert remote.read_sizes == []
    assert remote.closed is True
    assert manager._records == {}


def test_download_explicitly_does_not_support_http_ranges(
        app, client, monkeypatch, transfer_components):
    transfer_routes, manager = transfer_components
    payload = b'abcdef'
    sftp = FakeSFTP(payload)

    @contextmanager
    def fake_session(_session_id, io_lane='control'):
        yield sftp, 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    user_id = _login(client, app, 'download_range_user')
    token = _token(manager, user_id, 'download')

    response = client.get(
        f'/api/transfers/{token}/download',
        headers={'Range': 'bytes=0-1'},
    )

    assert response.status_code == 200
    assert response.headers['Accept-Ranges'] == 'none'
    assert 'Content-Range' not in response.headers
    assert response.data == payload


def test_range_request_keeps_the_original_open_object_after_path_swap(
        app, client, monkeypatch, transfer_components):
    """Renaming the target mid-response must not cause a second path open."""
    transfer_routes, manager = transfer_components
    original_payload = b'a' * (app.config['CHUNK_SIZE'] + 17)
    replacement_payload = b'not-the-opened-object'
    sftp = FakeSFTP(original_payload)
    original_reader = sftp.download_file

    @contextmanager
    def fake_session(_session_id, io_lane='control'):
        yield sftp, 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    user_id = _login(client, app, 'download_path_swap_user')
    token = _token(manager, user_id, 'download')

    response = client.get(
        f'/api/transfers/{token}/download',
        headers={'Range': 'bytes=0-1'},
        buffered=False,
    )
    sftp.download_file = TrackingRemoteFile(replacement_payload)
    body = b''.join(response.response)
    response.close()

    assert response.status_code == 200
    assert response.headers['Accept-Ranges'] == 'none'
    assert body == original_payload
    assert sftp.opened == [('/remote/report.bin', 'rb')]
    assert original_reader.closed is True
    assert sftp.download_file.read_sizes == []


def test_smb_upload_uses_atomic_backend_writer_and_bounded_request_reads(
        app, client, monkeypatch, transfer_components):
    transfer_routes, manager = transfer_components
    written = bytearray()
    commits = []

    class Writer:
        def write(self, chunk):
            accepted = bytes(chunk[:max(1, len(chunk) // 2)])
            written.extend(accepted)
            return len(accepted)

    class Backend:
        @contextmanager
        def open_atomic_writer(
                self, _source, path, *, replace, cancel_event,
                io_lane='control'):
            assert path == '/upload.bin'
            assert io_lane == 'transfer'
            assert replace is False
            writer = Writer()
            yield writer
            assert cancel_event.is_set() is False
            commits.append(bytes(written))

    resolved = SimpleNamespace(
        handle_id='smb-handle', backend=Backend(), source_id='smb-quick:owned',
    )
    monkeypatch.setattr(
        transfer_routes.file_service, 'resolve',
        lambda *_args, **_kwargs: resolved,
    )
    monkeypatch.setattr(
        transfer_routes.sftp_handler, 'sftp_session',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError('SMB upload must not enter SFTP')
        ),
    )
    user_id = _login(client, app, 'smb_upload_user')
    payload = b'smb-upload-' * 100
    record = manager.create(
        user_id=user_id,
        source_id='smb-quick:owned',
        direction='upload',
        metadata={'remote_path': '/upload.bin', 'filename': 'upload.bin'},
    )

    response = client.post(
        f'/api/transfers/{record.token}/upload',
        data=payload,
        content_type='application/octet-stream',
    )

    assert response.status_code == 200
    assert commits == [payload]
    assert manager._records == {}


def test_explicit_replace_token_is_the_only_path_to_backend_replacement(
    app, client, monkeypatch, transfer_components,
):
    transfer_routes, manager = transfer_components
    replacements = []

    class Writer:
        def write(self, chunk):
            return len(chunk)

    class Backend:
        @contextmanager
        def open_atomic_writer(
            self, _source, _path, *, replace, cancel_event,
            io_lane='control',
        ):
            assert io_lane == 'transfer'
            replacements.append(replace)
            assert cancel_event.is_set() is False
            yield Writer()

    resolved = SimpleNamespace(
        handle_id='smb-handle', backend=Backend(), source_id='smb-quick:owned',
    )
    monkeypatch.setattr(
        transfer_routes.file_service, 'resolve',
        lambda *_args, **_kwargs: resolved,
    )
    user_id = _login(client, app, 'smb_explicit_replace')
    record = manager.create(
        user_id=user_id,
        source_id='smb-quick:owned',
        direction='upload',
        metadata={
            'remote_path': '/upload.bin',
            'filename': 'upload.bin',
            'conflict_policy': 'replace',
        },
    )

    response = client.post(
        f'/api/transfers/{record.token}/upload',
        data=b'payload',
        content_type='application/octet-stream',
    )

    assert response.status_code == 200
    assert replacements == [True]


@pytest.mark.parametrize(
    ('error', 'code', 'message', 'status'),
    (
        (
            pytest.param(
                'permission',
                'PERMISSION_DENIED',
                'No write permission for the destination.',
                403,
                id='permission',
            )
        ),
        (
            pytest.param(
                'conflict',
                'CONFLICT',
                'A file or folder already exists at the destination.',
                409,
                id='conflict',
            )
        ),
        (
            pytest.param(
                'sftp-conflict',
                'CONFLICT',
                'A file or folder already exists at the destination.',
                409,
                id='sftp-conflict',
            )
        ),
        (
            pytest.param(
                'not-found',
                'NOT_FOUND',
                'The requested file or folder was not found.',
                404,
                id='not-found',
            )
        ),
        (
            pytest.param(
                'unknown',
                'TRANSFER_UNAVAILABLE',
                'The transfer could not be completed.',
                500,
                id='safe-fallback',
            )
        ),
    ),
)
def test_upload_http_socket_and_log_share_one_safe_failure_contract(
    app,
    client,
    monkeypatch,
    transfer_components,
    error,
    code,
    message,
    status,
):
    import app as app_package
    from app.smb_backend import FileConflict
    from app.smb_protocol import SMBProtocolError

    transfer_routes, manager = transfer_components
    failures = {
        'permission': SMBProtocolError(
            'PERMISSION_DENIED', r'secret \\server\share'
        ),
        'conflict': FileConflict(r'secret \\server\share'),
        # SFTPBackend.open_atomic_writer raises this without an errno.
        'sftp-conflict': FileExistsError(errno.EEXIST, 'destination already exists or changed'),
        'not-found': FileNotFoundError(r'secret \\server\share'),
        'unknown': RuntimeError(r'secret \\server\share'),
    }
    resolved = SimpleNamespace(
        handle_id='smb-handle',
        backend=object(),
        source_id='smb-quick:owned',
    )
    monkeypatch.setattr(
        transfer_routes.file_service,
        'resolve',
        lambda *_args, **_kwargs: resolved,
    )
    monkeypatch.setattr(
        transfer_routes,
        '_upload_to_backend',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(failures[error]),
    )
    monkeypatch.setattr(transfer_routes, '_audit_transfer_source', lambda *_args, **_kwargs: None)
    logs = []
    emitted = []
    monkeypatch.setattr(
        transfer_routes,
        'log_error',
        lambda event, **details: logs.append((event, details)),
    )
    monkeypatch.setattr(
        app_package.socketio,
        'emit',
        lambda event, payload, **kwargs: emitted.append((event, payload, kwargs)),
    )
    user_id = _login(client, app, f"upload_contract_{error.replace('-', '_')}")
    record = manager.create(
        user_id=user_id,
        source_id='smb-quick:owned',
        direction='upload',
        metadata={'remote_path': '/upload.bin', 'filename': 'upload.bin'},
    )

    response = client.post(
        f'/api/transfers/{record.token}/upload',
        data=b'payload',
        content_type='application/octet-stream',
    )

    expected = {
        'error_code': code,
        'error': message,
        'retryable': False,
    }
    assert response.status_code == status
    assert response.get_json() == expected
    finished = [event for event in emitted if event[0] == 'transfer_finished']
    assert finished == [(
        'transfer_finished',
        {
            'transfer_id': record.transfer_id,
            'direction': 'upload',
            'status': 'failed',
            **expected,
        },
        {'room': f'user_{user_id}'},
    )]
    assert logs == [(
        'HTTP upload failed',
        {
            'user_id': user_id,
            'result_code': code,
            'operation': 'upload',
            'exception_type': type(failures[error]).__name__,
        },
    )]
    assert 'secret' not in repr(response.get_json())
    assert 'server' not in repr(response.get_json())


@pytest.mark.parametrize(
    ('failure', 'code', 'message', 'status', 'retryable'),
    (
        (
            PermissionError(r'private \\server\share'),
            'PERMISSION_DENIED',
            'No read permission for the source.',
            403,
            False,
        ),
        (
            TimeoutError(r'private \\server\share'),
            'TIMEOUT',
            'The file operation timed out.',
            504,
            True,
        ),
    ),
)
def test_download_open_keeps_typed_failure_across_http_and_socket(
    app,
    client,
    monkeypatch,
    transfer_components,
    failure,
    code,
    message,
    status,
    retryable,
):
    import app as app_package

    transfer_routes, manager = transfer_components

    class Backend:
        @contextmanager
        def open_reader(self, *_args, **_kwargs):
            raise failure
            yield

    resolved = SimpleNamespace(
        handle_id='smb-handle',
        backend=Backend(),
        source_id='smb-quick:owned',
    )
    monkeypatch.setattr(
        transfer_routes.file_service,
        'resolve',
        lambda *_args, **_kwargs: resolved,
    )
    monkeypatch.setattr(
        transfer_routes, '_audit_transfer_source', lambda *_args, **_kwargs: None
    )
    emitted = []
    monkeypatch.setattr(
        app_package.socketio,
        'emit',
        lambda event, payload, **kwargs: emitted.append((event, payload, kwargs)),
    )
    user_id = _login(client, app, f'dl_preflight_{code.lower()}')
    record = manager.create(
        user_id=user_id,
        source_id='smb-quick:owned',
        direction='download',
        metadata={'remote_path': '/restricted.bin', 'filename': 'restricted.bin'},
    )

    response = client.get(f'/api/transfers/{record.token}/download')

    expected = {
        'error_code': code,
        'error': message,
        'retryable': retryable,
    }
    assert response.status_code == status
    assert response.get_json() == expected
    assert emitted == [(
        'transfer_finished',
        {
            'transfer_id': record.transfer_id,
            'direction': 'download',
            'status': 'failed',
            **expected,
        },
        {'room': f'user_{user_id}'},
    )]
    assert 'private' not in repr(response.get_json())


def test_download_propagates_io_failure_after_first_chunk(
        app, client, monkeypatch, transfer_components):
    import app as app_package

    transfer_routes, manager = transfer_components
    first_chunk = b'valid-prefix'

    class FailingRemoteFile(TrackingRemoteFile):
        def read(self, size=-1):
            if self.offset == 0:
                self.read_sizes.append(size)
                self.offset = len(first_chunk)
                return first_chunk
            raise OSError('midstream read failed')

    sftp = FakeSFTP()
    sftp.download_file = FailingRemoteFile()
    sftp.reported_size = len(first_chunk) * 2

    @contextmanager
    def fake_session(_session_id, io_lane='control'):
        yield sftp, 'session'

    monkeypatch.setattr(
        transfer_routes.sftp_handler,
        'sftp_session',
        fake_session,
    )
    emitted = []
    monkeypatch.setattr(
        app_package.socketio,
        'emit',
        lambda event, payload, **kwargs: emitted.append((event, payload, kwargs)),
    )
    user_id = _login(client, app, 'midstream_download_user')
    record = manager.create(
        user_id=user_id,
        source_id='sftp-session:owned-session',
        direction='download',
        metadata={
            'remote_path': '/remote/report.bin',
            'filename': 'report.bin',
        },
    )

    response = client.get(
        f'/api/transfers/{record.token}/download',
        buffered=False,
    )
    stream = iter(response.response)

    assert next(stream) == first_chunk
    with pytest.raises(OSError, match='midstream read failed'):
        next(stream)
    response.close()

    assert record.request_done_event.is_set()
    assert manager._records == {}
    finished = [event for event in emitted if event[0] == 'transfer_finished']
    assert finished == [(
        'transfer_finished',
        {
            'transfer_id': record.transfer_id,
            'direction': 'download',
            'status': 'failed',
            'error_code': 'TRANSFER_UNAVAILABLE',
            'error': 'The transfer could not be completed.',
            'retryable': False,
        },
        {'room': f'user_{user_id}'},
    )]


def test_content_disposition_has_safe_ascii_fallback_and_utf8_filename():
    from app.transfer_routes import _content_disposition

    value = _content_disposition('résumé\r\nInjected: yes\\final.txt')

    assert '\r' not in value
    assert '\n' not in value
    assert '\\' not in value
    assert value.startswith('attachment; filename="resumeInjected_ yes_final.txt"')
    assert "filename*=UTF-8''r%C3%A9sum%C3%A9%0D%0AInjected%3A%20yes%5Cfinal.txt" in value


def test_unicode_download_header_terminalizes_record(
        app, client, monkeypatch, transfer_components):
    transfer_routes, manager = transfer_components
    sftp = FakeSFTP(b'body')

    @contextmanager
    def fake_session(_session_id, io_lane='control'):
        yield sftp, 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    user_id = _login(client, app, 'unicode_header_user')
    record = manager.create(
        user_id, 'owned-session', 'download',
        {'remote_path': '/remote/résumé.txt', 'filename': 'résumé.txt'},
    )

    response = client.get(f'/api/transfers/{record.token}/download')

    assert response.status_code == 200
    assert response.data == b'body'
    assert "filename*=UTF-8''r%C3%A9sum%C3%A9.txt" in response.headers['Content-Disposition']
    assert manager._records == {}


@pytest.mark.parametrize(
    ('application_root', 'expected'),
    [
        ('', '/api/transfers/token/download'),
        ('/webssh', '/webssh/api/transfers/token/download'),
        ('/webssh/', '/webssh/api/transfers/token/download'),
    ],
)
def test_prepare_transfer_url_includes_application_root_once(
        app, monkeypatch, application_root, expected):
    from app import socket_events

    record = SimpleNamespace(
        transfer_id='transfer-id', token='token', expires_at=123,
    )
    monkeypatch.setattr(
        socket_events, 'prepare_transfer', lambda *_args, **_kwargs: record,
    )
    monkeypatch.setattr(
        socket_events.config, 'APPLICATION_ROOT', application_root,
        raising=False,
    )
    user = SimpleNamespace(id=7)

    with app.test_request_context('/'):
        result = socket_events.handle_prepare_transfer.__wrapped__(
                {
                    'direction': 'download',
                    'source_id': 'sftp-session:owned-session',
                    'remote_path': '/remote/report.bin',
                    'request_id': 'transfer:prepare:1',
                },
            current_user=user,
        )

    assert result['success'] is True
    assert result['url'] == expected


def test_prepare_transfer_requires_owner_socket(monkeypatch):
    from app import transfer_routes
    from app.transfer_manager import TransferManager

    manager = TransferManager()
    monkeypatch.setattr(transfer_routes, 'transfer_manager', manager)

    assert transfer_routes.prepare_transfer(
        'user-id', 'upload', 'sftp-session:owned-session',
        '/remote/report.bin',
    ) is None
    assert manager._records == {}


def test_prepare_upload_conflict_policy_defaults_to_error_and_rejects_unknown(monkeypatch):
    from app import transfer_routes
    from app.file_sources import SourceHoldSet
    from app.transfer_manager import TransferManager

    manager = TransferManager()
    monkeypatch.setattr(transfer_routes, 'transfer_manager', manager)
    monkeypatch.setattr(
        transfer_routes.file_service,
        'resolve',
        lambda *_args, **_kwargs: SimpleNamespace(
            handle_id='owned-session', backend=SFTPBackend(),
        ),
    )
    monkeypatch.setattr(
        transfer_routes.file_source_resolver,
        'acquire_transfer_holds',
        lambda _user_id, source_ids: SourceHoldSet(tuple(source_ids)),
    )

    initial = transfer_routes.prepare_transfer(
        7, 'upload', 'sftp-session:owned-session', '/remote/report.bin',
        owner_sid='socket-a',
    )
    replacement = transfer_routes.prepare_transfer(
        7, 'upload', 'sftp-session:owned-session', '/remote/report.bin',
        owner_sid='socket-a', conflict_policy='replace',
    )
    rejected = transfer_routes.prepare_transfer(
        7, 'upload', 'sftp-session:owned-session', '/remote/report.bin',
        owner_sid='socket-a', conflict_policy='rename-existing',
    )

    assert initial.metadata['conflict_policy'] == 'error'
    assert replacement.metadata['conflict_policy'] == 'replace'
    assert initial.token != replacement.token
    assert rejected is None
    assert len(manager._records) == 2
    assert manager.fail(initial.transfer_id, 7) is True
    assert manager.fail(replacement.transfer_id, 7) is True


def test_prepare_socket_passes_conflict_policy(app, monkeypatch):
    from app import socket_events

    captured = []
    record = SimpleNamespace(
        transfer_id='replacement-id', token='replacement-token', expires_at=123,
    )
    monkeypatch.setattr(
        socket_events,
        'prepare_transfer',
        lambda *_args, **kwargs: captured.append(kwargs) or record,
    )
    user = SimpleNamespace(id=7)

    with app.test_request_context('/'):
        result = socket_events.handle_prepare_transfer.__wrapped__(
            {
                'direction': 'upload',
                'source_id': 'sftp-session:owned-session',
                'remote_path': '/remote/report.bin',
                'request_id': 'transfer:replace:1',
                'conflict_policy': 'replace',
            },
            current_user=user,
        )

    assert result['success'] is True
    assert captured[0]['conflict_policy'] == 'replace'


def test_prepare_transfer_acquires_owned_source_hold_before_issuing_token(
        monkeypatch):
    from app import transfer_routes
    from app.file_sources import SourceHoldSet
    from app.transfer_manager import TransferManager

    manager = TransferManager()
    calls = []
    monkeypatch.setattr(transfer_routes, 'transfer_manager', manager)
    monkeypatch.setattr(
        transfer_routes.file_service,
        'resolve',
        lambda source_id, user_id, capability: calls.append(
            ('resolve', source_id, str(user_id), capability.value)
        ) or SimpleNamespace(
            handle_id='owned-session', backend=SFTPBackend(),
        ),
    )

    def acquire(user_id, source_ids):
        calls.append(('hold', str(user_id), tuple(source_ids)))
        return SourceHoldSet(tuple(source_ids))

    monkeypatch.setattr(
        transfer_routes.file_source_resolver,
        'acquire_transfer_holds',
        acquire,
    )

    record = transfer_routes.prepare_transfer(
        7,
        'download',
        'sftp-session:owned-session',
        '/remote/report.bin',
        owner_sid='socket-a',
    )

    assert record.source_id == 'sftp-session:owned-session'
    assert record.source_ids == ('sftp-session:owned-session',)
    assert calls == [
        ('resolve', 'sftp-session:owned-session', '7', 'read'),
        ('hold', '7', ('sftp-session:owned-session',)),
    ]
    assert manager.fail(record.transfer_id, 7) is True


def test_prepare_folder_download_requires_recursive_capability(monkeypatch):
    from app import transfer_routes
    from app.file_sources import SourceHoldSet
    from app.transfer_manager import TransferManager

    manager = TransferManager()
    calls = []
    monkeypatch.setattr(transfer_routes, 'transfer_manager', manager)
    monkeypatch.setattr(
        transfer_routes.file_service,
        'resolve',
        lambda source_id, user_id, capability: calls.append(
            ('resolve', source_id, str(user_id), capability.value)
        ) or SimpleNamespace(
            handle_id='owned-session', backend=SFTPBackend(),
        ),
    )
    monkeypatch.setattr(
        transfer_routes.file_source_resolver,
        'acquire_transfer_holds',
        lambda user_id, source_ids: calls.append(
            ('hold', str(user_id), tuple(source_ids))
        ) or SourceHoldSet(tuple(source_ids)),
    )

    record = transfer_routes.prepare_transfer(
        7,
        'download',
        'sftp-session:owned-session',
        '/remote/reports',
        owner_sid='socket-a',
        archive=True,
    )

    assert record is not None
    assert calls == [
        ('resolve', 'sftp-session:owned-session', '7', 'read'),
        ('resolve', 'sftp-session:owned-session', '7', 'recursive'),
        ('hold', '7', ('sftp-session:owned-session',)),
    ]
    assert manager.fail(record.transfer_id, 7) is True


def test_prepare_transfer_never_acquires_hold_for_unavailable_source(
        monkeypatch):
    from app import transfer_routes
    from app.file_sources import FileSourceUnavailable
    from app.transfer_manager import TransferManager

    manager = TransferManager()
    acquired = []
    monkeypatch.setattr(transfer_routes, 'transfer_manager', manager)
    monkeypatch.setattr(
        transfer_routes.file_service,
        'resolve',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            FileSourceUnavailable()
        ),
    )
    monkeypatch.setattr(
        transfer_routes.file_source_resolver,
        'acquire_transfer_holds',
        lambda *_args: acquired.append(True),
    )

    record = transfer_routes.prepare_transfer(
        7,
        'upload',
        'sftp-session:foreign',
        '/remote/report.bin',
        owner_sid='socket-a',
    )

    assert record is None
    assert acquired == []
    assert manager._records == {}


def test_prepare_transfer_uses_resolved_backend_path_policy_before_hold(
        monkeypatch):
    from app import transfer_routes
    from app.transfer_manager import TransferManager

    manager = TransferManager()
    raw_paths = []
    acquired = []
    backend = SimpleNamespace(
        normalize_path=lambda path: raw_paths.append(path) or None,
    )
    source = SimpleNamespace(handle_id='smb-owned', backend=backend)
    monkeypatch.setattr(transfer_routes, 'transfer_manager', manager)
    monkeypatch.setattr(
        transfer_routes.file_service,
        'resolve',
        lambda *_args, **_kwargs: source,
    )
    monkeypatch.setattr(
        transfer_routes.file_source_resolver,
        'acquire_transfer_holds',
        lambda *_args: acquired.append(True),
    )

    record = transfer_routes.prepare_transfer(
        7,
        'download',
        'smb-quick:owned',
        '/reports/../secrets.txt',
        owner_sid='socket-a',
    )

    assert record is None
    assert raw_paths == ['/reports/../secrets.txt']
    assert acquired == []
    assert manager._records == {}


def test_revoked_source_at_token_consumption_releases_hold_without_remote_io(
        app, client, monkeypatch, transfer_components):
    from app.file_sources import FileSourceUnavailable, SourceHoldSet

    transfer_routes, manager = transfer_components
    user_id = _login(client, app, 'revoked_transfer_source_user')
    released = []
    record = manager.create(
        user_id,
        'sftp-quick:revoked',
        'download',
        {'remote_path': '/remote/report.bin', 'filename': 'report.bin'},
        source_holds=SourceHoldSet(
            ('sftp-quick:revoked',),
            (lambda: released.append('revoked'),),
        ),
    )
    remote_calls = []
    monkeypatch.setattr(
        transfer_routes.file_service,
        'resolve',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            FileSourceUnavailable()
        ),
    )
    monkeypatch.setattr(
        transfer_routes.sftp_handler,
        'sftp_session',
        lambda *_args: remote_calls.append(True),
    )

    response = client.get(f'/api/transfers/{record.token}/download')

    assert response.status_code == 404
    assert released == ['revoked']
    assert remote_calls == []
    assert manager._records == {}


def test_upload_reads_request_stream_in_bounded_chunks_and_renames_only_on_success(
        app, client, monkeypatch, transfer_components):
    """The final remote path must not exist before every bounded write succeeds."""
    transfer_routes, manager = transfer_components
    payload = b'y' * (app.config['CHUNK_SIZE'] * 2 + 23)
    stream = BoundedRequestStream(payload)
    sftp = FakeSFTP()
    sftp.destination_exists = False

    @contextmanager
    def fake_session(_session_id, io_lane='control'):
        yield sftp, 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    user_id = _login(client, app, 'upload_user')
    token = _token(manager, user_id, 'upload')

    response = client.open(
        f'/api/transfers/{token}/upload',
        method='POST',
        input_stream=stream,
        content_type='application/octet-stream',
        content_length=len(payload),
    )

    assert response.status_code == 200
    assert bytes(sftp.upload_file.written) == payload
    assert stream.requested_sizes
    assert max(stream.requested_sizes) <= app.config['CHUNK_SIZE']
    assert len(sftp.renamed) == 1
    temporary, final = sftp.renamed[0]
    assert final == '/remote/report.bin'
    assert temporary != final
    assert sftp.removed == []


@pytest.mark.parametrize('method,direction,endpoint', [
    ('GET', 'upload', 'download'),
    ('POST', 'download', 'upload'),
])
def test_direction_and_method_mismatches_never_start_remote_io(
        app, client, monkeypatch, transfer_components, method, direction, endpoint):
    transfer_routes, manager = transfer_components
    sftp = FakeSFTP(b'payload')
    calls = []

    @contextmanager
    def fake_session(_session_id, io_lane='control'):
        calls.append(_session_id)
        yield sftp, 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    user_id = _login(client, app, f'method_user_{direction}')
    token = _token(manager, user_id, direction)

    response = client.open(f'/api/transfers/{token}/{endpoint}', method=method)

    assert response.status_code == 404
    assert calls == []


@pytest.mark.parametrize('payload,reported_size', [
    (b'grow-by-two', 4),
    (b'short', 20),
])
def test_download_omits_content_length_when_remote_size_can_change(
        app, client, monkeypatch, transfer_components, payload, reported_size):
    """A remote mutation must not create contradictory Content-Length headers."""
    transfer_routes, manager = transfer_components
    sftp = FakeSFTP(payload)
    sftp.reported_size = reported_size

    @contextmanager
    def fake_session(_session_id, io_lane='control'):
        yield sftp, 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    user_id = _login(client, app, f'mutation_{reported_size}')
    token = _token(manager, user_id, 'download')

    response = client.get(f'/api/transfers/{token}/download')

    assert response.status_code == 200
    assert response.data == payload
    assert 'Content-Length' not in response.headers


def _sftp_backend_upload(
        monkeypatch, sftp, payload, *, chunk_size, max_bytes, replace=False):
    """Run the route's upload writer against a fake SFTP session."""
    import threading

    from app import sftp_handler, transfer_routes

    @contextmanager
    def fake_session(_session_id, io_lane='control'):
        yield sftp, 'session'

    monkeypatch.setattr(sftp_handler, 'sftp_session', fake_session)
    source = SimpleNamespace(handle_id='owned-session', backend=SFTPBackend())
    return transfer_routes._upload_to_backend(
        source,
        '/remote/report.bin',
        BoundedRequestStream(payload),
        chunk_size=chunk_size,
        max_bytes=max_bytes,
        cancel_event=threading.Event(),
        cancelled=lambda: False,
        progress=lambda _count: None,
        replace=replace,
    )


def test_upload_uses_posix_rename_for_an_existing_remote_destination(
        monkeypatch):
    """Replacing an existing target must not depend on non-portable rename."""
    sftp = PosixRenameSFTP(supports_posix_rename=True)

    _sftp_backend_upload(
        monkeypatch, sftp, b'new', chunk_size=2, max_bytes=10, replace=True,
    )

    assert sftp.posix_renamed
    assert sftp.renamed == []
def test_sftp_upload_preserves_existing_destination_until_replace_is_explicit(
        monkeypatch):
    from app import sftp_handler

    sftp = PosixRenameSFTP(supports_posix_rename=True)

    with pytest.raises(FileExistsError) as conflict:
        _sftp_backend_upload(
            monkeypatch, sftp, b'new', chunk_size=2, max_bytes=10,
        )

    assert conflict.value.errno == errno.EEXIST
    assert isinstance(conflict.value.__cause__, sftp_handler.UploadConflict)
    assert sftp.posix_renamed == []
    assert sftp.renamed == []
    assert sftp.removed and sftp.removed[0] != '/remote/report.bin'
def test_upload_preserves_existing_destination_if_posix_rename_is_unavailable(
        monkeypatch):
    """Do not pre-delete a user file merely to emulate atomic replacement."""
    sftp = PosixRenameSFTP(supports_posix_rename=False)

    with pytest.raises(Exception):
        _sftp_backend_upload(
            monkeypatch, sftp, b'new', chunk_size=2, max_bytes=10,
            replace=True,
        )

    assert sftp.renamed == []
    assert sftp.removed and sftp.removed[0] != '/remote/report.bin'
def test_download_token_is_one_use_and_wrong_user_cannot_consume_it(
        app, monkeypatch, transfer_components):
    transfer_routes, manager = transfer_components
    sftp = FakeSFTP(b'ok')

    @contextmanager
    def fake_session(_session_id, io_lane='control'):
        yield sftp, 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    owner_client = app.test_client()
    owner_id = _login(owner_client, app, 'token_owner')
    token = _token(manager, owner_id, 'download')
    identity = {'user_id': 'other-user'}
    monkeypatch.setattr(transfer_routes, '_current_user_id', lambda: identity['user_id'])

    assert owner_client.get(f'/api/transfers/{token}/download').status_code == 404
    identity['user_id'] = owner_id
    response = owner_client.get(f'/api/transfers/{token}/download')
    assert response.status_code == 200
    assert response.data == b'ok'
    assert owner_client.get(f'/api/transfers/{token}/download').status_code == 404


def test_cancelled_download_never_opens_remote_file(app, client, monkeypatch,
                                                    transfer_components):
    transfer_routes, manager = transfer_components
    sftp = FakeSFTP(b'never-read')

    @contextmanager
    def fake_session(_session_id, io_lane='control'):
        yield sftp, 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    user_id = _login(client, app, 'cancel_before')
    record = manager.create(user_id, 'owned-session', 'download', {
        'remote_path': '/remote/report.bin', 'filename': 'report.bin',
    })
    assert manager.cancel(record.transfer_id, user_id) is True

    assert client.get(f'/api/transfers/{record.token}/download').status_code == 404
    assert sftp.opened == []


def test_midstream_upload_overflow_removes_only_temporary_remote_file(
        monkeypatch):
    from app import sftp_handler

    sftp = FakeSFTP()
    sftp.destination_exists = False

    with pytest.raises(sftp_handler.UploadSizeExceeded):
        _sftp_backend_upload(
            monkeypatch, sftp, b'abcdef', chunk_size=4, max_bytes=5,
        )

    assert sftp.renamed == []
    assert len(sftp.removed) == 1
    assert sftp.removed[0] != '/remote/report.bin'
def test_expired_route_token_never_opens_sftp(app, client, monkeypatch,
                                              transfer_components):
    """Expiry is enforced before any HTTP route can touch remote state."""
    transfer_routes, _manager = transfer_components
    from app.transfer_manager import TransferManager

    now = {'value': 10.0}
    manager = TransferManager(token_ttl=1, clock=lambda: now['value'])
    monkeypatch.setattr(transfer_routes, 'transfer_manager', manager)
    calls = []
    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', lambda *_: calls.append(1))
    user_id = _login(client, app, 'expired_route_user')
    token = _token(manager, user_id, 'download')
    now['value'] = 12.0

    assert client.get(f'/api/transfers/{token}/download').status_code == 404
    assert calls == []


def test_csrf_rejection_leaves_upload_token_pending(app, client, monkeypatch,
                                                    transfer_components):
    """CSRF runs before token consumption, so a browser retry is still valid."""
    transfer_routes, manager = transfer_components
    user_id = _login(client, app, 'csrf_route_user')
    token = _token(manager, user_id, 'upload')
    app.config['WTF_CSRF_ENABLED'] = True
    try:
        response = client.post(
            f'/api/transfers/{token}/upload', data=b'x',
            content_type='application/octet-stream',
        )
    finally:
        app.config['WTF_CSRF_ENABLED'] = False

    assert response.status_code == 400
    assert manager._records


def test_closing_download_response_cancels_record_and_closes_remote_file(
        app, client, monkeypatch, transfer_components):
    transfer_routes, manager = transfer_components
    sftp = FakeSFTP(b'x' * (app.config['CHUNK_SIZE'] + 1))

    @contextmanager
    def fake_session(_session_id, io_lane='control'):
        yield sftp, 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    user_id = _login(client, app, 'generator_close_user')
    record = manager.create(
        user_id=user_id,
        source_id='sftp-session:owned-session',
        direction='download',
        metadata={'remote_path': '/file.bin', 'filename': 'file.bin'},
    )
    response = client.get(
        f'/api/transfers/{record.token}/download', buffered=False
    )
    next(response.response)
    response.close()

    assert sftp.download_file.closed is True
    assert record.request_done_event.is_set()
    assert manager._records == {}


def test_unstarted_download_response_releases_record(
        app, client, monkeypatch, transfer_components):
    transfer_routes, manager = transfer_components
    sftp = FakeSFTP(b'not-consumed')

    @contextmanager
    def fake_session(_session_id, io_lane='control'):
        yield sftp, 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    user_id = _login(client, app, 'download_close_user')
    record = manager.create(
        user_id=user_id,
        source_id='sftp-session:owned-session',
        direction='download',
        metadata={'remote_path': '/remote/report.bin', 'filename': 'report.bin'},
    )

    response = client.get(
        f'/api/transfers/{record.token}/download', buffered=False,
    )
    response.close()

    assert record.request_done_event.is_set()
    assert manager._records == {}


def test_download_opened_handle_limit_marks_request_done(
        app, client, monkeypatch, transfer_components):
    transfer_routes, manager = transfer_components
    sftp = FakeSFTP()
    sftp.download_file.declared_size = app.config['MAX_DOWNLOAD_SIZE'] + 1

    @contextmanager
    def fake_session(_session_id, io_lane='control'):
        yield sftp, 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    user_id = _login(client, app, 'download_limit_user')
    record = manager.create(
        user_id=user_id,
        source_id='sftp-session:owned-session',
        direction='download',
        metadata={'remote_path': '/remote/large.bin', 'filename': 'large.bin'},
    )

    response = client.get(f'/api/transfers/{record.token}/download')

    assert response.status_code == 413
    assert response.get_json() == {
        'error_code': 'LIMIT_EXCEEDED',
        'error': 'The transfer exceeds the configured limit.',
        'retryable': False,
        'limit_kind': 'download',
        'limit_bytes': app.config['MAX_DOWNLOAD_SIZE'],
        'actual_bytes': sftp.download_file.declared_size,
    }
    assert record.request_done_event.is_set()
    assert manager._records == {}


def test_upload_close_failure_removes_temporary_file_and_keeps_final_hidden(
        monkeypatch):
    """A remote close error is terminal and never exposes the final pathname."""
    class CloseFailure(TrackingRemoteFile):
        def close(self):
            super().close()
            raise OSError('close failed')

    sftp = FakeSFTP()
    sftp.destination_exists = False
    sftp.upload_file = CloseFailure()

    with pytest.raises(OSError):
        _sftp_backend_upload(
            monkeypatch, sftp, b'body', chunk_size=4, max_bytes=10,
        )

    assert sftp.renamed == []
    assert sftp.removed and sftp.removed[0] != '/remote/report.bin'
def test_release_then_raise_still_removes_route_record(app, client, monkeypatch,
                                                       transfer_components):
    """A reservation that releases before raising cannot leave a hidden record."""
    transfer_routes, _manager = transfer_components
    from app.transfer_manager import TransferManager

    class Reservation:
        released = False
        def release(self):
            self.released = True
            raise RuntimeError('release after state change')

    class Quota:
        def reserve(self, *_args):
            return Reservation()

    manager = TransferManager(quota_manager=Quota())
    monkeypatch.setattr(transfer_routes, 'transfer_manager', manager)
    sftp = FakeSFTP()
    sftp.destination_exists = False

    @contextmanager
    def fake_session(_session_id, io_lane='control'):
        yield sftp, 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    user_id = _login(client, app, 'release_raise_user')
    token = _token(manager, user_id, 'upload')
    response = client.post(
        f'/api/transfers/{token}/upload', data=b'x',
        content_type='application/octet-stream',
    )

    assert response.status_code == 200
    assert manager._records == {}


def test_release_before_raise_is_retried_before_upload_reports_success(
        app, client, monkeypatch, transfer_components):
    transfer_routes, _manager = transfer_components
    from app.transfer_manager import TransferManager

    class Reservation:
        def __init__(self):
            self.released = False
            self.calls = 0
        def release(self):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError('before release')
            self.released = True

    class Quota:
        def __init__(self): self.reservation = Reservation()
        def reserve(self, *_args): return self.reservation

    quota = Quota()
    manager = TransferManager(quota_manager=quota)
    monkeypatch.setattr(transfer_routes, 'transfer_manager', manager)
    sftp = FakeSFTP(); sftp.destination_exists = False
    @contextmanager
    def fake_session(_session_id, io_lane='control'): yield sftp, 'session'
    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    user_id = _login(client, app, 'before_release_user')
    token = _token(manager, user_id, 'upload')
    response = client.post(f'/api/transfers/{token}/upload', data=b'x', content_type='application/octet-stream')

    assert response.status_code == 200
    assert quota.reservation.calls == 2
    assert quota.reservation.released is True
    assert manager._records == {}


def test_folder_download_streams_local_archive_and_removes_it(
        app, client, monkeypatch, tmp_path, transfer_components):
    import io
    import zipfile

    transfer_routes, manager = transfer_components
    payload = b'zip-data-' * (app.config['CHUNK_SIZE'] + 1)
    remote = TrackingRemoteFile(payload)
    monkeypatch.setattr(transfer_routes.config, 'TRANSFER_TEMP_DIR', str(tmp_path))
    _use_backend(
        monkeypatch, transfer_routes, _SingleFileFolderBackend(payload, remote),
    )
    user_id = _login(client, app, 'folder_download_user')
    record = _folder_record(manager, user_id)

    response = client.get(f'/api/transfers/{record.token}/folder-download')

    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        assert archive.read('reports/a.txt') == payload
    assert max(remote.read_sizes) <= transfer_routes.TRANSFER_CHUNK_SIZE
    assert list(tmp_path.iterdir()) == []
    assert manager._records == {}
def test_smb_folder_download_builds_bounded_local_zip_via_backend(
        app, client, monkeypatch, transfer_components):
    import io
    import zipfile
    from app.remote_transfer import TransferBudget

    transfer_routes, manager = transfer_components
    payload = b'encrypted-smb-folder-body'
    root_identity_chain = (17,)

    class Backend:
        def stat_or_raise(self, _source, path, *, follow_links=False):
            assert follow_links is False
            if path == '/reports':
                return {
                    'size': 0,
                    'is_dir': True,
                    'is_symlink': False,
                    '_smb_identity_chain': root_identity_chain,
                }
            return {
                'size': len(payload), 'is_dir': False, 'is_symlink': False,
            }

        def iter_tree(
                self, _source, path, *, budget, cancel_event,
                follow_links=False, io_lane='control',
                _expected_identities=None):
            assert path == '/reports'
            assert isinstance(budget, TransferBudget)
            assert follow_links is False
            assert io_lane == 'transfer'
            assert _expected_identities == root_identity_chain
            budget.consume()
            yield {
                'name': 'report.txt', 'path': '/reports/report.txt',
                'size': len(payload), 'is_dir': False, 'is_symlink': False,
                '_smb_identity_chain': (17, 23),
            }

        @contextmanager
        def open_reader(
                self, _source, path, *, io_lane='control',
                _expected_identities=None):
            assert path == '/reports/report.txt'
            assert io_lane == 'transfer'
            assert _expected_identities == (17, 23)
            with TrackingRemoteFile(payload) as remote:
                yield FileReaderLease(reader=remote, size=len(payload))

    resolved = SimpleNamespace(
        handle_id='smb-handle', backend=Backend(), source_id='smb-quick:owned',
    )
    monkeypatch.setattr(
        transfer_routes.file_service, 'resolve',
        lambda *_args, **_kwargs: resolved,
    )
    monkeypatch.setattr(
        transfer_routes.sftp_handler, 'sftp_session',
        lambda *_args: (_ for _ in ()).throw(
            AssertionError('SMB folder download must not enter SFTP')
        ),
    )
    user_id = _login(client, app, 'smb_folder_download_user')
    record = manager.create(
        user_id=user_id,
        source_id='smb-quick:owned',
        direction='download',
        metadata={
            'remote_path': '/reports', 'filename': 'reports', 'archive': True,
        },
    )

    response = client.get(f'/api/transfers/{record.token}/folder-download')

    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        assert archive.namelist() == ['reports/report.txt']
        assert archive.read('reports/report.txt') == payload
    assert manager._records == {}


def test_backend_zip_chmod_failure_removes_temporary_archive(
    tmp_path,
    monkeypatch,
):
    from app import transfer_routes

    def reject_chmod(_path, mode):
        assert mode == 0o600
        raise OSError('chmod unavailable')

    monkeypatch.setattr(transfer_routes.Path, 'chmod', reject_chmod)

    with pytest.raises(OSError, match='chmod unavailable'):
        transfer_routes._build_backend_zip_to_disk(
            SimpleNamespace(backend=None),
            '/reports',
            'reports',
            cancel_event=SimpleNamespace(is_set=lambda: False),
            max_bytes=1024,
            chunk_size=4,
            temp_dir=tmp_path,
        )

    assert list(tmp_path.iterdir()) == []


def test_backend_zip_base_exception_removes_temporary_archive(
    tmp_path,
    monkeypatch,
):
    from app import transfer_routes

    monkeypatch.setattr(
        transfer_routes.zipfile,
        'ZipFile',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
    )

    with pytest.raises(KeyboardInterrupt):
        transfer_routes._build_backend_zip_to_disk(
            SimpleNamespace(
                backend=SimpleNamespace(
                    iter_tree=lambda *_args, **_kwargs: []
                )
            ),
            '/reports',
            'reports',
            cancel_event=SimpleNamespace(is_set=lambda: False),
            max_bytes=1024,
            chunk_size=4,
            temp_dir=tmp_path,
        )

    assert list(tmp_path.iterdir()) == []


def test_folder_download_preflight_reports_smb_permission_failure(
        app, client, monkeypatch, transfer_components):
    import app as app_package

    transfer_routes, manager = transfer_components

    class Backend:
        def stat_or_raise(self, *_args, **_kwargs):
            raise PermissionError(r'private \\server\share')

    resolved = SimpleNamespace(
        handle_id='smb-handle', backend=Backend(), source_id='smb-quick:owned',
    )
    monkeypatch.setattr(
        transfer_routes.file_service, 'resolve',
        lambda *_args, **_kwargs: resolved,
    )
    monkeypatch.setattr(
        transfer_routes, '_audit_transfer_source', lambda *_args, **_kwargs: None
    )
    emitted = []
    monkeypatch.setattr(
        app_package.socketio,
        'emit',
        lambda event, payload, **kwargs: emitted.append((event, payload, kwargs)),
    )
    user_id = _login(client, app, 'folder_preflight_denied')
    record = manager.create(
        user_id=user_id,
        source_id='smb-quick:owned',
        direction='download',
        metadata={
            'remote_path': '/restricted',
            'filename': 'restricted',
            'archive': True,
        },
    )

    response = client.get(f'/api/transfers/{record.token}/folder-download')

    expected = {
        'error_code': 'PERMISSION_DENIED',
        'error': 'No read permission for the source.',
        'retryable': False,
    }
    assert response.status_code == 403
    assert response.get_json() == expected
    assert emitted == [(
        'transfer_finished',
        {
            'transfer_id': record.transfer_id,
            'direction': 'download',
            'status': 'failed',
            **expected,
        },
        {'room': f'user_{user_id}'},
    )]
    assert 'private' not in repr(response.get_json())


def test_smb_folder_enumeration_cancellation_is_reported_as_cancelled(
        app, client, monkeypatch, transfer_components):
    import app as app_package
    from app.file_backend import FileOperationCancelled

    transfer_routes, manager = transfer_components

    class Backend:
        def stat_or_raise(self, _source, _path, *, follow_links=False):
            assert follow_links is False
            return {'size': 0, 'is_dir': True, 'is_symlink': False}

        def iter_tree(
                self, _source, _path, *, budget, cancel_event,
                follow_links=False, io_lane='control'):
            assert follow_links is False
            assert io_lane == 'transfer'
            raise FileOperationCancelled('private backend detail')
            yield  # pragma: no cover - generator contract

    resolved = SimpleNamespace(
        handle_id='smb-handle', backend=Backend(), source_id='smb-quick:owned',
    )
    monkeypatch.setattr(
        transfer_routes.file_service, 'resolve',
        lambda *_args, **_kwargs: resolved,
    )
    monkeypatch.setattr(
        transfer_routes, '_audit_transfer_source', lambda *_args, **_kwargs: None
    )
    emitted = []
    monkeypatch.setattr(
        app_package.socketio,
        'emit',
        lambda event, payload, **kwargs: emitted.append((event, payload, kwargs)),
    )
    user_id = _login(client, app, 'folder_enumeration_cancelled')
    record = manager.create(
        user_id=user_id,
        source_id='smb-quick:owned',
        direction='download',
        metadata={
            'remote_path': '/reports', 'filename': 'reports', 'archive': True,
        },
    )

    response = client.get(f'/api/transfers/{record.token}/folder-download')

    expected = {
        'error_code': 'CANCELLED',
        'error': 'The transfer was cancelled.',
        'retryable': False,
    }
    assert response.status_code == 409
    assert response.get_json() == expected
    assert emitted == [(
        'transfer_finished',
        {
            'transfer_id': record.transfer_id,
            'direction': 'download',
            'status': 'cancelled',
            **expected,
        },
        {'room': f'user_{user_id}'},
    )]
    assert record.request_done_event.is_set()


def test_folder_download_rejects_oversized_archive_before_first_chunk(
        app, client, monkeypatch, tmp_path, transfer_components):
    transfer_routes, manager = transfer_components
    remote = TrackingRemoteFile(b'abcdef')
    monkeypatch.setattr(transfer_routes.config, 'TRANSFER_TEMP_DIR', str(tmp_path))
    monkeypatch.setattr(transfer_routes.config, 'MAX_ZIP_DOWNLOAD_SIZE', 4)
    monkeypatch.setattr(transfer_routes, 'TRANSFER_CHUNK_SIZE', 3)
    _use_backend(
        monkeypatch, transfer_routes, _SingleFileFolderBackend(b'abcdef', remote),
    )
    user_id = _login(client, app, 'folder_limit_user')
    record = _folder_record(manager, user_id)

    response = client.get(f'/api/transfers/{record.token}/folder-download')

    assert response.status_code == 413
    assert response.get_json()['error_code'] == 'LIMIT_EXCEEDED'
    assert remote.read_sizes == []
    assert list(tmp_path.iterdir()) == []
    assert record.request_done_event.is_set()
    assert manager._records == {}
def test_closed_folder_response_releases_local_archive_and_record(
        app, client, monkeypatch, tmp_path, transfer_components):
    transfer_routes, manager = transfer_components
    monkeypatch.setattr(transfer_routes.config, 'TRANSFER_TEMP_DIR', str(tmp_path))
    _use_backend(
        monkeypatch, transfer_routes, _SingleFileFolderBackend(b'zip-data'),
    )
    user_id = _login(client, app, 'folder_close_user')
    record = _folder_record(manager, user_id)

    response = client.get(
        f'/api/transfers/{record.token}/folder-download', buffered=False,
    )
    assert len(list(tmp_path.iterdir())) == 1
    response.close()

    assert list(tmp_path.iterdir()) == []
    assert record.request_done_event.is_set()
    assert manager._records == {}
def test_folder_preflight_failure_marks_request_done(
        app, client, monkeypatch, transfer_components):
    transfer_routes, manager = transfer_components

    class FolderSFTP:
        def stat(self, _path):
            raise OSError('preflight failed')

    @contextmanager
    def fake_session(_session_id, io_lane='control'):
        yield FolderSFTP(), 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    user_id = _login(client, app, 'folder_preflight_user')
    record = manager.create(
        user_id=user_id,
        source_id='sftp-session:owned-session',
        direction='download',
        metadata={
            'remote_path': '/reports', 'filename': 'reports', 'archive': True,
        },
    )

    response = client.get(f'/api/transfers/{record.token}/folder-download')

    assert response.status_code == 500
    assert record.request_done_event.is_set()
    assert manager._records == {}


class PoolRecordingRemoteFile(TrackingRemoteFile):
    """Record how many pooled database connections are out during remote I/O."""

    def __init__(self, payload=b'', *, pool):
        super().__init__(payload)
        self.pool = pool
        self.checked_out = []

    def read(self, size=-1):
        self.checked_out.append(self.pool.checkedout())
        return super().read(size)

    def write(self, chunk):
        self.checked_out.append(self.pool.checkedout())
        return super().write(chunk)


def _capture_transfer_events(monkeypatch):
    from app import socketio

    events = []
    original_emit = socketio.emit

    def emit(event, payload=None, *args, **kwargs):
        if event in {'transfer_progress', 'transfer_finished'}:
            events.append((event, dict(payload or {})))
            return None
        return original_emit(event, payload, *args, **kwargs)

    monkeypatch.setattr(socketio, 'emit', emit)
    return events


def _freeze_progress_clock(monkeypatch):
    from app import transfer_progress

    monkeypatch.setattr(
        transfer_progress.ProgressThrottle.__init__,
        '__defaults__',
        (transfer_progress.PROGRESS_INTERVAL_SECONDS, lambda: 100.0),
    )


def _progress_counts(events):
    return [
        payload['transferred']
        for name, payload in events
        if name == 'transfer_progress'
    ]


class _SingleFileFolderBackend:
    def __init__(self, payload, remote=None):
        self.payload = payload
        self.remote = remote

    def stat_or_raise(self, _source, _path, *, follow_links=False):
        return {'size': 0, 'is_dir': True, 'is_symlink': False}

    def iter_tree(self, _source, _path, *, budget, cancel_event,
                  follow_links=False, io_lane='control'):
        budget.consume()
        yield {
            'name': 'a.txt', 'path': '/reports/a.txt',
            'size': len(self.payload), 'is_dir': False, 'is_symlink': False,
        }

    @contextmanager
    def open_reader(self, _source, _path, *, io_lane='control'):
        remote = self.remote or TrackingRemoteFile(self.payload)
        yield FileReaderLease(reader=remote, size=len(self.payload))


def _folder_record(manager, user_id):
    return manager.create(
        user_id=user_id,
        source_id='smb-quick:owned',
        direction='download',
        metadata={
            'remote_path': '/reports', 'filename': 'reports', 'archive': True,
        },
    )


def _use_backend(monkeypatch, transfer_routes, backend):
    resolved = SimpleNamespace(
        handle_id='smb-handle', backend=backend, source_id='smb-quick:owned',
    )
    monkeypatch.setattr(
        transfer_routes.file_service, 'resolve',
        lambda *_args, **_kwargs: resolved,
    )


def test_download_streams_without_holding_a_database_connection(
        app, client, monkeypatch, transfer_components):
    from app.models import db

    transfer_routes, manager = transfer_components
    payload = b'p' * (app.config['CHUNK_SIZE'] * 3 + 5)
    sftp = FakeSFTP()
    sftp.download_file = PoolRecordingRemoteFile(payload, pool=db.engine.pool)

    @contextmanager
    def fake_session(_session_id, io_lane='control'):
        yield sftp, 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    user_id = _login(client, app, 'pool_download_user')
    token = _token(manager, user_id, 'download')

    response = client.get(f'/api/transfers/{token}/download')

    assert response.status_code == 200
    assert response.data == payload
    assert sftp.download_file.checked_out
    assert set(sftp.download_file.checked_out) == {0}


def test_upload_writes_without_holding_a_database_connection(
        app, client, monkeypatch, transfer_components):
    from app.models import db

    transfer_routes, manager = transfer_components
    payload = b'u' * (app.config['CHUNK_SIZE'] * 2 + 3)
    sftp = FakeSFTP()
    sftp.destination_exists = False
    sftp.upload_file = PoolRecordingRemoteFile(pool=db.engine.pool)

    @contextmanager
    def fake_session(_session_id, io_lane='control'):
        yield sftp, 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    user_id = _login(client, app, 'pool_upload_user')
    token = _token(manager, user_id, 'upload')

    response = client.open(
        f'/api/transfers/{token}/upload',
        method='POST',
        input_stream=BoundedRequestStream(payload),
        content_type='application/octet-stream',
        content_length=len(payload),
    )

    assert response.status_code == 200
    assert bytes(sftp.upload_file.written) == payload
    assert sftp.upload_file.checked_out
    assert set(sftp.upload_file.checked_out) == {0}


def test_folder_archive_build_runs_without_holding_a_database_connection(
        app, client, monkeypatch, transfer_components):
    import io
    import zipfile
    from app.models import db

    transfer_routes, manager = transfer_components
    payload = b'folder-body' * 50
    remote = PoolRecordingRemoteFile(payload, pool=db.engine.pool)
    _use_backend(
        monkeypatch, transfer_routes, _SingleFileFolderBackend(payload, remote),
    )
    user_id = _login(client, app, 'pool_folder_user')
    record = _folder_record(manager, user_id)

    response = client.get(f'/api/transfers/{record.token}/folder-download')

    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        assert archive.read('reports/a.txt') == payload
    assert remote.checked_out
    assert set(remote.checked_out) == {0}


def test_download_progress_is_throttled_but_final_count_is_sent(
        app, client, monkeypatch, transfer_components):
    transfer_routes, manager = transfer_components
    _freeze_progress_clock(monkeypatch)
    events = _capture_transfer_events(monkeypatch)
    payload = b'd' * (app.config['CHUNK_SIZE'] * 6 + 9)
    sftp = FakeSFTP(payload)

    @contextmanager
    def fake_session(_session_id, io_lane='control'):
        yield sftp, 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    user_id = _login(client, app, 'throttled_download_user')
    token = _token(manager, user_id, 'download')

    response = client.get(f'/api/transfers/{token}/download')

    assert response.status_code == 200
    assert response.data == payload
    assert _progress_counts(events) == [app.config['CHUNK_SIZE'], len(payload)]
    assert events[-1][0] == 'transfer_finished'
    assert events[-1][1]['status'] == 'completed'


def test_folder_download_progress_is_throttled_but_final_count_is_sent(
        app, client, monkeypatch, transfer_components):
    import os

    transfer_routes, manager = transfer_components
    _freeze_progress_clock(monkeypatch)
    events = _capture_transfer_events(monkeypatch)
    payload = os.urandom(app.config['CHUNK_SIZE'] * 3)
    _use_backend(monkeypatch, transfer_routes, _SingleFileFolderBackend(payload))
    user_id = _login(client, app, 'throttled_folder_user')
    record = _folder_record(manager, user_id)

    response = client.get(f'/api/transfers/{record.token}/folder-download')

    assert response.status_code == 200
    assert len(response.data) > app.config['CHUNK_SIZE'] * 2
    counts = _progress_counts(events)
    assert counts == [app.config['CHUNK_SIZE'], len(response.data)]
    assert events[-1][0] == 'transfer_finished'
    assert events[-1][1]['status'] == 'completed'


def test_upload_progress_is_throttled_but_final_count_is_sent(
        app, client, monkeypatch, transfer_components):
    transfer_routes, manager = transfer_components
    _freeze_progress_clock(monkeypatch)
    events = _capture_transfer_events(monkeypatch)
    payload = b'v' * (app.config['CHUNK_SIZE'] * 5 + 1)
    sftp = FakeSFTP()
    sftp.destination_exists = False

    @contextmanager
    def fake_session(_session_id, io_lane='control'):
        yield sftp, 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    user_id = _login(client, app, 'throttled_upload_user')
    token = _token(manager, user_id, 'upload')

    response = client.open(
        f'/api/transfers/{token}/upload',
        method='POST',
        input_stream=BoundedRequestStream(payload),
        content_type='application/octet-stream',
        content_length=len(payload),
    )

    assert response.status_code == 200
    assert _progress_counts(events) == [app.config['CHUNK_SIZE'], len(payload)]
    assert all(
        payload_['total'] == len(payload)
        for name, payload_ in events
        if name == 'transfer_progress'
    )
    assert events[-1][0] == 'transfer_finished'
    assert events[-1][1]['status'] == 'completed'


def test_failed_download_reports_the_error_after_throttled_progress(
        app, client, monkeypatch, transfer_components):
    transfer_routes, manager = transfer_components
    _freeze_progress_clock(monkeypatch)
    events = _capture_transfer_events(monkeypatch)
    chunk = app.config['CHUNK_SIZE']

    class FailingFile(TrackingRemoteFile):
        def read(self, size=-1):
            if self.offset >= chunk * 3:
                raise OSError(errno.EIO, 'remote read failed')
            return super().read(size)

    sftp = FakeSFTP(b'f' * (chunk * 6))
    sftp.download_file = FailingFile(b'f' * (chunk * 6))

    @contextmanager
    def fake_session(_session_id, io_lane='control'):
        yield sftp, 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    user_id = _login(client, app, 'throttled_failure_user')
    token = _token(manager, user_id, 'download')

    with pytest.raises(OSError):
        client.get(f'/api/transfers/{token}/download').get_data()

    assert _progress_counts(events) == [chunk]
    assert events[-1][0] == 'transfer_finished'
    assert events[-1][1]['status'] == 'failed'


def test_progress_throttle_sends_first_update_and_reports_skipped_ones():
    from app.transfer_progress import ProgressThrottle

    now = [10.0]
    throttle = ProgressThrottle(interval=0.25, clock=lambda: now[0])

    assert throttle.flush() is False
    assert throttle.ready() is True
    assert throttle.ready() is False
    now[0] += 0.1
    assert throttle.ready() is False
    assert throttle.flush() is True
    assert throttle.flush() is False
    now[0] += 0.15
    assert throttle.ready() is True
    assert throttle.flush() is False


def test_folder_archive_uses_temp_quota_when_zip_limit_is_larger(
        app, client, monkeypatch, transfer_components):
    import io
    import zipfile

    transfer_routes, manager = transfer_components
    payload = b'quota-bounded'
    reserved = []
    limits = []
    real_reserve = transfer_routes.quota_manager.reserve
    real_build = transfer_routes._build_backend_zip_to_disk

    def recording_reserve(kind, user_id, amount=1):
        reserved.append((kind, amount))
        return real_reserve(kind, user_id, amount)

    def recording_build(*args, **kwargs):
        limits.append(kwargs['max_bytes'])
        return real_build(*args, **kwargs)

    _use_backend(monkeypatch, transfer_routes, _SingleFileFolderBackend(payload))
    monkeypatch.setattr(transfer_routes.quota_manager, 'reserve', recording_reserve)
    monkeypatch.setattr(transfer_routes, '_build_backend_zip_to_disk', recording_build)
    quota = transfer_routes.config.QUOTA_TEMP_BYTES_PER_USER
    monkeypatch.setattr(
        transfer_routes.config, 'MAX_ZIP_DOWNLOAD_SIZE', quota * 2,
    )
    user_id = _login(client, app, 'zip_quota_user')
    record = _folder_record(manager, user_id)

    response = client.get(f'/api/transfers/{record.token}/folder-download')

    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        assert archive.read('reports/a.txt') == payload
    assert [
        amount for kind, amount in reserved
        if kind == transfer_routes.QuotaKind.TEMP_BYTES
    ] == [quota]
    assert limits == [quota]


@pytest.mark.parametrize('limit', [0, -1])
def test_non_positive_zip_limit_is_a_limit_failure(
        app, client, monkeypatch, transfer_components, limit):
    transfer_routes, manager = transfer_components

    class Backend(_SingleFileFolderBackend):
        def iter_tree(self, *_args, **_kwargs):
            raise AssertionError('no enumeration without a usable limit')

    _use_backend(monkeypatch, transfer_routes, Backend(b''))
    monkeypatch.setattr(transfer_routes.config, 'MAX_ZIP_DOWNLOAD_SIZE', limit)
    user_id = _login(client, app, f'zip_limit_user_{abs(limit)}')
    record = _folder_record(manager, user_id)

    response = client.get(f'/api/transfers/{record.token}/folder-download')

    assert response.status_code != 200
    assert response.get_json()['error_code'] == 'LIMIT_EXCEEDED'
    assert manager._records == {}


@pytest.mark.parametrize(('archive_limit', 'expected'), [
    (0, 'not positive'),
    (-5, 'not positive'),
    (None, 'exceeds QUOTA_TEMP_BYTES_PER_USER'),
])
def test_startup_warns_about_unusable_folder_archive_limits(
        monkeypatch, archive_limit, expected):
    import app as app_module

    quota = app_module.config.QUOTA_TEMP_BYTES_PER_USER
    if archive_limit is None:
        archive_limit = quota + 1
    warnings = []
    monkeypatch.setattr(app_module.config, 'MAX_ZIP_DOWNLOAD_SIZE', archive_limit)
    monkeypatch.setattr(
        app_module, 'log_warning',
        lambda message, **details: warnings.append((message, details)),
    )

    app_module._warn_about_folder_archive_limits()

    assert len(warnings) == 1
    assert expected in warnings[0][0]


def test_startup_is_silent_for_folder_archive_limits_within_quota(monkeypatch):
    import app as app_module

    warnings = []
    monkeypatch.setattr(
        app_module.config,
        'MAX_ZIP_DOWNLOAD_SIZE',
        app_module.config.QUOTA_TEMP_BYTES_PER_USER,
    )
    monkeypatch.setattr(
        app_module, 'log_warning',
        lambda message, **details: warnings.append((message, details)),
    )

    app_module._warn_about_folder_archive_limits()

    assert warnings == []


def test_folder_archives_use_a_prefix_the_startup_sweep_recognizes(tmp_path):
    from app import sftp_handler, transfer_routes

    archive = transfer_routes._create_private_temporary_archive(tmp_path)

    assert archive.parent == tmp_path
    assert sftp_handler._is_folder_archive_name(archive.name)
    assert sftp_handler.sweep_orphaned_folder_archives(tmp_path, min_age_seconds=0) == 1
    assert list(tmp_path.iterdir()) == []
def test_startup_sweep_removes_only_regular_folder_archives(tmp_path):
    import os
    from app import sftp_handler

    archive = tmp_path / 'webssh-folder-abc_1234.zip'
    archive.write_bytes(b'orphan')
    kept = {
        # The default tempfile pattern of earlier releases is not swept:
        # TRANSFER_TEMP_DIR may be a directory other programs use too.
        'tmpabc_1234.zip': b'other',
        'webssh-folder-abc_1234.zip.part': b'other',
        'webssh-folder-ABCDEFGH.zip': b'other',
        'webssh-folder-short.zip': b'other',
        'notes.txt': b'other',
    }
    for name, content in kept.items():
        (tmp_path / name).write_bytes(content)
    directory = tmp_path / 'webssh-folder-dir12345.zip'
    directory.mkdir()
    outside = tmp_path.parent / f'{tmp_path.name}-outside.zip'
    outside.write_bytes(b'outside')
    link = tmp_path / 'webssh-folder-link1234.zip'
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        link = None

    removed = sftp_handler.sweep_orphaned_folder_archives(tmp_path, min_age_seconds=0)

    assert removed == 1
    assert not archive.exists()
    for name, content in kept.items():
        assert (tmp_path / name).read_bytes() == content
    assert directory.is_dir()
    assert outside.read_bytes() == b'outside'
    if link is not None:
        assert os.path.islink(link)


def test_startup_sweep_keeps_recent_archives_of_another_instance(tmp_path):
    import os
    import time
    from app import sftp_handler

    recent = tmp_path / 'webssh-folder-recent12.zip'
    recent.write_bytes(b'in use')
    stale = tmp_path / 'webssh-folder-stale123.zip'
    stale.write_bytes(b'orphan')
    old = time.time() - sftp_handler.ORPHANED_ARCHIVE_MIN_AGE_SECONDS - 60
    os.utime(stale, (old, old))

    assert sftp_handler.sweep_orphaned_folder_archives(tmp_path) == 1
    assert recent.read_bytes() == b'in use'
    assert not stale.exists()


def test_startup_sweep_ignores_missing_or_symlinked_directory(tmp_path):
    import os
    from app import sftp_handler

    assert sftp_handler.sweep_orphaned_folder_archives(tmp_path / 'missing') == 0
    target = tmp_path / 'target'
    target.mkdir()
    archive = target / 'webssh-folder-abc_1234.zip'
    archive.write_bytes(b'kept')
    link = tmp_path / 'linked'
    try:
        os.symlink(target, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip('symbolic links are unavailable')

    assert sftp_handler.sweep_orphaned_folder_archives(link) == 0
    assert archive.exists()


def test_only_runtime_start_sweeps_orphaned_folder_archives(
        monkeypatch, database_template):
    import config
    from app import sftp_handler
    from tests.conftest import _isolated_test_app

    swept = []
    monkeypatch.setattr(
        sftp_handler, 'sweep_orphaned_folder_archives',
        lambda directory: swept.append(directory) or 0,
    )
    for _app in _isolated_test_app(
        monkeypatch, database_template, start_runtime=False,
    ):
        assert swept == []
    for _app in _isolated_test_app(
        monkeypatch, database_template, start_runtime=True,
    ):
        assert swept == [config.TRANSFER_TEMP_DIR]
