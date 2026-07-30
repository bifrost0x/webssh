"""HTTP streaming transfer boundary tests.

These tests deliberately use streams that reject unbounded reads.  A future
regression back to buffering the request or a remote file must therefore fail
at the route boundary, rather than merely consume more memory in production.
"""

from contextlib import contextmanager
import stat
from types import SimpleNamespace

import pytest


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
    def __init__(self, payload=b''):
        self.payload = payload
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
        return SimpleNamespace(st_size=self.reported_size)

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


@pytest.fixture
def transfer_components(monkeypatch):
    from app import transfer_routes
    from app.transfer_manager import TransferManager

    manager = TransferManager(token_ttl=60)
    monkeypatch.setattr(transfer_routes, 'transfer_manager', manager)
    monkeypatch.setattr(transfer_routes, 'session_is_owned', lambda *_args: True)
    return transfer_routes, manager


def _token(manager, user_id, direction, path='/remote/report.bin'):
    return manager.create(
        user_id=user_id,
        session_id='owned-session',
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
    def fake_session(_session_id):
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
    def fake_session(_session_id):
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
                'session_id': 'owned-session',
                'remote_path': '/remote/report.bin',
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
    monkeypatch.setattr(transfer_routes, 'session_is_owned', lambda *_args: True)

    assert transfer_routes.prepare_transfer(
        'user-id', 'upload', 'owned-session', '/remote/report.bin',
    ) is None
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
    def fake_session(_session_id):
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
    def fake_session(_session_id):
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
    def fake_session(_session_id):
        yield sftp, 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    user_id = _login(client, app, f'mutation_{reported_size}')
    token = _token(manager, user_id, 'download')

    response = client.get(f'/api/transfers/{token}/download')

    assert response.status_code == 200
    assert response.data == payload
    assert 'Content-Length' not in response.headers


def test_upload_uses_posix_rename_for_an_existing_remote_destination():
    """Replacing an existing target must not depend on non-portable rename."""
    from app import sftp_handler

    sftp = PosixRenameSFTP(supports_posix_rename=True)

    @contextmanager
    def fake_session(_session_id):
        yield sftp, 'session'

    original_session = sftp_handler.sftp_session
    sftp_handler.sftp_session = fake_session
    try:
        sftp_handler.upload_request_stream(
            'owned-session', '/remote/report.bin', BoundedRequestStream(b'new'),
            chunk_size=2, max_bytes=10,
        )
    finally:
        sftp_handler.sftp_session = original_session

    assert sftp.posix_renamed
    assert sftp.renamed == []


def test_upload_preserves_existing_destination_if_posix_rename_is_unavailable():
    """Do not pre-delete a user file merely to emulate atomic replacement."""
    from app import sftp_handler

    sftp = PosixRenameSFTP(supports_posix_rename=False)

    @contextmanager
    def fake_session(_session_id):
        yield sftp, 'session'

    original_session = sftp_handler.sftp_session
    sftp_handler.sftp_session = fake_session
    try:
        with pytest.raises(Exception):
            sftp_handler.upload_request_stream(
                'owned-session', '/remote/report.bin', BoundedRequestStream(b'new'),
                chunk_size=2, max_bytes=10,
            )
    finally:
        sftp_handler.sftp_session = original_session

    assert sftp.renamed == []
    assert sftp.removed and sftp.removed[0] != '/remote/report.bin'


def test_download_token_is_one_use_and_wrong_user_cannot_consume_it(
        app, monkeypatch, transfer_components):
    transfer_routes, manager = transfer_components
    sftp = FakeSFTP(b'ok')

    @contextmanager
    def fake_session(_session_id):
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
    def fake_session(_session_id):
        yield sftp, 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    user_id = _login(client, app, 'cancel_before')
    record = manager.create(user_id, 'owned-session', 'download', {
        'remote_path': '/remote/report.bin', 'filename': 'report.bin',
    })
    assert manager.cancel(record.transfer_id, user_id) is True

    assert client.get(f'/api/transfers/{record.token}/download').status_code == 404
    assert sftp.opened == []


def test_midstream_upload_overflow_removes_only_temporary_remote_file():
    from app import sftp_handler

    sftp = FakeSFTP()
    sftp.destination_exists = False

    @contextmanager
    def fake_session(_session_id):
        yield sftp, 'session'

    original_session = sftp_handler.sftp_session
    sftp_handler.sftp_session = fake_session
    try:
        with pytest.raises(sftp_handler.UploadSizeExceeded):
            sftp_handler.upload_request_stream(
                'owned-session', '/remote/report.bin', BoundedRequestStream(b'abcdef'),
                chunk_size=4, max_bytes=5,
            )
    finally:
        sftp_handler.sftp_session = original_session

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
    def fake_session(_session_id):
        yield sftp, 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    user_id = _login(client, app, 'generator_close_user')
    record = manager.create(
        user_id=user_id,
        session_id='owned-session',
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
    def fake_session(_session_id):
        yield sftp, 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    user_id = _login(client, app, 'download_close_user')
    record = manager.create(
        user_id=user_id,
        session_id='owned-session',
        direction='download',
        metadata={'remote_path': '/remote/report.bin', 'filename': 'report.bin'},
    )

    response = client.get(
        f'/api/transfers/{record.token}/download', buffered=False,
    )
    response.close()

    assert record.request_done_event.is_set()
    assert manager._records == {}


def test_download_preflight_limit_marks_request_done(
        app, client, monkeypatch, transfer_components):
    transfer_routes, manager = transfer_components
    sftp = FakeSFTP()
    sftp.reported_size = app.config['MAX_DOWNLOAD_SIZE'] + 1

    @contextmanager
    def fake_session(_session_id):
        yield sftp, 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    user_id = _login(client, app, 'download_limit_user')
    record = manager.create(
        user_id=user_id,
        session_id='owned-session',
        direction='download',
        metadata={'remote_path': '/remote/large.bin', 'filename': 'large.bin'},
    )

    response = client.get(f'/api/transfers/{record.token}/download')

    assert response.status_code == 413
    assert record.request_done_event.is_set()
    assert manager._records == {}


def test_upload_close_failure_removes_temporary_file_and_keeps_final_hidden():
    """A remote close error is terminal and never exposes the final pathname."""
    from app import sftp_handler

    class CloseFailure(TrackingRemoteFile):
        def close(self):
            super().close()
            raise OSError('close failed')

    sftp = FakeSFTP()
    sftp.destination_exists = False
    sftp.upload_file = CloseFailure()

    @contextmanager
    def fake_session(_session_id):
        yield sftp, 'session'

    original = sftp_handler.sftp_session
    sftp_handler.sftp_session = fake_session
    try:
        with pytest.raises(OSError):
            sftp_handler.upload_request_stream(
                'owned', '/remote/report.bin', BoundedRequestStream(b'body'),
                chunk_size=4, max_bytes=10,
            )
    finally:
        sftp_handler.sftp_session = original

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
    def fake_session(_session_id):
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
    def fake_session(_session_id): yield sftp, 'session'
    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    user_id = _login(client, app, 'before_release_user')
    token = _token(manager, user_id, 'upload')
    response = client.post(f'/api/transfers/{token}/upload', data=b'x', content_type='application/octet-stream')

    assert response.status_code == 200
    assert quota.reservation.calls == 2
    assert quota.reservation.released is True
    assert manager._records == {}


def test_folder_download_streams_remote_zip_and_cleans_it(
        app, client, monkeypatch, transfer_components):
    transfer_routes, manager = transfer_components
    payload = b'zip-data-' * (app.config['CHUNK_SIZE'] + 1)

    class SSHClient:
        def exec_command(self, _command):
            channel = SimpleNamespace(
                settimeout=lambda _timeout: None,
                recv_exit_status=lambda: 0,
            )
            return None, SimpleNamespace(channel=channel), None

    class FolderSFTP:
        def __init__(self):
            self._client = SSHClient()
            self.remote = TrackingRemoteFile(payload)
            self.removed = []

        def stat(self, path):
            if path == '/reports':
                return SimpleNamespace(st_mode=stat.S_IFDIR)
            return SimpleNamespace(st_size=len(payload))

        def file(self, _path, _mode):
            return self.remote

        def remove(self, path):
            self.removed.append(path)

    sftp = FolderSFTP()

    @contextmanager
    def fake_session(_session_id):
        yield sftp, 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    monkeypatch.setattr(
        transfer_routes.sftp_handler, 'inspect_remote_tree',
        lambda *_args, **_kwargs: (len(payload), False),
    )
    monkeypatch.setattr(
        transfer_routes.sftp_handler, 'get_ssh_client',
        lambda _session_id: sftp._client,
    )
    user_id = _login(client, app, 'folder_download_user')
    token = manager.create(
        user_id=user_id,
        session_id='owned-session',
        direction='download',
        metadata={
            'remote_path': '/reports',
            'filename': 'reports',
            'archive': True,
        },
    ).token

    response = client.get(f'/api/transfers/{token}/folder-download')

    assert response.status_code == 200
    assert response.data == payload
    assert max(sftp.remote.read_sizes) <= app.config['CHUNK_SIZE']
    assert len(sftp.removed) == 1
    assert sftp.removed[0].startswith('/tmp/reports_')
    assert manager._records == {}


def test_unstarted_folder_response_releases_remote_archive_and_record(
        app, client, monkeypatch, transfer_components):
    transfer_routes, manager = transfer_components

    class FolderSFTP:
        def __init__(self):
            self.removed = []

        def stat(self, path):
            return SimpleNamespace(st_mode=stat.S_IFDIR)

        def remove(self, path):
            self.removed.append(path)

    sftp = FolderSFTP()

    @contextmanager
    def fake_session(_session_id):
        yield sftp, 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    monkeypatch.setattr(
        transfer_routes.sftp_handler, 'inspect_remote_tree',
        lambda *_args, **_kwargs: (0, False),
    )
    monkeypatch.setattr(
        transfer_routes, '_remote_zip_path',
        lambda *_args: ('/tmp/reports.zip', 10),
    )
    user_id = _login(client, app, 'folder_close_user')
    record = manager.create(
        user_id=user_id,
        session_id='owned-session',
        direction='download',
        metadata={
            'remote_path': '/reports', 'filename': 'reports', 'archive': True,
        },
    )

    response = client.get(
        f'/api/transfers/{record.token}/folder-download', buffered=False,
    )
    response.close()

    assert sftp.removed == ['/tmp/reports.zip']
    assert record.request_done_event.is_set()
    assert manager._records == {}


def test_folder_preflight_failure_marks_request_done(
        app, client, monkeypatch, transfer_components):
    transfer_routes, manager = transfer_components

    class FolderSFTP:
        def stat(self, _path):
            raise OSError('preflight failed')

    @contextmanager
    def fake_session(_session_id):
        yield FolderSFTP(), 'session'

    monkeypatch.setattr(transfer_routes.sftp_handler, 'sftp_session', fake_session)
    user_id = _login(client, app, 'folder_preflight_user')
    record = manager.create(
        user_id=user_id,
        session_id='owned-session',
        direction='download',
        metadata={
            'remote_path': '/reports', 'filename': 'reports', 'archive': True,
        },
    )

    response = client.get(f'/api/transfers/{record.token}/folder-download')

    assert response.status_code == 500
    assert record.request_done_event.is_set()
    assert manager._records == {}


def test_remote_zip_command_uses_private_permissions():
    from app.transfer_routes import _remote_zip_path

    commands = []

    class SSHClient:
        def exec_command(self, command):
            commands.append(command)
            channel = SimpleNamespace(
                settimeout=lambda _timeout: None,
                recv_exit_status=lambda: 0,
            )
            return None, SimpleNamespace(channel=channel), None

    class SFTP:
        def stat(self, _path):
            return SimpleNamespace(st_size=10)

    result = _remote_zip_path(SFTP(), SSHClient(), '/reports')

    assert result[1] == 10
    assert commands[0].startswith('umask 077 && ')
    assert 'chmod 600 ' in commands[0]
