from contextlib import contextmanager
import stat
from types import SimpleNamespace


def test_preview_download_uses_the_capped_buffered_path(monkeypatch):
    from app import binary_transfer

    class RemoteFile:
        def __init__(self):
            self.read_sizes = []

        def read(self, size):
            self.read_sizes.append(size)
            return b'preview' if len(self.read_sizes) == 1 else b''

        def stat(self):
            return SimpleNamespace(
                st_size=7,
                st_mode=stat.S_IFREG | 0o600,
                st_mtime=1,
            )

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    remote_file = RemoteFile()
    sftp = SimpleNamespace(
        stat=lambda _path: SimpleNamespace(st_size=7),
        file=lambda *_args: remote_file,
    )

    @contextmanager
    def fake_session(_session_id):
        yield sftp, 'session'

    monkeypatch.setattr(binary_transfer.sftp_handler, 'sftp_session', fake_session)
    monkeypatch.setattr(binary_transfer.sftp_handler, 'sanitize_path', lambda path: path)

    data, error = binary_transfer.handle_binary_download(
        'owned-session', '/remote/preview.txt', max_size=7,
    )

    assert error is None
    assert data == b'preview'
    assert remote_file.read_sizes == [65536, 65536]


def test_preview_download_rejects_remote_growth_past_the_cap(monkeypatch):
    from app import binary_transfer

    class GrowingRemoteFile:
        def __init__(self):
            self.chunks = iter((b'abcd', b'e', b''))

        def read(self, _size):
            return next(self.chunks)

        def stat(self):
            return SimpleNamespace(
                st_size=4,
                st_mode=stat.S_IFREG | 0o600,
                st_mtime=1,
            )

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    sftp = SimpleNamespace(
        stat=lambda _path: SimpleNamespace(st_size=4),
        file=lambda *_args: GrowingRemoteFile(),
    )

    @contextmanager
    def fake_session(_session_id):
        yield sftp, 'session'

    monkeypatch.setattr(binary_transfer.sftp_handler, 'sftp_session', fake_session)
    monkeypatch.setattr(binary_transfer.sftp_handler, 'sanitize_path', lambda path: path)

    data, error = binary_transfer.handle_binary_download(
        'owned-session',
        '/remote/growing.txt',
        max_size=4,
    )

    assert data is None
    assert 'File too large for download' in error


def test_preview_download_limit_uses_the_opened_object_metadata(monkeypatch):
    """A replacement opened after path stat must not inherit the old size."""
    from app import binary_transfer

    class Replacement:
        def __init__(self):
            self.read_called = False

        def stat(self):
            return SimpleNamespace(
                st_size=9,
                st_mode=stat.S_IFREG | 0o600,
                st_mtime=1,
            )

        def read(self, _size):
            self.read_called = True
            return b'replacement'

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    replacement = Replacement()
    sftp = SimpleNamespace(
        stat=lambda _path: SimpleNamespace(st_size=1),
        file=lambda *_args: replacement,
    )

    @contextmanager
    def fake_session(_session_id):
        yield sftp, 'session'

    monkeypatch.setattr(binary_transfer.sftp_handler, 'sftp_session', fake_session)
    monkeypatch.setattr(binary_transfer.sftp_handler, 'sanitize_path', lambda path: path)

    data, error = binary_transfer.handle_binary_download(
        'owned-session', '/allowed/link.txt', max_size=8,
    )

    assert data is None
    assert 'File too large for download' in error
    assert replacement.read_called is False
