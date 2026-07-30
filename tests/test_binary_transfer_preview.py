from contextlib import contextmanager
from types import SimpleNamespace


def test_preview_download_uses_the_capped_buffered_path(monkeypatch):
    from app import binary_transfer

    class RemoteFile:
        def __init__(self):
            self.read_sizes = []

        def read(self, size):
            self.read_sizes.append(size)
            return b'preview' if len(self.read_sizes) == 1 else b''

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
