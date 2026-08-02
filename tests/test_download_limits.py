import pytest


class ChunkReader:
    def __init__(self, chunks):
        self.chunks = iter(chunks)

    def read(self, _size):
        return next(self.chunks, b'')


def test_streaming_http_download_checks_remote_growth_after_each_chunk():
    """A lying remote stat must not permit a streamed response past its cap."""
    from app.transfer_routes import DownloadLimitExceeded, read_bounded_remote

    remote = ChunkReader([b'abcd', b'efgh'])

    with pytest.raises(DownloadLimitExceeded):
        list(read_bounded_remote(remote, chunk_size=4, max_bytes=6))
