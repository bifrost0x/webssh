"""Tests for SFTP path sanitization."""

import pytest


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
