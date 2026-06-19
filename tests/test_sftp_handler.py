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
