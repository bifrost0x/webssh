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
