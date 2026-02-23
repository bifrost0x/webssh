"""Tests for SSH key type detection."""

import pytest


class TestDetectKeyType:
    """Tests for key type detection from content."""

    def test_rsa_pem_key(self):
        from app.key_manager import detect_key_type
        content = '-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----'
        assert detect_key_type(content) == 'RSA'

    def test_dsa_key(self):
        from app.key_manager import detect_key_type
        content = '-----BEGIN DSA PRIVATE KEY-----\nMIIB...\n-----END DSA PRIVATE KEY-----'
        assert detect_key_type(content) == 'DSA'

    def test_ecdsa_key(self):
        from app.key_manager import detect_key_type
        content = '-----BEGIN EC PRIVATE KEY-----\nMHQ...\n-----END EC PRIVATE KEY-----'
        assert detect_key_type(content) == 'ECDSA'

    def test_generic_pkcs8_key(self):
        from app.key_manager import detect_key_type
        content = '-----BEGIN PRIVATE KEY-----\nMC4...\n-----END PRIVATE KEY-----'
        assert detect_key_type(content) == 'Ed25519/Generic'

    def test_openssh_format_fallback(self):
        from app.key_manager import detect_key_type
        # OpenSSH format that can't be parsed by paramiko without real key data
        # Should return 'OpenSSH' as fallback
        content = '-----BEGIN OPENSSH PRIVATE KEY-----\ninvalid-data\n-----END OPENSSH PRIVATE KEY-----'
        result = detect_key_type(content)
        assert result == 'OpenSSH'

    def test_invalid_key_format(self):
        from app.key_manager import detect_key_type
        assert detect_key_type('not a key at all') is None

    def test_empty_content(self):
        from app.key_manager import detect_key_type
        assert detect_key_type('') is None

    def test_whitespace_handling(self):
        from app.key_manager import detect_key_type
        content = '  \n  -----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----  \n  '
        assert detect_key_type(content) == 'RSA'


class TestSSHUtils:
    """Tests for shared SSH key parsing utility."""

    def test_parse_invalid_key_raises(self):
        import paramiko
        from app.ssh_utils import parse_private_key
        with pytest.raises(paramiko.ssh_exception.SSHException):
            parse_private_key('not a valid key')
