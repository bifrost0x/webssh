"""Tests for SSH key encryption/decryption."""

import os
import tempfile
import pytest


class TestKeyEncryption:
    """Tests for encrypt/decrypt operations."""

    def test_encrypt_decrypt_roundtrip(self):
        from app.key_encryption import encrypt_key_content, decrypt_key_content
        user_id = '42'
        key_content = '-----BEGIN RSA PRIVATE KEY-----\nfake-key-content\n-----END RSA PRIVATE KEY-----'
        encrypted = encrypt_key_content(user_id, key_content)
        decrypted = decrypt_key_content(user_id, encrypted)
        assert decrypted == key_content

    def test_different_users_different_ciphertext(self):
        from app.key_encryption import encrypt_key_content
        content = '-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----'
        enc1 = encrypt_key_content('1', content)
        enc2 = encrypt_key_content('2', content)
        assert enc1 != enc2

    def test_cross_user_decryption_fails(self):
        from app.key_encryption import encrypt_key_content, decrypt_key_content
        from cryptography.fernet import InvalidToken
        content = '-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----'
        encrypted = encrypt_key_content('1', content)
        with pytest.raises(InvalidToken):
            decrypt_key_content('2', encrypted)

    def test_is_encrypted_detects_fernet(self):
        from app.key_encryption import encrypt_key_content, is_encrypted
        encrypted = encrypt_key_content('1', 'test content')
        assert is_encrypted(encrypted) is True

    def test_is_encrypted_detects_pem(self):
        from app.key_encryption import is_encrypted
        pem = b'-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----'
        assert is_encrypted(pem) is False

    def test_is_encrypted_short_data(self):
        from app.key_encryption import is_encrypted
        assert is_encrypted(b'short') is False


class TestKeyFileOperations:
    """Tests for key file read/write operations."""

    def test_write_and_read_key(self):
        from app.key_encryption import write_key_content, read_key_content
        user_id = '42'
        content = '-----BEGIN RSA PRIVATE KEY-----\ntest-key-data\n-----END RSA PRIVATE KEY-----'

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, 'test_key.pem')
            assert write_key_content(user_id, key_path, content) is True

            # File should have restricted permissions
            mode = os.stat(key_path).st_mode & 0o777
            assert mode == 0o600

            decrypted = read_key_content(user_id, key_path)
            assert decrypted == content

    def test_read_nonexistent_key(self):
        from app.key_encryption import read_key_content
        with pytest.raises(FileNotFoundError):
            read_key_content('1', '/nonexistent/path')

    def test_migrate_unencrypted_key(self):
        from app.key_encryption import (
            migrate_key_to_encrypted, read_key_content, is_encrypted
        )
        user_id = '42'
        content = '-----BEGIN RSA PRIVATE KEY-----\nplaintext-key\n-----END RSA PRIVATE KEY-----'

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, 'unencrypted.pem')
            with open(key_path, 'w') as f:
                f.write(content)

            assert migrate_key_to_encrypted(user_id, key_path) is True

            with open(key_path, 'rb') as f:
                data = f.read()
            assert is_encrypted(data) is True

            decrypted = read_key_content(user_id, key_path)
            assert decrypted == content
