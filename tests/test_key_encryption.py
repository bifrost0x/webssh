"""Tests for SSH key encryption/decryption."""

import base64
import os
from pathlib import Path
import tempfile
import threading
import uuid

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

    def test_is_encrypted_empty(self):
        from app.key_encryption import is_encrypted
        assert is_encrypted(b'') is False


class TestKeyFileOperations:
    """Tests for key file read/write operations."""

    def test_write_and_read_key(self):
        from app.key_encryption import write_key_content, read_key_content
        user_id = '42'
        content = '-----BEGIN RSA PRIVATE KEY-----\ntest-key-data\n-----END RSA PRIVATE KEY-----'

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, 'test_key.pem')
            assert write_key_content(user_id, key_path, content) is True

            # File should have restricted permissions (POSIX only; Windows
            # does not implement Unix permission bits).
            if os.name == 'posix':
                mode = os.stat(key_path).st_mode & 0o777
                assert mode == 0o600

            decrypted = read_key_content(user_id, key_path)
            assert decrypted == content

    def test_read_nonexistent_key(self):
        from app.key_encryption import read_key_content
        with pytest.raises(FileNotFoundError):
            read_key_content('1', '/nonexistent/path')

    def test_migrate_unencrypted_key(self, rsa_private_key_pem):
        from app.key_encryption import (
            migrate_key_to_encrypted, read_key_content, is_encrypted
        )
        user_id = '42'
        content = rsa_private_key_pem

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, 'unencrypted.pem')
            # newline='' keeps the bytes exactly as written so the roundtrip
            # comparison holds on Windows too (text mode would turn \n into \r\n).
            with open(key_path, 'w', newline='') as f:
                f.write(content)

            assert migrate_key_to_encrypted(user_id, key_path) is None

            with open(key_path, 'rb') as f:
                data = f.read()
            assert is_encrypted(data) is True

            decrypted = read_key_content(user_id, key_path)
            assert decrypted == content

    @pytest.mark.parametrize(
        'fixture_name',
        (
            'rsa_private_key_pem',
            'ed25519_private_key_pem',
            'ecdsa_private_key_pem',
        ),
    )
    def test_migrates_real_supported_legacy_key_types(
            self, request, fixture_name):
        from app.key_encryption import (
            is_encrypted,
            migrate_key_to_encrypted,
            read_key_content,
        )

        user_id = 'real-key-types'
        content = request.getfixturevalue(fixture_name)
        original = content.encode('utf-8')

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / f'{fixture_name}.pem'
            key_path.write_bytes(original)

            migrate_key_to_encrypted(user_id, str(key_path))

            stored = key_path.read_bytes()
            assert stored != original
            assert is_encrypted(stored)
            assert read_key_content(user_id, str(key_path)) == content

    def test_existing_encrypted_key_is_authenticated_without_rewrite(self):
        from cryptography.fernet import InvalidToken
        from app.key_encryption import (
            encrypt_key_content,
            is_encrypted,
            migrate_key_to_encrypted,
        )

        valid = encrypt_key_content('owner', 'private key material')
        other_user = encrypt_key_content('other-user', 'private key material')
        decoded = bytearray(base64.urlsafe_b64decode(valid))
        decoded[-1] ^= 0x01
        corrupt = base64.urlsafe_b64encode(decoded)
        assert is_encrypted(corrupt)

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / 'encrypted.pem'

            key_path.write_bytes(valid)
            migrate_key_to_encrypted('owner', str(key_path))
            assert key_path.read_bytes() == valid

            key_path.write_bytes(other_user)
            with pytest.raises(InvalidToken):
                migrate_key_to_encrypted('owner', str(key_path))
            assert key_path.read_bytes() == other_user

            key_path.write_bytes(corrupt)
            with pytest.raises(InvalidToken):
                migrate_key_to_encrypted('owner', str(key_path))
            assert key_path.read_bytes() == corrupt

    @pytest.mark.parametrize(
        'invalid_content',
        (
            b'gAAAAinvalid',
            b'this is not an SSH private key',
        ),
        ids=('truncated-fernet', 'arbitrary-text'),
    )
    @pytest.mark.parametrize(
        'operation_name',
        ('migrate_key_to_encrypted', 'read_key_content'),
    )
    def test_invalid_legacy_content_is_rejected_without_rewrite(
            self, invalid_content, operation_name, tmp_path):
        from app import key_encryption
        from app.ssh_key_loader import UnsupportedPrivateKeyError

        key_path = tmp_path / f'{operation_name}.pem'
        key_path.write_bytes(invalid_content)
        operation = getattr(key_encryption, operation_name)

        with pytest.raises(UnsupportedPrivateKeyError):
            operation('owner', str(key_path))

        assert key_path.read_bytes() == invalid_content

    @pytest.mark.parametrize(
        'operation_name',
        ('migrate_key_to_encrypted', 'read_key_content'),
    )
    def test_passphrase_encrypted_legacy_key_is_rejected_without_rewrite(
            self, encrypted_rsa_private_key_pem, operation_name, tmp_path):
        import paramiko
        from app import key_encryption

        original = encrypted_rsa_private_key_pem.encode('utf-8')
        key_path = tmp_path / f'{operation_name}.pem'
        key_path.write_bytes(original)
        operation = getattr(key_encryption, operation_name)

        with pytest.raises(paramiko.PasswordRequiredException):
            operation('owner', str(key_path))

        assert key_path.read_bytes() == original

    @pytest.mark.skipif(os.name != 'posix', reason='POSIX permissions only')
    def test_existing_encrypted_key_permissions_are_corrected_without_rewrite(
            self):
        from app.key_encryption import (
            encrypt_key_content,
            migrate_key_to_encrypted,
        )

        encrypted = encrypt_key_content('owner', 'private key material')
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / 'encrypted.pem'
            key_path.write_bytes(encrypted)
            key_path.chmod(0o644)

            migrate_key_to_encrypted('owner', str(key_path))

            assert key_path.read_bytes() == encrypted
            assert key_path.stat().st_mode & 0o077 == 0

    def test_read_legacy_key_returns_plaintext_and_migrates(
            self, rsa_private_key_pem):
        # read_key_content transparently reads a legacy unencrypted key,
        # returns its plaintext, and migrates the file to encrypted on disk.
        from app.key_encryption import read_key_content, is_encrypted
        user_id = '7'
        content = rsa_private_key_pem

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, 'legacy.pem')
            with open(key_path, 'w', newline='') as f:
                f.write(content)

            # Precondition: file is plaintext on disk.
            with open(key_path, 'rb') as f:
                assert is_encrypted(f.read()) is False

            # Reading returns the plaintext...
            assert read_key_content(user_id, key_path) == content

            # ...and the file has been migrated to encrypted form.
            with open(key_path, 'rb') as f:
                assert is_encrypted(f.read()) is True

    def test_failed_legacy_migration_never_returns_plaintext_as_success(
            self, monkeypatch, rsa_private_key_pem):
        from app import key_encryption

        user_id = '7'
        original = rsa_private_key_pem.encode('utf-8')

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, 'legacy.pem')
            with open(key_path, 'wb') as handle:
                handle.write(original)

            def fail_write(*_args, **_kwargs):
                raise OSError('simulated write failure')

            monkeypatch.setattr(
                key_encryption, 'atomic_write_bytes', fail_write
            )

            with pytest.raises(OSError):
                key_encryption.read_key_content(user_id, key_path)

            assert open(key_path, 'rb').read() == original
            assert sorted(os.listdir(tmpdir)) == ['legacy.pem']

    def test_post_replace_failure_restores_plaintext_without_leftovers(
            self, monkeypatch, ed25519_private_key_pem):
        from app import key_encryption
        from app.storage_utils import atomic_write_bytes as real_atomic_write

        user_id = '8'
        original = ed25519_private_key_pem.encode('utf-8')

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, 'legacy.pem')
            with open(key_path, 'wb') as handle:
                handle.write(original)

            def replace_then_fail(path, payload, mode=0o600):
                real_atomic_write(path, payload, mode)
                raise OSError('simulated post-replace failure')

            monkeypatch.setattr(
                key_encryption, 'atomic_write_bytes', replace_then_fail
            )

            with pytest.raises(OSError):
                key_encryption.migrate_key_to_encrypted(user_id, key_path)

            assert open(key_path, 'rb').read() == original
            assert sorted(os.listdir(tmpdir)) == ['legacy.pem']

    def test_key_replacement_post_replace_failure_restores_ciphertext(
            self, monkeypatch, rsa_private_key_pem,
            rsa_openssh_private_key_pem):
        from app import key_encryption
        from app.storage_utils import atomic_write_bytes as real_atomic_write

        user_id = 'replacement-rollback'
        original = key_encryption.encrypt_key_content(
            user_id, rsa_private_key_pem
        )
        errors = []

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / 'stored.pem'
            key_path.write_bytes(original)

            def replace_then_fail(path, payload, mode=0o600):
                real_atomic_write(path, payload, mode)
                raise OSError('private post-replace failure detail')

            monkeypatch.setattr(
                key_encryption, 'atomic_write_bytes', replace_then_fail
            )
            monkeypatch.setattr(
                key_encryption,
                'log_error',
                lambda message, **fields: errors.append((message, fields)),
            )

            replaced = key_encryption.replace_key_content(
                user_id,
                str(key_path),
                rsa_openssh_private_key_pem,
                allowed_root=Path(tmpdir),
            )

            assert replaced is False
            assert key_path.read_bytes() == original
            assert sorted(os.listdir(tmpdir)) == ['stored.pem']
            assert errors == [(
                'Failed to replace encrypted key',
                {'user_id': user_id, 'error_type': 'OSError'},
            )]
            assert 'private post-replace failure detail' not in repr(errors)

    def test_failed_readback_verification_restores_plaintext(
            self, monkeypatch, ecdsa_private_key_pem):
        from app import key_encryption

        user_id = '9'
        original = ecdsa_private_key_pem.encode('utf-8')

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, 'legacy.pem')
            with open(key_path, 'wb') as handle:
                handle.write(original)

            monkeypatch.setattr(
                key_encryption,
                'decrypt_key_content',
                lambda *_args: 'different plaintext',
            )

            with pytest.raises(ValueError, match='verification'):
                key_encryption.migrate_key_to_encrypted(user_id, key_path)

            assert open(key_path, 'rb').read() == original
            assert sorted(os.listdir(tmpdir)) == ['legacy.pem']

    def test_readback_error_restores_plaintext(
            self, monkeypatch, rsa_private_key_pem):
        from app import key_encryption

        user_id = '12'
        original = rsa_private_key_pem.encode('utf-8')

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, 'legacy.pem')
            with open(key_path, 'wb') as handle:
                handle.write(original)

            real_read_bytes = Path.read_bytes
            reads = 0

            def fail_stored_read(path):
                nonlocal reads
                reads += 1
                if reads == 2:
                    raise OSError('simulated stored read failure')
                return real_read_bytes(path)

            monkeypatch.setattr(Path, 'read_bytes', fail_stored_read)

            with pytest.raises(OSError):
                key_encryption.migrate_key_to_encrypted(user_id, key_path)

            assert real_read_bytes(Path(key_path)) == original
            assert sorted(os.listdir(tmpdir)) == ['legacy.pem']

    def test_decrypt_error_restores_plaintext_without_logging_error_text(
            self, monkeypatch, rsa_private_key_pem):
        from app import key_encryption

        user_id = '13'
        original = rsa_private_key_pem.encode('utf-8')
        secret_error = 'private-material-must-not-be-logged'
        errors = []

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, 'legacy.pem')
            with open(key_path, 'wb') as handle:
                handle.write(original)

            monkeypatch.setattr(
                key_encryption,
                'decrypt_key_content',
                lambda *_args: (_ for _ in ()).throw(
                    RuntimeError(secret_error)
                ),
            )
            monkeypatch.setattr(
                key_encryption,
                'log_error',
                lambda message, **fields: errors.append((message, fields)),
            )

            with pytest.raises(RuntimeError, match=secret_error):
                key_encryption.migrate_key_to_encrypted(user_id, key_path)

            assert open(key_path, 'rb').read() == original
            assert sorted(os.listdir(tmpdir)) == ['legacy.pem']
            assert errors == [(
                'Failed to migrate legacy key',
                {'user_id': user_id, 'error_type': 'RuntimeError'},
            )]
            assert secret_error not in repr(errors)

    def test_rollback_fsync_failure_is_reported_even_after_replace(
            self, monkeypatch, rsa_private_key_pem):
        from app import key_encryption

        user_id = 'rollback-fsync'
        original = rsa_private_key_pem.encode('utf-8')
        errors = []

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / 'legacy.pem'
            key_path.write_bytes(original)
            monkeypatch.setattr(
                key_encryption,
                'decrypt_key_content',
                lambda *_args: 'different plaintext',
            )
            monkeypatch.setattr(
                key_encryption,
                'fsync_parent_directory',
                lambda *_args: (_ for _ in ()).throw(
                    OSError('sentinel rollback fsync detail')
                ),
            )
            monkeypatch.setattr(
                key_encryption,
                'log_error',
                lambda message, **fields: errors.append((message, fields)),
            )

            with pytest.raises(
                    RuntimeError,
                    match='Legacy key migration rollback failed'):
                key_encryption.migrate_key_to_encrypted(
                    user_id, str(key_path)
                )

            assert key_path.read_bytes() == original
            assert sorted(os.listdir(tmpdir)) == ['legacy.pem']
            assert errors == [(
                'Failed to migrate legacy key',
                {'user_id': user_id, 'error_type': 'RuntimeError'},
            )]
            assert 'sentinel rollback fsync detail' not in repr(errors)

    @pytest.mark.parametrize(
        'invalid_content',
        (
            b'gAAAAinvalid',
            b'this is not an SSH private key',
        ),
        ids=('truncated-fernet', 'arbitrary-text'),
    )
    def test_read_invalid_legacy_without_migration_rejects_without_write(
            self, invalid_content, monkeypatch, tmp_path):
        from app import key_encryption
        from app.ssh_key_loader import UnsupportedPrivateKeyError

        key_path = tmp_path / 'invalid.pem'
        key_path.write_bytes(invalid_content)
        monkeypatch.setattr(
            key_encryption,
            'atomic_write_bytes',
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError('migration-disabled read must not write')
            ),
        )

        with pytest.raises(UnsupportedPrivateKeyError):
            key_encryption.read_key_content(
                '10', str(key_path), migrate_legacy=False
            )

        assert key_path.read_bytes() == invalid_content

    def test_read_real_legacy_without_migration_validates_without_write(
            self, rsa_private_key_pem, monkeypatch, tmp_path):
        from app import key_encryption

        user_id = '10'
        original = rsa_private_key_pem.encode('utf-8')
        key_path = tmp_path / 'legacy.pem'
        key_path.write_bytes(original)
        monkeypatch.setattr(
            key_encryption,
            'atomic_write_bytes',
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError('migration-disabled read must not write')
            ),
        )

        assert key_encryption.read_key_content(
            user_id, str(key_path), migrate_legacy=False
        ) == rsa_private_key_pem
        assert key_path.read_bytes() == original

    def test_concurrent_legacy_reads_migrate_once_without_corruption(
            self, monkeypatch, rsa_private_key_pem):
        from app import key_encryption
        from app.storage_utils import atomic_write_bytes as real_atomic_write

        user_id = '11'
        original = rsa_private_key_pem.encode('utf-8')
        writes = []
        writes_guard = threading.Lock()

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, 'legacy.pem')
            with open(key_path, 'wb') as handle:
                handle.write(original)

            def recording_write(path, payload, mode=0o600):
                with writes_guard:
                    writes.append(bytes(payload))
                return real_atomic_write(path, payload, mode)

            monkeypatch.setattr(
                key_encryption, 'atomic_write_bytes', recording_write
            )
            barrier = threading.Barrier(3)
            results = []
            errors = []

            def read_key():
                barrier.wait()
                try:
                    results.append(
                        key_encryption.read_key_content(user_id, key_path)
                    )
                except Exception as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=read_key) for _ in range(2)]
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join(timeout=5)

            assert errors == []
            assert results == [original.decode('utf-8')] * 2
            assert len(writes) == 1
            stored = open(key_path, 'rb').read()
            assert key_encryption.is_encrypted(stored)
            assert key_encryption.decrypt_key_content(
                user_id, stored
            ).encode('utf-8') == original
            assert sorted(os.listdir(tmpdir)) == ['legacy.pem']

    def test_key_file_lock_registry_returns_to_baseline_for_unique_paths(self):
        from app import key_encryption

        baseline = len(key_encryption._key_file_locks)
        with tempfile.TemporaryDirectory() as tmpdir:
            for _ in range(200):
                path = Path(tmpdir) / f'{uuid.uuid4()}.pem'
                with key_encryption._key_file_lock(
                        path, must_exist=False):
                    assert len(key_encryption._key_file_locks) >= baseline + 1

        assert len(key_encryption._key_file_locks) == baseline

    def test_key_file_lock_canonicalizes_aliases_and_serializes_waiters(self):
        from app import key_encryption

        baseline = len(key_encryption._key_file_locks)
        with tempfile.TemporaryDirectory() as tmpdir:
            directory = Path(tmpdir)
            path = directory / 'key.pem'
            alias = directory / 'nested' / '..' / 'key.pem'
            entered = []
            first_holds_lock = threading.Event()
            release_first = threading.Event()

            def first():
                with key_encryption._key_file_lock(
                        path, must_exist=False):
                    entered.append('first')
                    first_holds_lock.set()
                    release_first.wait(timeout=5)

            def second():
                first_holds_lock.wait(timeout=5)
                with key_encryption._key_file_lock(
                        alias, must_exist=False):
                    entered.append('second')

            threads = [
                threading.Thread(target=first),
                threading.Thread(target=second),
            ]
            for thread in threads:
                thread.start()
            assert first_holds_lock.wait(timeout=5)
            assert entered == ['first']
            release_first.set()
            for thread in threads:
                thread.join(timeout=5)

            assert entered == ['first', 'second']
            assert len(key_encryption._key_file_locks) == baseline

    def test_key_file_lock_canonicalizes_symlink_alias_when_supported(self):
        from app import key_encryption

        with tempfile.TemporaryDirectory() as tmpdir:
            directory = Path(tmpdir)
            path = directory / 'key.pem'
            alias = directory / 'key-alias.pem'
            path.write_bytes(b'legacy')
            try:
                alias.symlink_to(path)
            except OSError as exc:
                pytest.skip(f'symlink creation unavailable: {type(exc).__name__}')

            assert key_encryption._canonical_key_path(alias) == (
                key_encryption._canonical_key_path(path)
            )

    def test_migration_through_symlink_preserves_link_and_encrypts_target(
            self, rsa_private_key_pem, monkeypatch):
        from app import key_encryption

        user_id = 'symlink-migration'
        original = rsa_private_key_pem.encode('utf-8')
        with tempfile.TemporaryDirectory() as tmpdir:
            directory = Path(tmpdir)
            target = directory / 'target.pem'
            alias = directory / 'alias.pem'
            target.write_bytes(original)
            try:
                alias.symlink_to(target)
            except OSError as exc:
                pytest.skip(
                    f'symlink creation unavailable: {type(exc).__name__}'
                )
            real_resolve = Path.resolve
            operation_resolves = []

            def recording_resolve(path, *args, **kwargs):
                if path == alias:
                    operation_resolves.append(path)
                return real_resolve(path, *args, **kwargs)

            monkeypatch.setattr(Path, 'resolve', recording_resolve)

            key_encryption.migrate_key_to_encrypted(
                user_id, str(alias)
            )

            assert operation_resolves == [alias]
            assert alias.is_symlink()
            stored = target.read_bytes()
            assert key_encryption.is_encrypted(stored)
            assert original not in stored
            assert key_encryption.read_key_content(
                user_id, str(alias)
            ) == rsa_private_key_pem

    def test_symlink_alias_and_target_share_operation_lock(
            self, rsa_private_key_pem, monkeypatch):
        from app import key_encryption
        from app.storage_utils import atomic_write_bytes as real_atomic_write

        user_id = 'symlink-concurrency'
        original = rsa_private_key_pem.encode('utf-8')
        writes = []
        first_write_started = threading.Event()
        release_first_write = threading.Event()
        errors = []
        results = []

        with tempfile.TemporaryDirectory() as tmpdir:
            directory = Path(tmpdir)
            target = directory / 'target.pem'
            alias = directory / 'alias.pem'
            target.write_bytes(original)
            try:
                alias.symlink_to(target)
            except OSError as exc:
                pytest.skip(
                    f'symlink creation unavailable: {type(exc).__name__}'
                )

            def controlled_write(path, payload, mode=0o600):
                writes.append(Path(path))
                if len(writes) == 1:
                    first_write_started.set()
                    assert release_first_write.wait(timeout=5)
                return real_atomic_write(path, payload, mode)

            monkeypatch.setattr(
                key_encryption, 'atomic_write_bytes', controlled_write
            )

            def read(path):
                try:
                    results.append(
                        key_encryption.read_key_content(user_id, str(path))
                    )
                except Exception as exc:
                    errors.append(exc)

            alias_thread = threading.Thread(target=read, args=(alias,))
            target_thread = threading.Thread(target=read, args=(target,))
            alias_thread.start()
            assert first_write_started.wait(timeout=5)
            target_thread.start()
            release_first_write.set()
            alias_thread.join(timeout=5)
            target_thread.join(timeout=5)

            assert errors == []
            assert results == [rsa_private_key_pem] * 2
            assert writes == [target.resolve(strict=True)]
            assert alias.is_symlink()
            assert key_encryption.is_encrypted(target.read_bytes())
            assert key_encryption._key_file_locks == {}

    def test_symlink_migration_write_failure_restores_target_and_link(
            self, rsa_private_key_pem, monkeypatch):
        from app import key_encryption
        from app.storage_utils import atomic_write_bytes as real_atomic_write

        user_id = 'symlink-rollback'
        original = rsa_private_key_pem.encode('utf-8')
        with tempfile.TemporaryDirectory() as tmpdir:
            directory = Path(tmpdir)
            target = directory / 'target.pem'
            alias = directory / 'alias.pem'
            target.write_bytes(original)
            try:
                alias.symlink_to(target)
            except OSError as exc:
                pytest.skip(
                    f'symlink creation unavailable: {type(exc).__name__}'
                )

            def replace_then_fail(path, payload, mode=0o600):
                real_atomic_write(path, payload, mode)
                raise OSError('simulated post-replace failure')

            monkeypatch.setattr(
                key_encryption, 'atomic_write_bytes', replace_then_fail
            )

            with pytest.raises(OSError):
                key_encryption.migrate_key_to_encrypted(
                    user_id, str(alias)
                )

            assert alias.is_symlink()
            assert target.read_bytes() == original
            assert sorted(path.name for path in directory.iterdir()) == [
                'alias.pem',
                'target.pem',
            ]

    def test_broken_symlink_migration_fails_closed(self):
        from app import key_encryption

        with tempfile.TemporaryDirectory() as tmpdir:
            directory = Path(tmpdir)
            alias = directory / 'broken.pem'
            try:
                alias.symlink_to(directory / 'missing-target.pem')
            except OSError as exc:
                pytest.skip(
                    f'symlink creation unavailable: {type(exc).__name__}'
                )

            with pytest.raises(FileNotFoundError):
                key_encryption.migrate_key_to_encrypted(
                    'broken-symlink', str(alias)
                )

            assert alias.is_symlink()
            assert sorted(path.name for path in directory.iterdir()) == [
                'broken.pem',
            ]
