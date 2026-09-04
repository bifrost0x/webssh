"""
SSH Key Encryption Module

Provides at-rest encryption for SSH private keys stored on disk.
Uses Fernet (AES-128-CBC with HMAC) for authenticated encryption.

Key derivation:
- Master key derived from SECRET_KEY
- Per-user keys derived from master + user_id (prevents cross-user access)
"""

import base64
from contextlib import contextmanager
from functools import wraps
import hmac
import os
from pathlib import Path
import tempfile
import threading

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import config
from .audit_logger import log_info, log_warning, log_error
from .ssh_key_loader import identify_private_key
from .storage_utils import atomic_write_bytes, fsync_parent_directory

_DERIVATION_SALT = b'webssh_key_encryption_v1'
_key_file_locks = {}
_key_file_locks_guard = threading.Lock()
key_operation_lock = threading.RLock()


def _serialized_key_operation(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        with key_operation_lock:
            return function(*args, **kwargs)
    return wrapper

def _derive_key(secret: str, user_id: str) -> bytes:
    """
    Derive a Fernet-compatible encryption key from secret and user_id.

    Uses PBKDF2 with SHA256 and 600,000 iterations.

    Args:
        secret: The application secret key
        user_id: User identifier (ensures keys are user-specific)

    Returns:
        32-byte key suitable for Fernet encryption
    """
    combined = f"{secret}:{user_id}".encode()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_DERIVATION_SALT,
        iterations=600000,
    )

    key = kdf.derive(combined)
    return base64.urlsafe_b64encode(key)

def get_user_fernet(user_id: str) -> Fernet:
    """
    Get a Fernet instance for a specific user.

    Args:
        user_id: User identifier

    Returns:
        Fernet instance configured with user-specific key
    """
    key = _derive_key(config.SECRET_KEY, str(user_id))
    return Fernet(key)

def encrypt_key_content(user_id: str, key_content: str) -> bytes:
    """
    Encrypt SSH key content for storage.

    Args:
        user_id: User identifier
        key_content: The SSH private key content (PEM format)

    Returns:
        Encrypted bytes (includes authentication tag)
    """
    fernet = get_user_fernet(user_id)
    return fernet.encrypt(key_content.encode('utf-8'))

def decrypt_key_content(user_id: str, encrypted_data: bytes) -> str:
    """
    Decrypt SSH key content from storage.

    Args:
        user_id: User identifier
        encrypted_data: The encrypted key bytes

    Returns:
        Decrypted SSH private key content (PEM format)

    Raises:
        InvalidToken: If decryption fails (wrong key or tampered data)
    """
    fernet = get_user_fernet(user_id)
    decrypted = fernet.decrypt(encrypted_data)
    return decrypted.decode('utf-8')

def is_encrypted(data: bytes) -> bool:
    """
    Check if data appears to be Fernet-encrypted.

    Distinguishes between:
    - PEM-encoded SSH keys (start with '-----BEGIN')
    - Fernet-encrypted data (base64 urlsafe, specific structure)

    Args:
        data: The data to check

    Returns:
        True if data appears to be Fernet-encrypted
    """
    if isinstance(data, str):
        data = data.encode()

    if data.strip().startswith(b'-----BEGIN'):
        return False

    try:
        if len(data) < 50:
            return False

        decoded = base64.urlsafe_b64decode(data)

        if len(decoded) >= 73 and decoded[0] == 0x80:
            return True

        return False
    except Exception:
        return False

def _canonical_key_path(path: Path) -> str:
    """Return one identity for path aliases, including existing symlinks."""
    return os.path.normcase(str(path.resolve(strict=False)))


@contextmanager
def _key_file_lock(
        path: Path, *, must_exist: bool = True,
        allowed_root: Path = None):
    """Lock and yield the one canonical path used for the whole operation.

    Callers that obtain paths from metadata must validate the resolved target
    against the user's keys directory before entering this trusted file layer.
    """
    operation_path = path.resolve(strict=must_exist)
    if allowed_root is not None:
        canonical_root = Path(allowed_root).resolve(strict=True)
        if not operation_path.is_relative_to(canonical_root):
            raise ValueError('key path escaped user keys directory')
    identity = os.path.normcase(str(operation_path))
    with _key_file_locks_guard:
        entry = _key_file_locks.get(identity)
        if entry is None:
            entry = {'lock': threading.Lock(), 'refs': 0}
            _key_file_locks[identity] = entry
        entry['refs'] += 1

    acquired = False
    try:
        entry['lock'].acquire()
        acquired = True
        yield operation_path
    finally:
        if acquired:
            entry['lock'].release()
        with _key_file_locks_guard:
            entry['refs'] -= 1
            if (
                entry['refs'] == 0
                and _key_file_locks.get(identity) is entry
            ):
                del _key_file_locks[identity]


def _ensure_private_permissions(path: Path) -> None:
    """Enforce and verify the key-file mode on POSIX systems."""
    if os.name != 'posix':
        return
    if path.stat().st_mode & 0o077:
        path.chmod(0o600)
    if path.stat().st_mode & 0o077:
        raise PermissionError('SSH key file permissions are not private')


def _decrypt_stored_key(
        user_id: str, path: Path, encrypted: bytes) -> str:
    """Authenticate stored ciphertext and enforce its private file mode."""
    plaintext = decrypt_key_content(user_id, encrypted)
    _ensure_private_permissions(path)
    return plaintext


def _restore_plaintext(path: Path, plaintext: bytes) -> None:
    """Atomically restore plaintext after a failed migration attempt."""
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='wb',
            dir=path.parent,
            prefix=f'.{path.name}.',
            suffix='.rollback.tmp',
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(plaintext)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
        temporary_path = None
        fsync_parent_directory(path)
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass


def _decode_validated_legacy_key(plaintext: bytes) -> str:
    plaintext_text = plaintext.decode('utf-8')
    identify_private_key(plaintext_text)
    return plaintext_text


def _migrate_key_to_encrypted_locked(
        user_id: str, path: Path, plaintext: bytes) -> None:
    """Replace plaintext with verified ciphertext while its file lock is held."""
    plaintext_text = _decode_validated_legacy_key(plaintext)
    encrypted = encrypt_key_content(
        user_id, plaintext_text
    )

    try:
        atomic_write_bytes(path, encrypted, mode=0o600)
        stored = path.read_bytes()
        verified = decrypt_key_content(user_id, stored).encode('utf-8')
        if not hmac.compare_digest(verified, plaintext):
            raise ValueError('Legacy key migration verification failed')
    except Exception:
        try:
            _restore_plaintext(path, plaintext)
        except Exception as rollback_error:
            raise RuntimeError(
                'Legacy key migration rollback failed'
            ) from rollback_error
        raise


@_serialized_key_operation
def migrate_key_to_encrypted(
        user_id: str, key_path: str, *,
        allowed_root: Path = None) -> None:
    """
    Migrate an unencrypted key file to encrypted format.

    Reads the plaintext key, encrypts it, atomically writes it, and verifies
    the stored ciphertext before returning. Any failed migration restores the
    original plaintext bytes before raising.

    Args:
        user_id: User identifier
        key_path: Path to the key file

    Raises:
        FileNotFoundError: If the key file does not exist.
        Exception: If encryption, writing, or verification fails.
    """
    path = Path(key_path)
    with _key_file_lock(
            path, allowed_root=allowed_root) as operation_path:
        content = operation_path.read_bytes()
        if is_encrypted(content):
            _decrypt_stored_key(str(user_id), operation_path, content)
            return

        try:
            _migrate_key_to_encrypted_locked(
                str(user_id), operation_path, content
            )
        except Exception as exc:
            log_error(
                "Failed to migrate legacy key",
                user_id=user_id,
                error_type=type(exc).__name__,
            )
            raise
        log_info("Legacy key encrypted successfully", user_id=user_id)


@_serialized_key_operation
def read_key_content(
        user_id: str, key_path: str, migrate_legacy: bool = True, *,
        allowed_root: Path = None) -> str:
    """
    Read and decrypt SSH key content from file.

    Handles both encrypted and legacy unencrypted keys.
    Legacy keys are automatically migrated to encrypted format.

    Args:
        user_id: User identifier
        key_path: Path to the key file
        migrate_legacy: Encrypt a legacy plaintext key before returning it.

    Returns:
        Decrypted SSH private key content

    Raises:
        FileNotFoundError: If key file doesn't exist
        InvalidToken: If decryption fails
    """
    path = Path(key_path)
    with _key_file_lock(
            path, allowed_root=allowed_root) as operation_path:
        content = operation_path.read_bytes()
        if is_encrypted(content):
            return _decrypt_stored_key(
                str(user_id), operation_path, content
            )

        plaintext = _decode_validated_legacy_key(content)
        if not migrate_legacy:
            return plaintext

        log_warning(
            "Found unencrypted legacy key, migrating",
            user_id=user_id,
        )
        try:
            _migrate_key_to_encrypted_locked(
                str(user_id), operation_path, content
            )
        except Exception as exc:
            log_error(
                "Failed to migrate legacy key",
                user_id=user_id,
                error_type=type(exc).__name__,
            )
            raise
        return plaintext

def _write_prepared_key_content(
        user_id: str, key_path: str, encrypted: bytes, *,
        allowed_root: Path = None) -> bool:
    """Write ciphertext prepared by ``encrypt_key_content``."""
    try:
        path = Path(key_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with _key_file_lock(
                path, must_exist=False,
                allowed_root=allowed_root) as operation_path:
            atomic_write_bytes(operation_path, encrypted, mode=0o600)

        return True

    except Exception as e:
        log_error(
            "Failed to write encrypted key",
            user_id=user_id,
            error_type=type(e).__name__,
        )
        return False


@_serialized_key_operation
def write_prepared_key_content(
        user_id: str, key_path: str, encrypted: bytes, *,
        allowed_root: Path = None) -> bool:
    """Write server-prepared ciphertext without deriving the key twice."""
    return _write_prepared_key_content(
        user_id, key_path, encrypted, allowed_root=allowed_root
    )


@_serialized_key_operation
def write_key_content(
        user_id: str, key_path: str, key_content: str, *,
        allowed_root: Path = None) -> bool:
    """Encrypt and write SSH key content to file."""
    encrypted = encrypt_key_content(user_id, key_content)
    return _write_prepared_key_content(
        user_id, key_path, encrypted, allowed_root=allowed_root
    )


def _replace_prepared_key_content(
        user_id: str, key_path: str, key_content: str, encrypted: bytes, *,
        allowed_root: Path = None) -> bool:
    """Replace an encrypted key using already prepared ciphertext."""
    path = Path(key_path)
    try:
        with _key_file_lock(
                path, allowed_root=allowed_root) as operation_path:
            original = operation_path.read_bytes()
            try:
                atomic_write_bytes(operation_path, encrypted, mode=0o600)
                stored = operation_path.read_bytes()
                verified = decrypt_key_content(
                    str(user_id), stored
                ).encode('utf-8')
                if not hmac.compare_digest(
                    verified,
                    key_content.encode('utf-8'),
                ):
                    raise ValueError('SSH key replacement verification failed')
            except Exception as exc:
                try:
                    _restore_plaintext(operation_path, original)
                except Exception as rollback_error:
                    raise RuntimeError(
                        'SSH key replacement rollback failed'
                    ) from rollback_error
                log_error(
                    "Failed to replace encrypted key",
                    user_id=user_id,
                    error_type=type(exc).__name__,
                )
                return False
        return True
    except RuntimeError:
        raise
    except Exception as exc:
        log_error(
            "Failed to replace encrypted key",
            user_id=user_id,
            error_type=type(exc).__name__,
        )
        return False


@_serialized_key_operation
def replace_prepared_key_content(
        user_id: str, key_path: str, key_content: str, encrypted: bytes, *,
        allowed_root: Path = None) -> bool:
    """Atomically replace a key with server-prepared ciphertext."""
    return _replace_prepared_key_content(
        user_id, key_path, key_content, encrypted,
        allowed_root=allowed_root,
    )


@_serialized_key_operation
def replace_key_content(
        user_id: str, key_path: str, key_content: str, *,
        allowed_root: Path = None) -> bool:
    """Replace an existing encrypted key and restore its bytes on failure."""
    encrypted = encrypt_key_content(str(user_id), key_content)
    return _replace_prepared_key_content(
        user_id, key_path, key_content, encrypted,
        allowed_root=allowed_root,
    )
