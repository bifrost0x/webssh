"""
SSH Key Encryption Module

Provides at-rest encryption for SSH private keys stored on disk.
Uses Fernet (AES-128-CBC with HMAC) for authenticated encryption.

Key derivation:
- Master key derived from SECRET_KEY
- Per-user keys derived from master + user_id (prevents cross-user access)
"""

import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import config
from .audit_logger import log_info, log_warning, log_error

# Salt for key derivation (fixed per installation)
# In production, this could be stored separately for additional security
_DERIVATION_SALT = b'webssh_key_encryption_v1'


def _derive_key(secret: str, user_id: str) -> bytes:
    """
    Derive a Fernet-compatible encryption key from secret and user_id.

    Uses PBKDF2 with SHA256 and 100,000 iterations.

    Args:
        secret: The application secret key
        user_id: User identifier (ensures keys are user-specific)

    Returns:
        32-byte key suitable for Fernet encryption
    """
    # Combine secret with user_id to create per-user keys
    combined = f"{secret}:{user_id}".encode()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_DERIVATION_SALT,
        iterations=600000,  # OWASP recommended minimum for PBKDF2-SHA256
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

    # PEM-encoded SSH keys start with '-----BEGIN' - NOT encrypted by us
    if data.strip().startswith(b'-----BEGIN'):
        return False

    # Fernet tokens are base64 urlsafe encoded
    try:
        # Check minimum length for Fernet token
        if len(data) < 50:
            return False

        # Fernet tokens use urlsafe base64 (with - and _ instead of + and /)
        # and have a specific structure
        decoded = base64.urlsafe_b64decode(data)

        # Fernet format: version (1) + timestamp (8) + IV (16) + ciphertext + HMAC (32)
        # Minimum size: 1 + 8 + 16 + 16 + 32 = 73 bytes
        # Also check version byte is 0x80 (Fernet version)
        if len(decoded) >= 73 and decoded[0] == 0x80:
            return True

        return False
    except:
        return False


def migrate_key_to_encrypted(user_id: str, key_path: str) -> bool:
    """
    Migrate an unencrypted key file to encrypted format.

    Reads the plaintext key, encrypts it, and writes back.
    Creates a backup with .bak extension first.

    Args:
        user_id: User identifier
        key_path: Path to the key file

    Returns:
        True if migration successful, False otherwise
    """
    from pathlib import Path
    import os

    try:
        path = Path(key_path)
        if not path.exists():
            log_warning(f"Key file not found for migration", path=key_path)
            return False

        # Read current content
        with open(path, 'rb') as f:
            content = f.read()

        # Check if already encrypted
        if is_encrypted(content):
            log_info(f"Key already encrypted", path=key_path)
            return True

        # Encrypt the content
        encrypted = encrypt_key_content(user_id, content.decode('utf-8'))

        # Create backup
        backup_path = str(path) + '.bak'
        with open(backup_path, 'wb') as f:
            f.write(content)
        os.chmod(backup_path, 0o600)

        # Write encrypted content
        with open(path, 'wb') as f:
            f.write(encrypted)
        os.chmod(path, 0o600)

        # Remove backup after successful write
        Path(backup_path).unlink(missing_ok=True)

        log_info(f"Key encrypted successfully", path=key_path, user_id=user_id)
        return True

    except Exception as e:
        log_error(f"Failed to encrypt key", path=key_path, error=str(e))
        return False


def read_key_content(user_id: str, key_path: str) -> str:
    """
    Read and decrypt SSH key content from file.

    Handles both encrypted and legacy unencrypted keys.
    Legacy keys are automatically migrated to encrypted format.

    Args:
        user_id: User identifier
        key_path: Path to the key file

    Returns:
        Decrypted SSH private key content

    Raises:
        FileNotFoundError: If key file doesn't exist
        InvalidToken: If decryption fails
    """
    from pathlib import Path

    path = Path(key_path)
    if not path.exists():
        raise FileNotFoundError(f"Key file not found: {key_path}")

    with open(path, 'rb') as f:
        content = f.read()

    # Check if encrypted
    if is_encrypted(content):
        return decrypt_key_content(user_id, content)
    else:
        # Legacy unencrypted key - migrate it
        log_warning(f"Found unencrypted legacy key, migrating", path=key_path)
        plaintext = content.decode('utf-8')

        # Migrate to encrypted format
        migrate_key_to_encrypted(user_id, key_path)

        return plaintext


def write_key_content(user_id: str, key_path: str, key_content: str) -> bool:
    """
    Encrypt and write SSH key content to file.

    Args:
        user_id: User identifier
        key_path: Path to write the key
        key_content: SSH private key content (PEM format)

    Returns:
        True if successful
    """
    import os
    from pathlib import Path

    try:
        encrypted = encrypt_key_content(user_id, key_content)

        path = Path(key_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, 'wb') as f:
            f.write(encrypted)

        # Set restrictive permissions
        os.chmod(path, 0o600)

        return True

    except Exception as e:
        log_error(f"Failed to write encrypted key", path=key_path, error=str(e))
        return False
