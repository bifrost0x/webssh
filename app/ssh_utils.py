"""
Shared SSH utility functions.

Provides common SSH operations used across ssh_manager and connection_pool
to avoid code duplication.
"""

import io
import paramiko


def parse_private_key(key_content):
    """
    Parse SSH private key content, trying all supported key types.

    Tries RSA, Ed25519, ECDSA, and DSS in order. Returns the first
    successfully parsed key.

    Args:
        key_content: SSH private key content as string (PEM format)

    Returns:
        paramiko.PKey: The parsed private key

    Raises:
        paramiko.ssh_exception.SSHException: If no key type matches
    """
    key_file = io.StringIO(key_content)
    last_error = None

    for key_class in (paramiko.RSAKey, paramiko.Ed25519Key,
                      paramiko.ECDSAKey, paramiko.DSSKey):
        key_file.seek(0)
        try:
            return key_class.from_private_key(key_file)
        except paramiko.ssh_exception.SSHException as e:
            last_error = e
            continue

    raise paramiko.ssh_exception.SSHException(
        f"Unsupported key format: {last_error}"
    )
