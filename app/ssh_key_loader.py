"""Private-key parsing shared by terminal and temporary SSH connections."""

import io

import paramiko


class UnsupportedPrivateKeyError(paramiko.SSHException):
    """Raised when key material is invalid or unsupported."""


class InvalidPrivateKeyPassphraseError(paramiko.SSHException):
    """Raised when encrypted key material cannot be decrypted."""


_SUPPORTED_KEY_CLASSES = (
    ('RSA', paramiko.RSAKey),
    ('Ed25519', paramiko.Ed25519Key),
    ('ECDSA', paramiko.ECDSAKey),
)


def _parse_private_key(key_content, password=None):
    if not isinstance(key_content, str) or not key_content.strip():
        raise UnsupportedPrivateKeyError(
            'Unsupported or invalid private key format'
        )

    if 'BEGIN DSA PRIVATE KEY' in key_content:
        raise UnsupportedPrivateKeyError(
            'DSA private keys are not supported; use Ed25519, ECDSA, or RSA'
        )

    password = password or None
    password_required = False
    for key_type, key_class in _SUPPORTED_KEY_CLASSES:
        try:
            key = key_class.from_private_key(
                io.StringIO(key_content),
                password=password,
            )
            return key, key_type
        except paramiko.PasswordRequiredException:
            password_required = True
        except paramiko.SSHException:
            continue

    if password_required:
        raise paramiko.PasswordRequiredException(
            'SSH key passphrase required'
        )

    if password is not None:
        raise InvalidPrivateKeyPassphraseError(
            'Invalid private key or passphrase'
        )

    raise UnsupportedPrivateKeyError(
        'Unsupported or invalid private key format'
    )


def load_private_key(key_content, password=None):
    """Return a supported Paramiko private key."""
    key, _key_type = _parse_private_key(key_content, password=password)
    return key


def identify_private_key(key_content, password=None):
    """Return the normalized supported key type."""
    _key, key_type = _parse_private_key(key_content, password=password)
    return key_type
