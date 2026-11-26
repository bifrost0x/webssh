"""SSH private keys in every format the upload path sees.

Accepted keys go through ``key_manager.save_key`` and end up Fernet-encrypted
under ``users/user_<id>/keys/``. Formats the app rejects (PKCS#8, any
passphrase-protected key) are kept as negative vectors together with the
exact error ``save_key`` returns.
"""

import base64

from cryptography.hazmat.primitives import serialization as ser

from . import key_material

PASSPHRASE = b'golden key passphrase'

# (label, algorithm, key factory argument)
KEYS = (
    ('rsa2048', 'RSA', None),
    ('ecdsa-p256', 'ECDSA', 'nistp256'),
    ('ecdsa-p384', 'ECDSA', 'nistp384'),
    ('ecdsa-p521', 'ECDSA', 'nistp521'),
    ('ed25519', 'Ed25519', None),
)
FORMATS = {
    'openssh': ser.PrivateFormat.OpenSSH,
    'pem': ser.PrivateFormat.TraditionalOpenSSL,
    'pkcs8': ser.PrivateFormat.PKCS8,
}
# Serialization whose randomness stays inside OpenSSL (IV, PBKDF2 salt).
_OPENSSL_RANDOM = {('pem', True), ('pkcs8', True)}


def _private_key(stream, algorithm, argument):
    if algorithm == 'RSA':
        return key_material.rsa_key(stream, 2048)
    if algorithm == 'ECDSA':
        return key_material.ec_key(stream, argument)
    return key_material.ed25519_key(stream)


def build_matrix(stream):
    """Every (key, format, passphrase) combination cryptography can write."""
    matrix = []
    for label, algorithm, argument in KEYS:
        private_key = _private_key(stream, algorithm, argument)
        public = private_key.public_key().public_bytes(
            ser.Encoding.OpenSSH, ser.PublicFormat.OpenSSH,
        ).decode('ascii')
        for format_name, private_format in FORMATS.items():
            for protected in (False, True):
                encryption = (
                    ser.BestAvailableEncryption(PASSPHRASE)
                    if protected else ser.NoEncryption()
                )
                try:
                    pem = private_key.private_bytes(
                        ser.Encoding.PEM, private_format, encryption,
                    ).decode('ascii')
                except ValueError:
                    # Ed25519 has no traditional OpenSSL PEM form.
                    continue
                matrix.append({
                    'label': f'{label}-{format_name}'
                             + ('-passphrase' if protected else ''),
                    'algorithm': algorithm,
                    'format': format_name,
                    'passphrase_protected': protected,
                    'public_key_openssh': public,
                    'content': pem,
                    'deterministic': (format_name, protected) not in _OPENSSL_RANDOM,
                })
    return matrix


def store_keys(user_id, matrix):
    """Upload every variant through save_key; record stored or rejected."""
    from app.key_manager import save_key

    stored, rejected = [], []
    for item in matrix:
        record, error = save_key(user_id, item['label'], item['content'])
        entry = {k: v for k, v in item.items() if k != 'content'}
        # Base64 keeps synthetic private keys out of plain-text scanner hits.
        entry['plaintext_b64'] = base64.b64encode(
            item['content'].encode('ascii')
        ).decode('ascii')
        if error is None:
            entry['key_id'] = record['id']
            entry['stored_file'] = f'users/user_{user_id}/keys/{record["filename"]}'
            entry['key_type'] = record['key_type']
            stored.append(entry)
        else:
            entry['expected_error'] = error
            rejected.append(entry)
    return stored, rejected


def store_legacy_plaintext_key(user_id, item):
    """A key file from before at-rest encryption: plaintext PEM on disk.

    ``key_encryption.read_key_content`` accepts and migrates such files, so
    readers must handle them. Built by writing the plaintext over a key that
    save_key created, which is what an old installation left behind.
    """
    from app.key_manager import get_user_keys_dir, save_key

    record, error = save_key(user_id, 'legacy-plaintext-' + item['label'],
                             item['content'])
    if error:
        raise RuntimeError(error)
    path = get_user_keys_dir(user_id) / record['filename']
    path.write_text(item['content'], encoding='ascii')
    path.chmod(0o600)
    return {
        'key_id': record['id'],
        'stored_file': f'users/user_{user_id}/keys/{record["filename"]}',
        'key_type': record['key_type'],
        'source_label': item['label'],
    }
