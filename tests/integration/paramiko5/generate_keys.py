#!/usr/bin/env python3
"""Generate throwaway keys for the disposable OpenSSH integration fixture."""

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa


BASE_DIR = Path(__file__).resolve().parent
RUNTIME_DIR = (BASE_DIR / 'runtime').resolve()
KEY_PASSPHRASE = b'Paramiko5-Key-Passphrase!'


def _write_private_key(path, key, private_format, encryption=None):
    content = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=private_format,
        encryption_algorithm=encryption or serialization.NoEncryption(),
    )
    path.write_bytes(content)
    if os.name == 'posix':
        path.chmod(0o600)


def main():
    expected_runtime = (BASE_DIR / 'runtime').resolve()
    if RUNTIME_DIR != expected_runtime or RUNTIME_DIR.parent != BASE_DIR:
        raise RuntimeError('Refusing to write outside the fixture runtime directory')

    RUNTIME_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

    keys = {
        'rsa': (
            rsa.generate_private_key(public_exponent=65537, key_size=2048),
            serialization.PrivateFormat.OpenSSH,
        ),
        'ed25519': (
            ed25519.Ed25519PrivateKey.generate(),
            serialization.PrivateFormat.OpenSSH,
        ),
        'ecdsa': (
            ec.generate_private_key(ec.SECP256R1()),
            serialization.PrivateFormat.OpenSSH,
        ),
    }

    authorized = []
    for name, (key, private_format) in keys.items():
        _write_private_key(RUNTIME_DIR / f'{name}.pem', key, private_format)
        _write_private_key(
            RUNTIME_DIR / f'{name}_encrypted.pem',
            key,
            private_format,
            serialization.BestAvailableEncryption(KEY_PASSPHRASE),
        )
        public_key = key.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        ).decode('ascii')
        authorized.append(f'{public_key} paramiko5-{name}')

    authorized_keys = RUNTIME_DIR / 'authorized_keys'
    authorized_keys.write_text(
        '\n'.join(authorized) + '\n',
        encoding='utf-8',
    )
    if os.name == 'posix':
        authorized_keys.chmod(0o600)


if __name__ == '__main__':
    main()
