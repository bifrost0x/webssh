"""Domain-separated encryption for the admin-managed GitHub client secret."""

import base64
import hashlib

from cryptography.fernet import Fernet
from flask import current_app


_GITHUB_AUTH_SALT = b'webssh-github-auth-config-v1'
_KDF_ITERATIONS = 600_000


def derive_github_auth_key(master_secret):
    material = f'{master_secret}:github-auth:configuration'.encode('utf-8')
    key = hashlib.pbkdf2_hmac(
        'sha256', material, _GITHUB_AUTH_SALT, _KDF_ITERATIONS, dklen=32
    )
    return base64.urlsafe_b64encode(key)


def encrypt_client_secret(secret, *, master_secret=None):
    master = (
        current_app.config['SECRET_KEY']
        if master_secret is None
        else master_secret
    )
    return Fernet(derive_github_auth_key(master)).encrypt(
        str(secret).encode('utf-8')
    )


def decrypt_client_secret(ciphertext, *, master_secret=None):
    master = (
        current_app.config['SECRET_KEY']
        if master_secret is None
        else master_secret
    )
    return Fernet(derive_github_auth_key(master)).decrypt(
        bytes(ciphertext)
    ).decode('utf-8')
