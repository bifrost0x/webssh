"""Domain-separated encryption for MFA secrets."""

import base64
import hashlib

from cryptography.fernet import Fernet
from flask import current_app


_TOTP_SALT = b"webssh-mfa-totp-v1"
_KDF_ITERATIONS = 600_000


def derive_totp_key(master_secret, user_id):
    """Derive one Fernet key that cannot be reused for SSH-key ciphertexts."""
    material = f"{master_secret}:totp:{int(user_id)}".encode("utf-8")
    key = hashlib.pbkdf2_hmac(
        "sha256",
        material,
        _TOTP_SALT,
        _KDF_ITERATIONS,
        dklen=32,
    )
    return base64.urlsafe_b64encode(key)


def encrypt_totp_secret(user_id, secret, *, master_secret=None):
    master = (
        current_app.config["SECRET_KEY"]
        if master_secret is None
        else master_secret
    )
    return Fernet(derive_totp_key(master, user_id)).encrypt(
        str(secret).encode("ascii")
    )


def decrypt_totp_secret(user_id, ciphertext, *, master_secret=None):
    master = (
        current_app.config["SECRET_KEY"]
        if master_secret is None
        else master_secret
    )
    return Fernet(derive_totp_key(master, user_id)).decrypt(
        bytes(ciphertext)
    ).decode("ascii")
