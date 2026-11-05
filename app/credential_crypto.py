"""Authenticated, domain-separated encryption using the application secret."""
import base64
import json
import os
import config
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .automation_store import incarnation, AutomationError


def _context(user_id, record_id, account_incarnation):
    return json.dumps(['webssh-named-credentials-v1', int(user_id), account_incarnation, record_id], separators=(',', ':')).encode()


def _cipher(secret, context):
    if isinstance(secret, str):
        secret = secret.encode()
    return AESGCM(HKDF(algorithm=hashes.SHA256(), length=32, salt=b'webssh-named-credential-master-v1', info=context).derive(secret))


def encrypt_with_secret(user_id, record_id, password, *, master_secret, account_incarnation):
    """Encrypt offline with an explicit account incarnation and master secret."""
    context = _context(user_id, record_id, account_incarnation)
    nonce = os.urandom(12)
    return base64.b64encode(nonce + _cipher(master_secret, context).encrypt(nonce, password.encode(), context)).decode()


def decrypt_with_secret(user_id, record_id, ciphertext, *, master_secret, account_incarnation):
    """Decrypt offline without consulting application configuration or the ORM."""
    try:
        context = _context(user_id, record_id, account_incarnation)
        data = base64.b64decode(ciphertext, validate=True)
        return _cipher(master_secret, context).decrypt(data[:12], data[12:], context).decode()
    except Exception as error:
        raise AutomationError('credential_unreadable') from error


def encrypt(user_id, record_id, password):
    return encrypt_with_secret(user_id, record_id, password,
                               master_secret=config.SECRET_KEY,
                               account_incarnation=incarnation(user_id))


def decrypt(user_id, record_id, ciphertext):
    try:
        return decrypt_with_secret(user_id, record_id, ciphertext,
                                   master_secret=config.SECRET_KEY,
                                   account_incarnation=incarnation(user_id))
    except Exception as error:
        raise AutomationError('credential_unreadable') from error
