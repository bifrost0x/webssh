#!/usr/bin/env python3
"""Read-only Paramiko 5 readiness check for stored private keys."""

import argparse
import base64
import io
import json
import os
import re
import sys
from pathlib import Path

import paramiko
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

SUPPORTED_KEY_CLASSES = (
    ('RSA', paramiko.RSAKey),
    ('Ed25519', paramiko.Ed25519Key),
    ('ECDSA', paramiko.ECDSAKey),
)
_DERIVATION_SALT = b'webssh_key_encryption_v1'
_SAFE_IDENTIFIER = re.compile(r'^[A-Za-z0-9._-]{1,128}$')
_KNOWN_METADATA_TYPES = {'RSA', 'Ed25519', 'ECDSA', 'DSA'}


def _get_user_fernet(user_id):
    secret_key = os.environ.get('SECRET_KEY')
    if not secret_key:
        raise RuntimeError('SECRET_KEY is required to inspect encrypted keys')
    combined = f'{secret_key}:{user_id}'.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_DERIVATION_SALT,
        iterations=600000,
    )
    return Fernet(base64.urlsafe_b64encode(kdf.derive(combined)))


def _decrypt_key_content(user_id, encrypted_data):
    return _get_user_fernet(str(user_id)).decrypt(encrypted_data).decode('utf-8')


def _is_encrypted(data):
    if isinstance(data, str):
        data = data.encode()
    if data.strip().startswith(b'-----BEGIN') or len(data) < 50:
        return False
    try:
        decoded = base64.urlsafe_b64decode(data)
    except Exception:
        return False
    return len(decoded) >= 73 and decoded[0] == 0x80


def _safe_identifier(value):
    return value if isinstance(value, str) and _SAFE_IDENTIFIER.fullmatch(value) else None


def _safe_metadata_type(value):
    return value if value in _KNOWN_METADATA_TYPES else 'UNKNOWN'


def read_without_migration(user_id, key_path):
    """Read a key without invoking the legacy plaintext migration path."""
    raw = Path(key_path).read_bytes()
    if _is_encrypted(raw):
        return _decrypt_key_content(str(user_id), raw)
    return raw.decode('utf-8')


def classify_key(content):
    """Return normalized actual type and Paramiko-5 compatibility."""
    if not isinstance(content, str):
        return 'UNPARSEABLE', False

    if 'BEGIN DSA PRIVATE KEY' in content:
        return 'DSA', False

    key_classes = list(SUPPORTED_KEY_CLASSES)
    dss_class = getattr(paramiko, 'DSSKey', None)
    if dss_class is not None:
        key_classes.append(('DSA', dss_class))

    for key_type, key_class in key_classes:
        try:
            key_class.from_private_key(io.StringIO(content))
            return key_type, key_type != 'DSA'
        except paramiko.PasswordRequiredException:
            return 'PASSPHRASE_ENCRYPTED', True
        except paramiko.SSHException:
            continue

    return 'UNPARSEABLE', False


def _read_error(error_type, **fields):
    return {
        **fields,
        'actual_type': 'READ_ERROR',
        'compatible': False,
        'error_type': error_type,
    }


def audit_data_dir(data_dir):
    """Classify stored keys without mutating or following unsafe paths."""
    results = []
    try:
        data_root = Path(data_dir).resolve(strict=True)
    except Exception as exc:
        return [_read_error(type(exc).__name__, scope='data')]

    users_dir = data_root / 'users'
    if not users_dir.exists():
        return results
    if users_dir.is_symlink() or not users_dir.is_dir():
        return [_read_error('UnsafeUsersDirectory', scope='users')]

    for user_dir in sorted(users_dir.iterdir(), key=lambda path: path.name):
        if not user_dir.name.startswith('user_'):
            continue
        if user_dir.is_symlink() or not user_dir.is_dir():
            results.append(_read_error(
                'UnsafeUserDirectory',
                scope='user',
            ))
            continue

        try:
            user_id = int(user_dir.name.removeprefix('user_'))
        except ValueError:
            continue

        keys_dir = user_dir / 'keys'
        keys_file = keys_dir / 'keys.json'
        if not keys_file.exists():
            continue

        try:
            if keys_dir.is_symlink() or keys_file.is_symlink():
                raise ValueError('unsafe key metadata path')
            resolved_keys_dir = keys_dir.resolve(strict=True)
            resolved_keys_file = keys_file.resolve(strict=True)
            if not resolved_keys_file.is_relative_to(resolved_keys_dir):
                raise ValueError('key metadata escaped its directory')
            metadata = json.loads(
                resolved_keys_file.read_text(encoding='utf-8')
            )
            if (
                not isinstance(metadata, dict)
                or not isinstance(metadata.get('keys', []), list)
            ):
                raise ValueError('invalid key metadata structure')
        except Exception as exc:
            results.append(_read_error(
                type(exc).__name__,
                user_id=user_id,
            ))
            continue

        for item in metadata.get('keys', []):
            result = {
                'user_id': user_id,
                'key_id': (
                    _safe_identifier(item.get('id'))
                    if isinstance(item, dict) else None
                ),
                'metadata_type': (
                    _safe_metadata_type(item.get('key_type'))
                    if isinstance(item, dict) else 'UNKNOWN'
                ),
            }
            try:
                if not isinstance(item, dict):
                    raise ValueError('invalid key metadata entry')
                filename = item.get('filename')
                if not isinstance(filename, str) or not filename:
                    raise ValueError('invalid key filename')

                candidate = keys_dir / filename
                if candidate.is_symlink():
                    raise ValueError('symlinked key file')
                key_path = candidate.resolve(strict=True)
                if not key_path.is_relative_to(resolved_keys_dir):
                    raise ValueError('key file escaped its directory')

                actual_type, compatible = classify_key(
                    read_without_migration(user_id, key_path)
                )
                if actual_type == 'PASSPHRASE_ENCRYPTED':
                    compatible = result['metadata_type'] in {
                        'RSA', 'Ed25519', 'ECDSA'
                    }
                result.update(
                    actual_type=actual_type,
                    compatible=compatible,
                )
            except Exception as exc:
                result.update(
                    actual_type='READ_ERROR',
                    compatible=False,
                    error_type=type(exc).__name__,
                )
            results.append(result)

    return results


def readiness_exit_code(results):
    """Return zero only when every discovered key is compatible."""
    return 0 if all(item['compatible'] for item in results) else 2


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--data-dir',
        type=Path,
        default=Path(os.environ.get('DATA_DIR', PROJECT_ROOT / 'data')),
    )
    args = parser.parse_args()
    results = audit_data_dir(args.data_dir)
    print(json.dumps(results, indent=2, ensure_ascii=False))
    raise SystemExit(readiness_exit_code(results))


if __name__ == '__main__':
    main()
