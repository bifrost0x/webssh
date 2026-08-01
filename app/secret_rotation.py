"""Transactional rotation of the secret used for stored SSH keys."""

from dataclasses import dataclass
from datetime import datetime, timezone
import hmac
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import uuid

from cryptography.fernet import Fernet, InvalidToken

from .backup_manager import create_backup
from .key_encryption import _derive_key, is_encrypted, key_operation_lock
from .storage_migrations import CURRENT_STORAGE_VERSIONS, migrate_document
from .storage_utils import atomic_write_bytes


class SecretRotationError(ValueError):
    """Raised when secret rotation cannot proceed safely."""


@dataclass(frozen=True)
class RotationReport:
    rotated_keys: int
    backup_path: Path


_MIGRATION_BACKUP_PATTERN = re.compile(
    r'^keys\.json\.[0-9a-f]{32}\.bak$'
)


def _write_staged_key(path, payload):
    atomic_write_bytes(Path(path), payload, mode=0o600)


def _validate_secret(value, label):
    if (
        not isinstance(value, str)
        or not value
        or '\n' in value
        or '\r' in value
    ):
        raise SecretRotationError(f'{label} secret is invalid')


def _read_persisted_secret(secret_path):
    try:
        path_stat = secret_path.lstat()
    except FileNotFoundError as exc:
        raise SecretRotationError(
            'persisted secret_key is required for rotation'
        ) from exc
    if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISREG(path_stat.st_mode):
        raise SecretRotationError(
            'persisted secret_key must be a regular non-symlink file'
        )
    try:
        persisted = secret_path.read_text(encoding='utf-8')
    except (OSError, UnicodeError) as exc:
        raise SecretRotationError(
            'persisted secret_key could not be read'
        ) from exc
    if persisted.endswith('\n'):
        persisted = persisted[:-1]
        if persisted.endswith('\r'):
            persisted = persisted[:-1]
    if not persisted or '\n' in persisted or '\r' in persisted:
        raise SecretRotationError(
            'persisted secret_key is invalid'
        )
    return persisted


def _stored_key_files(data_dir):
    users_dir = data_dir / 'users'
    if not users_dir.exists():
        return ()
    if users_dir.is_symlink() or not users_dir.is_dir():
        raise SecretRotationError('users storage path is unsafe')

    key_files = []
    for current_root, directory_names, file_names in os.walk(
        users_dir,
        topdown=True,
        followlinks=False,
    ):
        current = Path(current_root)
        for directory_name in directory_names:
            if (current / directory_name).is_symlink():
                raise SecretRotationError(
                    'SSH key storage contains a symbolic link'
                )
        if current.name != 'keys':
            continue
        if directory_names:
            raise SecretRotationError(
                'SSH key storage contains an unexpected directory'
            )
        user_directory = current.parent.name
        if (
            not user_directory.startswith('user_')
            or not user_directory.removeprefix('user_').isdigit()
        ):
            raise SecretRotationError('SSH key user directory is invalid')
        user_id = user_directory.removeprefix('user_')
        metadata_path = current / 'keys.json'
        referenced_names = set()
        if 'keys.json' in file_names:
            try:
                metadata_stat = metadata_path.lstat()
                if (
                    stat.S_ISLNK(metadata_stat.st_mode)
                    or not stat.S_ISREG(metadata_stat.st_mode)
                ):
                    raise SecretRotationError(
                        'SSH key metadata is not a regular file'
                    )
                document = json.loads(
                    metadata_path.read_text(encoding='utf-8')
                )
            except SecretRotationError:
                raise
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise SecretRotationError(
                    'SSH key metadata is unreadable'
                ) from exc
            try:
                document, _changed = migrate_document('keys', document)
            except ValueError as exc:
                raise SecretRotationError(
                    'SSH key metadata is invalid'
                ) from exc
            items = document.get('keys')
            if (
                document.get('schema_version')
                != CURRENT_STORAGE_VERSIONS['keys']
                or not isinstance(items, list)
            ):
                raise SecretRotationError('SSH key metadata is invalid')
            for item in items:
                filename = item.get('filename') if isinstance(item, dict) else None
                if (
                    not isinstance(filename, str)
                    or not filename
                    or Path(filename).name != filename
                    or filename in referenced_names
                ):
                    raise SecretRotationError('SSH key metadata is invalid')
                referenced_names.add(filename)

        migration_backups = {
            name for name in file_names
            if _MIGRATION_BACKUP_PATTERN.fullmatch(name)
        }
        stored_names = set(file_names) - {'keys.json'} - migration_backups
        if stored_names - referenced_names:
            raise SecretRotationError(
                'SSH key storage contains an unreferenced file'
            )
        if referenced_names - stored_names:
            raise SecretRotationError(
                'SSH key metadata references a missing file'
            )

        for file_name in sorted(migration_backups | referenced_names):
            path = current / file_name
            path_stat = path.lstat()
            if (
                stat.S_ISLNK(path_stat.st_mode)
                or not stat.S_ISREG(path_stat.st_mode)
            ):
                raise SecretRotationError(
                    'SSH key storage contains an unsafe file'
                )
            if file_name in migration_backups:
                continue
            key_files.append((user_id, path))
    return tuple(sorted(key_files, key=lambda item: str(item[1])))


def _rotation_backup_path(data_dir):
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    return data_dir.parent / (
        f'{data_dir.name}-pre-rotation-{timestamp}-{uuid.uuid4().hex}.zip'
    )


def _reencrypt_key(old_secret, new_secret, user_id, ciphertext):
    if not is_encrypted(ciphertext):
        raise SecretRotationError(
            'stored SSH key is not encrypted; read it once to migrate it '
            'before rotation'
        )
    try:
        plaintext = Fernet(
            _derive_key(old_secret, user_id)
        ).decrypt(ciphertext)
    except InvalidToken as exc:
        raise SecretRotationError(
            'stored SSH key could not be decrypted with the persisted secret'
        ) from exc
    staged = Fernet(_derive_key(new_secret, user_id)).encrypt(plaintext)
    try:
        verified = Fernet(
            _derive_key(new_secret, user_id)
        ).decrypt(staged)
    except InvalidToken as exc:
        raise SecretRotationError(
            'staged SSH key verification failed'
        ) from exc
    if not hmac.compare_digest(verified, plaintext):
        raise SecretRotationError('staged SSH key verification failed')
    return staged


def _rollback_key_files(originals):
    rollback_error = None
    for path, payload in originals.items():
        try:
            atomic_write_bytes(path, payload, mode=0o600)
        except Exception as exc:
            rollback_error = rollback_error or exc
    if rollback_error is not None:
        raise RuntimeError('secret rotation rollback failed') from rollback_error


def rotate_secret(old_secret, new_secret, data_dir):
    _validate_secret(old_secret, 'old')
    _validate_secret(new_secret, 'new')
    if hmac.compare_digest(old_secret, new_secret):
        raise SecretRotationError('new secret must differ from old secret')

    data_dir = Path(data_dir)
    if data_dir.is_symlink():
        raise SecretRotationError(
            'DATA_DIR must be a real directory'
        )
    data_dir = data_dir.resolve(strict=True)
    if not data_dir.is_dir():
        raise SecretRotationError('DATA_DIR must be a directory')
    secret_path = data_dir / 'secret_key'
    persisted_secret = _read_persisted_secret(secret_path)
    if not hmac.compare_digest(persisted_secret, old_secret):
        raise SecretRotationError(
            'persisted secret_key does not match the active old secret'
        )

    with key_operation_lock:
        key_files = _stored_key_files(data_dir)
        originals = {
            path: path.read_bytes()
            for _, path in key_files
        }
        backup_path = _rotation_backup_path(data_dir)
        create_backup(data_dir, backup_path)

        with tempfile.TemporaryDirectory(
            dir=data_dir.parent,
            prefix='.webssh-secret-rotation-',
        ) as temporary_directory:
            stage = Path(temporary_directory)
            staged_files = {}
            for index, (user_id, path) in enumerate(key_files):
                staged = stage / f'{index}.key'
                payload = _reencrypt_key(
                    old_secret,
                    new_secret,
                    user_id,
                    originals[path],
                )
                _write_staged_key(staged, payload)
                try:
                    staged_plaintext = Fernet(
                        _derive_key(new_secret, user_id)
                    ).decrypt(staged.read_bytes())
                    original_plaintext = Fernet(
                        _derive_key(old_secret, user_id)
                    ).decrypt(originals[path])
                except InvalidToken as exc:
                    raise SecretRotationError(
                        'staged SSH key verification failed'
                    ) from exc
                if not hmac.compare_digest(
                    staged_plaintext,
                    original_plaintext,
                ):
                    raise SecretRotationError(
                        'staged SSH key verification failed'
                    )
                staged_files[path] = staged

            committed = False
            try:
                for path, staged in staged_files.items():
                    atomic_write_bytes(
                        path,
                        staged.read_bytes(),
                        mode=0o600,
                    )
                atomic_write_bytes(
                    secret_path,
                    (new_secret + '\n').encode('utf-8'),
                    mode=0o600,
                )
                if _read_persisted_secret(secret_path) != new_secret:
                    raise SecretRotationError(
                        'new persisted secret verification failed'
                    )
                committed = True
            finally:
                if not committed:
                    rollback_error = None
                    try:
                        _rollback_key_files(originals)
                    except Exception as exc:
                        rollback_error = exc
                    try:
                        atomic_write_bytes(
                            secret_path,
                            (old_secret + '\n').encode('utf-8'),
                            mode=0o600,
                        )
                    except Exception as exc:
                        rollback_error = rollback_error or exc
                    if rollback_error is not None:
                        raise RuntimeError(
                            'secret rotation rollback failed'
                        ) from rollback_error

    return RotationReport(len(key_files), backup_path)
