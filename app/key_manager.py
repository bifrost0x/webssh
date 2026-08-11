import uuid
import os
import paramiko
import stat
from datetime import datetime, timezone
from pathlib import Path
from cryptography.fernet import InvalidToken
from .audit_logger import log_info, log_warning, log_error
from . import key_encryption
from .ssh_key_loader import identify_private_key, UnsupportedPrivateKeyError
from .storage_errors import StorageCorruptionError
from .storage_utils import (
    atomic_write_json,
    fsync_parent_directory,
    load_json_migrated,
    storage_lock,
)
from .storage_migrations import CURRENT_STORAGE_VERSIONS

def get_user_keys_dir(user_id):
    """Get the keys directory for a specific user."""
    from .models import User, db
    user = db.session.get(User, user_id)
    if not user:
        return None
    user_dir = user.get_data_dir()
    keys_dir = user_dir / 'keys'
    keys_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(keys_dir, 0o700)
    return keys_dir

def get_user_keys_file(user_id):
    """Get the keys metadata file path for a specific user."""
    keys_dir = get_user_keys_dir(user_id)
    if not keys_dir:
        return None
    return keys_dir / 'keys.json'


def _is_safe_key_filename(filename):
    return (
        isinstance(filename, str)
        and bool(filename)
        and filename not in {'.', '..', 'keys.json'}
        and '/' not in filename
        and '\\' not in filename
        and '\x00' not in filename
        and not Path(filename).is_absolute()
        and Path(filename).name == filename
    )


def _safe_key_path(keys_dir, filename):
    """Resolve one metadata filename without leaving its owning key store."""
    keys_dir = Path(keys_dir)
    metadata_path = keys_dir / 'keys.json'
    if not _is_safe_key_filename(filename):
        raise StorageCorruptionError(metadata_path, 'invalid key filename')
    try:
        resolved_keys_dir = keys_dir.resolve(strict=True)
        lexical_path = keys_dir / filename
        candidate = lexical_path.resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise StorageCorruptionError(
            metadata_path, 'key path validation failed'
        ) from exc
    if candidate.parent != resolved_keys_dir:
        raise StorageCorruptionError(
            metadata_path, 'key path escaped keys directory'
        )
    return lexical_path


def _valid_key_metadata(item):
    if not isinstance(item, dict):
        return False
    required_strings = ('id', 'name', 'filename', 'key_type')
    if not all(isinstance(item.get(field), str) for field in required_strings):
        return False
    if not _is_safe_key_filename(item['filename']):
        return False
    if 'encrypted' in item and type(item['encrypted']) is not bool:
        return False
    if 'uploaded_at' in item and not isinstance(item['uploaded_at'], str):
        return False
    if 'usable' in item and type(item['usable']) is not bool:
        return False
    return True


def _valid_key_document(value):
    if (
        not isinstance(value, dict)
        or value.get('schema_version') != CURRENT_STORAGE_VERSIONS['keys']
        or not isinstance(value.get('keys'), list)
        or not all(_valid_key_metadata(item) for item in value['keys'])
    ):
        return False
    key_ids = [item['id'] for item in value['keys']]
    filenames = [item['filename'] for item in value['keys']]
    return (
        len(key_ids) == len(set(key_ids))
        and len(filenames) == len(set(filenames))
    )


_DELETE_STAGING_PREFIX = '.delete-'
_DELETE_TOKEN_LENGTH = 32


def _pending_delete_filename(path):
    name = Path(path).name
    if not name.startswith(_DELETE_STAGING_PREFIX):
        return None
    remainder = name[len(_DELETE_STAGING_PREFIX):]
    token, separator, filename = remainder.partition('-')
    if (
        separator != '-'
        or len(token) != _DELETE_TOKEN_LENGTH
        or any(character not in '0123456789abcdef' for character in token)
        or not _is_safe_key_filename(filename)
    ):
        return None
    return filename


def _path_entry_exists(path):
    try:
        Path(path).lstat()
    except FileNotFoundError:
        return False
    return True


def _replace_key_entry(source, destination):
    os.replace(source, destination)
    fsync_parent_directory(destination)


def _remove_pending_key_entry(path, *, user_id, key_id=None):
    try:
        Path(path).unlink(missing_ok=True)
        fsync_parent_directory(path)
    except Exception as exc:
        log_warning(
            "Failed to remove pending key deletion",
            user_id=user_id,
            key_id=key_id,
            cleanup_error=type(exc).__name__,
        )
        return False
    return True


def _reconcile_pending_key_deletions(user_id, keys_dir, keys):
    """Recover an interrupted delete using committed metadata as authority."""
    referenced_filenames = {key['filename'] for key in keys}
    try:
        pending_entries = sorted(
            path for path in Path(keys_dir).iterdir()
            if _pending_delete_filename(path) is not None
        )
    except OSError as exc:
        raise StorageCorruptionError(
            Path(keys_dir) / 'keys.json',
            'pending key deletion scan failed',
        ) from exc

    for pending_path in pending_entries:
        if pending_path.name in referenced_filenames:
            continue
        try:
            pending_stat = pending_path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise StorageCorruptionError(
                Path(keys_dir) / 'keys.json',
                'pending key deletion inspection failed',
            ) from exc
        if not (
            stat.S_ISREG(pending_stat.st_mode)
            or stat.S_ISLNK(pending_stat.st_mode)
        ):
            raise StorageCorruptionError(
                Path(keys_dir) / 'keys.json',
                'invalid pending key deletion entry',
            )
        filename = _pending_delete_filename(pending_path)
        key_path = Path(keys_dir) / filename
        if filename not in referenced_filenames or _path_entry_exists(key_path):
            _remove_pending_key_entry(pending_path, user_id=user_id)
            continue
        try:
            _replace_key_entry(pending_path, key_path)
        except OSError as exc:
            raise StorageCorruptionError(
                Path(keys_dir) / 'keys.json',
                'pending key deletion recovery failed',
            ) from exc


def _stage_key_deletion(keys_dir, key_path):
    try:
        key_stat = Path(key_path).lstat()
    except FileNotFoundError:
        return None
    if not (
        stat.S_ISREG(key_stat.st_mode)
        or stat.S_ISLNK(key_stat.st_mode)
    ):
        raise StorageCorruptionError(
            Path(keys_dir) / 'keys.json',
            'key path is not a file',
        )
    pending_path = Path(keys_dir) / (
        f'{_DELETE_STAGING_PREFIX}{uuid.uuid4().hex}-{Path(key_path).name}'
    )
    try:
        _replace_key_entry(key_path, pending_path)
    except Exception:
        if _path_entry_exists(pending_path) and not _path_entry_exists(key_path):
            try:
                os.replace(pending_path, key_path)
                fsync_parent_directory(key_path)
            except Exception:
                pass
        raise
    return pending_path


def _rollback_key_deletion(user_id, key_id, pending_path, key_path):
    if pending_path is None or not _path_entry_exists(pending_path):
        return True
    try:
        if _path_entry_exists(key_path):
            return _remove_pending_key_entry(
                pending_path,
                user_id=user_id,
                key_id=key_id,
            )
        _replace_key_entry(pending_path, key_path)
    except Exception as exc:
        log_warning(
            "Failed to restore key after metadata save failure",
            user_id=user_id,
            key_id=key_id,
            cleanup_error=type(exc).__name__,
        )
        return False
    return True


def _load_keys_with_lock_held(user_id):
    keys_file = get_user_keys_file(user_id)
    if keys_file is None:
        return []
    data = load_json_migrated(
        keys_file,
        'keys',
        lambda: {'keys': []},
        _valid_key_document,
    )
    keys = data['keys']
    _reconcile_pending_key_deletions(user_id, keys_file.parent, keys)
    return keys


def load_keys(user_id):
    """Load all SSH key metadata for a specific user."""
    with storage_lock(f'keys:{user_id}'):
        return _load_keys_with_lock_held(user_id)

def save_keys(user_id, keys):
    """Save keys list to JSON file for a specific user."""
    try:
        keys_file = get_user_keys_file(user_id)
        document = {
            'schema_version': CURRENT_STORAGE_VERSIONS['keys'],
            'keys': keys,
        }
        if not keys_file or not _valid_key_document(document):
            return False

        keys_file.parent.mkdir(parents=True, exist_ok=True)

        atomic_write_json(keys_file, document)
        return True
    except OSError as e:
        log_error("Error saving keys", user_id=user_id, error=str(e))
        return False


def rename_key(user_id, key_id, new_name):
    """Rename one owned key without changing its identity or encrypted data."""
    if not isinstance(new_name, str) or not new_name.strip():
        return None, "Invalid key name"
    name = new_name.strip()
    if len(name) > 128:
        return None, "Key name too long (max 128 characters)"
    if not isinstance(key_id, str) or not key_id:
        return None, "Key not found"

    with storage_lock(f'keys:{user_id}'):
        keys = _load_keys_with_lock_held(user_id)
        for index, key in enumerate(keys):
            if key['id'] != key_id:
                continue
            before = dict(key)
            updated = {**key, 'name': name}
            replacement = [*keys]
            replacement[index] = updated
            if not save_keys(user_id, replacement):
                return None, "Failed to rename key"
            return {'before': before, 'key': updated}, None
    return None, "Key not found"


def _remove_key_after_metadata_failure(user_id, key_id, key_path):
    """Best-effort rollback when the encrypted key has no metadata entry."""
    try:
        key_path.unlink(missing_ok=True)
    except Exception as exc:
        log_warning(
            "Failed to remove key after metadata save failure",
            user_id=user_id,
            key_id=key_id,
            cleanup_error=type(exc).__name__,
        )


def save_key(user_id, name, key_content):
    """Store a new SSH private key for a specific user (encrypted at rest)."""
    try:
        if not isinstance(name, str) or not name:
            return None, "Invalid key name"
        keys_dir = get_user_keys_dir(user_id)
        if not keys_dir:
            return None, "User not found"
        key_id = str(uuid.uuid4())
        filename = f"{key_id}.pem"
        key_path = keys_dir / filename
        try:
            key_type = identify_private_key(key_content)
        except paramiko.PasswordRequiredException:
            return None, "Passphrase-encrypted private keys are not supported"
        except UnsupportedPrivateKeyError as exc:
            return None, str(exc)
        except paramiko.SSHException:
            return None, "Invalid key format"

        key_meta = {
            'id': key_id,
            'name': name,
            'filename': filename,
            'key_type': key_type,
            'encrypted': True,
            'uploaded_at': datetime.now(timezone.utc).replace(
                tzinfo=None
            ).isoformat()
        }
        with storage_lock(f'keys:{user_id}'):
            keys = _load_keys_with_lock_held(user_id)
            if not key_encryption.write_key_content(
                str(user_id),
                str(key_path),
                key_content,
                allowed_root=keys_dir,
            ):
                return None, "Failed to encrypt and save key"
            keys.append(key_meta)

            try:
                metadata_saved = save_keys(user_id, keys)
            except StorageCorruptionError:
                _remove_key_after_metadata_failure(
                    user_id, key_id, key_path
                )
                raise
            except Exception:
                _remove_key_after_metadata_failure(
                    user_id, key_id, key_path
                )
                return None, "Failed to save key metadata"

            if metadata_saved:
                log_info("SSH key saved (encrypted)", user_id=user_id, key_name=name)
                return key_meta, None
            _remove_key_after_metadata_failure(user_id, key_id, key_path)
            return None, "Failed to save key metadata"
    except StorageCorruptionError:
        raise
    except Exception as e:
        return None, str(e)

def get_key_path(user_id, key_id):
    """Get the file path for a key by ID for a specific user."""
    keys = load_keys(user_id)
    keys_dir = get_user_keys_dir(user_id)
    if not keys_dir:
        return None

    for key in keys:
        if key['id'] == key_id:
            return str(_safe_key_path(keys_dir, key['filename']))
    return None


def _get_key_path_with_lock_held(user_id, key_id):
    keys = _load_keys_with_lock_held(user_id)
    keys_dir = get_user_keys_dir(user_id)
    if not keys_dir:
        return None
    for key in keys:
        if key['id'] == key_id:
            return str(_safe_key_path(keys_dir, key['filename']))
    return None

def get_key(user_id, key_id):
    """Get key metadata by ID for a specific user."""
    keys = load_keys(user_id)
    for key in keys:
        if key['id'] == key_id:
            return key
    return None

def read_key_content(user_id, key_id):
    """
    Read and decrypt SSH key content.

    Handles both encrypted and legacy unencrypted keys.
    Legacy keys are automatically migrated to encrypted format.

    Args:
        user_id: User identifier
        key_id: Key identifier

    Returns:
        tuple: (key_content: str or None, error: str or None)
    """
    try:
        with storage_lock(f'keys:{user_id}'):
            key_path = _get_key_path_with_lock_held(user_id, key_id)
            if not key_path:
                return None, "Key not found"
            keys_dir = get_user_keys_dir(user_id)
            if not keys_dir:
                return None, "Key not found"

            content = key_encryption.read_key_content(
                str(user_id),
                key_path,
                allowed_root=keys_dir,
            )
            return content, None

    except StorageCorruptionError:
        raise
    except FileNotFoundError:
        return None, "Key file not found"
    except Exception as exc:
        log_error(
            "Error reading key content",
            user_id=user_id,
            key_id=key_id,
            exception_type=type(exc).__name__,
        )
        return None, "Failed to read key"


def load_key_summaries(user_id):
    """Return key metadata with a transient usability status for clients."""
    keys = load_keys(user_id)
    keys_dir = get_user_keys_dir(user_id)
    if not keys_dir:
        return [{**key, 'usable': False} for key in keys]

    fernet = None
    summaries = []
    for key in keys:
        if not isinstance(key, dict):
            continue
        usable = False
        try:
            key_path = _safe_key_path(keys_dir, key.get('filename'))
            raw = key_path.read_bytes()
            if key_encryption.is_encrypted(raw):
                if fernet is None:
                    fernet = key_encryption.get_user_fernet(str(user_id))
                raw = fernet.decrypt(raw)

            identify_private_key(raw.decode('utf-8'))
            usable = True
        except (
            OSError,
            UnicodeDecodeError,
            InvalidToken,
            paramiko.PasswordRequiredException,
            paramiko.SSHException,
            UnsupportedPrivateKeyError,
            ValueError,
            TypeError,
        ):
            pass
        summaries.append({**key, 'usable': usable})
    return summaries


def delete_key(user_id, key_id):
    """Delete an SSH key and its metadata for a specific user."""
    try:
        with storage_lock(f'command-config:{user_id}'):
            with storage_lock(f'keys:{user_id}'):
                keys = _load_keys_with_lock_held(user_id)
                key_to_delete = None
                for key in keys:
                    if key['id'] == key_id:
                        key_to_delete = key
                        break

                if not key_to_delete:
                    return False

                keys_dir = get_user_keys_dir(user_id)
                key_path = None
                pending_path = None
                if keys_dir:
                    key_path = _safe_key_path(
                        keys_dir, key_to_delete['filename']
                    )
                    pending_path = _stage_key_deletion(keys_dir, key_path)

                keys = [k for k in keys if k['id'] != key_id]
                try:
                    metadata_saved = save_keys(user_id, keys)
                except Exception:
                    if key_path is not None:
                        _rollback_key_deletion(
                            user_id,
                            key_id,
                            pending_path,
                            key_path,
                        )
                    raise

                if not metadata_saved:
                    if key_path is not None:
                        _rollback_key_deletion(
                            user_id,
                            key_id,
                            pending_path,
                            key_path,
                        )
                    return False

                if pending_path is not None:
                    _remove_pending_key_entry(
                        pending_path,
                        user_id=user_id,
                        key_id=key_id,
                    )
                return True
    except StorageCorruptionError:
        raise
    except Exception as e:
        log_error("Error deleting key", user_id=user_id, error=str(e))
        return False

def detect_key_type(key_content):
    """Return a supported key type, or None for invalid/unsupported content."""
    try:
        return identify_private_key(key_content)
    except (paramiko.SSHException, TypeError, ValueError):
        return None
