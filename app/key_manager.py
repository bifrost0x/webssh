import uuid
import os
import paramiko
from datetime import datetime
from pathlib import Path
import config
from .audit_logger import log_info, log_warning, log_error, log_debug
from . import key_encryption
from .ssh_key_loader import identify_private_key, UnsupportedPrivateKeyError
from .storage_errors import StorageCorruptionError
from .storage_utils import atomic_write_json, load_json_migrated, storage_lock
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


def _valid_key_metadata(item):
    if not isinstance(item, dict):
        return False
    required_strings = ('id', 'name', 'filename', 'key_type')
    if not all(isinstance(item.get(field), str) for field in required_strings):
        return False
    if 'encrypted' in item and type(item['encrypted']) is not bool:
        return False
    if 'uploaded_at' in item and not isinstance(item['uploaded_at'], str):
        return False
    if 'usable' in item and type(item['usable']) is not bool:
        return False
    return True


def _valid_key_document(value):
    return (
        isinstance(value, dict)
        and value.get('schema_version') == CURRENT_STORAGE_VERSIONS['keys']
        and isinstance(value.get('keys'), list)
        and all(_valid_key_metadata(item) for item in value['keys'])
    )


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
    return data['keys']


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
        log_error(f"Error saving keys", user_id=user_id, error=str(e))
        return False


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
            'uploaded_at': datetime.utcnow().isoformat()
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
                log_info(f"SSH key saved (encrypted)", user_id=user_id, key_name=name)
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
            return str(keys_dir / key['filename'])
    return None


def _get_key_path_with_lock_held(user_id, key_id):
    keys = _load_keys_with_lock_held(user_id)
    keys_dir = get_user_keys_dir(user_id)
    if not keys_dir:
        return None
    for key in keys:
        if key['id'] == key_id:
            filename = key['filename']
            if not filename or Path(filename).name != filename:
                raise ValueError('invalid key filename')
            return str(keys_dir / filename)
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
            filename = key.get('filename')
            if not filename or Path(filename).name != filename:
                raise ValueError('invalid key filename')

            raw = (keys_dir / filename).read_bytes()
            if key_encryption.is_encrypted(raw):
                if fernet is None:
                    fernet = key_encryption.get_user_fernet(str(user_id))
                raw = fernet.decrypt(raw)

            identify_private_key(raw.decode('utf-8'))
            usable = True
        except (
            OSError,
            UnicodeDecodeError,
            key_encryption.InvalidToken,
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
                if keys_dir:
                    key_path = keys_dir / key_to_delete['filename']
                    key_path.unlink(missing_ok=True)

                keys = [k for k in keys if k['id'] != key_id]
                return save_keys(user_id, keys)
    except StorageCorruptionError:
        raise
    except Exception as e:
        log_error(f"Error deleting key", user_id=user_id, error=str(e))
        return False

def detect_key_type(key_content):
    """Return a supported key type, or None for invalid/unsupported content."""
    try:
        return identify_private_key(key_content)
    except (paramiko.SSHException, TypeError, ValueError):
        return None
