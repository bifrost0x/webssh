import json
import uuid
import os
from datetime import datetime
from pathlib import Path
import config
from .audit_logger import log_info, log_warning, log_error, log_debug
from . import key_encryption

def get_user_keys_dir(user_id):
    """Get the keys directory for a specific user."""
    from .models import User
    user = User.query.get(user_id)
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

def load_keys(user_id):
    """Load all SSH key metadata for a specific user."""
    try:
        keys_file = get_user_keys_file(user_id)
        if not keys_file or not keys_file.exists():
            return []

        with open(keys_file, 'r') as f:
            data = json.load(f)
            return data.get('keys', [])
    except Exception as e:
        log_error(f"Error loading keys", user_id=user_id, error=str(e))
        return []

def save_keys(user_id, keys):
    """Save keys list to JSON file for a specific user."""
    try:
        keys_file = get_user_keys_file(user_id)
        if not keys_file:
            return False

        keys_file.parent.mkdir(parents=True, exist_ok=True)

        with open(keys_file, 'w') as f:
            json.dump({'keys': keys}, f, indent=2)
        return True
    except Exception as e:
        log_error(f"Error saving keys", user_id=user_id, error=str(e))
        return False

def save_key(user_id, name, key_content):
    """Store a new SSH private key for a specific user (encrypted at rest)."""
    try:
        keys_dir = get_user_keys_dir(user_id)
        if not keys_dir:
            return None, "User not found"
        key_id = str(uuid.uuid4())
        filename = f"{key_id}.pem"
        key_path = keys_dir / filename
        key_type = detect_key_type(key_content)
        if not key_type:
            return None, "Invalid key format"

        if not key_encryption.write_key_content(str(user_id), str(key_path), key_content):
            return None, "Failed to encrypt and save key"

        key_meta = {
            'id': key_id,
            'name': name,
            'filename': filename,
            'key_type': key_type,
            'encrypted': True,
            'uploaded_at': datetime.utcnow().isoformat()
        }
        keys = load_keys(user_id)
        keys.append(key_meta)

        if save_keys(user_id, keys):
            log_info(f"SSH key saved (encrypted)", user_id=user_id, key_name=name)
            return key_meta, None
        else:
            key_path.unlink(missing_ok=True)
            return None, "Failed to save key metadata"
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
        key_path = get_key_path(user_id, key_id)
        if not key_path:
            return None, "Key not found"

        content = key_encryption.read_key_content(str(user_id), key_path)
        return content, None

    except FileNotFoundError:
        return None, "Key file not found"
    except Exception as e:
        log_error(f"Error reading key content", user_id=user_id, key_id=key_id, error=str(e))
        return None, f"Failed to read key: {str(e)}"

def delete_key(user_id, key_id):
    """Delete an SSH key and its metadata for a specific user."""
    try:
        keys = load_keys(user_id)
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
    except Exception as e:
        log_error(f"Error deleting key", user_id=user_id, error=str(e))
        return False

def detect_key_type(key_content):
    """Detect SSH key type from content."""
    content = key_content.strip()

    if 'BEGIN RSA PRIVATE KEY' in content or 'BEGIN OPENSSH PRIVATE KEY' in content:
        return 'RSA'
    elif 'BEGIN DSA PRIVATE KEY' in content:
        return 'DSA'
    elif 'BEGIN EC PRIVATE KEY' in content:
        return 'ECDSA'
    elif 'BEGIN PRIVATE KEY' in content:
        return 'Ed25519/Generic'
    else:
        return None
