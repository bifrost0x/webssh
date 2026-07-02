"""Per-user storage of reusable jump hosts (bastions).

Mirrors profile_manager: a JSON file per user under their data dir. Stores only
non-secret connection metadata (name/host/port/username/auth_type/key_id) — never
a password, consistent with connection profiles.
"""
import json
import re
import uuid
import ipaddress
from datetime import datetime
from .audit_logger import log_error, log_info
from .storage_utils import storage_lock, atomic_write_json


def _is_valid_host(host):
    host = (host or '').strip()
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    pattern = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    )
    return bool(pattern.match(host))


def _get_file(user_id):
    from .models import User
    user = User.query.get(user_id)
    if not user:
        return None
    return user.get_data_dir() / 'jump_hosts.json'


def load_jump_hosts(user_id):
    """Load all jump hosts for a user."""
    try:
        f = _get_file(user_id)
        if not f or not f.exists():
            return []
        with open(f, 'r') as fh:
            return json.load(fh).get('jump_hosts', [])
    except Exception as e:
        log_error("Error loading jump hosts", user_id=user_id, error=str(e))
        return []


def save_jump_hosts(user_id, jump_hosts):
    try:
        f = _get_file(user_id)
        if not f:
            return False
        f.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(f, {'jump_hosts': jump_hosts})
        return True
    except Exception as e:
        log_error("Error saving jump hosts", user_id=user_id, error=str(e))
        return False


def add_jump_host(user_id, name, host, port, username, auth_type, key_id=None):
    """Validate and store a new jump host. Never stores a password."""
    try:
        if not all([name, host, username, auth_type]):
            return None, "Missing required fields"

        host = str(host).strip()
        if not _is_valid_host(host):
            return None, "Invalid host format"

        try:
            port = int(port) if port else 22
            if not (1 <= port <= 65535):
                return None, "Port must be between 1 and 65535"
        except (ValueError, TypeError):
            return None, "Invalid port number"

        username = str(username).strip()
        if not re.match(r'^[a-zA-Z0-9_\-\.]{1,32}$', username):
            return None, "Invalid username format"

        if auth_type not in ['password', 'key']:
            return None, "Invalid auth_type"
        if auth_type == 'key' and not key_id:
            return None, "key_id required for key authentication"

        jump_host = {
            'id': str(uuid.uuid4()),
            'name': str(name)[:128],
            'host': host,
            'port': port,
            'username': username,
            'auth_type': auth_type,
            'key_id': key_id if auth_type == 'key' else None,
            'created_at': datetime.utcnow().isoformat()
        }
        with storage_lock(f'jump_hosts:{user_id}'):
            jump_hosts = load_jump_hosts(user_id)
            jump_hosts.append(jump_host)
            if save_jump_hosts(user_id, jump_hosts):
                log_info("Jump host saved", user_id=user_id, name=name)
                return jump_host, None
            return None, "Failed to save jump host"
    except Exception as e:
        return None, str(e)


def delete_jump_host(user_id, jump_host_id):
    try:
        with storage_lock(f'jump_hosts:{user_id}'):
            jump_hosts = load_jump_hosts(user_id)
            new_list = [j for j in jump_hosts if j.get('id') != jump_host_id]
            if len(new_list) == len(jump_hosts):
                return False
            return save_jump_hosts(user_id, new_list)
    except Exception as e:
        log_error("Error deleting jump host", user_id=user_id, error=str(e))
        return False
