"""Per-user storage of reusable jump hosts (bastions).

Mirrors profile_manager: a JSON file per user under their data dir. Stores only
non-secret connection metadata (name/host/port/username/auth_type/key_id) — never
a password, consistent with connection profiles.
"""
import re
import uuid
import ipaddress
from datetime import datetime
from .audit_logger import log_error, log_info
from .storage_errors import StorageCorruptionError
from .storage_utils import (
    atomic_write_json,
    load_json_migrated,
    safe_reference_name,
    storage_lock,
)
from .storage_migrations import CURRENT_STORAGE_VERSIONS


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


def _valid_jump_host(item):
    if not isinstance(item, dict):
        return False
    required_strings = ('id', 'name', 'host', 'username', 'auth_type')
    if not all(isinstance(item.get(field), str) for field in required_strings):
        return False
    if type(item.get('port')) is not int:
        return False
    if item['auth_type'] not in {'password', 'key'}:
        return False
    if 'key_id' in item and item['key_id'] is not None:
        if not isinstance(item['key_id'], str):
            return False
    if 'created_at' in item and not isinstance(item['created_at'], str):
        return False
    return True


def _valid_jump_host_document(value):
    return (
        isinstance(value, dict)
        and value.get('schema_version') == CURRENT_STORAGE_VERSIONS['jump_hosts']
        and isinstance(value.get('jump_hosts'), list)
        and all(_valid_jump_host(item) for item in value['jump_hosts'])
    )


def _load_jump_hosts_with_lock_held(user_id):
    path = _get_file(user_id)
    if path is None:
        return []
    data = load_json_migrated(
        path,
        'jump_hosts',
        lambda: {'jump_hosts': []},
        _valid_jump_host_document,
    )
    return data['jump_hosts']


def load_jump_hosts(user_id):
    """Load all jump hosts for a user."""
    with storage_lock(f'jump_hosts:{user_id}'):
        return _load_jump_hosts_with_lock_held(user_id)


def save_jump_hosts(user_id, jump_hosts):
    try:
        f = _get_file(user_id)
        document = {
            'schema_version': CURRENT_STORAGE_VERSIONS['jump_hosts'],
            'jump_hosts': jump_hosts,
        }
        if not f or not _valid_jump_host_document(document):
            return False
        f.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(f, document)
        return True
    except OSError as e:
        log_error("Error saving jump hosts", user_id=user_id, error=str(e))
        return False


def _load_profile_references(user_id):
    from . import profile_manager

    path = profile_manager.get_user_profiles_file(user_id)
    if path is None:
        return []
    return profile_manager._load_profiles_with_lock_held(user_id)


def _get_jump_host_with_coordinator_held(user_id, jump_host_id):
    """Return one live jump-host snapshot while the coordinator is held."""
    if not isinstance(jump_host_id, str) or not jump_host_id:
        return None
    with storage_lock(f'jump_hosts:{user_id}'):
        jump_hosts = _load_jump_hosts_with_lock_held(user_id)
    for jump_host in jump_hosts:
        if jump_host.get('id') == jump_host_id:
            return dict(jump_host)
    return None


def get_jump_host(user_id, jump_host_id):
    """Resolve a saved jump host from current server-side storage."""
    with storage_lock(f'command-config:{user_id}'):
        return _get_jump_host_with_coordinator_held(
            user_id, jump_host_id
        )


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
            jump_hosts = _load_jump_hosts_with_lock_held(user_id)
            jump_hosts.append(jump_host)
            if save_jump_hosts(user_id, jump_hosts):
                log_info("Jump host saved", user_id=user_id, name=name)
                return jump_host, None
            return None, "Failed to save jump host"
    except StorageCorruptionError:
        raise
    except Exception as e:
        return None, str(e)


def delete_jump_host(user_id, jump_host_id):
    try:
        with storage_lock(f'command-config:{user_id}'):
            with storage_lock(f'profiles:{user_id}'):
                profiles = _load_profile_references(user_id)
            usages = [
                safe_reference_name(profile.get('name'))
                for profile in profiles
                if (
                    isinstance(profile, dict)
                    and profile.get('jump_host_id') == jump_host_id
                )
            ]
            if usages:
                noun = 'profile' if len(usages) == 1 else 'profiles'
                return (
                    False,
                    f'Jump host is used by {len(usages)} {noun}',
                    usages,
                )

            with storage_lock(f'jump_hosts:{user_id}'):
                jump_hosts = _load_jump_hosts_with_lock_held(user_id)
                new_list = [
                    jump_host for jump_host in jump_hosts
                    if jump_host.get('id') != jump_host_id
                ]
                if len(new_list) == len(jump_hosts):
                    return False, 'Jump host not found', []
                if save_jump_hosts(user_id, new_list):
                    return True, None, []
                return False, 'Failed to delete jump host', []
    except StorageCorruptionError:
        raise
    except Exception as e:
        log_error("Error deleting jump host", user_id=user_id, error=str(e))
        return False, 'Failed to delete jump host', []
