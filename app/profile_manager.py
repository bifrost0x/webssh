import json
import re
import ipaddress
import uuid
from datetime import datetime, timezone

from .audit_logger import log_error
from .post_connect_manager import validate_configuration
from .storage_utils import storage_lock, atomic_write_json
from .startup_commands import normalize_startup_commands


def _is_valid_host(host_str):
    """Validate host is a valid hostname or IP address."""
    if not host_str or not isinstance(host_str, str):
        return False
    host_str = host_str.strip()
    try:
        ipaddress.ip_address(host_str)
        return True
    except ValueError:
        pass
    hostname_pattern = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    )
    return bool(hostname_pattern.match(host_str))

def get_user_profiles_file(user_id):
    """Get the profiles file path for a specific user."""
    from .models import User
    user = User.query.get(user_id)
    if not user:
        return None
    user_dir = user.get_data_dir()
    return user_dir / 'profiles.json'

def load_profiles(user_id):
    """Load all connection profiles for a specific user."""
    try:
        profiles_file = get_user_profiles_file(user_id)
        if not profiles_file or not profiles_file.exists():
            return []

        with open(profiles_file, 'r') as f:
            data = json.load(f)
            return data.get('profiles', [])
    except Exception as e:
        log_error(f"Error loading profiles", user_id=user_id, error=str(e))
        return []


def _load_profiles_for_write(user_id):
    """Load profiles without masking corruption before a mutation."""
    profiles_file = get_user_profiles_file(user_id)
    if not profiles_file:
        return None, 'User not found'
    if not profiles_file.exists():
        return [], None
    try:
        with open(profiles_file, 'r', encoding='utf-8') as handle:
            data = json.load(handle)
        if not isinstance(data, dict) or not isinstance(data.get('profiles'), list):
            raise ValueError('invalid profile storage shape')
        return data['profiles'], None
    except (OSError, ValueError, TypeError) as exc:
        log_error('Error loading profiles for write', user_id=user_id, error=str(exc))
        return None, 'Profile storage is unreadable'

def save_profiles(user_id, profiles):
    """Save profiles list to JSON file for a specific user."""
    try:
        profiles_file = get_user_profiles_file(user_id)
        if not profiles_file:
            return False

        profiles_file.parent.mkdir(parents=True, exist_ok=True)

        atomic_write_json(profiles_file, {'profiles': profiles})
        return True
    except Exception as e:
        log_error(f"Error saving profiles", user_id=user_id, error=str(e))
        return False

def _validate_profile_payload(user_id, payload):
    """Validate storable profile fields without accepting credentials."""
    if not isinstance(payload, dict):
        return None, 'Invalid profile data'

    name = payload.get('name')
    host = payload.get('host')
    username = payload.get('username')
    auth_type = payload.get('auth_type')
    if not all([name, host, username, auth_type]):
        return None, 'Missing required fields'
    if not isinstance(name, str) or not name.strip():
        return None, 'Invalid profile name'
    name = name.strip()[:128]

    host = str(host).strip()
    if not _is_valid_host(host):
        return None, 'Invalid host format'

    try:
        port = int(payload.get('port') or 22)
        if not 1 <= port <= 65535:
            return None, 'Port must be between 1 and 65535'
    except (ValueError, TypeError):
        return None, 'Invalid port number'

    username = str(username).strip()
    if not re.match(r'^[a-zA-Z0-9_\-\.]{1,32}$', username):
        return None, 'Invalid username format'
    if auth_type not in {'password', 'key', 'tailscale'}:
        return None, 'Invalid auth_type'

    key_id = payload.get('key_id')
    if auth_type == 'key' and not key_id:
        return None, 'key_id required for key authentication'

    post_connect, error = validate_configuration(user_id, payload)
    if error:
        return None, error

    result = {
        'name': name,
        'host': host,
        'port': port,
        'username': username,
        'auth_type': auth_type,
        'key_id': key_id if auth_type == 'key' else None,
        **post_connect,
    }
    jump_host_id = payload.get('jump_host_id')
    if jump_host_id:
        result['jump_host_id'] = str(jump_host_id)[:64]
    return result, None


def upsert_profile(user_id, payload, preserve_legacy_fallback=False):
    """Create or update a profile under the per-user coordinator lock."""
    try:
        with storage_lock(f'command-config:{user_id}'):
            validated, error = _validate_profile_payload(user_id, payload)
            if error:
                return None, error

            if preserve_legacy_fallback and payload.get('startup_commands'):
                legacy, error = normalize_startup_commands(
                    payload['startup_commands']
                )
                if error:
                    return None, error
                if legacy:
                    validated['startup_commands'] = legacy

            with storage_lock(f'profiles:{user_id}'):
                profiles, error = _load_profiles_for_write(user_id)
                if error:
                    return None, error

                profile_id = payload.get('id')
                now = datetime.now(timezone.utc).isoformat()
                if profile_id:
                    for index, existing in enumerate(profiles):
                        if existing.get('id') == profile_id:
                            result = {
                                **validated,
                                'id': profile_id,
                                'created_at': existing.get('created_at', now),
                                'updated_at': now,
                            }
                            profiles[index] = result
                            break
                    else:
                        return None, 'Profile not found'
                else:
                    result = {
                        **validated,
                        'id': str(uuid.uuid4()),
                        'created_at': now,
                        'updated_at': now,
                    }
                    profiles.append(result)

                if save_profiles(user_id, profiles):
                    return result, None
                return None, 'Failed to save profile'
    except Exception as exc:
        log_error('Error saving profile', user_id=user_id, error=str(exc))
        return None, 'Failed to save profile'


def add_profile(user_id, name, host, port, username, auth_type, key_id=None,
                jump_host_id=None, startup_commands=None, command_set_id=None):
    """Compatibility wrapper for callers that create legacy profile payloads."""
    payload = {
        'name': name,
        'host': host,
        'port': port,
        'username': username,
        'auth_type': auth_type,
        'key_id': key_id,
        'jump_host_id': jump_host_id,
    }
    if startup_commands is not None:
        payload['startup_commands'] = startup_commands
    if command_set_id is not None:
        payload['command_set_id'] = command_set_id
    return upsert_profile(
        user_id,
        payload,
        preserve_legacy_fallback=bool(command_set_id and startup_commands),
    )

def get_profile(user_id, profile_id):
    """Get a specific profile by ID for a specific user."""
    profiles = load_profiles(user_id)
    for profile in profiles:
        if profile['id'] == profile_id:
            return profile
    return None

def delete_profile(user_id, profile_id):
    """Delete a profile by ID for a specific user."""
    try:
        with storage_lock(f'command-config:{user_id}'):
            with storage_lock(f'profiles:{user_id}'):
                profiles, error = _load_profiles_for_write(user_id)
                if error:
                    return False
                profiles = [p for p in profiles if p['id'] != profile_id]
                return save_profiles(user_id, profiles)
    except Exception as e:
        log_error(f"Error deleting profile", user_id=user_id, error=str(e))
        return False


def assign_command_set(user_id, profile_id, command_set_id):
    """Assign an existing command set without removing legacy fallback data."""
    try:
        with storage_lock(f'command-config:{user_id}'):
            from .command_set_manager import get_command_set

            command_set, error = get_command_set(user_id, command_set_id)
            if error:
                return None, error

            with storage_lock(f'profiles:{user_id}'):
                profiles, error = _load_profiles_for_write(user_id)
                if error:
                    return None, error
                for profile in profiles:
                    if profile.get('id') == profile_id:
                        profile['startup_mode'] = 'command_set'
                        profile['command_set_id'] = command_set['id']
                        if not save_profiles(user_id, profiles):
                            return None, 'Failed to save profile'
                        return profile, None
                return None, 'Profile not found'
    except Exception as e:
        log_error('Error assigning command set to profile', user_id=user_id, error=str(e))
        return None, str(e)
