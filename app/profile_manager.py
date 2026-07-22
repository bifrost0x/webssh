import json
import uuid
import re
import ipaddress
from datetime import datetime
from pathlib import Path
import config
from .audit_logger import log_info, log_warning, log_error, log_debug
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

def add_profile(user_id, name, host, port, username, auth_type, key_id=None,
                jump_host_id=None, startup_commands=None, command_set_id=None):
    """Add a new connection profile for a specific user.

    jump_host_id (optional): reference to a saved jump host (bastion). Only the id
    is stored; the jump host details live in jump_hosts.json.
    """
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

        if auth_type not in ['password', 'key', 'tailscale']:
            return None, "Invalid auth_type"

        if auth_type == 'key' and not key_id:
            return None, "key_id required for key authentication"

        normalized_startup_commands = None
        if startup_commands is not None:
            normalized_startup_commands, error = normalize_startup_commands(startup_commands)
            if error:
                return None, error

        with storage_lock(f'command-config:{user_id}'):
            if command_set_id is not None:
                from .command_set_manager import get_command_set

                command_set, error = get_command_set(user_id, command_set_id)
                if error:
                    return None, error
                command_set_id = command_set['id']

            profile = {
                'id': str(uuid.uuid4()),
                'name': name[:128],
                'host': host,
                'port': port,
                'username': username,
                'auth_type': auth_type,
                'key_id': key_id,
                'created_at': datetime.utcnow().isoformat()
            }

            # Optional reference to a saved jump host (bastion).
            if jump_host_id:
                profile['jump_host_id'] = str(jump_host_id)[:64]

            if normalized_startup_commands:
                profile['startup_commands'] = normalized_startup_commands
            if command_set_id:
                profile['command_set_id'] = command_set_id

            with storage_lock(f'profiles:{user_id}'):
                profiles = load_profiles(user_id)
                profiles.append(profile)

                if save_profiles(user_id, profiles):
                    return profile, None
                return None, "Failed to save profile"
    except Exception as e:
        return None, str(e)

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
                profiles = load_profiles(user_id)
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
                profiles = load_profiles(user_id)
                for profile in profiles:
                    if profile.get('id') == profile_id:
                        profile['command_set_id'] = command_set['id']
                        if not save_profiles(user_id, profiles):
                            return None, 'Failed to save profile'
                        return profile, None
                return None, 'Profile not found'
    except Exception as e:
        log_error('Error assigning command set to profile', user_id=user_id, error=str(e))
        return None, str(e)
