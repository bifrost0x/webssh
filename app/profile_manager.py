import re
import ipaddress
import uuid
from datetime import datetime, timezone

from .audit_logger import log_error
from .post_connect_manager import infer_mode, validate_configuration
from .storage_errors import StorageCorruptionError
from .storage_utils import atomic_write_json, load_json_migrated, storage_lock
from .storage_migrations import CURRENT_STORAGE_VERSIONS
from .startup_commands import normalize_startup_commands


_MAX_PROFILE_GROUP_LENGTH = 64
_UNSET = object()


def _normalize_group(value):
    if value is _UNSET:
        return _UNSET, None
    if not isinstance(value, str):
        return None, 'Invalid group'
    normalized = value.strip()
    if len(normalized) > _MAX_PROFILE_GROUP_LENGTH:
        return None, 'Group must not exceed 64 characters'
    return normalized or None, None


def _group_key(value):
    return str(value or '').strip().casefold()


def _valid_sort_order(value):
    return type(value) is int and value >= 0


def _ordered_group(profiles, group, exclude_id=None):
    """Return one real group in its persisted order with stable legacy fallbacks."""
    key = _group_key(group)
    indexed = [
        (index, profile)
        for index, profile in enumerate(profiles)
        if _group_key(profile.get('group')) == key
        and profile.get('id') != exclude_id
    ]
    if not all(_valid_sort_order(profile.get('sort_order')) for _, profile in indexed):
        return [profile for _, profile in indexed]
    return [
        profile
        for _, profile in sorted(
            indexed,
            key=lambda item: (
                item[1]['sort_order'],
                item[0],
                str(item[1].get('name', '')).casefold(),
                str(item[1].get('host', '')).casefold(),
                str(item[1].get('id', '')),
            ),
        )
    ]


def _next_sort_order(profiles, group, exclude_id=None):
    return len(_ordered_group(profiles, group, exclude_id=exclude_id))


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
    from .models import User, db
    user = db.session.get(User, user_id)
    if not user:
        return None
    user_dir = user.get_data_dir()
    return user_dir / 'profiles.json'


def _optional_string(item, field, allow_none=False):
    if field not in item:
        return True
    return isinstance(item[field], str) or (allow_none and item[field] is None)


def _valid_profile(item):
    if not isinstance(item, dict):
        return False
    if not isinstance(item.get('id'), str) or not isinstance(item.get('name'), str):
        return False
    for field in (
        'host', 'username', 'startup_commands', 'command_id',
        'command_set_id', 'parameters_override', 'created_at', 'updated_at',
        'group',
    ):
        if not _optional_string(item, field):
            return False
    for field in ('key_id', 'jump_host_id'):
        if not _optional_string(item, field, allow_none=True):
            return False
    if 'port' in item and type(item['port']) is not int:
        return False
    if 'auth_type' in item and item['auth_type'] not in {
        'password', 'key', 'tailscale',
    }:
        return False
    if 'startup_mode' in item and item['startup_mode'] not in {
        'none', 'free_text', 'command', 'command_set',
    }:
        return False
    for field in ('use_tmux', 'tailscale_authorized', 'favorite'):
        if field in item and type(item[field]) is not bool:
            return False
    if 'sort_order' in item and not _valid_sort_order(item['sort_order']):
        return False
    return True


def _valid_profile_document(value):
    return (
        isinstance(value, dict)
        and value.get('schema_version') == CURRENT_STORAGE_VERSIONS['profiles']
        and isinstance(value.get('profiles'), list)
        and all(_valid_profile(item) for item in value['profiles'])
    )


_PROFILE_FIELDS = {
    'id', 'name', 'host', 'port', 'username', 'auth_type', 'key_id',
    'jump_host_id', 'startup_mode', 'startup_commands', 'command_id',
    'command_set_id', 'parameters_override', 'use_tmux',
    'tailscale_authorized', 'group', 'favorite', 'created_at', 'updated_at',
    'sort_order',
}


def _load_profiles_with_lock_held(user_id):
    profiles_file = get_user_profiles_file(user_id)
    if profiles_file is None:
        return []
    data = load_json_migrated(
        profiles_file,
        'profiles',
        lambda: {'profiles': []},
        _valid_profile_document,
    )
    return data['profiles']


def load_profiles(user_id):
    """Load all connection profiles for a specific user."""
    with storage_lock(f'profiles:{user_id}'):
        return _load_profiles_with_lock_held(user_id)


def _load_profiles_for_write(user_id):
    """Load profiles without masking corruption before a mutation."""
    profiles_file = get_user_profiles_file(user_id)
    if not profiles_file:
        return None, 'User not found'
    return _load_profiles_with_lock_held(user_id), None

def save_profiles(user_id, profiles):
    """Save profiles list to JSON file for a specific user."""
    try:
        profiles_file = get_user_profiles_file(user_id)
        document = {
            'schema_version': CURRENT_STORAGE_VERSIONS['profiles'],
            'profiles': profiles,
        }
        if not profiles_file or not _valid_profile_document(document):
            return False

        profiles_file.parent.mkdir(parents=True, exist_ok=True)

        atomic_write_json(profiles_file, document)
        return True
    except Exception as e:
        log_error("Error saving profiles", user_id=user_id, error=str(e))
        return False

def _validate_profile_payload(user_id, payload, dependent_lock_held=False):
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

    group, error = _normalize_group(payload.get('group', _UNSET))
    if error:
        return None, error
    favorite = payload.get('favorite', _UNSET)
    if favorite is not _UNSET and type(favorite) is not bool:
        return None, 'favorite must be a boolean'
    use_tmux = payload.get('use_tmux', _UNSET)
    if use_tmux is not _UNSET and type(use_tmux) is not bool:
        return None, 'use_tmux must be a boolean'

    key_id = payload.get('key_id')
    if auth_type == 'key' and not key_id:
        return None, 'key_id required for key authentication'

    post_connect, error = validate_configuration(
        user_id,
        payload,
        dependent_lock_held=dependent_lock_held,
    )
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
    if group is not _UNSET and group:
        result['group'] = group
    if favorite is True:
        result['favorite'] = True
    if use_tmux is not _UNSET:
        result['use_tmux'] = use_tmux
    jump_host_id = payload.get('jump_host_id')
    if jump_host_id:
        result['jump_host_id'] = str(jump_host_id)[:64]
    return result, None


def upsert_profile(user_id, payload, preserve_legacy_fallback=False):
    """Create or update a profile under the per-user coordinator lock."""
    try:
        with storage_lock(f'command-config:{user_id}'):
            mode = infer_mode(payload)
            dependent_store = {
                'command': 'commands',
                'command_set': 'command-sets',
            }.get(mode)
            if dependent_store:
                with storage_lock(f'{dependent_store}:{user_id}'):
                    validated, error = _validate_profile_payload(
                        user_id,
                        payload,
                        dependent_lock_held=True,
                    )
            else:
                validated, error = _validate_profile_payload(user_id, payload)
            if error:
                return None, error

            jump_host_id = validated.get('jump_host_id')
            if jump_host_id:
                from .jump_host_manager import (
                    _get_jump_host_with_coordinator_held,
                )

                jump_host = _get_jump_host_with_coordinator_held(
                    user_id, jump_host_id
                )
                if jump_host is None:
                    return None, 'Jump host not found'

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
                            existing_group = existing.get('group')
                            target_group = (
                                validated.get('group')
                                if 'group' in payload
                                else existing_group
                            )
                            unknown = {
                                key: value
                                for key, value in existing.items()
                                if key not in _PROFILE_FIELDS
                            }
                            result = {
                                **unknown,
                                **validated,
                                'id': profile_id,
                                'created_at': existing.get('created_at', now),
                                'updated_at': now,
                            }
                            if 'group' not in payload and existing.get('group'):
                                result['group'] = existing['group']
                            if (
                                'favorite' not in payload
                                and existing.get('favorite') is True
                            ):
                                result['favorite'] = True
                            if (
                                'use_tmux' not in payload
                                and 'use_tmux' in existing
                            ):
                                result['use_tmux'] = existing['use_tmux']
                            if _group_key(existing_group) == _group_key(target_group):
                                result['sort_order'] = (
                                    existing['sort_order']
                                    if _valid_sort_order(existing.get('sort_order'))
                                    else _ordered_group(profiles, existing_group)
                                    .index(existing)
                                )
                            else:
                                result['sort_order'] = _next_sort_order(
                                    profiles, target_group, exclude_id=profile_id
                                )
                            profiles[index] = result
                            break
                    else:
                        return None, 'Profile not found'
                else:
                    result = {
                        **validated,
                        'id': str(uuid.uuid4()),
                        'sort_order': _next_sort_order(
                            profiles, validated.get('group')
                        ),
                        'created_at': now,
                        'updated_at': now,
                    }
                    profiles.append(result)

                if save_profiles(user_id, profiles):
                    return result, None
                return None, 'Failed to save profile'
    except StorageCorruptionError:
        raise
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


def update_profile_organization(user_id, profile_id, patch):
    """Update only grouping metadata for one user-owned profile."""
    if not isinstance(patch, dict):
        return None, 'No organization fields provided'
    supplied = {'group', 'favorite'} & patch.keys()
    if not supplied:
        return None, 'No organization fields provided'

    group, error = _normalize_group(patch.get('group', _UNSET))
    if error:
        return None, error
    favorite = patch.get('favorite', _UNSET)
    if favorite is not _UNSET and type(favorite) is not bool:
        return None, 'favorite must be a boolean'

    try:
        with storage_lock(f'command-config:{user_id}'):
            with storage_lock(f'profiles:{user_id}'):
                profiles, error = _load_profiles_for_write(user_id)
                if error:
                    return None, error
                for profile in profiles:
                    if profile.get('id') != profile_id:
                        continue
                    if group is not _UNSET:
                        if group:
                            profile['group'] = group
                        else:
                            profile.pop('group', None)
                    if favorite is not _UNSET:
                        if favorite:
                            profile['favorite'] = True
                        else:
                            profile.pop('favorite', None)
                    profile['updated_at'] = datetime.now(timezone.utc).isoformat()
                    if not save_profiles(user_id, profiles):
                        return None, 'Failed to save profile'
                    return dict(profile), None
                return None, 'Profile not found'
    except StorageCorruptionError:
        raise
    except Exception as exc:
        log_error(
            'Error updating profile organization',
            user_id=user_id,
            error=str(exc),
        )
        return None, 'Failed to save profile'


def move_profile(
    user_id,
    profile_id,
    expected_source_group,
    target_group,
    target_index,
    confirm_source_group_removal=False,
):
    """Atomically move one profile to an exact position in a flat group."""
    if not isinstance(profile_id, str) or not profile_id:
        return None, 'Profile ID required'
    expected_source_group, error = _normalize_group(expected_source_group)
    if error:
        return None, error
    target_group, error = _normalize_group(target_group)
    if error:
        return None, error
    if type(target_index) is not int or target_index < 0:
        return None, 'Invalid target index'
    if type(confirm_source_group_removal) is not bool:
        return None, 'Invalid confirmation value'

    try:
        with storage_lock(f'command-config:{user_id}'):
            with storage_lock(f'profiles:{user_id}'):
                profiles, error = _load_profiles_for_write(user_id)
                if error:
                    return None, error
                profile = next(
                    (item for item in profiles if item.get('id') == profile_id),
                    None,
                )
                if profile is None:
                    return None, 'Profile not found'

                source_group = profile.get('group')
                if _group_key(source_group) != _group_key(expected_source_group):
                    return {
                        'profiles': profiles,
                        'requires_confirmation': False,
                    }, 'Profile group changed; retry move'

                source_members = _ordered_group(profiles, source_group)
                changes_group = _group_key(source_group) != _group_key(target_group)
                removes_source_group = (
                    bool(_group_key(source_group))
                    and changes_group
                    and len(source_members) == 1
                )
                if removes_source_group and not confirm_source_group_removal:
                    return {
                        'profiles': profiles,
                        'requires_confirmation': True,
                        'profile_id': profile_id,
                        'profile_name': profile.get('name', ''),
                        'source_group': source_group,
                    }, None

                target_members = _ordered_group(
                    profiles,
                    target_group,
                    exclude_id=profile_id,
                )
                insert_at = min(target_index, len(target_members))
                target_members.insert(insert_at, profile)

                if changes_group:
                    if target_group:
                        profile['group'] = target_group
                    else:
                        profile.pop('group', None)
                    for index, member in enumerate(
                        _ordered_group(profiles, source_group, exclude_id=profile_id)
                    ):
                        member['sort_order'] = index

                now = datetime.now(timezone.utc).isoformat()
                for index, member in enumerate(target_members):
                    member['sort_order'] = index
                    if member.get('id') == profile_id:
                        member['updated_at'] = now

                if not save_profiles(user_id, profiles):
                    return None, 'Failed to save profile'
                return {
                    'profiles': profiles,
                    'requires_confirmation': False,
                }, None
    except StorageCorruptionError:
        raise
    except Exception as exc:
        log_error(
            'Error moving profile',
            user_id=user_id,
            error=str(exc),
        )
        return None, 'Failed to move profile'

def delete_profile(user_id, profile_id):
    """Delete a profile by ID for a specific user."""
    try:
        with storage_lock(f'command-config:{user_id}'):
            with storage_lock(f'profiles:{user_id}'):
                profiles, error = _load_profiles_for_write(user_id)
                if error:
                    return False, error
                found = any(profile.get('id') == profile_id for profile in profiles)
                if not found:
                    return False, 'Profile not found'
                remaining = [profile for profile in profiles if profile.get('id') != profile_id]
                if save_profiles(user_id, remaining):
                    return True, None
                return False, 'Failed to delete profile'
    except StorageCorruptionError:
        raise
    except Exception as e:
        log_error("Error deleting profile", user_id=user_id, error=str(e))
        return False, 'Failed to delete profile'


def assign_command_set(user_id, profile_id, command_set_id):
    """Assign an existing command set without removing legacy fallback data."""
    try:
        with storage_lock(f'command-config:{user_id}'):
            from .command_set_manager import _get_command_set_with_lock_held

            with storage_lock(f'command-sets:{user_id}'):
                command_set, error = _get_command_set_with_lock_held(
                    user_id, command_set_id
                )
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
    except StorageCorruptionError:
        raise
    except Exception as e:
        log_error('Error assigning command set to profile', user_id=user_id, error=str(e))
        return None, str(e)
