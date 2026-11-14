import re
import ipaddress
import time
import uuid
from datetime import datetime, timezone

import config

from .host_platform import PLATFORMS, endpoint
from .audit_logger import log_error
from .connection_storage_policy import (
    ConnectionStorageLimitError,
    enforce_store_read_limit,
    enforce_store_recovery_limit,
    enforce_store_transition,
    recovery_record_selector,
    resolve_recovery_record_selector,
    validate_profile,
)
from .post_connect_manager import infer_mode, validate_configuration
from .storage_errors import StorageCorruptionError
from .storage_utils import (
    atomic_write_bytes,
    load_json_migrated,
    safe_reference_name,
    storage_lock,
)
from .storage_migrations import CURRENT_STORAGE_VERSIONS
from .startup_commands import normalize_startup_commands
from .data_access import user_operation


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

@user_operation
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
    if 'tailscale_authorized' in item:
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
    for field in ('key_id', 'jump_host_id', 'socks_proxy_id'):
        if not _optional_string(item, field, allow_none=True):
            return False
    socks_proxy_id = item.get('socks_proxy_id')
    if socks_proxy_id and (
        len(socks_proxy_id) > 64
        or item.get('jump_host_id')
        or item.get('auth_type') == 'tailscale'
    ):
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
    for field in ('use_tmux', 'favorite'):
        if field in item and type(item[field]) is not bool:
            return False
    if 'sort_order' in item and not _valid_sort_order(item['sort_order']):
        return False
    if 'greeting_platform' in item and not isinstance(item['greeting_platform'], str):
        return False
    if 'detected_services' in item and not (isinstance(item['detected_services'], list)
                                            and all(isinstance(entry, str) for entry in item['detected_services'])):
        return False
    if 'services_checked_at' in item and (isinstance(item['services_checked_at'], bool)
                                          or not isinstance(item['services_checked_at'], (int, float))):
        return False
    # detected_maintenance is never validated here: a malformed or newer value
    # must not make the whole profiles document unreadable. Its only reader,
    # the overview, ignores what it does not understand.
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
    'jump_host_id', 'socks_proxy_id', 'startup_mode', 'startup_commands', 'command_id',
    'command_set_id', 'parameters_override', 'use_tmux',
    'group', 'favorite', 'created_at', 'updated_at',
    'sort_order', 'platform_icon', 'detected_platform', 'greeting_platform',
    'detected_services', 'services_checked_at', 'detected_maintenance',
}


def _profile_migration_payload(profiles_file, document):
    """Return a quota-safe exact migration payload, or keep it in memory."""
    profiles = document['profiles']
    try:
        return enforce_store_transition(
            path=profiles_file,
            other_paths=(profiles_file.parent / 'jump_hosts.json', profiles_file.parent / 'socks_proxies.json'),
            prospective_document=document,
            prospective_count=len(profiles),
            previous_count=None,
            maximum_count=config.PROFILE_MAX_RECORDS,
        )
    except ConnectionStorageLimitError:
        return None


def _load_profiles_with_lock_held(user_id):
    profiles_file = get_user_profiles_file(user_id)
    if profiles_file is None:
        return []
    data = load_json_migrated(
        profiles_file,
        'profiles',
        lambda: {'profiles': []},
        _valid_profile_document,
        migration_payload_factory=lambda document: (
            _profile_migration_payload(profiles_file, document)
        ),
    )
    return data['profiles']


def _load_profiles_for_read_with_lock_held(user_id):
    """Load only a response-safe profile store while its lock is held."""
    profiles_file = get_user_profiles_file(user_id)
    if profiles_file is None:
        return []
    enforce_store_read_limit(profiles_file)
    profiles = _load_profiles_with_lock_held(user_id)
    enforce_store_read_limit(
        profiles_file,
        record_count=len(profiles),
        maximum_count=config.PROFILE_MAX_RECORDS,
    )
    return profiles


@user_operation
def load_profiles(user_id):
    """Load all connection profiles for a specific user."""
    # A read can persist a schema migration.  Hold the same coordinator used
    # by normal profile and jump-host mutations so the sibling-store size check
    # and the eventual migration write are one cross-store quota transaction.
    with storage_lock(f'command-config:{user_id}'):
        with storage_lock(f'profiles:{user_id}'):
            return _load_profiles_for_read_with_lock_held(user_id)


def _load_profiles_for_write(user_id):
    """Load only a response-safe profile store before normal mutation."""
    profiles_file = get_user_profiles_file(user_id)
    if not profiles_file:
        return None, 'User not found'
    return _load_profiles_for_read_with_lock_held(user_id), None


def _load_profiles_for_recovery_delete(user_id):
    """Load an oversized legacy store within the hard recovery ceilings."""
    profiles_file = get_user_profiles_file(user_id)
    if not profiles_file:
        return None, 'User not found'
    enforce_store_recovery_limit(profiles_file)
    data = load_json_migrated(
        profiles_file,
        'profiles',
        lambda: {'profiles': []},
        _valid_profile_document,
        persist_migration=False,
        pre_migration_check=lambda document: enforce_store_recovery_limit(
            profiles_file,
            record_count=(
                len(document['profiles'])
                if isinstance(document, dict)
                and isinstance(document.get('profiles'), list)
                else None
            ),
        ),
    )
    profiles = data['profiles']
    enforce_store_recovery_limit(
        profiles_file,
        record_count=len(profiles),
    )
    return profiles, None


@user_operation
def load_profile_recovery_summaries(user_id):
    """Return bounded, non-secret selectors for offline legacy recovery."""
    with storage_lock(f'profiles:{user_id}'):
        profiles, error = _load_profiles_for_recovery_delete(user_id)
        if error:
            return None, error
        scope = f'profiles:{user_id}'
        return [
            {
                'selector': recovery_record_selector(
                    scope,
                    index,
                    profile,
                ),
                'id': safe_reference_name(profile.get('id')),
                'name': safe_reference_name(profile.get('name')),
                'host': safe_reference_name(profile.get('host')),
            }
            for index, profile in enumerate(profiles)
            if isinstance(profile, dict)
        ], None

@user_operation
def save_profiles(
    user_id,
    profiles,
    *,
    previous_count=None,
    previous_document=None,
    compact=False,
):
    """Save profiles, compacting only explicitly requested recovery writes."""
    try:
        profiles_file = get_user_profiles_file(user_id)
        stored_profiles = []
        for profile in profiles:
            stored_profile = dict(profile) if isinstance(profile, dict) else profile
            if isinstance(stored_profile, dict):
                # This is derived from live launch policy for responses only.
                stored_profile.pop('tailscale_authorized', None)
            stored_profiles.append(stored_profile)
        document = {
            'schema_version': CURRENT_STORAGE_VERSIONS['profiles'],
            'profiles': stored_profiles,
        }
        if not profiles_file or not _valid_profile_document(document):
            return False

        payload = enforce_store_transition(
            path=profiles_file,
            other_paths=(profiles_file.parent / 'jump_hosts.json', profiles_file.parent / 'socks_proxies.json'),
            prospective_document=document,
            prospective_count=len(stored_profiles),
            previous_count=previous_count,
            maximum_count=config.PROFILE_MAX_RECORDS,
            previous_document=previous_document,
            compact=compact,
        )

        profiles_file.parent.mkdir(parents=True, exist_ok=True)

        atomic_write_bytes(profiles_file, payload)
        return True
    except ConnectionStorageLimitError:
        raise
    except Exception as e:
        log_error("Error saving profiles", user_id=user_id, error=str(e))
        return False

def _validate_profile_payload(user_id, payload, dependent_lock_held=False):
    """Validate storable profile fields without accepting credentials."""
    if not isinstance(payload, dict):
        return None, 'Invalid profile data'

    if 'platform_icon' in payload and (not isinstance(payload['platform_icon'], str) or payload['platform_icon'] not in PLATFORMS | {'auto'}):
        return None, 'Invalid platform icon'
    # What a discovery scan read from the SSH greeting; shown until a connection detects the platform.
    if 'greeting_platform' in payload and (not isinstance(payload['greeting_platform'], str) or payload['greeting_platform'] not in PLATFORMS):
        return None, 'Invalid platform icon'

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

    from .ssh_gateway import parse_selector
    if isinstance(username, str) and ':' in username:
        from .app_settings import is_ssh_gateway_enabled
        if not is_ssh_gateway_enabled():
            return None, 'SSH gateway integration is disabled by the administrator'
        if auth_type == 'tailscale':
            return None, 'Gateway selectors cannot use Tailscale SSH'
        try:
            parse_selector(username)
        except ValueError as error:
            return None, str(error)
    else:
        username = str(username).strip()
        if not re.match(r'^[a-zA-Z0-9_\-\.]{1,32}$', username):
            return None, 'Invalid username format'
    if auth_type not in {'password', 'key', 'tailscale'}:
        return None, 'Invalid auth_type'
    if auth_type == 'tailscale' and payload.get('jump_host_id'):
        return None, 'Tailscale SSH cannot be used with a jump host'
    socks_proxy_id = payload.get('socks_proxy_id')
    if socks_proxy_id is not None and (
        not isinstance(socks_proxy_id, str) or len(socks_proxy_id) > 64
    ):
        return None, 'Invalid SOCKS proxy reference'
    if socks_proxy_id and payload.get('jump_host_id'):
        return None, 'A host can use either a jump host or a SOCKS5 proxy, not both'
    if socks_proxy_id and auth_type == 'tailscale':
        return None, 'Tailscale SSH cannot be used with a SOCKS5 proxy'

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
    if key_id is not None and not isinstance(key_id, str):
        return None, 'Invalid key reference'
    if auth_type == 'key':
        from .key_manager import get_key

        if get_key(user_id, key_id) is None:
            return None, 'SSH key not found'

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
    if 'platform_icon' in payload:
        result['platform_icon'] = payload['platform_icon']
    if 'greeting_platform' in payload:
        result['greeting_platform'] = payload['greeting_platform']
    if group is not _UNSET and group:
        result['group'] = group
    if favorite is True:
        result['favorite'] = True
    if use_tmux is not _UNSET:
        result['use_tmux'] = use_tmux
    jump_host_id = payload.get('jump_host_id')
    if jump_host_id:
        result['jump_host_id'] = str(jump_host_id)[:64]
    if socks_proxy_id:
        result['socks_proxy_id'] = socks_proxy_id
    return result, None


@user_operation
def upsert_profile(user_id, payload, preserve_legacy_fallback=False,
                   skip_duplicate=False, on_created=None):
    """Create or update a profile under the per-user coordinator lock."""
    try:
        with storage_lock(f'command-config:{user_id}'):
            mode = infer_mode(payload)
            dependent_store = {
                'command': 'commands',
                'command_set': 'command-sets',
            }.get(mode) if isinstance(mode, str) else None
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

            socks_proxy_id = validated.get('socks_proxy_id')
            if socks_proxy_id:
                from .socks_proxy_manager import (
                    _get_socks_proxy_with_coordinator_held,
                )

                if _get_socks_proxy_with_coordinator_held(user_id, socks_proxy_id) is None:
                    return None, 'SOCKS proxy not found'

            if preserve_legacy_fallback and payload.get('startup_commands'):
                legacy, error = normalize_startup_commands(
                    payload['startup_commands']
                )
                if error:
                    return None, error
                if legacy:
                    validated['startup_commands'] = legacy

            with storage_lock(f'profiles:{user_id}'):
                transaction_path = get_user_profiles_file(user_id)
                transaction_before = transaction_path.read_bytes() if on_created and transaction_path.exists() else None
                profiles, error = _load_profiles_for_write(user_id)
                if error:
                    return None, error

                profile_id = payload.get('id')
                if skip_duplicate:
                    if profile_id:
                        return None, 'Import cannot update profiles'
                    for existing in profiles:
                        same_name = existing.get('name', '').casefold() == validated['name'].casefold()
                        same_endpoint = all(
                            existing.get(field) == validated.get(field)
                            for field in ('host', 'port', 'username', 'jump_host_id', 'socks_proxy_id')
                        )
                        if same_name or same_endpoint:
                            return None, 'Duplicate profile'
                previous_count = len(profiles)
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
                            if 'platform_icon' not in payload and 'platform_icon' in existing:
                                result['platform_icon'] = existing['platform_icon']
                            if endpoint(existing) == endpoint(result) and existing.get('detected_platform') in PLATFORMS:
                                result['detected_platform'] = existing['detected_platform']
                            # Detected services describe the same login on the same host.
                            if endpoint(existing) == endpoint(result) and 'detected_services' in existing:
                                result['detected_services'] = existing['detected_services']
                                if 'services_checked_at' in existing:
                                    result['services_checked_at'] = existing['services_checked_at']
                            if endpoint(existing) == endpoint(result) and 'detected_maintenance' in existing:
                                result['detected_maintenance'] = existing['detected_maintenance']
                            # The greeting belongs to an address and port; it goes when either changes.
                            if ('greeting_platform' not in payload and existing.get('greeting_platform') in PLATFORMS
                                    and (existing.get('host'), existing.get('port', 22)) == (result.get('host'), result.get('port', 22))):
                                result['greeting_platform'] = existing['greeting_platform']
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
                            validate_profile(result, existing)
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
                    validate_profile(result)

                if save_profiles(
                    user_id,
                    profiles,
                    previous_count=previous_count,
                ):
                    if on_created:
                        from .credential_store import finish_resource_transaction
                        finish_resource_transaction(transaction_path,transaction_before,result,on_created)
                    return result, None
                return None, 'Failed to save profile'
    except StorageCorruptionError:
        raise
    except ConnectionStorageLimitError as exc:
        return None, str(exc)
    except Exception as exc:
        log_error('Error saving profile', user_id=user_id, error=str(exc))
        return None, 'Failed to save profile'


@user_operation
def add_profile(user_id, name, host, port, username, auth_type, key_id=None,
                jump_host_id=None, startup_commands=None, command_set_id=None,
                socks_proxy_id=None):
    """Compatibility wrapper for callers that create legacy profile payloads."""
    payload = {
        'name': name,
        'host': host,
        'port': port,
        'username': username,
        'auth_type': auth_type,
        'key_id': key_id,
        'jump_host_id': jump_host_id,
        'socks_proxy_id': socks_proxy_id,
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

@user_operation
def get_profile(user_id, profile_id):
    """Get a specific profile by ID for a specific user."""
    profiles = load_profiles(user_id)
    for profile in profiles:
        if profile['id'] == profile_id:
            return profile
    return None


@user_operation
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
                    previous = dict(profile)
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
                    validate_profile(profile, previous)
                    if not save_profiles(
                        user_id,
                        profiles,
                        previous_count=len(profiles),
                    ):
                        return None, 'Failed to save profile'
                    return dict(profile), None
                return None, 'Profile not found'
    except StorageCorruptionError:
        raise
    except ConnectionStorageLimitError as exc:
        return None, str(exc)
    except Exception as exc:
        log_error(
            'Error updating profile organization',
            user_id=user_id,
            error=str(exc),
        )
        return None, 'Failed to save profile'


@user_operation
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
                previous = dict(profile)

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

                validate_profile(profile, previous)
                if not save_profiles(
                    user_id,
                    profiles,
                    previous_count=len(profiles),
                ):
                    return None, 'Failed to save profile'
                return {
                    'profiles': profiles,
                    'requires_confirmation': False,
                }, None
    except StorageCorruptionError:
        raise
    except ConnectionStorageLimitError as exc:
        return None, str(exc)
    except Exception as exc:
        log_error(
            'Error moving profile',
            user_id=user_id,
            error=str(exc),
        )
        return None, 'Failed to move profile'

@user_operation
def delete_profile(user_id, profile_id):
    """Delete a profile by ID for a specific user."""
    try:
        with storage_lock(f'command-config:{user_id}'):
            with storage_lock(f'profiles:{user_id}'):
                profiles, error = _load_profiles_for_write(user_id)
                if error:
                    return False, error
                index = next(
                    (
                        index
                        for index, profile in enumerate(profiles)
                        if profile.get('id') == profile_id
                    ),
                    None,
                )
                if index is None:
                    return False, 'Profile not found'
                previous_document = {
                    'schema_version': CURRENT_STORAGE_VERSIONS['profiles'],
                    'profiles': profiles,
                }
                remaining = list(profiles)
                remaining.pop(index)
                if save_profiles(
                    user_id,
                    remaining,
                    previous_count=len(profiles),
                    previous_document=previous_document,
                ):
                    return True, None
                return False, 'Failed to delete profile'
    except StorageCorruptionError:
        raise
    except ConnectionStorageLimitError as exc:
        return False, str(exc)
    except Exception as e:
        log_error("Error deleting profile", user_id=user_id, error=str(e))
        return False, 'Failed to delete profile'


@user_operation
def delete_profile_recovery_record(user_id, selector):
    """Delete one selector-bound profile from an offline recovery store."""
    try:
        with storage_lock(f'command-config:{user_id}'):
            with storage_lock(f'profiles:{user_id}'):
                profiles, error = _load_profiles_for_recovery_delete(user_id)
                if error:
                    return False, error
                index = resolve_recovery_record_selector(
                    f'profiles:{user_id}',
                    profiles,
                    selector,
                )
                if index is None:
                    return (
                        False,
                        'Recovery selector not found; list the store again.',
                    )
                previous_document = {
                    'schema_version': CURRENT_STORAGE_VERSIONS['profiles'],
                    'profiles': profiles,
                }
                remaining = list(profiles)
                remaining.pop(index)
                if save_profiles(
                    user_id,
                    remaining,
                    previous_count=len(profiles),
                    previous_document=previous_document,
                    compact=True,
                ):
                    return True, None
                return False, 'Failed to delete profile'
    except StorageCorruptionError:
        raise
    except ConnectionStorageLimitError as exc:
        return False, str(exc)
    except Exception as exc:
        log_error(
            'Error deleting recovery profile',
            user_id=user_id,
            error=str(exc),
        )
        return False, 'Failed to delete profile'


@user_operation
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
            if command_set.get('parameters'):
                return None, 'Parameterized command sets require interactive launch after connecting'
            with storage_lock(f'profiles:{user_id}'):
                profiles, error = _load_profiles_for_write(user_id)
                if error:
                    return None, error
                for profile in profiles:
                    if profile.get('id') == profile_id:
                        profile['startup_mode'] = 'command_set'
                        profile['command_set_id'] = command_set['id']
                        validate_profile(profile)
                        if not save_profiles(
                            user_id,
                            profiles,
                            previous_count=len(profiles),
                        ):
                            return None, 'Failed to save profile'
                        return profile, None
                return None, 'Profile not found'
    except StorageCorruptionError:
        raise
    except ConnectionStorageLimitError as exc:
        return None, str(exc)
    except Exception as e:
        log_error('Error assigning command set to profile', user_id=user_id, error=str(e))
        return None, str(e)


@user_operation
def cache_greeting_platforms(user_id, observed):
    """Record what saved direct hosts' SSH greetings named; return how many changed.

    ``observed`` maps profile ids to ((canonical host, port), platform) as probed.
    A host edited meanwhile, routed through a jump host or already showing the
    same hint is left alone; detections and manual choices still take precedence.
    """
    from .network_policy import canonicalize_hostname
    wanted = {key: value for key, value in observed.items() if value and value[1] in PLATFORMS}
    if not wanted:
        return 0
    with storage_lock(f'command-config:{user_id}'):
        with storage_lock(f'profiles:{user_id}'):
            profiles, error = _load_profiles_for_write(user_id)
            if error:
                return 0
            changed = 0
            for profile in profiles:
                item = wanted.get(profile.get('id'))
                if not item or profile.get('jump_host_id') or profile.get('socks_proxy_id'):
                    continue
                probed, platform = item
                try:
                    current = (canonicalize_hostname(profile.get('host')), int(profile.get('port') or 22))
                except (TypeError, ValueError):
                    continue
                if current != tuple(probed) or profile.get('greeting_platform') == platform:
                    continue
                profile['greeting_platform'] = platform
                changed += 1
            if changed and save_profiles(user_id, profiles, previous_count=len(profiles)):
                return changed
    return 0


@user_operation
def cache_detected_facts(user_id, profile_id, expected_endpoint, *, platform=None, services=None,
                         maintenance=None, now=None):
    """Merge detected platform, service and maintenance facts into the current owned profile under its lock."""
    from .host_platform import valid_maintenance, valid_services
    if expected_endpoint is None or (platform is None and services is None and maintenance is None):
        return False
    if maintenance is not None and (not valid_maintenance(maintenance) or 'checked_at' in maintenance):
        return False
    if platform is not None and platform not in PLATFORMS:
        return False
    if services is not None and not valid_services(services):
        return False
    with storage_lock(f'command-config:{user_id}'):
        with storage_lock(f'profiles:{user_id}'):
            profiles, error = _load_profiles_for_write(user_id)
            if error:
                return False
            for profile in profiles:
                if profile.get('id') != profile_id or endpoint(profile) != expected_endpoint:
                    continue
                if platform is not None:
                    profile['detected_platform'] = platform
                if services is not None:
                    profile['detected_services'] = list(services)
                    profile['services_checked_at'] = time.time() if now is None else now
                if maintenance is not None:
                    profile['detected_maintenance'] = {**maintenance, 'checked_at': time.time() if now is None else now}
                return save_profiles(user_id, profiles, previous_count=len(profiles))
    return False


@user_operation
def settle_reboot_hint(user_id, profile_id, expected_endpoint, checked_at, *, cleared):
    """Lower a restart hint, or stop rechecking it, if it is still the one that was read.

    Only the hint from the check stamped checked_at changes; a newer full
    check replaces detected_maintenance and starts over. Update counts and
    the check time stay as that check reported them.
    """
    if expected_endpoint is None or isinstance(checked_at, bool) or not isinstance(checked_at, (int, float)):
        return False
    with storage_lock(f'command-config:{user_id}'):
        with storage_lock(f'profiles:{user_id}'):
            profiles, error = _load_profiles_for_write(user_id)
            if error:
                return False
            for profile in profiles:
                if profile.get('id') != profile_id or endpoint(profile) != expected_endpoint:
                    continue
                facts = profile.get('detected_maintenance')
                if (not isinstance(facts, dict) or facts.get('reboot_required') is not True
                        or facts.get('recheck_stopped') or facts.get('checked_at') != checked_at):
                    return False
                change = {'reboot_required': False} if cleared else {'recheck_stopped': True}
                profile['detected_maintenance'] = {**facts, **change}
                return save_profiles(user_id, profiles, previous_count=len(profiles))
    return False


@user_operation
def cache_detected_platform(user_id, profile_id, expected_endpoint, platform):
    """Merge only platform facts into the current owned profile under its lock."""
    if expected_endpoint is None or platform not in PLATFORMS:
        return False
    with storage_lock(f'command-config:{user_id}'):
        with storage_lock(f'profiles:{user_id}'):
            profiles, error = _load_profiles_for_write(user_id)
            if error:
                return False
            for profile in profiles:
                if profile.get('id') != profile_id or endpoint(profile) != expected_endpoint:
                    continue
                if profile.get('detected_platform') == platform:
                    return True
                profile['detected_platform'] = platform
                return save_profiles(user_id, profiles, previous_count=len(profiles))
    return False
