"""Per-user storage of reusable jump hosts (bastions).

Mirrors profile_manager: a JSON file per user under their data dir. Stores only
non-secret connection metadata (name/host/port/username/auth_type/key_id) — never
a password, consistent with connection profiles.
"""
import re
import uuid
import ipaddress
from datetime import datetime, timezone

import config

from .audit_logger import log_error, log_info
from .connection_storage_policy import (
    ConnectionStorageLimitError,
    enforce_store_read_limit,
    enforce_store_recovery_limit,
    enforce_store_transition,
    recovery_record_selector,
    resolve_recovery_record_selector,
    validate_jump_host,
)
from .storage_errors import StorageCorruptionError
from .storage_utils import (
    atomic_write_bytes,
    load_json_migrated,
    safe_reference_name,
    storage_lock,
)
from .storage_migrations import CURRENT_STORAGE_VERSIONS


_JUMP_HOST_USAGE_DETAIL_LIMIT = 20


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
    from .models import User, db
    user = db.session.get(User, user_id)
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


def _jump_host_migration_payload(path, document):
    """Return a quota-safe exact migration payload, or keep it in memory."""
    jump_hosts = document['jump_hosts']
    try:
        return enforce_store_transition(
            path=path,
            other_path=path.parent / 'profiles.json',
            prospective_document=document,
            prospective_count=len(jump_hosts),
            previous_count=None,
            maximum_count=config.JUMP_HOST_MAX_RECORDS,
        )
    except ConnectionStorageLimitError:
        return None


def _load_jump_hosts_with_lock_held(user_id):
    path = _get_file(user_id)
    if path is None:
        return []
    data = load_json_migrated(
        path,
        'jump_hosts',
        lambda: {'jump_hosts': []},
        _valid_jump_host_document,
        migration_payload_factory=lambda document: (
            _jump_host_migration_payload(path, document)
        ),
    )
    return data['jump_hosts']


def _load_jump_hosts_for_read_with_lock_held(user_id):
    """Load only a response-safe jump-host store while its lock is held."""
    path = _get_file(user_id)
    if path is None:
        return []
    enforce_store_read_limit(path)
    jump_hosts = _load_jump_hosts_with_lock_held(user_id)
    enforce_store_read_limit(
        path,
        record_count=len(jump_hosts),
        maximum_count=config.JUMP_HOST_MAX_RECORDS,
    )
    return jump_hosts


def load_jump_hosts(user_id):
    """Load all jump hosts for a user."""
    # A read can persist a schema migration.  Coordinate it with profile and
    # jump-host mutations so combined byte accounting cannot observe a stale
    # sibling store before the migration replaces this file.
    with storage_lock(f'command-config:{user_id}'):
        with storage_lock(f'jump_hosts:{user_id}'):
            return _load_jump_hosts_for_read_with_lock_held(user_id)


def save_jump_hosts(
    user_id,
    jump_hosts,
    *,
    previous_count=None,
    previous_document=None,
    compact=False,
):
    try:
        f = _get_file(user_id)
        document = {
            'schema_version': CURRENT_STORAGE_VERSIONS['jump_hosts'],
            'jump_hosts': jump_hosts,
        }
        if not f or not _valid_jump_host_document(document):
            return False
        payload = enforce_store_transition(
            path=f,
            other_path=f.parent / 'profiles.json',
            prospective_document=document,
            prospective_count=len(jump_hosts),
            previous_count=previous_count,
            maximum_count=config.JUMP_HOST_MAX_RECORDS,
            previous_document=previous_document,
            compact=compact,
        )
        f.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_bytes(f, payload)
        return True
    except ConnectionStorageLimitError:
        raise
    except OSError as e:
        log_error("Error saving jump hosts", user_id=user_id, error=str(e))
        return False


def _load_profile_references(user_id):
    from . import profile_manager

    return profile_manager._load_profiles_for_read_with_lock_held(user_id)


def _load_jump_hosts_for_recovery_delete(user_id):
    """Load legacy jump hosts within the hard recovery ceiling."""
    path = _get_file(user_id)
    if path is None:
        return []
    enforce_store_recovery_limit(path)
    data = load_json_migrated(
        path,
        'jump_hosts',
        lambda: {'jump_hosts': []},
        _valid_jump_host_document,
        persist_migration=False,
        pre_migration_check=lambda document: enforce_store_recovery_limit(
            path,
            record_count=(
                len(document['jump_hosts'])
                if isinstance(document, dict)
                and isinstance(document.get('jump_hosts'), list)
                else None
            ),
        ),
    )
    jump_hosts = data['jump_hosts']
    enforce_store_recovery_limit(
        path,
        record_count=len(jump_hosts),
    )
    return jump_hosts


def load_jump_host_recovery_summaries(user_id):
    """Return bounded, non-secret selectors for offline legacy recovery."""
    with storage_lock(f'jump_hosts:{user_id}'):
        jump_hosts = _load_jump_hosts_for_recovery_delete(user_id)
        scope = f'jump-hosts:{user_id}'
        return [
            {
                'selector': recovery_record_selector(
                    scope,
                    index,
                    jump_host,
                ),
                'id': safe_reference_name(jump_host.get('id')),
                'name': safe_reference_name(jump_host.get('name')),
                'host': safe_reference_name(jump_host.get('host')),
            }
            for index, jump_host in enumerate(jump_hosts)
            if isinstance(jump_host, dict)
        ]


def _profile_usage_summary(profiles, jump_host_id):
    usage_count = 0
    usages = []
    for profile in profiles:
        if (
            not isinstance(profile, dict)
            or profile.get('jump_host_id') != jump_host_id
        ):
            continue
        usage_count += 1
        if len(usages) < _JUMP_HOST_USAGE_DETAIL_LIMIT:
            usages.append(safe_reference_name(profile.get('name')))
    return usage_count, usages


def _jump_host_in_use_result(profiles, jump_host_id):
    usage_count, usages = _profile_usage_summary(profiles, jump_host_id)
    if not usage_count:
        return None
    noun = 'profile' if usage_count == 1 else 'profiles'
    details = ''
    if usage_count > len(usages):
        details = f' (showing first {len(usages)})'
    return (
        False,
        f'Jump host is used by {usage_count} {noun}{details}',
        usages,
    )


def _get_jump_host_with_coordinator_held(user_id, jump_host_id):
    """Return one live jump-host snapshot while the coordinator is held."""
    if not isinstance(jump_host_id, str) or not jump_host_id:
        return None
    with storage_lock(f'jump_hosts:{user_id}'):
        jump_hosts = _load_jump_hosts_for_read_with_lock_held(user_id)
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
        if not isinstance(name, str) or not name.strip():
            return None, "Invalid jump host name"

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
        if key_id is not None and not isinstance(key_id, str):
            return None, "Invalid key reference"
        # One coordinator protects cross-store byte accounting and keeps key
        # deletion from racing between reference validation and persistence.
        with storage_lock(f'command-config:{user_id}'):
            if auth_type == 'key':
                from .key_manager import get_key

                if get_key(user_id, key_id) is None:
                    return None, "SSH key not found"

            jump_host = {
                'id': str(uuid.uuid4()),
                'name': name.strip()[:128],
                'host': host,
                'port': port,
                'username': username,
                'auth_type': auth_type,
                'key_id': key_id if auth_type == 'key' else None,
                'created_at': datetime.now(timezone.utc).replace(
                    tzinfo=None
                ).isoformat()
            }
            validate_jump_host(jump_host)
            with storage_lock(f'jump_hosts:{user_id}'):
                jump_hosts = _load_jump_hosts_for_read_with_lock_held(user_id)
                previous_count = len(jump_hosts)
                jump_hosts.append(jump_host)
                if save_jump_hosts(
                    user_id,
                    jump_hosts,
                    previous_count=previous_count,
                ):
                    log_info("Jump host saved", user_id=user_id, name=name)
                    return jump_host, None
                return None, "Failed to save jump host"
    except StorageCorruptionError:
        raise
    except ConnectionStorageLimitError as exc:
        return None, str(exc)
    except Exception as e:
        return None, str(e)


def delete_jump_host(user_id, jump_host_id):
    try:
        with storage_lock(f'command-config:{user_id}'):
            with storage_lock(f'profiles:{user_id}'):
                profiles = _load_profile_references(user_id)
            in_use = _jump_host_in_use_result(profiles, jump_host_id)
            if in_use is not None:
                return in_use

            with storage_lock(f'jump_hosts:{user_id}'):
                jump_hosts = _load_jump_hosts_for_read_with_lock_held(user_id)
                index = next(
                    (
                        index
                        for index, jump_host in enumerate(jump_hosts)
                        if jump_host.get('id') == jump_host_id
                    ),
                    None,
                )
                if index is None:
                    return False, 'Jump host not found', []
                new_list = list(jump_hosts)
                new_list.pop(index)
                previous_document = {
                    'schema_version': CURRENT_STORAGE_VERSIONS['jump_hosts'],
                    'jump_hosts': jump_hosts,
                }
                if save_jump_hosts(
                    user_id,
                    new_list,
                    previous_count=len(jump_hosts),
                    previous_document=previous_document,
                ):
                    return True, None, []
                return False, 'Failed to delete jump host', []
    except StorageCorruptionError:
        raise
    except ConnectionStorageLimitError as exc:
        return False, str(exc), []
    except Exception as e:
        log_error("Error deleting jump host", user_id=user_id, error=str(e))
        return False, 'Failed to delete jump host', []


def delete_jump_host_recovery_record(user_id, selector):
    """Delete one selector-bound jump host from an offline recovery store."""
    try:
        with storage_lock(f'command-config:{user_id}'):
            from . import profile_manager

            with storage_lock(f'profiles:{user_id}'):
                profiles, error = (
                    profile_manager._load_profiles_for_recovery_delete(user_id)
                )
                if error:
                    return False, error, []
                with storage_lock(f'jump_hosts:{user_id}'):
                    jump_hosts = _load_jump_hosts_for_recovery_delete(user_id)
                    index = resolve_recovery_record_selector(
                        f'jump-hosts:{user_id}',
                        jump_hosts,
                        selector,
                    )
                    if index is None:
                        return (
                            False,
                            'Recovery selector not found; list the store again.',
                            [],
                        )
                    jump_host_id = jump_hosts[index].get('id')
                    in_use = _jump_host_in_use_result(
                        profiles,
                        jump_host_id,
                    )
                    if in_use is not None:
                        return in_use

                    remaining = list(jump_hosts)
                    remaining.pop(index)
                    previous_document = {
                        'schema_version': CURRENT_STORAGE_VERSIONS['jump_hosts'],
                        'jump_hosts': jump_hosts,
                    }
                    if save_jump_hosts(
                        user_id,
                        remaining,
                        previous_count=len(jump_hosts),
                        previous_document=previous_document,
                        compact=True,
                    ):
                        return True, None, []
                    return False, 'Failed to delete jump host', []
    except StorageCorruptionError:
        raise
    except ConnectionStorageLimitError as exc:
        return False, str(exc), []
    except Exception as exc:
        log_error(
            'Error deleting recovery jump host',
            user_id=user_id,
            error=str(exc),
        )
        return False, 'Failed to delete jump host', []
