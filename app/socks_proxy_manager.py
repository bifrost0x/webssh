"""Per-user SOCKS5 route metadata; passwords belong to the credential store."""
import uuid
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
    validate_socks_proxy,
)
from .storage_errors import StorageCorruptionError
from .storage_utils import (
    atomic_write_bytes,
    load_json_migrated,
    safe_reference_name,
    storage_lock,
)
from .storage_migrations import CURRENT_STORAGE_VERSIONS
from .data_access import user_operation
from .jump_host_manager import _is_valid_host


_SOCKS_PROXY_USAGE_DETAIL_LIMIT = 20
_SOCKS_PROXY_FIELDS = {
    'id', 'name', 'host', 'port', 'auth_type', 'username', 'remote_dns',
    'created_at',
}


def _get_file(user_id):
    from .models import User, db
    user = db.session.get(User, user_id)
    if not user:
        return None
    return user.get_data_dir() / 'socks_proxies.json'


def _valid_socks_proxy(item):
    if not isinstance(item, dict) or set(item) != _SOCKS_PROXY_FIELDS:
        return False
    required_strings = ('id', 'name', 'host', 'username', 'auth_type', 'created_at')
    if not all(isinstance(item.get(field), str) for field in required_strings):
        return False
    if not item['id'] or len(item['id']) > 64 or not item['name'].strip():
        return False
    if not _is_valid_host(item['host']):
        return False
    if type(item.get('port')) is not int or not 1 <= item['port'] <= 65535:
        return False
    if item['auth_type'] not in {'none', 'password'}:
        return False
    if type(item.get('remote_dns')) is not bool:
        return False
    if item['auth_type'] == 'none' and item['username'] != '':
        return False
    if item['auth_type'] == 'password' and not item['username']:
        return False
    try:
        validate_socks_proxy(item)
    except ConnectionStorageLimitError:
        return False
    return True


def _valid_socks_proxy_document(value):
    return (
        isinstance(value, dict)
        and set(value) == {'schema_version', 'socks_proxies'}
        and value.get('schema_version') == CURRENT_STORAGE_VERSIONS['socks_proxies']
        and isinstance(value.get('socks_proxies'), list)
        and all(_valid_socks_proxy(item) for item in value['socks_proxies'])
        and len({item['id'] for item in value['socks_proxies']}) == len(value['socks_proxies'])
    )


def _socks_proxy_migration_payload(path, document):
    """Return a quota-safe exact migration payload, or keep it in memory."""
    socks_proxies = document['socks_proxies']
    try:
        return enforce_store_transition(
            path=path,
            other_paths=(
                path.parent / 'profiles.json',
                path.parent / 'jump_hosts.json',
            ),
            prospective_document=document,
            prospective_count=len(socks_proxies),
            previous_count=None,
            maximum_count=config.SOCKS_PROXY_MAX_RECORDS,
        )
    except ConnectionStorageLimitError:
        return None


def _load_socks_proxies_with_lock_held(user_id):
    path = _get_file(user_id)
    if path is None:
        return []
    data = load_json_migrated(
        path,
        'socks_proxies',
        lambda: {'socks_proxies': []},
        _valid_socks_proxy_document,
        migration_payload_factory=lambda document: (
            _socks_proxy_migration_payload(path, document)
        ),
    )
    return data['socks_proxies']


def _load_socks_proxies_for_read_with_lock_held(user_id):
    """Load only a response-safe SOCKS-proxy store while its lock is held."""
    path = _get_file(user_id)
    if path is None:
        return []
    enforce_store_read_limit(path)
    socks_proxies = _load_socks_proxies_with_lock_held(user_id)
    enforce_store_read_limit(
        path,
        record_count=len(socks_proxies),
        maximum_count=config.SOCKS_PROXY_MAX_RECORDS,
    )
    return socks_proxies


@user_operation
def load_socks_proxies(user_id):
    """Load all SOCKS proxies for a user."""
    # A read can persist a schema migration. Coordinate it with route and
    # profile mutations so combined byte accounting cannot observe a stale
    # sibling store before the migration replaces this file.
    with storage_lock(f'command-config:{user_id}'):
        with storage_lock(f'socks_proxies:{user_id}'):
            return _load_socks_proxies_for_read_with_lock_held(user_id)


@user_operation
def save_socks_proxies(
    user_id,
    socks_proxies,
    *,
    previous_count=None,
    previous_document=None,
    compact=False,
):
    try:
        f = _get_file(user_id)
        document = {
            'schema_version': CURRENT_STORAGE_VERSIONS['socks_proxies'],
            'socks_proxies': socks_proxies,
        }
        if not f or not _valid_socks_proxy_document(document):
            return False
        payload = enforce_store_transition(
            path=f,
            other_paths=(f.parent / 'profiles.json', f.parent / 'jump_hosts.json'),
            prospective_document=document,
            prospective_count=len(socks_proxies),
            previous_count=previous_count,
            maximum_count=config.SOCKS_PROXY_MAX_RECORDS,
            previous_document=previous_document,
            compact=compact,
        )
        f.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_bytes(f, payload)
        return True
    except ConnectionStorageLimitError:
        raise
    except OSError as e:
        log_error("Error saving SOCKS proxies", user_id=user_id, error=str(e))
        return False


def _load_profile_references(user_id):
    from . import profile_manager

    return profile_manager._load_profiles_for_read_with_lock_held(user_id)


def _load_socks_proxies_for_recovery_delete(user_id):
    """Load legacy SOCKS proxies within the hard recovery ceiling."""
    path = _get_file(user_id)
    if path is None:
        return []
    enforce_store_recovery_limit(path)
    data = load_json_migrated(
        path,
        'socks_proxies',
        lambda: {'socks_proxies': []},
        _valid_socks_proxy_document,
        persist_migration=False,
        pre_migration_check=lambda document: enforce_store_recovery_limit(
            path,
            record_count=(
                len(document['socks_proxies'])
                if isinstance(document, dict)
                and isinstance(document.get('socks_proxies'), list)
                else None
            ),
        ),
    )
    socks_proxies = data['socks_proxies']
    enforce_store_recovery_limit(
        path,
        record_count=len(socks_proxies),
    )
    return socks_proxies


@user_operation
def load_socks_proxy_recovery_summaries(user_id):
    """Return bounded, non-secret selectors for offline legacy recovery."""
    with storage_lock(f'socks_proxies:{user_id}'):
        socks_proxies = _load_socks_proxies_for_recovery_delete(user_id)
        scope = f'socks-proxies:{user_id}'
        return [
            {
                'selector': recovery_record_selector(
                    scope,
                    index,
                    socks_proxy,
                ),
                'id': safe_reference_name(socks_proxy.get('id')),
                'name': safe_reference_name(socks_proxy.get('name')),
                'host': safe_reference_name(socks_proxy.get('host')),
            }
            for index, socks_proxy in enumerate(socks_proxies)
            if isinstance(socks_proxy, dict)
        ]


def _profile_usage_summary(profiles, socks_proxy_id):
    usage_count = 0
    usages = []
    for profile in profiles:
        if (
            not isinstance(profile, dict)
            or profile.get('socks_proxy_id') != socks_proxy_id
        ):
            continue
        usage_count += 1
        if len(usages) < _SOCKS_PROXY_USAGE_DETAIL_LIMIT:
            usages.append(safe_reference_name(profile.get('name')))
    return usage_count, usages


def _socks_proxy_in_use_result(profiles, socks_proxy_id):
    usage_count, usages = _profile_usage_summary(profiles, socks_proxy_id)
    if not usage_count:
        return None
    noun = 'profile' if usage_count == 1 else 'profiles'
    details = ''
    if usage_count > len(usages):
        details = f' (showing first {len(usages)})'
    return (
        False,
        f'SOCKS proxy is used by {usage_count} {noun}{details}',
        usages,
    )


def _get_socks_proxy_with_coordinator_held(user_id, socks_proxy_id):
    """Return one live SOCKS-proxy snapshot while the coordinator is held."""
    if (
        not isinstance(socks_proxy_id, str)
        or not socks_proxy_id
        or len(socks_proxy_id) > 64
    ):
        return None
    with storage_lock(f'socks_proxies:{user_id}'):
        socks_proxies = _load_socks_proxies_for_read_with_lock_held(user_id)
    for socks_proxy in socks_proxies:
        if socks_proxy.get('id') == socks_proxy_id:
            return dict(socks_proxy)
    return None


@user_operation
def get_socks_proxy(user_id, socks_proxy_id):
    """Resolve a saved SOCKS proxy from current server-side storage."""
    with storage_lock(f'command-config:{user_id}'):
        return _get_socks_proxy_with_coordinator_held(
            user_id, socks_proxy_id
        )


@user_operation
def add_socks_proxy(
    user_id, name, host, port, auth_type='none', username='',
    remote_dns=True, socks_proxy_id=None, on_created=None,
):
    """Validate and create or update a user-owned SOCKS proxy without storing passwords."""
    try:
        if not isinstance(name, str) or not name.strip():
            return None, 'Invalid SOCKS proxy name'

        if not isinstance(host, str) or not _is_valid_host(host):
            return None, 'Invalid host format'
        host = host.strip()

        if type(port) is not int:
            return None, 'Invalid port number'
        if not 1 <= port <= 65535:
            return None, 'Port must be between 1 and 65535'

        if not isinstance(auth_type, str) or auth_type not in {'none', 'password'}:
            return None, 'Invalid auth_type'
        if not isinstance(username, str):
            return None, 'Invalid SOCKS proxy username'
        if auth_type == 'none' and username != '':
            return None, 'Username requires password authentication'
        if auth_type == 'password' and not username:
            return None, 'Username required for password authentication'
        if type(remote_dns) is not bool:
            return None, 'remote_dns must be a boolean'
        if socks_proxy_id is not None and (
            not isinstance(socks_proxy_id, str)
            or not socks_proxy_id
            or len(socks_proxy_id) > 64
        ):
            return None, 'Invalid SOCKS proxy reference'

        # The coordinator serializes cross-store budgets and reference changes.
        with storage_lock(f'command-config:{user_id}'):
            socks_proxy = {
                'id': str(uuid.uuid4()),
                'name': name.strip(),
                'host': host,
                'port': port,
                'username': username,
                'auth_type': auth_type,
                'remote_dns': remote_dns,
                'created_at': datetime.now(timezone.utc).replace(
                    tzinfo=None
                ).isoformat()
            }
            validate_socks_proxy(socks_proxy)
            with storage_lock(f'socks_proxies:{user_id}'):
                transaction_path = _get_file(user_id)
                if transaction_path is None:
                    return None, 'User not found'
                transaction_before = (
                    transaction_path.read_bytes()
                    if on_created and transaction_path.exists()
                    else None
                )
                socks_proxies = _load_socks_proxies_for_read_with_lock_held(user_id)
                previous_count = len(socks_proxies)
                if socks_proxy_id is not None:
                    existing = next(
                        (item for item in socks_proxies if item['id'] == socks_proxy_id),
                        None,
                    )
                    if existing is None:
                        return None, "SOCKS proxy not found"
                    socks_proxy['id'] = existing['id']
                    socks_proxy['created_at'] = existing['created_at']
                    socks_proxies = [
                        socks_proxy if item['id'] == socks_proxy_id else item
                        for item in socks_proxies
                    ]
                else:
                    socks_proxies.append(socks_proxy)
                if save_socks_proxies(
                    user_id,
                    socks_proxies,
                    previous_count=previous_count,
                ):
                    if on_created:
                        from .credential_store import finish_resource_transaction
                        finish_resource_transaction(
                            transaction_path, transaction_before, socks_proxy,
                            on_created,
                        )
                    log_info(
                        'SOCKS proxy saved', user_id=user_id,
                        proxy_id=socks_proxy['id'],
                    )
                    return socks_proxy, None
                return None, "Failed to save SOCKS proxy"
    except StorageCorruptionError:
        raise
    except ConnectionStorageLimitError as exc:
        return None, str(exc)
    except Exception:
        log_error('Error saving SOCKS proxy', user_id=user_id)
        return None, 'Failed to save SOCKS proxy'


@user_operation
def delete_socks_proxy(user_id, socks_proxy_id):
    try:
        with storage_lock(f'command-config:{user_id}'):
            with storage_lock(f'profiles:{user_id}'):
                profiles = _load_profile_references(user_id)
            in_use = _socks_proxy_in_use_result(profiles, socks_proxy_id)
            if in_use is not None:
                return in_use

            with storage_lock(f'socks_proxies:{user_id}'):
                socks_proxies = _load_socks_proxies_for_read_with_lock_held(user_id)
                index = next(
                    (
                        index
                        for index, socks_proxy in enumerate(socks_proxies)
                        if socks_proxy.get('id') == socks_proxy_id
                    ),
                    None,
                )
                if index is None:
                    return False, 'SOCKS proxy not found', []
                new_list = list(socks_proxies)
                new_list.pop(index)
                previous_document = {
                    'schema_version': CURRENT_STORAGE_VERSIONS['socks_proxies'],
                    'socks_proxies': socks_proxies,
                }
                if save_socks_proxies(
                    user_id,
                    new_list,
                    previous_count=len(socks_proxies),
                    previous_document=previous_document,
                ):
                    return True, None, []
                return False, 'Failed to delete SOCKS proxy', []
    except StorageCorruptionError:
        raise
    except ConnectionStorageLimitError as exc:
        return False, str(exc), []
    except Exception as e:
        log_error("Error deleting SOCKS proxy", user_id=user_id, error=str(e))
        return False, 'Failed to delete SOCKS proxy', []


@user_operation
def delete_socks_proxy_recovery_record(user_id, selector):
    """Delete one selector-bound SOCKS proxy from an offline recovery store."""
    try:
        with storage_lock(f'command-config:{user_id}'):
            from . import profile_manager

            with storage_lock(f'profiles:{user_id}'):
                profiles, error = (
                    profile_manager._load_profiles_for_recovery_delete(user_id)
                )
                if error:
                    return False, error, []
                with storage_lock(f'socks_proxies:{user_id}'):
                    socks_proxies = _load_socks_proxies_for_recovery_delete(user_id)
                    index = resolve_recovery_record_selector(
                        f'socks-proxies:{user_id}',
                        socks_proxies,
                        selector,
                    )
                    if index is None:
                        return (
                            False,
                            'Recovery selector not found; list the store again.',
                            [],
                        )
                    socks_proxy_id = socks_proxies[index].get('id')
                    in_use = _socks_proxy_in_use_result(
                        profiles,
                        socks_proxy_id,
                    )
                    if in_use is not None:
                        return in_use

                    remaining = list(socks_proxies)
                    remaining.pop(index)
                    previous_document = {
                        'schema_version': CURRENT_STORAGE_VERSIONS['socks_proxies'],
                        'socks_proxies': socks_proxies,
                    }
                    if save_socks_proxies(
                        user_id,
                        remaining,
                        previous_count=len(socks_proxies),
                        previous_document=previous_document,
                        compact=True,
                    ):
                        return True, None, []
                    return False, 'Failed to delete SOCKS proxy', []
    except StorageCorruptionError:
        raise
    except ConnectionStorageLimitError as exc:
        return False, str(exc), []
    except Exception as exc:
        log_error(
            'Error deleting recovery SOCKS proxy',
            user_id=user_id,
            error=str(exc),
        )
        return False, 'Failed to delete SOCKS proxy', []
