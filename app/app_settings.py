"""Application-wide runtime settings persisted to a JSON file in DATA_DIR.

Unlike user_settings (per user), these are global settings an admin can toggle
at runtime without restarting (e.g. whether self-registration is open). Each
value falls back to its config/env default when no override has been saved.
"""
import config

from .storage_utils import atomic_write_json, load_json_migrated, storage_lock
from .storage_migrations import CURRENT_STORAGE_VERSIONS

_SETTINGS_FILE = config.DATA_DIR / 'app_settings.json'


def _valid_settings(value):
    return (
        isinstance(value, dict)
        and value.get('schema_version') == CURRENT_STORAGE_VERSIONS['app_settings']
        and (
            'registration_enabled' not in value
            or type(value['registration_enabled']) is bool
        )
        and (
            'audit_backup_count' not in value
            or (
                type(value['audit_backup_count']) is int
                and 1 <= value['audit_backup_count'] <= 90
            )
        )
    )


def _load_with_lock_held():
    return load_json_migrated(
        _SETTINGS_FILE,
        'app_settings',
        dict,
        _valid_settings,
    )


def _load():
    with storage_lock(f'app-settings:{_SETTINGS_FILE}'):
        return _load_with_lock_held()


def _save(data):
    _SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    data['schema_version'] = CURRENT_STORAGE_VERSIONS['app_settings']
    atomic_write_json(_SETTINGS_FILE, data)


def is_registration_enabled():
    """Effective registration state: saved override if present, else env default."""
    data = _load()
    if config.DEPLOYMENT_PROFILE == 'production':
        return False
    if 'registration_enabled' in data:
        return bool(data['registration_enabled'])
    return bool(config.REGISTRATION_ENABLED)


def set_registration_enabled(value):
    if type(value) is not bool:
        return False
    if config.DEPLOYMENT_PROFILE == 'production' and value:
        return False
    with storage_lock(f'app-settings:{_SETTINGS_FILE}'):
        data = _load_with_lock_held()
        data['registration_enabled'] = value
        if not _valid_settings(data):
            return False
        _save(data)
    return value


def get_audit_backup_count():
    data = _load()
    return int(data.get(
        'audit_backup_count',
        config.AUDIT_LOG_BACKUP_COUNT,
    ))


def set_audit_backup_count(value):
    if type(value) is not int or not 1 <= value <= 90:
        return False
    with storage_lock(f'app-settings:{_SETTINGS_FILE}'):
        data = _load_with_lock_held()
        data['audit_backup_count'] = value
        if not _valid_settings(data):
            return False
        _save(data)
    return value
