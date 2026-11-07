"""Application-wide runtime settings persisted to a JSON file in DATA_DIR.

Unlike user_settings (per user), these are global settings an admin can toggle
at runtime without restarting (e.g. whether self-registration is open). Each
value falls back to its config/env default when no override has been saved.
"""
import secrets

import config

from .storage_utils import atomic_write_json, load_json_migrated, storage_lock
from .storage_migrations import CURRENT_STORAGE_VERSIONS

_SETTINGS_FILE = config.DATA_DIR / 'app_settings.json'

_BOOLEAN_SETTINGS = (
    'credentials_enabled',
    'automation_enabled',
    'automation_effective_observed',
    'sftp_chmod_enabled',
    'server_operations_enabled',
    'tmux_enabled',
    'tmux_default',
)


def _valid_settings(value):
    return (
        isinstance(value, dict)
        and value.get('schema_version') == CURRENT_STORAGE_VERSIONS['app_settings']
        and all(name not in value or type(value[name]) is bool for name in _BOOLEAN_SETTINGS)
        and ('runtime_feature_migration' not in value or (isinstance(value['runtime_feature_migration'], list) and all(isinstance(name, str) and name in RUNTIME_FEATURES for name in value['runtime_feature_migration'])))
        and all(name not in value or isinstance(value[name],str) for name in ('credentials_enabled_revision','automation_enabled_revision'))
        and (
            'ssh_gateway_enabled' not in value
            or type(value['ssh_gateway_enabled']) is bool
        )
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
    """Effective registration state: saved override if present, else env default.

    REGISTRATION_ENABLED has always been only the initial value; a saved
    administrator choice wins. Keeping that precedence guarantees that an
    upgrade never reopens registration an administrator closed.
    """
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


def is_ssh_gateway_enabled():
    """Gateway authentication requires an explicit, persisted admin opt-in."""
    return _load().get('ssh_gateway_enabled') is True


def set_ssh_gateway_enabled(value):
    if type(value) is not bool:
        return False
    with storage_lock(f'app-settings:{_SETTINGS_FILE}'):
        data = _load_with_lock_held()
        data['ssh_gateway_enabled'] = value
        if not _valid_settings(data):
            return False
        _save(data)
    return value


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

# Feature policies intentionally require a persisted administrator opt-in.
def is_credentials_enabled():
    return _load().get('credentials_enabled') is True


def is_automation_enabled():
    if 'AUTOMATION_ENABLED' in config.EXPLICIT_ENVIRONMENT_KEYS:
        return bool(config.AUTOMATION_ENABLED)
    return _load().get('automation_enabled') is True


def _set_feature(name, value):
    if type(value) is not bool:
        return False
    with storage_lock(f'app-settings:{_SETTINGS_FILE}'):
        data = _load_with_lock_held()
        if data.get(name) is value:
            return value
        data[name] = value
        # Changing away and back must revoke old background grants too.
        data[name + '_revision'] = secrets.token_hex(32)
        if name == 'automation_enabled':
            # The new revision already reflects this change; a restart must
            # not rotate it a second time and revoke grants approved since.
            data['automation_effective_observed'] = _effective_automation_enabled(data)
        _save(data)
    return value


def set_credentials_enabled(value):
    return _set_feature('credentials_enabled', value)


def set_automation_enabled(value):
    return _set_feature('automation_enabled', value)


def credentials_policy_revision():
    return _load().get('credentials_enabled_revision', '')

def get_automation_policy_revision():
    return _load().get('automation_enabled_revision', '')


def _effective_automation_enabled(data):
    if 'AUTOMATION_ENABLED' in config.EXPLICIT_ENVIRONMENT_KEYS:
        return bool(config.AUTOMATION_ENABLED)
    return data.get('automation_enabled') is True


def migrate_feature_policies(*, credentials_enabled=False, automation_enabled=False):
    """Startup migration; a saved administrator choice wins.

    AUTOMATION_ENABLED can change between restarts without passing through the
    Admin toggle. Any change of the effective value observed at startup rotates
    the policy revision, so schedules approved before an environment disable
    cannot resume after a later re-enable.
    """
    with storage_lock(f'app-settings:{_SETTINGS_FILE}'):
        data = _load_with_lock_held()
        changed = False
        for name, value in (
            ('credentials_enabled', credentials_enabled),
            ('automation_enabled', automation_enabled),
        ):
            if name not in data:
                data[name] = value is True
                data[name + '_revision'] = secrets.token_hex(32)
                changed = True
        effective = _effective_automation_enabled(data)
        observed = data.get('automation_effective_observed')
        if observed is not effective:
            if type(observed) is bool:
                data['automation_enabled_revision'] = secrets.token_hex(32)
            data['automation_effective_observed'] = effective
            changed = True
        if changed:
            _save(data)


RUNTIME_FEATURES = {
    'sftp_chmod_enabled': 'SFTP_CHMOD_ENABLED',
    'server_operations_enabled': 'SERVER_OPERATIONS_ENABLED',
    'tmux_enabled': 'TMUX_ENABLED',
    'tmux_default': 'TMUX_DEFAULT',
}


def runtime_feature_status(name):
    key = RUNTIME_FEATURES[name]
    data = _load()
    locked = key in config.EXPLICIT_ENVIRONMENT_KEYS
    saved = data.get(name)
    return {
        'enabled': bool(getattr(config, key)) if locked or type(saved) is not bool else saved,
        'source': 'compose' if locked else ('admin' if type(saved) is bool else 'default'),
        'locked': locked, 'environment_key': key,
        'saved_value': saved if type(saved) is bool else None,
        'migrated': name in data.get('runtime_feature_migration', []),
    }


def runtime_feature_enabled(name):
    return runtime_feature_status(name)['enabled']


def set_runtime_feature(name, enabled):
    if type(enabled) is not bool:
        raise ValueError('Expected a boolean')
    status = runtime_feature_status(name)
    if status['locked']:
        raise ValueError(status['environment_key'])
    with storage_lock(f'app-settings:{_SETTINGS_FILE}'):
        data = _load_with_lock_held()
        data[name] = enabled
        data['runtime_feature_migration'] = [key for key in data.get('runtime_feature_migration', []) if key != name]
        _save(data)


def migrate_runtime_features():
    """Preserve the pre-upgrade effective values, including old Compose files.

    An explicit environment value without a saved Admin value is recorded
    once, so removing the Compose line later keeps the same behavior.
    """
    with storage_lock(f'app-settings:{_SETTINGS_FILE}'):
        data = _load_with_lock_held()
        migrated = list(data.get('runtime_feature_migration', []))
        changed = False
        for name, key in RUNTIME_FEATURES.items():
            if name not in data and key in config.EXPLICIT_ENVIRONMENT_KEYS:
                data[name] = bool(getattr(config, key))
                migrated.append(name)
                changed = True
        if changed:
            data['runtime_feature_migration'] = migrated
            _save(data)


def native_setting_sources():
    """Lock state of Admin switches that have an environment counterpart."""
    automation_locked = 'AUTOMATION_ENABLED' in config.EXPLICIT_ENVIRONMENT_KEYS
    production = config.DEPLOYMENT_PROFILE == 'production'
    return {
        'automation_enabled': {
            'locked': automation_locked,
            'environment_key': 'AUTOMATION_ENABLED',
            'source': 'compose' if automation_locked else 'admin',
        },
        # REGISTRATION_ENABLED is only the initial value (see
        # is_registration_enabled); only the production profile locks it.
        'registration_enabled': {
            'locked': production,
            'environment_key': 'REGISTRATION_ENABLED',
            'source': 'production' if production else 'admin',
        },
    }
