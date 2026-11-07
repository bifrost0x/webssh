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
        and all(name not in value or type(value[name]) is bool for name in ('credentials_enabled','automation_enabled','sftp_chmod_enabled','server_operations_enabled','tmux_enabled','tmux_default'))
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
    """Effective registration state: saved override if present, else env default."""
    data = _load()
    if config.DEPLOYMENT_PROFILE == 'production':
        return False
    if 'REGISTRATION_ENABLED' in config.EXPLICIT_ENVIRONMENT_KEYS:
        return bool(config.REGISTRATION_ENABLED)
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
        import secrets
        data[name + '_revision'] = secrets.token_hex(32)
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


def migrate_feature_policies(*, credentials_enabled=False, automation_enabled=False):
    """Explicit one-time startup migration; a saved administrator choice wins."""
    with storage_lock(f'app-settings:{_SETTINGS_FILE}'):
        data = _load_with_lock_held()
        for name,value in [('credentials_enabled',credentials_enabled),('automation_enabled',automation_enabled)]:
            if name not in data:
                data[name]=value is True
                import secrets
                data[name+'_revision']=secrets.token_hex(32)
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
    """Preserve the pre-upgrade effective values, including old Compose files."""
    with storage_lock(f'app-settings:{_SETTINGS_FILE}'):
        data = _load_with_lock_held()
        migrated = data.setdefault('runtime_feature_migration', [])
        for name, key in RUNTIME_FEATURES.items():
            if name not in data and key in config.EXPLICIT_ENVIRONMENT_KEYS:
                data[name] = bool(getattr(config, key))
                migrated.append(name)
        _save(data)


def native_setting_sources():
    return {name: {
        'locked': key in config.EXPLICIT_ENVIRONMENT_KEYS or (name == 'registration_enabled' and config.DEPLOYMENT_PROFILE == 'production'),
        'environment_key': key,
        'source': 'compose' if key in config.EXPLICIT_ENVIRONMENT_KEYS else ('production' if name == 'registration_enabled' and config.DEPLOYMENT_PROFILE == 'production' else 'admin'),
    } for name, key in {'automation_enabled':'AUTOMATION_ENABLED', 'registration_enabled':'REGISTRATION_ENABLED'}.items()}
