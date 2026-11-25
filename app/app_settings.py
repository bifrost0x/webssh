"""Application-wide runtime settings persisted to a JSON file in DATA_DIR.

Unlike user_settings (per user), these are global settings an admin can toggle
at runtime without restarting (e.g. whether self-registration is open). Each
value falls back to its config/env default when no override has been saved.
"""
import secrets
import threading

import config

from .storage_utils import atomic_write_json, load_json_migrated, storage_lock
from .storage_migrations import CURRENT_STORAGE_VERSIONS

_SETTINGS_FILE = config.DATA_DIR / 'app_settings.json'

_BOOLEAN_SETTINGS = (
    'credentials_enabled',
    'automation_enabled',
    'automation_effective_observed',
    'automation_enabled_from_environment',
    'sftp_chmod_enabled',
    'server_operations_enabled',
    'tmux_enabled',
    'tmux_default',
    'support_links_enabled',
    'tailscale_ssh_restrict_tailnet_routes',
)

# Both username limits count failed password attempts per minute; the prefix
# is the IPv6 network length that shares one source rate limit bucket.
SIGN_IN_PROTECTION_DEFAULTS = {
    'login_username_limit': 10,
    'login_username_global_limit': 100,
    'ratelimit_ipv6_prefix': 128,
}
SIGN_IN_PROTECTION_BOUNDS = {
    'login_username_limit': (1, 1000),
    'login_username_global_limit': (1, 1000),
    'ratelimit_ipv6_prefix': (48, 128),
}

_cache_lock = threading.Lock()
_cached_document = None


def _valid_bounded_int(value, bounds):
    low, high = bounds
    return type(value) is int and low <= value <= high


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
            'herdr_enabled' not in value
            or type(value['herdr_enabled']) is bool
        )
        and (
            'registration_enabled' not in value
            or type(value['registration_enabled']) is bool
        )
        and all(
            name not in value or _valid_bounded_int(value[name], bounds)
            for name, bounds in SIGN_IN_PROTECTION_BOUNDS.items()
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
    global _cached_document
    _SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    data['schema_version'] = CURRENT_STORAGE_VERSIONS['app_settings']
    try:
        atomic_write_json(_SETTINGS_FILE, data)
    finally:
        with _cache_lock:
            _cached_document = None


def _file_signature(path):
    try:
        stat = path.stat()
    except FileNotFoundError:
        return None
    return (stat.st_ino, stat.st_mtime_ns, stat.st_size)


def _load_cached():
    """Return the stored settings for hot read paths.

    Login requests, rate limit checks and SSH connects consult these values,
    so the parsed document is reused while the file is unchanged. The stat
    signature catches writes outside this process, such as the admin CLI or
    a restore; writes in this process also drop the cache in ``_save``.
    Callers must treat the returned mapping as read-only.
    """
    global _cached_document
    path = _SETTINGS_FILE
    signature = _file_signature(path)
    cached = _cached_document
    if cached is not None and cached[0] == path and cached[1] == signature:
        return cached[2]
    # A write between the stat and the load pairs an old signature with new
    # data, which only costs one extra reload on the next call.
    data = _load()
    with _cache_lock:
        _cached_document = (path, signature, data)
    return data


def sign_in_protection():
    """Effective username limits (per minute) and IPv6 grouping prefix."""
    data = _load_cached()
    return {
        name: data.get(name, default)
        for name, default in SIGN_IN_PROTECTION_DEFAULTS.items()
    }


def login_username_rate_limits():
    """Return the per-source and global username limits as limit strings."""
    settings = sign_in_protection()
    return (
        f"{settings['login_username_limit']} per minute",
        f"{settings['login_username_global_limit']} per minute",
    )


def ratelimit_ipv6_prefix():
    return sign_in_protection()['ratelimit_ipv6_prefix']


def invalid_sign_in_protection_field(values):
    """Return the first field of ``values`` that is unknown or out of range."""
    for name, value in values.items():
        bounds = SIGN_IN_PROTECTION_BOUNDS.get(name)
        if bounds is None or not _valid_bounded_int(value, bounds):
            return name
    return None


def _global_limit_below_source_limit(data):
    """A ceiling across all sources below the per-source limit is a mistake."""
    defaults = SIGN_IN_PROTECTION_DEFAULTS
    return (
        data.get('login_username_global_limit', defaults['login_username_global_limit'])
        < data.get('login_username_limit', defaults['login_username_limit'])
    )


def is_tailnet_route_restricted():
    """Ordinary SSH to tailnet node addresses stays blocked unless lifted."""
    return _load_cached().get('tailscale_ssh_restrict_tailnet_routes') is not False


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


def is_herdr_enabled():
    """The Herdr integration requires an explicit, persisted admin opt-in."""
    return _load().get('herdr_enabled') is True


def set_herdr_enabled(value):
    if type(value) is not bool:
        return False
    with storage_lock(f'app-settings:{_SETTINGS_FILE}'):
        data = _load_with_lock_held()
        data['herdr_enabled'] = value
        if not _valid_settings(data):
            return False
        _save(data)
    return value


def is_support_links_enabled():
    """Project support links are shown unless an administrator hid them."""
    return _load().get('support_links_enabled') is not False


def set_support_links_enabled(value):
    if type(value) is not bool:
        return False
    with storage_lock(f'app-settings:{_SETTINGS_FILE}'):
        data = _load_with_lock_held()
        data['support_links_enabled'] = value
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


def _apply_feature(data, name, value):
    """Return whether ``data`` changed."""
    if data.get(name) is value:
        return False
    data[name] = value
    # Changing away and back must revoke old background grants too.
    data[name + '_revision'] = secrets.token_hex(32)
    if name == 'automation_enabled':
        # The new revision already reflects this change; a restart must
        # not rotate it a second time and revoke grants approved since.
        data['automation_effective_observed'] = _effective_automation_enabled(data)
        data['automation_enabled_from_environment'] = False
    return True


def _set_feature(name, value):
    if type(value) is not bool:
        return False
    with storage_lock(f'app-settings:{_SETTINGS_FILE}'):
        data = _load_with_lock_held()
        if _apply_feature(data, name, value):
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
                if name == 'automation_enabled' and 'AUTOMATION_ENABLED' in config.EXPLICIT_ENVIRONMENT_KEYS:
                    data['automation_enabled_from_environment'] = True
                changed = True
        # Like the runtime switches: until an administrator decides, the stored
        # automation value follows the last explicit environment value.
        if (data.get('automation_enabled_from_environment') is True
                and 'AUTOMATION_ENABLED' in config.EXPLICIT_ENVIRONMENT_KEYS
                and data.get('automation_enabled') is not bool(config.AUTOMATION_ENABLED)):
            data['automation_enabled'] = bool(config.AUTOMATION_ENABLED)
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
        _apply_runtime_feature(data, name, enabled)
        _save(data)


def _apply_runtime_feature(data, name, enabled):
    data[name] = enabled
    data['runtime_feature_migration'] = [key for key in data.get('runtime_feature_migration', []) if key != name]


# Admin switches that are stored as plain booleans.
_ADMIN_FLAGS = (
    'registration_enabled',
    'ssh_gateway_enabled',
    'herdr_enabled',
    'support_links_enabled',
    'tailscale_ssh_restrict_tailnet_routes',
)


class SettingsUpdateError(ValueError):
    """An admin settings change was rejected; nothing was written."""

    def __init__(self, message, *, setting=None, code='invalid_settings'):
        super().__init__(message)
        self.setting = setting
        self.code = code


def _stored_value(data, name):
    if name in SIGN_IN_PROTECTION_DEFAULTS:
        return data.get(name, SIGN_IN_PROTECTION_DEFAULTS[name])
    if name == 'tailscale_ssh_restrict_tailnet_routes':
        return data.get(name) is not False
    return data.get(name)


def update_admin_settings(changes):
    """Apply type-checked admin changes as one locked load-modify-save.

    Returns ``{name: (previous, current)}`` read under the same lock, so the
    audit record describes exactly this write. Raises SettingsUpdateError for
    a combination that is invalid as a whole; then nothing is written, and an
    I/O error during the single save also leaves the stored file unchanged.
    """
    with storage_lock(f'app-settings:{_SETTINGS_FILE}'):
        data = _load_with_lock_held()
        previous = {name: _stored_value(data, name) for name in changes}
        changed = False
        for name, value in changes.items():
            if name in ('credentials_enabled', 'automation_enabled'):
                changed = _apply_feature(data, name, value) or changed
            elif name in RUNTIME_FEATURES:
                _apply_runtime_feature(data, name, value)
                changed = True
            elif name in _ADMIN_FLAGS or name in SIGN_IN_PROTECTION_BOUNDS:
                data[name] = value
                changed = True
            else:
                raise SettingsUpdateError(
                    f'{name} is not an admin setting', setting=name,
                    code='unknown_setting',
                )
        if not _valid_settings(data):
            raise SettingsUpdateError('Invalid settings')
        # Loading accepts any in-range pair, so only a change to one of the
        # two limits is held to their relation; an older file with a lower
        # ceiling must not block unrelated settings.
        limits_changed = [
            name for name in ('login_username_global_limit', 'login_username_limit')
            if name in changes
        ]
        if limits_changed and _global_limit_below_source_limit(data):
            raise SettingsUpdateError(
                'login_username_global_limit must not be lower than '
                'login_username_limit',
                setting=limits_changed[0],
                code='global_limit_below_source_limit',
            )
        if changed:
            _save(data)
    return {
        name: (previous[name], _stored_value(data, name)) for name in changes
    }


def migrate_runtime_features():
    """Preserve the pre-upgrade effective values, including old Compose files.

    While no administrator has chosen a value, the stored value follows the
    last explicit environment value. Removing the Compose line later keeps
    the behavior the operator set last; it never revives an older value.
    """
    with storage_lock(f'app-settings:{_SETTINGS_FILE}'):
        data = _load_with_lock_held()
        migrated = list(data.get('runtime_feature_migration', []))
        changed = False
        for name, key in RUNTIME_FEATURES.items():
            if key not in config.EXPLICIT_ENVIRONMENT_KEYS:
                continue
            value = bool(getattr(config, key))
            if name not in data:
                data[name] = value
                migrated.append(name)
                changed = True
            elif name in migrated and data[name] is not value:
                data[name] = value
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
