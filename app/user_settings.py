from .storage_errors import StorageCorruptionError
from .storage_utils import atomic_write_json, load_json_migrated, storage_lock
from .storage_migrations import CURRENT_STORAGE_VERSIONS

DEFAULT_SETTINGS = {
    'theme': 'glass',
    'notepad': ''
}


def _valid_settings(value):
    if not isinstance(value, dict):
        return False
    if value.get('schema_version') != CURRENT_STORAGE_VERSIONS['settings']:
        return False
    if 'theme' in value and not isinstance(value['theme'], str):
        return False
    if 'notepad' in value and not isinstance(value['notepad'], str):
        return False
    return True


def _valid_settings_update(value):
    return (
        isinstance(value, dict)
        and (
            'theme' not in value
            or isinstance(value['theme'], str)
        )
        and (
            'notepad' not in value
            or isinstance(value['notepad'], str)
        )
    )


def _get_user_settings_with_lock_held(user_id):
    from .models import User
    user = User.query.get(user_id)
    if not user:
        return DEFAULT_SETTINGS.copy()

    settings_file = user.get_data_dir() / 'settings.json'
    data = load_json_migrated(
        settings_file,
        'settings',
        dict,
        _valid_settings,
    )
    settings = DEFAULT_SETTINGS.copy()
    settings.update(data)
    settings.pop('schema_version', None)
    return settings


def get_user_settings(user_id):
    """Load user settings from disk with defaults."""
    with storage_lock(f'settings:{user_id}'):
        return _get_user_settings_with_lock_held(user_id)

def save_user_settings(user_id, settings):
    """Persist user settings to disk."""
    from .models import User
    user = User.query.get(user_id)
    if not user or not _valid_settings_update(settings):
        return False

    settings_file = user.get_data_dir() / 'settings.json'
    settings_file.parent.mkdir(parents=True, exist_ok=True)

    try:
        with storage_lock(f'settings:{user_id}'):
            merged = _get_user_settings_with_lock_held(user_id)
            merged.update(settings or {})
            merged['schema_version'] = CURRENT_STORAGE_VERSIONS['settings']
            if not _valid_settings(merged):
                return False
            atomic_write_json(settings_file, merged)
        return True
    except StorageCorruptionError:
        raise
    except OSError:
        return False
