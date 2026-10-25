from copy import deepcopy

from .storage_errors import StorageCorruptionError
from .storage_utils import atomic_write_json, load_json_migrated, storage_lock
from .storage_migrations import CURRENT_STORAGE_VERSIONS
from .terminal_appearance import valid_terminal_appearance
from .data_access import user_operation

AUTHENTICATION_SESSION_DURATION_MINUTES = frozenset({30, 60, 120, 240, 480})
DEFAULT_AUTHENTICATION_SESSION_DURATION_MINUTES = 30

DEFAULT_SETTINGS = {
    'theme': 'glass',
    'terminal_appearance': {},
    'notepad': '',
    'confirm_session_close': False,
    'sync_terminal_directory': True,
    'disconnect_session_action': 'retry',
    'authentication_session_duration_minutes': (
        DEFAULT_AUTHENTICATION_SESSION_DURATION_MINUTES
    ),
}


def _defaults_for_user(user):
    settings = deepcopy(DEFAULT_SETTINGS)
    if int(user.settings_default_generation or 0) < 1:
        settings['confirm_session_close'] = True
    return settings


def _valid_settings(value):
    if not isinstance(value, dict):
        return False
    if value.get('schema_version') != CURRENT_STORAGE_VERSIONS['settings']:
        return False
    if 'theme' in value and not isinstance(value['theme'], str):
        return False
    if 'notepad' in value and not isinstance(value['notepad'], str):
        return False
    if ('sync_terminal_directory' in value
            and not isinstance(value['sync_terminal_directory'], bool)):
        return False
    if (
        'terminal_appearance' in value
        and not valid_terminal_appearance(value['terminal_appearance'])
    ):
        return False
    if (
        'confirm_session_close' in value
        and not isinstance(value['confirm_session_close'], bool)
    ):
        return False
    if (
        'disconnect_session_action' in value
        and (
            not isinstance(value['disconnect_session_action'], str)
            or value['disconnect_session_action'] not in {'retry', 'close'}
        )
    ):
        return False
    if (
        'authentication_session_duration_minutes' in value
        and (
            type(value['authentication_session_duration_minutes']) is not int
            or value['authentication_session_duration_minutes']
            not in AUTHENTICATION_SESSION_DURATION_MINUTES
        )
    ):
        return False
    return True


def _valid_settings_update(value):
    return (
        isinstance(value, dict)
        and (
            'terminal_appearance' not in value
            or valid_terminal_appearance(value['terminal_appearance'])
        )
        and (
            'theme' not in value
            or isinstance(value['theme'], str)
        )
        and (
            'notepad' not in value
            or isinstance(value['notepad'], str)
        )
        and (
            'sync_terminal_directory' not in value
            or isinstance(value['sync_terminal_directory'], bool)
        )
        and (
            'confirm_session_close' not in value
            or isinstance(value['confirm_session_close'], bool)
        )
        and (
            'disconnect_session_action' not in value
            or (
                isinstance(value['disconnect_session_action'], str)
                and value['disconnect_session_action'] in {'retry', 'close'}
            )
        )
        and (
            'authentication_session_duration_minutes' not in value
            or (
                type(value['authentication_session_duration_minutes']) is int
                and value['authentication_session_duration_minutes']
                in AUTHENTICATION_SESSION_DURATION_MINUTES
            )
        )
    )


def _get_user_settings_with_lock_held(user_id):
    from .models import User, db
    user = db.session.get(User, user_id)
    if not user:
        return deepcopy(DEFAULT_SETTINGS)

    settings_file = user.get_data_dir() / 'settings.json'
    data = load_json_migrated(
        settings_file,
        'settings',
        dict,
        _valid_settings,
    )
    settings = _defaults_for_user(user)
    settings.update(data)
    settings.pop('schema_version', None)
    return settings


@user_operation
def get_user_settings(user_id):
    """Load user settings from disk with defaults."""
    with storage_lock(f'settings:{user_id}'):
        return _get_user_settings_with_lock_held(user_id)

@user_operation
def save_user_settings(user_id, settings):
    """Persist user settings to disk."""
    from .models import User, db
    user = db.session.get(User, user_id)
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
