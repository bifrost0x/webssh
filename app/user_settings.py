from copy import deepcopy

from .storage_errors import StorageCorruptionError
from .storage_utils import atomic_write_json, load_json_migrated, storage_lock
from .storage_migrations import CURRENT_STORAGE_VERSIONS
from .terminal_appearance import valid_terminal_appearance
from .data_access import user_operation

AUTHENTICATION_SESSION_DURATION_MINUTES = frozenset({30, 60, 120, 240, 480})
DEFAULT_AUTHENTICATION_SESSION_DURATION_MINUTES = 30

# off: never probe; manual: probe on request; automatic: probe when the
# Overview opens and periodically while it is visible.
OVERVIEW_REACHABILITY_MODES = frozenset({'off', 'manual', 'automatic'})

# Overview panels the account can arrange. Widths are columns of a 12-column
# grid; a height of None follows the content, otherwise it is in 8px rows.
OVERVIEW_PANELS = ('kpis', 'topology', 'hosts', 'attention', 'automation', 'platforms', 'activity', 'continue')
OVERVIEW_PANEL_WIDTHS = range(3, 13)
OVERVIEW_PANEL_HEIGHTS = range(8, 161)
OVERVIEW_DISMISSED_LIMIT = 100
_DISMISSED_KINDS = frozenset({'host-keys', 'jump-missing', 'socks-missing', 'unreachable', 'credentials', 'reboot', 'security-updates', 'run-failed', 'schedule-review'})


def valid_overview_layout(value):
    """An ordered list of panel placements, or None for the default layout."""
    if value is None:
        return True
    if not isinstance(value, list) or len(value) > len(OVERVIEW_PANELS):
        return False
    seen = set()
    for item in value:
        if not isinstance(item, dict) or set(item) - {'id', 'w', 'h', 'hidden'}:
            return False
        panel = item.get('id')
        if not isinstance(panel, str) or panel not in OVERVIEW_PANELS or panel in seen:
            return False
        seen.add(panel)
        if type(item.get('w')) is not int or item['w'] not in OVERVIEW_PANEL_WIDTHS:
            return False
        height = item.get('h')
        if height is not None and (type(height) is not int or height not in OVERVIEW_PANEL_HEIGHTS):
            return False
        if not isinstance(item.get('hidden', False), bool):
            return False
    return True


def valid_overview_dismissed(value):
    """Acknowledged attention items as "kind:fingerprint" strings."""
    if not isinstance(value, list) or len(value) > OVERVIEW_DISMISSED_LIMIT:
        return False
    for item in value:
        if not isinstance(item, str) or len(item) > 160 or ':' not in item:
            return False
        kind, fingerprint = item.split(':', 1)
        if kind not in _DISMISSED_KINDS or not fingerprint or not all(
                char.isalnum() or char in '-_.' for char in fingerprint):
            return False
    return len(set(value)) == len(value)

DEFAULT_SETTINGS = {
    'theme': 'glass',
    'overview_layout': 'dashboard',
    'overview_reachability': 'manual',
    'overview_panels': None,
    'overview_dismissed': [],
    'start_page': 'overview',
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
    from .customer_workflows import valid_presets, valid_recovery_timestamp
    if isinstance(value, dict) and 'recovery_reviewed_at' in value and not (
            value['recovery_reviewed_at'] == '' or valid_recovery_timestamp(value['recovery_reviewed_at'])):
        return False
    if isinstance(value, dict) and "workspace_presets" in value and not valid_presets(value["workspace_presets"]):
        return False
    if not isinstance(value, dict):
        return False
    if value.get('schema_version') != CURRENT_STORAGE_VERSIONS['settings']:
        return False
    if ('overview_layout' in value and (not isinstance(value['overview_layout'], str)
            or value['overview_layout'] not in {'dashboard', 'classic'})):
        return False
    if ('start_page' in value and (not isinstance(value['start_page'], str)
            or value['start_page'] not in {'overview', 'workspaces'})):
        return False
    if ('overview_reachability' in value and (not isinstance(value['overview_reachability'], str)
            or value['overview_reachability'] not in OVERVIEW_REACHABILITY_MODES)):
        return False
    # Stored overview values are only type-checked: entries a newer version wrote
    # (another panel, another attention kind) are dropped on read instead of
    # making the whole settings file unreadable after a rollback.
    if 'overview_panels' in value and not (value['overview_panels'] is None or isinstance(value['overview_panels'], list)):
        return False
    if 'overview_dismissed' in value and not isinstance(value['overview_dismissed'], list):
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
    from .customer_workflows import valid_presets, valid_recovery_timestamp
    if isinstance(value, dict) and 'recovery_reviewed_at' in value and not (
            value['recovery_reviewed_at'] == '' or valid_recovery_timestamp(value['recovery_reviewed_at'])):
        return False
    if isinstance(value, dict) and "workspace_presets" in value and not valid_presets(value["workspace_presets"]):
        return False
    return (
        isinstance(value, dict)
        and ('start_page' not in value or (isinstance(value['start_page'], str)
             and value['start_page'] in {'overview', 'workspaces'}))
        and ('overview_layout' not in value or (isinstance(value['overview_layout'], str)
             and value['overview_layout'] in {'dashboard', 'classic'}))
        and ('overview_reachability' not in value or (isinstance(value['overview_reachability'], str)
             and value['overview_reachability'] in OVERVIEW_REACHABILITY_MODES))
        and ('overview_panels' not in value or valid_overview_layout(value['overview_panels']))
        and ('overview_dismissed' not in value or valid_overview_dismissed(value['overview_dismissed']))
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
    settings['overview_panels'] = _known_overview_panels(settings.get('overview_panels'))
    settings['overview_dismissed'] = _known_overview_dismissed(settings.get('overview_dismissed'))
    return settings


def _known_overview_panels(value):
    if not isinstance(value, list):
        return None
    kept, seen = [], set()
    for item in value:
        if valid_overview_layout([item]) and item['id'] not in seen:
            seen.add(item['id'])
            kept.append(item)
    return kept or None


def _known_overview_dismissed(value):
    if not isinstance(value, list):
        return []
    kept = []
    for item in value:
        if item not in kept and valid_overview_dismissed([item]):
            kept.append(item)
    return kept[-OVERVIEW_DISMISSED_LIMIT:]


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
