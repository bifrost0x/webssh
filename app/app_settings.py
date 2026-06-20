"""Application-wide runtime settings persisted to a JSON file in DATA_DIR.

Unlike user_settings (per user), these are global settings an admin can toggle
at runtime without restarting (e.g. whether self-registration is open). Each
value falls back to its config/env default when no override has been saved.
"""
import json
import os
import config

_SETTINGS_FILE = config.DATA_DIR / 'app_settings.json'


def _load():
    try:
        with open(_SETTINGS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (FileNotFoundError, ValueError, OSError):
        return {}


def _save(data):
    tmp = str(_SETTINGS_FILE) + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f)
    os.replace(tmp, _SETTINGS_FILE)


def is_registration_enabled():
    """Effective registration state: saved override if present, else env default."""
    data = _load()
    if 'registration_enabled' in data:
        return bool(data['registration_enabled'])
    return bool(config.REGISTRATION_ENABLED)


def set_registration_enabled(value):
    data = _load()
    data['registration_enabled'] = bool(value)
    _save(data)
    return bool(value)
