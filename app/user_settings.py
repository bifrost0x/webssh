import json


DEFAULT_SETTINGS = {
    'theme': 'glass',
    'notepad': ''
}


def get_user_settings(user_id):
    """Load user settings from disk with defaults."""
    from .models import User
    user = User.query.get(user_id)
    if not user:
        return DEFAULT_SETTINGS.copy()

    settings_file = user.get_data_dir() / 'settings.json'
    if not settings_file.exists():
        return DEFAULT_SETTINGS.copy()

    try:
        with open(settings_file, 'r') as f:
            data = json.load(f)
            settings = DEFAULT_SETTINGS.copy()
            settings.update(data)
            return settings
    except Exception:
        return DEFAULT_SETTINGS.copy()


def save_user_settings(user_id, settings):
    """Persist user settings to disk."""
    from .models import User
    user = User.query.get(user_id)
    if not user:
        return False

    settings_file = user.get_data_dir() / 'settings.json'
    settings_file.parent.mkdir(parents=True, exist_ok=True)
    merged = get_user_settings(user_id)
    merged.update(settings or {})

    try:
        with open(settings_file, 'w') as f:
            json.dump(merged, f, indent=2)
        return True
    except Exception:
        return False
