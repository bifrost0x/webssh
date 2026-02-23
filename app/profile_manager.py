import json
import uuid
from datetime import datetime
from pathlib import Path
import config
from .audit_logger import log_info, log_warning, log_error, log_debug

def get_user_profiles_file(user_id):
    """Get the profiles file path for a specific user."""
    from .models import User
    user = User.query.get(user_id)
    if not user:
        return None
    user_dir = user.get_data_dir()
    return user_dir / 'profiles.json'

def load_profiles(user_id):
    """Load all connection profiles for a specific user."""
    try:
        profiles_file = get_user_profiles_file(user_id)
        if not profiles_file or not profiles_file.exists():
            return []

        with open(profiles_file, 'r') as f:
            data = json.load(f)
            return data.get('profiles', [])
    except Exception as e:
        log_error(f"Error loading profiles", user_id=user_id, error=str(e))
        return []

def save_profiles(user_id, profiles):
    """Save profiles list to JSON file for a specific user."""
    try:
        profiles_file = get_user_profiles_file(user_id)
        if not profiles_file:
            return False

        profiles_file.parent.mkdir(parents=True, exist_ok=True)

        with open(profiles_file, 'w') as f:
            json.dump({'profiles': profiles}, f, indent=2)
        return True
    except Exception as e:
        log_error(f"Error saving profiles", user_id=user_id, error=str(e))
        return False

def add_profile(user_id, name, host, port, username, auth_type, key_id=None):
    """Add a new connection profile for a specific user."""
    try:
        if not all([name, host, username, auth_type]):
            return None, "Missing required fields"

        if auth_type not in ['password', 'key']:
            return None, "Invalid auth_type"

        if auth_type == 'key' and not key_id:
            return None, "key_id required for key authentication"

        profile = {
            'id': str(uuid.uuid4()),
            'name': name,
            'host': host,
            'port': int(port) if port else 22,
            'username': username,
            'auth_type': auth_type,
            'key_id': key_id,
            'created_at': datetime.utcnow().isoformat()
        }

        profiles = load_profiles(user_id)
        profiles.append(profile)

        if save_profiles(user_id, profiles):
            return profile, None
        else:
            return None, "Failed to save profile"
    except Exception as e:
        return None, str(e)

def get_profile(user_id, profile_id):
    """Get a specific profile by ID for a specific user."""
    profiles = load_profiles(user_id)
    for profile in profiles:
        if profile['id'] == profile_id:
            return profile
    return None

def delete_profile(user_id, profile_id):
    """Delete a profile by ID for a specific user."""
    try:
        profiles = load_profiles(user_id)
        profiles = [p for p in profiles if p['id'] != profile_id]
        return save_profiles(user_id, profiles)
    except Exception as e:
        log_error(f"Error deleting profile", user_id=user_id, error=str(e))
        return False
