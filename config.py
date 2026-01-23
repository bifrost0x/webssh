import os
import secrets
from pathlib import Path
from datetime import timedelta

BASE_DIR = Path(__file__).parent

DATA_DIR = Path(os.environ.get('DATA_DIR', BASE_DIR / 'data'))
KEYS_DIR = DATA_DIR / 'keys'
PROFILES_FILE = DATA_DIR / 'profiles.json'
KEYS_FILE = KEYS_DIR / 'keys.json'
SYSTEM_COMMANDS_FILE = BASE_DIR / 'app' / 'resources' / 'commands' / 'system_commands.json'
KNOWN_HOSTS_FILE = DATA_DIR / 'known_hosts'

SESSION_TIMEOUT = 300
MAX_SESSIONS = 10
SSH_CONNECT_TIMEOUT = 10

CHUNK_SIZE = 65536
MAX_UPLOAD_SIZE = 1024 * 1024 * 100

# SECURITY FIX: Default to False (was True) - require explicit opt-in for debug mode
DEBUG = os.environ.get('DEBUG', 'False') == 'True'

# SECURITY: SECRET_KEY handling
_secret_key = os.environ.get('SECRET_KEY')
if not _secret_key:
    if DEBUG:
        # Allow auto-generated key in development only
        _secret_key = secrets.token_hex(32)
        print("⚠️  DEBUG MODE: Using auto-generated SECRET_KEY (not for production!)")
    else:
        # FAIL in production if SECRET_KEY not set
        raise RuntimeError(
            "SECURITY ERROR: SECRET_KEY environment variable is required in production. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )

SECRET_KEY = _secret_key

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_SECURE = not DEBUG
PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

MIN_PASSWORD_LENGTH = 8
MAX_USERNAME_LENGTH = 32

SOCKETIO_ASYNC_MODE = 'eventlet'
SOCKETIO_PING_TIMEOUT = 60
SOCKETIO_PING_INTERVAL = 25

# SECURITY: CORS configuration
# ALLOW_CORS_WILDCARD=true explicitly permits wildcard (*) in production (e.g., homelab use)
_allow_cors_wildcard = os.environ.get('ALLOW_CORS_WILDCARD', 'false').lower() == 'true'
_cors_origins = os.environ.get('CORS_ORIGINS', '')
if _cors_origins == '*':
    if DEBUG or _allow_cors_wildcard:
        # Allow wildcard in debug mode or when explicitly permitted
        if _allow_cors_wildcard and not DEBUG:
            print("⚠️  CORS wildcard (*) enabled via ALLOW_CORS_WILDCARD - use only in trusted networks!")
        elif DEBUG:
            print("⚠️  DEBUG MODE: CORS set to wildcard (*) - not for production!")
        CORS_ORIGINS = '*'
    else:
        # FAIL in production if CORS is wildcard without explicit opt-in
        raise RuntimeError(
            "SECURITY ERROR: CORS_ORIGINS cannot be wildcard (*) in production. "
            "Set it to your specific domain(s), e.g., CORS_ORIGINS=https://ssh.example.com "
            "Or set ALLOW_CORS_WILDCARD=true if you understand the risks (e.g., homelab use)."
        )
elif _cors_origins:
    CORS_ORIGINS = [origin.strip() for origin in _cors_origins.split(',')]
else:
    # Safe default - only localhost (for local development)
    CORS_ORIGINS = ['http://localhost:5000', 'http://127.0.0.1:5000']
    if not DEBUG:
        print("ℹ️  CORS_ORIGINS not set, using localhost only. Set CORS_ORIGINS for other origins.")

RATELIMIT_ENABLED = os.environ.get('RATELIMIT_ENABLED', 'True') == 'True'
RATELIMIT_STORAGE_URL = os.environ.get('RATELIMIT_STORAGE_URL', 'memory://')
RATELIMIT_LOGIN_LIMIT = os.environ.get('RATELIMIT_LOGIN_LIMIT', '5 per minute')
RATELIMIT_DEFAULT = os.environ.get('RATELIMIT_DEFAULT', '200 per hour')
