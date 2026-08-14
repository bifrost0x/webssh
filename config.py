import os
import secrets
import ipaddress
import re
import tempfile
from pathlib import Path, PurePosixPath
from datetime import timedelta
from urllib.parse import urlsplit

from dotenv import load_dotenv

BASE_DIR = Path(__file__).parent

# Load variables from a .env file in the project root, if present.
# override=False ensures real environment variables (Docker, systemd, shell)
# always take precedence over .env, so existing deployments are unaffected.
load_dotenv(BASE_DIR / '.env')

DEPLOYMENT_PROFILE = os.environ.get(
    'DEPLOYMENT_PROFILE',
    'homelab',
).strip().lower()
if DEPLOYMENT_PROFILE not in {'homelab', 'production'}:
    raise RuntimeError(
        'CONFIGURATION ERROR: DEPLOYMENT_PROFILE must be either '
        '"homelab" or "production"'
    )

DATA_DIR = Path(os.environ.get('DATA_DIR', BASE_DIR / 'data'))
USERS_DIR = DATA_DIR / 'users'
KEYS_DIR = DATA_DIR / 'keys'
PROFILES_FILE = DATA_DIR / 'profiles.json'
KEYS_FILE = KEYS_DIR / 'keys.json'
SYSTEM_COMMANDS_FILE = BASE_DIR / 'app' / 'resources' / 'commands' / 'system_commands.json'
KNOWN_HOSTS_FILE = DATA_DIR / 'known_hosts'
TRANSFER_TEMP_DIR = Path(os.environ.get(
    'TRANSFER_TEMP_DIR', DATA_DIR / 'tmp'
))

SESSION_TIMEOUT = int(os.environ.get('SESSION_TIMEOUT', '1800'))

WEBAUTHN_ENABLED = (
    os.environ.get('WEBAUTHN_ENABLED', 'false').lower() == 'true'
)
WEBAUTHN_RP_ID = os.environ.get('WEBAUTHN_RP_ID', 'localhost').strip()
WEBAUTHN_RP_NAME = os.environ.get('WEBAUTHN_RP_NAME', 'WebSSH').strip()
WEBAUTHN_ORIGIN = os.environ.get(
    'WEBAUTHN_ORIGIN',
    'https://localhost',
).strip()

HOST_KEY_MANAGEMENT_ENABLED = (
    os.environ.get('HOST_KEY_MANAGEMENT_ENABLED', 'true').lower() == 'true'
)
RECOVERY_CODES_ENABLED = (
    os.environ.get('RECOVERY_CODES_ENABLED', 'true').lower() == 'true'
)
AUDIT_EXPORT_ENABLED = (
    os.environ.get('AUDIT_EXPORT_ENABLED', 'true').lower() == 'true'
)
OIDC_ENABLED = os.environ.get('OIDC_ENABLED', 'false').lower() == 'true'
OIDC_ISSUER = os.environ.get('OIDC_ISSUER', '').strip().rstrip('/')
OIDC_CLIENT_ID = os.environ.get('OIDC_CLIENT_ID', '').strip()
OIDC_CLIENT_SECRET_FILE = os.environ.get(
    'OIDC_CLIENT_SECRET_FILE',
    '',
).strip()
OIDC_REDIRECT_URI = os.environ.get('OIDC_REDIRECT_URI', '').strip()
OIDC_ALLOWED_SUBJECTS = {
    value.strip()
    for value in os.environ.get('OIDC_ALLOWED_SUBJECTS', '').split(',')
    if value.strip()
}
OIDC_ALLOWED_DOMAINS = {
    value.strip().lower()
    for value in os.environ.get('OIDC_ALLOWED_DOMAINS', '').split(',')
    if value.strip()
}
OIDC_HTTP_TIMEOUT = 5
OIDC_LOGIN_RATE_LIMIT = os.environ.get(
    'OIDC_LOGIN_RATE_LIMIT',
    '10 per minute',
)

# Optional LDAP authentication. Configuration values remain inert until the
# explicit feature flag is enabled; in particular, secret files are never read
# while LDAP is disabled.
LDAP_ENABLED = os.environ.get('LDAP_ENABLED', 'false').lower() == 'true'
LDAP_PROVIDER_ID = os.environ.get('LDAP_PROVIDER_ID', 'default').strip()
LDAP_URL = os.environ.get('LDAP_URL', '').strip()
LDAP_BASE_DN = os.environ.get('LDAP_BASE_DN', '').strip()
LDAP_BIND_DN = os.environ.get('LDAP_BIND_DN', '').strip()
LDAP_BIND_PASSWORD_FILE = os.environ.get(
    'LDAP_BIND_PASSWORD_FILE',
    '/run/webssh-auth/ldap_bind_password',
).strip()
LDAP_CA_FILE = os.environ.get(
    'LDAP_CA_FILE',
    '/run/webssh-auth/ldap_ca.pem',
).strip()
LDAP_USER_FILTER = os.environ.get('LDAP_USER_FILTER', '').strip()
LDAP_UNIQUE_ID_ATTRIBUTE = os.environ.get(
    'LDAP_UNIQUE_ID_ATTRIBUTE',
    '',
).strip()
LDAP_LOGIN_RATE_LIMIT = os.environ.get(
    'LDAP_LOGIN_RATE_LIMIT',
    '5 per minute',
)


def _positive_int_env(name, default):
    raw_value = os.environ.get(name, str(default))
    try:
        value = int(raw_value)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            f'CONFIGURATION ERROR: {name} must be a positive integer'
        ) from exc
    if value <= 0:
        raise RuntimeError(
            f'CONFIGURATION ERROR: {name} must be a positive integer'
        )
    return value


def _bounded_int_env(name, default, minimum, maximum):
    raw_value = os.environ.get(name, str(default))
    try:
        value = int(raw_value)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            f'CONFIGURATION ERROR: {name} must be between {minimum} and '
            f'{maximum}'
        ) from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(
            f'CONFIGURATION ERROR: {name} must be between {minimum} and '
            f'{maximum}'
        )
    return value


def _non_negative_int_env(name, default):
    raw_value = os.environ.get(name, str(default))
    try:
        value = int(raw_value)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            f'CONFIGURATION ERROR: {name} must be a non-negative integer'
        ) from exc
    if value < 0:
        raise RuntimeError(
            f'CONFIGURATION ERROR: {name} must be a non-negative integer'
        )
    return value


LDAP_CONNECT_TIMEOUT = _bounded_int_env(
    'LDAP_CONNECT_TIMEOUT', 5, 1, 15
)
LDAP_OPERATION_TIMEOUT = _bounded_int_env(
    'LDAP_OPERATION_TIMEOUT', 5, 1, 30
)
LDAP_SESSION_REVALIDATION_SECONDS = _bounded_int_env(
    'LDAP_SESSION_REVALIDATION_SECONDS', 300, 60, 3600
)


AUDIT_LOG_MAX_BYTES = _positive_int_env(
    'AUDIT_LOG_MAX_BYTES', 10 * 1024 * 1024
)
AUDIT_LOG_BACKUP_COUNT = _positive_int_env(
    'AUDIT_LOG_BACKUP_COUNT', 5
)
BACKUP_MAX_MEMBERS = _positive_int_env('BACKUP_MAX_MEMBERS', 10000)
BACKUP_MAX_FILE_SIZE = _positive_int_env(
    'BACKUP_MAX_FILE_SIZE', 1024 * 1024 * 1024
)
BACKUP_MAX_TOTAL_SIZE = _positive_int_env(
    'BACKUP_MAX_TOTAL_SIZE', 10 * 1024 * 1024 * 1024
)
BACKUP_MAX_COMPRESSION_RATIO = _positive_int_env(
    'BACKUP_MAX_COMPRESSION_RATIO', 200
)
BACKUP_MAX_MANIFEST_SIZE = _positive_int_env(
    'BACKUP_MAX_MANIFEST_SIZE', 10 * 1024 * 1024
)
BACKUP_UPLOAD_MAX_SIZE = _positive_int_env(
    'BACKUP_UPLOAD_MAX_SIZE', 1024 * 1024 * 1024
)
BACKUP_OPERATION_TIMEOUT = _positive_int_env(
    'BACKUP_OPERATION_TIMEOUT', 1800
)
BACKUP_DOWNLOAD_TTL = _positive_int_env('BACKUP_DOWNLOAD_TTL', 600)
BACKUP_TEMP_DIR = Path(os.environ.get(
    'BACKUP_TEMP_DIR',
    Path(tempfile.gettempdir()) / 'webssh-backup-operations',
))


# Atomic, in-process resource quotas. Per-user defaults remain below their
# corresponding global limit so one account cannot consume all capacity.
QUOTA_SSH_SESSION_GLOBAL = _positive_int_env(
    'QUOTA_SSH_SESSION_GLOBAL', 10
)
QUOTA_SSH_SESSION_PER_USER = _positive_int_env(
    'QUOTA_SSH_SESSION_PER_USER', 5
)
QUOTA_QUICK_CONNECTION_GLOBAL = _positive_int_env(
    'QUOTA_QUICK_CONNECTION_GLOBAL', 12
)
QUOTA_QUICK_CONNECTION_PER_USER = _positive_int_env(
    'QUOTA_QUICK_CONNECTION_PER_USER', 3
)
QUOTA_TRANSFER_GLOBAL = _positive_int_env('QUOTA_TRANSFER_GLOBAL', 8)
QUOTA_TRANSFER_PER_USER = _positive_int_env(
    'QUOTA_TRANSFER_PER_USER', 2
)
QUOTA_TEMP_BYTES_GLOBAL = _positive_int_env(
    'QUOTA_TEMP_BYTES_GLOBAL', 1024 * 1024 * 1024
)
QUOTA_TEMP_BYTES_PER_USER = _positive_int_env(
    'QUOTA_TEMP_BYTES_PER_USER', 512 * 1024 * 1024
)
QUOTA_BACKGROUND_JOB_GLOBAL = _positive_int_env(
    'QUOTA_BACKGROUND_JOB_GLOBAL', 4
)
QUOTA_BACKGROUND_JOB_PER_USER = _positive_int_env(
    'QUOTA_BACKGROUND_JOB_PER_USER', 1
)


def _validate_quota_pair(kind, global_limit, per_user_limit, fair_slots):
    if per_user_limit > global_limit or (
        fair_slots and per_user_limit == global_limit
    ):
        relation = 'below' if fair_slots else 'at most'
        raise RuntimeError(
            f'CONFIGURATION ERROR: QUOTA_{kind}_PER_USER must be '
            f'{relation} QUOTA_{kind}_GLOBAL'
        )


_validate_quota_pair(
    'SSH_SESSION',
    QUOTA_SSH_SESSION_GLOBAL,
    QUOTA_SSH_SESSION_PER_USER,
    True,
)
_validate_quota_pair(
    'QUICK_CONNECTION',
    QUOTA_QUICK_CONNECTION_GLOBAL,
    QUOTA_QUICK_CONNECTION_PER_USER,
    True,
)
_validate_quota_pair(
    'TRANSFER',
    QUOTA_TRANSFER_GLOBAL,
    QUOTA_TRANSFER_PER_USER,
    True,
)
_validate_quota_pair(
    'TEMP_BYTES',
    QUOTA_TEMP_BYTES_GLOBAL,
    QUOTA_TEMP_BYTES_PER_USER,
    False,
)
_validate_quota_pair(
    'BACKGROUND_JOB',
    QUOTA_BACKGROUND_JOB_GLOBAL,
    QUOTA_BACKGROUND_JOB_PER_USER,
    False,
)

# Three permanent cleanup jobs occupy executor slots for the app lifetime.
# Reader and transfer capacity must stay available beyond those loops, otherwise
# an idle cleanup job can starve an accepted SSH session or background transfer.
BACKGROUND_CLEANUP_JOBS = 3 + (1 if LDAP_ENABLED else 0)
BACKGROUND_WORKERS_MAX = 128
BACKGROUND_WORKERS_MIN = (
    BACKGROUND_CLEANUP_JOBS
    + QUOTA_SSH_SESSION_GLOBAL
    + QUOTA_BACKGROUND_JOB_GLOBAL
)
if BACKGROUND_WORKERS_MIN > BACKGROUND_WORKERS_MAX:
    raise RuntimeError(
        'CONFIGURATION ERROR: QUOTA_SSH_SESSION_GLOBAL plus '
        'QUOTA_BACKGROUND_JOB_GLOBAL exceeds the supported background '
        'worker capacity'
    )
BACKGROUND_WORKERS = _positive_int_env(
    'BACKGROUND_WORKERS', BACKGROUND_WORKERS_MIN
)
if not BACKGROUND_WORKERS_MIN <= BACKGROUND_WORKERS <= BACKGROUND_WORKERS_MAX:
    raise RuntimeError(
        'CONFIGURATION ERROR: BACKGROUND_WORKERS must be between '
        f'{BACKGROUND_WORKERS_MIN} and {BACKGROUND_WORKERS_MAX}'
    )
RUNTIME_SHUTDOWN_GRACE_SECONDS_MAX = 30
RUNTIME_SHUTDOWN_GRACE_SECONDS = _positive_int_env(
    'RUNTIME_SHUTDOWN_GRACE_SECONDS', 5
)
if RUNTIME_SHUTDOWN_GRACE_SECONDS > RUNTIME_SHUTDOWN_GRACE_SECONDS_MAX:
    raise RuntimeError(
        'CONFIGURATION ERROR: RUNTIME_SHUTDOWN_GRACE_SECONDS must be between '
        f'1 and {RUNTIME_SHUTDOWN_GRACE_SECONDS_MAX}'
    )

# Backwards-compatible code/config alias for the former global-only limit.
MAX_SESSIONS = QUOTA_SSH_SESSION_GLOBAL
SSH_CONNECT_TIMEOUT = 10
SFTP_OPERATION_TIMEOUT = _positive_int_env('SFTP_OPERATION_TIMEOUT', 30)

CHUNK_SIZE = 65536
MAX_UPLOAD_SIZE = 1024 * 1024 * 100
MAX_EDITOR_FILE_SIZE = _positive_int_env(
    'MAX_EDITOR_FILE_SIZE', 5 * 1024 * 1024
)
# Socket.IO now carries control events and bounded editor text only; bulk file
# transfers use streaming HTTP routes. JSON can expand control characters to a
# six-byte ``\uXXXX`` escape, so retain that worst-case expansion plus a small
# envelope for the event name and metadata without preserving the obsolete
# 110 MiB socket-upload allowance.
SOCKETIO_MAX_MESSAGE_SIZE = MAX_EDITOR_FILE_SIZE * 6 + 64 * 1024

# Admin panel: comma-separated usernames granted admin on startup.
ADMIN_USERS = [u.strip() for u in os.environ.get('ADMIN_USERS', '').split(',') if u.strip()]
ADMIN_PANEL_ENABLED = os.environ.get('ADMIN_PANEL_ENABLED', 'True') == 'True'


def _csv_env(name):
    """Parse a comma-separated environment variable into an immutable set."""
    return frozenset(value.strip() for value in os.environ.get(name, '').split(',') if value.strip())


# Tailscale SSH uses the WebSSH node's shared tailnet identity. Keep it disabled
# unless the operator explicitly enables it and grants access to trusted users.
TAILSCALE_SSH_ENABLED = os.environ.get('TAILSCALE_SSH_ENABLED', 'false').lower() == 'true'
TAILSCALE_SSH_ALLOWED_WEBSSH_USERS = _csv_env('TAILSCALE_SSH_ALLOWED_WEBSSH_USERS')
TAILSCALE_SSH_ALLOWED_TARGETS = frozenset(
    target.lower() for target in _csv_env('TAILSCALE_SSH_ALLOWED_TARGETS')
)
TAILSCALE_SSH_ALLOWED_REMOTE_USERS = _csv_env('TAILSCALE_SSH_ALLOWED_REMOTE_USERS')

DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'

_secret_key = os.environ.get('SECRET_KEY')
_KNOWN_PLACEHOLDERS = {'<YOUR-SECRET-KEY>', 'changeme', 'secret', 'your-secret-key'}
if not _secret_key or _secret_key.strip().lower() in _KNOWN_PLACEHOLDERS:
    if DEBUG:
        _secret_key = secrets.token_hex(32)
        print("⚠️  DEBUG MODE: Using auto-generated SECRET_KEY (not for production!)")
    else:
        raise RuntimeError(
            "SECURITY ERROR: SECRET_KEY environment variable is required in production. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )

SECRET_KEY = _secret_key

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
_session_secure = os.environ.get('SESSION_COOKIE_SECURE', '').lower()
if _session_secure == 'false':
    SESSION_COOKIE_SECURE = False
elif _session_secure == 'true':
    SESSION_COOKIE_SECURE = True
else:
    SESSION_COOKIE_SECURE = not DEBUG
PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

REMEMBER_COOKIE_HTTPONLY = True
REMEMBER_COOKIE_SAMESITE = 'Lax'
REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE
REMEMBER_COOKIE_DURATION = timedelta(days=7)

_trusted_proxies_explicit = 'TRUSTED_PROXIES' in os.environ
TRUSTED_PROXIES = _non_negative_int_env('TRUSTED_PROXIES', 0)

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 72  # bcrypt silently truncates beyond 72 bytes
MAX_USERNAME_LENGTH = 32

# Socket.IO runs on native threads in the canary. The Gunicorn process remains
# single-worker because sessions and rate-limit state are process-local.
SOCKETIO_ASYNC_MODE = 'threading'
# Socket.IO event handlers run in the bounded gthread request context. Leaving
# this at python-socketio's default would create one unbounded daemon thread
# for every event received by a client.
SOCKETIO_ASYNC_HANDLERS = False
GUNICORN_THREADS = _bounded_int_env('GUNICORN_THREADS', 64, 8, 256)
MAX_SOCKET_CONNECTIONS = _bounded_int_env(
    'MAX_SOCKET_CONNECTIONS', 48, 1, 252)
MAX_SOCKET_CONNECTIONS_PER_USER = _bounded_int_env(
    'MAX_SOCKET_CONNECTIONS_PER_USER', 8, 1, 64)
if MAX_SOCKET_CONNECTIONS_PER_USER > MAX_SOCKET_CONNECTIONS:
    raise RuntimeError(
        'CONFIGURATION ERROR: MAX_SOCKET_CONNECTIONS_PER_USER cannot exceed '
        'MAX_SOCKET_CONNECTIONS'
    )
if GUNICORN_THREADS - MAX_SOCKET_CONNECTIONS < 4:
    raise RuntimeError(
        'CONFIGURATION ERROR: MAX_SOCKET_CONNECTIONS must leave at least 4 '
        'Gunicorn threads available for HTTP'
    )
SOCKETIO_PING_TIMEOUT = 60
SOCKETIO_PING_INTERVAL = 25

ALLOW_CORS_WILDCARD = (
    os.environ.get('ALLOW_CORS_WILDCARD', 'false').lower() == 'true'
)
_allow_cors_wildcard = ALLOW_CORS_WILDCARD
_cors_origins = os.environ.get('CORS_ORIGINS', '')
if _cors_origins == '*':
    if DEBUG or _allow_cors_wildcard:
        if _allow_cors_wildcard and not DEBUG:
            print("⚠️  CORS wildcard (*) enabled via ALLOW_CORS_WILDCARD - use only in trusted networks!")
        elif DEBUG:
            print("⚠️  DEBUG MODE: CORS set to wildcard (*) - not for production!")
        CORS_ORIGINS = '*'
    else:
        raise RuntimeError(
            "SECURITY ERROR: CORS_ORIGINS cannot be wildcard (*) in production. "
            "Set it to your specific domain(s), e.g., CORS_ORIGINS=https://ssh.example.com "
            "Or set ALLOW_CORS_WILDCARD=true if you understand the risks (e.g., homelab use)."
        )
elif _cors_origins and _cors_origins.strip().strip('<>') not in ('YOUR-DOMAIN', 'YOUR-ORIGIN'):
    CORS_ORIGINS = [origin.strip() for origin in _cors_origins.split(',')]
else:
    CORS_ORIGINS = ['http://localhost:5000', 'http://127.0.0.1:5000']
    if not DEBUG:
        print("ℹ️  CORS_ORIGINS not set, using localhost only. Set CORS_ORIGINS for other origins.")

RATELIMIT_ENABLED = os.environ.get('RATELIMIT_ENABLED', 'True') == 'True'
# Backend for rate-limit counters.
#   memory://  (default) — per-process, no external dependency.
#   redis://host:port/db — survives app restarts while Redis keeps running.
#   rediss://…           — same but over TLS.
# Redis-backed rate limiting does not change the mandatory single-worker
# deployment model. If Redis is unreachable, the app uses a recoverable
# in-memory fallback and retries Redis periodically.
RATELIMIT_STORAGE_URL = os.environ.get('RATELIMIT_STORAGE_URL', 'memory://')
RATELIMIT_LOGIN_LIMIT = os.environ.get('RATELIMIT_LOGIN_LIMIT', '5 per minute')
RATELIMIT_DEFAULT = os.environ.get('RATELIMIT_DEFAULT', '200 per hour')
RATELIMIT_REAUTH = os.environ.get('RATELIMIT_REAUTH', '5 per minute')
RATELIMIT_BACKUP_CREATE = os.environ.get(
    'RATELIMIT_BACKUP_CREATE', '3 per hour'
)
RATELIMIT_BACKUP_UPLOAD = os.environ.get(
    'RATELIMIT_BACKUP_UPLOAD', '5 per hour'
)
RATELIMIT_BACKUP_DOWNLOAD = os.environ.get(
    'RATELIMIT_BACKUP_DOWNLOAD', '10 per hour'
)
RATELIMIT_BACKUP_RESTORE = os.environ.get(
    'RATELIMIT_BACKUP_RESTORE', '3 per hour'
)
# Per-user limit on SSH connection attempts via WebSocket (ssh_connect /
# quick_connect). Prevents an authenticated user from abusing the server as an
# unthrottled SSH brute-force / port-scan proxy against third-party hosts.
# Generous default so normal use and reconnects never hit it.
RATELIMIT_SSH_CONNECT = os.environ.get('SSH_CONNECT_RATELIMIT', '10 per minute')

REGISTRATION_ENABLED = os.environ.get(
    'REGISTRATION_ENABLED',
    'True' if DEBUG else 'False',
).lower() == 'true'
BOOTSTRAP_REGISTRATION_ENABLED = os.environ.get(
    'BOOTSTRAP_REGISTRATION_ENABLED',
    'true' if DEPLOYMENT_PROFILE == 'homelab' else 'false',
).lower() == 'true'

_env_app_root = os.environ.get('APPLICATION_ROOT', '').rstrip('/')
if _env_app_root:
    APPLICATION_ROOT = _env_app_root

# SSRF protection: block SSH connections to loopback/link-local addresses.
# Set to 'true' in multi-tenant deployments to prevent users from probing
# internal services via SSH. Defaults to 'false' for homelab use where
# connecting to internal IPs is the primary use case.
BLOCK_INTERNAL_SSH = os.environ.get('BLOCK_INTERNAL_SSH', 'false').lower() == 'true'
# Exact remote-DNS hostnames that a ProxyJump bastion may resolve when local
# validation cannot produce an allowed address. Wildcards and IPs are rejected
# by app.network_policy. Keep empty unless the bastion-only name is trusted.
PROXY_JUMP_REMOTE_DNS_ALLOWLIST = tuple(
    entry.strip()
    for entry in os.environ.get(
        'PROXY_JUMP_REMOTE_DNS_ALLOWLIST', ''
    ).split(',')
    if entry.strip()
)

MAX_DOWNLOAD_SIZE = int(os.environ.get('MAX_DOWNLOAD_SIZE', str(MAX_UPLOAD_SIZE)))
MAX_ZIP_DOWNLOAD_SIZE = int(os.environ.get('MAX_ZIP_DOWNLOAD_SIZE', str(500 * 1024 * 1024)))
MAX_TRANSFER_MEMBERS = _positive_int_env('MAX_TRANSFER_MEMBERS', 10000)
MAX_PREVIEW_SIZE = _positive_int_env('MAX_PREVIEW_SIZE', 512000)
MAX_PREVIEW_TAIL_LINES = _positive_int_env('MAX_PREVIEW_TAIL_LINES', 10000)
MAX_SUPPORTED_FILE_SIZE = _positive_int_env(
    'MAX_SUPPORTED_FILE_SIZE', 1024 * 1024 * 1024
)
MAX_WEBAUTHN_JSON_SIZE = min(
    _positive_int_env('MAX_WEBAUTHN_JSON_SIZE', 64 * 1024),
    64 * 1024,
)
MAX_RECOVERY_JSON_SIZE = min(
    _positive_int_env('MAX_RECOVERY_JSON_SIZE', 4096),
    4096,
)

# Persistent sessions via tmux on the remote host.
# When enabled, SSH sessions are wrapped in a tmux session on the remote host.
# This means commands keep running even if the webssh server restarts.
# Reconnecting to the same host/user will reattach to the existing tmux session.
TMUX_ENABLED = os.environ.get('TMUX_ENABLED', 'false').lower() == 'true'
TMUX_SESSION_PREFIX = os.environ.get('TMUX_SESSION_PREFIX', 'webssh')
TMUX_DEFAULT = os.environ.get('TMUX_DEFAULT', 'false').lower() == 'true'


def validate_security_config():
    """Validate the selected deployment profile and return compatibility warnings."""
    if LDAP_ENABLED:
        required_ldap_settings = {
            'LDAP_URL': LDAP_URL,
            'LDAP_PROVIDER_ID': LDAP_PROVIDER_ID,
            'LDAP_BASE_DN': LDAP_BASE_DN,
            'LDAP_BIND_DN': LDAP_BIND_DN,
            'LDAP_BIND_PASSWORD_FILE': LDAP_BIND_PASSWORD_FILE,
            'LDAP_CA_FILE': LDAP_CA_FILE,
            'LDAP_USER_FILTER': LDAP_USER_FILTER,
            'LDAP_UNIQUE_ID_ATTRIBUTE': LDAP_UNIQUE_ID_ATTRIBUTE,
        }
        for setting_name, setting_value in required_ldap_settings.items():
            if not setting_value:
                raise RuntimeError(
                    f'SECURITY ERROR: {setting_name} is required when '
                    'LDAP_ENABLED is true'
                )

        parsed_ldap_url = urlsplit(LDAP_URL)
        if (
            parsed_ldap_url.scheme not in {'ldap', 'ldaps'}
            or not parsed_ldap_url.hostname
            or parsed_ldap_url.username is not None
            or parsed_ldap_url.password is not None
            or parsed_ldap_url.path
            or parsed_ldap_url.query
            or parsed_ldap_url.fragment
        ):
            raise RuntimeError(
                'SECURITY ERROR: LDAP_URL must be an exact ldap:// or '
                'ldaps:// server URL without credentials, path, query, or '
                'fragment'
            )
        if LDAP_USER_FILTER.count('{username}') != 1:
            raise RuntimeError(
                'SECURITY ERROR: LDAP_USER_FILTER must contain exactly one '
                '{username} placeholder'
            )
        if (
            len(LDAP_USER_FILTER) > 4096
            or '\x00' in LDAP_USER_FILTER
            or '{' in LDAP_USER_FILTER.replace('{username}', '')
            or '}' in LDAP_USER_FILTER.replace('{username}', '')
        ):
            raise RuntimeError(
                'SECURITY ERROR: LDAP_USER_FILTER contains an unsupported '
                'template or exceeds the size limit'
            )
        if not re.fullmatch(
            r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}',
            LDAP_PROVIDER_ID,
        ):
            raise RuntimeError(
                'SECURITY ERROR: LDAP_PROVIDER_ID must be a short, stable '
                'identifier containing only letters, digits, dot, dash, or '
                'underscore'
            )
        ldap_attribute_pattern = (
            r'(?:[A-Za-z][A-Za-z0-9-]*|[0-9]+(?:\.[0-9]+)+)'
        )
        if not re.fullmatch(ldap_attribute_pattern, LDAP_UNIQUE_ID_ATTRIBUTE):
            raise RuntimeError(
                'SECURITY ERROR: LDAP_UNIQUE_ID_ATTRIBUTE must be an LDAP '
                'attribute name or numeric OID'
            )
        for setting_name, distinguished_name in (
            ('LDAP_BASE_DN', LDAP_BASE_DN),
            ('LDAP_BIND_DN', LDAP_BIND_DN),
        ):
            if len(distinguished_name) > 2048 or '\x00' in distinguished_name:
                raise RuntimeError(
                    f'SECURITY ERROR: {setting_name} is invalid or exceeds '
                    'the size limit'
                )

        def _is_absolute_secret_path(value):
            return Path(value).is_absolute() or PurePosixPath(value).is_absolute()

        if not _is_absolute_secret_path(LDAP_BIND_PASSWORD_FILE):
            raise RuntimeError(
                'SECURITY ERROR: LDAP_BIND_PASSWORD_FILE must be an '
                'absolute path'
            )
        if not _is_absolute_secret_path(LDAP_CA_FILE):
            raise RuntimeError(
                'SECURITY ERROR: LDAP_CA_FILE must be an absolute path'
            )
        if Path(LDAP_BIND_PASSWORD_FILE) == Path(LDAP_CA_FILE):
            raise RuntimeError(
                'SECURITY ERROR: LDAP_BIND_PASSWORD_FILE and LDAP_CA_FILE '
                'must be different files'
            )

    if WEBAUTHN_ENABLED:
        parsed_webauthn_origin = urlsplit(WEBAUTHN_ORIGIN)
        origin_host = (parsed_webauthn_origin.hostname or '').lower()
        origin_is_local_http = (
            parsed_webauthn_origin.scheme == 'http'
            and origin_host == 'localhost'
            and DEPLOYMENT_PROFILE == 'homelab'
        )
        origin_is_valid = (
            bool(origin_host)
            and parsed_webauthn_origin.username is None
            and parsed_webauthn_origin.password is None
            and not parsed_webauthn_origin.path
            and not parsed_webauthn_origin.query
            and not parsed_webauthn_origin.fragment
            and (
                parsed_webauthn_origin.scheme == 'https'
                or origin_is_local_http
            )
        )
        if not origin_is_valid:
            raise RuntimeError(
                'SECURITY ERROR: WEBAUTHN_ORIGIN must be an exact HTTPS '
                'origin (HTTP is allowed only for localhost in homelab)'
            )
        normalized_rp_id = WEBAUTHN_RP_ID.lower().rstrip('.')
        try:
            rp_id_is_ip = bool(ipaddress.ip_address(normalized_rp_id))
        except ValueError:
            rp_id_is_ip = False
        if (
            not normalized_rp_id
            or rp_id_is_ip
            or (
                origin_host != normalized_rp_id
                and not origin_host.endswith('.' + normalized_rp_id)
            )
        ):
            raise RuntimeError(
                'SECURITY ERROR: WEBAUTHN_RP_ID must be the origin domain '
                'or one of its parent domains, not an IP address'
            )
    if OIDC_ENABLED:
        parsed_oidc_issuer = urlsplit(OIDC_ISSUER)
        if (
            parsed_oidc_issuer.scheme != 'https'
            or not parsed_oidc_issuer.hostname
            or parsed_oidc_issuer.username is not None
            or parsed_oidc_issuer.password is not None
            or parsed_oidc_issuer.query
            or parsed_oidc_issuer.fragment
        ):
            raise RuntimeError(
                'SECURITY ERROR: OIDC_ISSUER must be an exact HTTPS issuer URL'
            )
        parsed_oidc_redirect = urlsplit(OIDC_REDIRECT_URI)
        redirect_host = (parsed_oidc_redirect.hostname or '').lower()
        redirect_is_local_http = (
            parsed_oidc_redirect.scheme == 'http'
            and redirect_host in {'localhost', '127.0.0.1', '::1'}
            and DEPLOYMENT_PROFILE == 'homelab'
        )
        application_root = os.environ.get(
            'APPLICATION_ROOT', ''
        ).rstrip('/')
        expected_callback_path = f'{application_root}/oidc/callback'
        redirect_is_valid = (
            bool(redirect_host)
            and parsed_oidc_redirect.username is None
            and parsed_oidc_redirect.password is None
            and parsed_oidc_redirect.path == expected_callback_path
            and not parsed_oidc_redirect.query
            and not parsed_oidc_redirect.fragment
            and (
                parsed_oidc_redirect.scheme == 'https'
                or redirect_is_local_http
            )
        )
        if not redirect_is_valid:
            raise RuntimeError(
                'SECURITY ERROR: OIDC_REDIRECT_URI must be the exact HTTPS '
                'callback URL for /oidc/callback (HTTP is allowed only for '
                'loopback hosts in homelab)'
            )

    if DEPLOYMENT_PROFILE == 'production':
        violations = []
        if DEBUG:
            violations.append('DEBUG must be False')
        production_origins = [
            origin.strip() for origin in _cors_origins.split(',')
        ]
        origins_are_valid = bool(production_origins) and all(
            origin
            and (parsed := urlsplit(origin)).scheme == 'https'
            and bool(parsed.netloc)
            and parsed.username is None
            and parsed.password is None
            and not parsed.path
            and not parsed.query
            and not parsed.fragment
            for origin in production_origins
        )
        if CORS_ORIGINS == '*' or not origins_are_valid:
            violations.append(
                'CORS_ORIGINS must explicitly list trusted HTTPS origins'
            )
        if ALLOW_CORS_WILDCARD:
            violations.append('ALLOW_CORS_WILDCARD must be false')
        if not SESSION_COOKIE_SECURE or not REMEMBER_COOKIE_SECURE:
            violations.append('SESSION_COOKIE_SECURE must be true')
        if REGISTRATION_ENABLED:
            violations.append('REGISTRATION_ENABLED must be False')
        if BOOTSTRAP_REGISTRATION_ENABLED:
            violations.append(
                'BOOTSTRAP_REGISTRATION_ENABLED must be false'
            )
        if not BLOCK_INTERNAL_SSH:
            violations.append('BLOCK_INTERNAL_SSH must be true')
        if not _trusted_proxies_explicit:
            violations.append(
                'TRUSTED_PROXIES must be set explicitly, including 0 when '
                'no proxy headers are trusted'
            )
        if violations:
            raise RuntimeError(
                'SECURITY ERROR: unsafe production profile: '
                + '; '.join(violations)
            )
        return []

    warnings = []
    if CORS_ORIGINS == '*' or ALLOW_CORS_WILDCARD:
        warnings.append(
            'CORS_ORIGINS wildcard compatibility is enabled for the homelab '
            'profile'
        )
    if not SESSION_COOKIE_SECURE:
        warnings.append(
            'SESSION_COOKIE_SECURE is disabled for the homelab profile'
        )
    if REGISTRATION_ENABLED:
        warnings.append(
            'REGISTRATION_ENABLED is enabled for the homelab profile'
        )
    if BOOTSTRAP_REGISTRATION_ENABLED:
        warnings.append(
            'BOOTSTRAP_REGISTRATION_ENABLED permits one browser-created '
            'administrator while no user account exists'
        )
    if not BLOCK_INTERNAL_SSH:
        warnings.append(
            'BLOCK_INTERNAL_SSH is disabled for the homelab profile'
        )
    return warnings


SECURITY_CONFIG_WARNINGS = validate_security_config()
