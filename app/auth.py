import bcrypt
import config
from threading import Lock
from flask import request
from flask_login import LoginManager
from datetime import datetime, timedelta, timezone
from .models import db, User, SocketSession
from .rate_limiter import create_rate_limiter

login_manager = LoginManager()

# Precomputed bcrypt hash of a random value. Used to run a real verification
# even when the supplied username does not exist, so login response timing does
# not reveal whether an account exists (user enumeration mitigation).
_DUMMY_PASSWORD_HASH = bcrypt.hashpw(b'account-enumeration-mitigation', bcrypt.gensalt())

# Rate limiter instance — initialized in init_auth().
# Falls back to in-memory automatically if Redis is unavailable.
_rate_limiter = None
_registration_lock = Lock()


def _get_rate_limiter():
    """Return the module-level rate limiter, lazily creating a default if init_auth() hasn't run yet."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = create_rate_limiter('memory://')
    return _rate_limiter


def password_exceeds_bcrypt_limit(password):
    """Return whether a password exceeds bcrypt's UTF-8 byte limit."""
    try:
        return len((password or '').encode('utf-8')) > config.MAX_PASSWORD_LENGTH
    except UnicodeEncodeError:
        return True

def parse_rate_limit(limit_str, default_limit=5, default_window=60):
    """Parse rate limit strings like '5 per minute'."""
    if not limit_str or not isinstance(limit_str, str):
        return default_limit, default_window

    try:
        parts = limit_str.strip().lower().split()
        limit = int(parts[0])
        unit = parts[-1].rstrip('s')
        if unit == 'second':
            window = 1
        elif unit == 'minute':
            window = 60
        elif unit == 'hour':
            window = 3600
        else:
            return default_limit, default_window
        return limit, window
    except (ValueError, IndexError):
        return default_limit, default_window

def check_rate_limit(ip_address, endpoint, limit_str):
    """Return True if request should be blocked."""
    limit, window = parse_rate_limit(limit_str)
    key = f'{endpoint}:{ip_address}'
    return not _get_rate_limiter().allow(key, limit, window)

def check_socket_rate_limit(user_id, endpoint, limit_str):
    """Return True if a per-user socket action should be blocked.

    Keyed by user_id (not IP), so it throttles the authenticated user behind
    an event regardless of source address. Every call counts toward the limit,
    so both successful and failed attempts are rate-limited.
    """
    limit, window = parse_rate_limit(limit_str)
    key = f'{endpoint}:{user_id}'
    return not _get_rate_limiter().allow(key, limit, window)


def check_reauth_rate_limit(user_id, ip_address, endpoint, limit_str):
    """Return True when either the user or source IP exceeds reauth limits."""
    limit, window = parse_rate_limit(limit_str)
    limiter = _get_rate_limiter()
    user_allowed = limiter.allow(
        f'{endpoint}:user:{int(user_id)}',
        limit,
        window,
    )
    ip_allowed = limiter.allow(
        f'{endpoint}:ip:{ip_address or "unknown"}',
        limit,
        window,
    )
    return not (user_allowed and ip_allowed)


@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login."""
    user = db.session.get(User, int(user_id))
    if user is None or user.is_locked:
        return None
    return user

def init_auth(app):
    """Initialize authentication system and rate limiter."""
    global _rate_limiter
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message = 'Please log in to access this page.'

    # Create the rate limiter based on the configured storage URL.
    # Falls back to in-memory automatically if Redis is unavailable.
    _rate_limiter = create_rate_limiter(
        getattr(config, 'RATELIMIT_STORAGE_URL', 'memory://')
    )

def validate_new_user(username, password):
    """Return a validation error for new credentials, or None."""
    if not username or len(username) < 3 or len(username) > 32:
        return "Username must be between 3 and 32 characters"

    if not username.replace('_', '').isalnum():
        return "Username can only contain letters, numbers, and underscores"

    if User.query.filter_by(username=username).first():
        return "Username already exists"

    if not password or len(password) < 8:
        return "Password must be at least 8 characters"

    if password_exceeds_bcrypt_limit(password):
        return (
            f"Password must not exceed {config.MAX_PASSWORD_LENGTH} bytes "
            "when encoded as UTF-8"
        )

    return None


def register_user(username, password):
    """
    Register a user, granting administrator rights only to the first account.
    Returns:
        tuple: (User object, error message) - one will be None
    """
    with _registration_lock:
        error = validate_new_user(username, password)
        if error:
            return None, error

        is_first_user = User.query.order_by(User.id).first() is None
        user = User(username=username, is_admin=is_first_user)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
    user.get_data_dir()
    if is_first_user:
        from .audit_logger import log_security_event
        log_security_event(
            'INITIAL_ADMIN_REGISTERED',
            user=user.username,
        )
    return user, None


def ensure_initial_admin():
    """Return an existing admin or promote the oldest user if none exists."""
    with _registration_lock:
        existing_admin = User.query.filter_by(
            is_admin=True
        ).order_by(User.id).first()
        if existing_admin is not None:
            return existing_admin

        oldest_user = User.query.order_by(User.id).first()
        if oldest_user is None:
            return None

        oldest_user.is_admin = True
        db.session.commit()

    from .audit_logger import log_security_event
    log_security_event(
        'INITIAL_ADMIN_REPAIRED',
        user=oldest_user.username,
    )
    return oldest_user

def authenticate_user(username, password):
    """
    Authenticate user credentials.

    Returns:
        tuple: (User object, error message) - one will be None
    """
    password = password or ''
    if password_exceeds_bcrypt_limit(password):
        return None, "Invalid username or password"
    user = User.query.filter_by(username=username).first()
    if user is None:
        # Verify against a dummy hash so a missing account takes the same time
        # as a wrong password, preventing username enumeration by timing.
        bcrypt.checkpw(password.encode('utf-8'), _DUMMY_PASSWORD_HASH)
        return None, "Invalid username or password"
    if user.check_password(password):
        if getattr(user, 'is_locked', False):
            return None, "This account is locked. Please contact an administrator."
        user.last_login = datetime.now(timezone.utc)
        db.session.commit()
        return user, None
    return None, "Invalid username or password"


def sync_admin_users():
    """Grant admin to every username listed in config.ADMIN_USERS (idempotent).

    Runs on startup so an operator can promote existing accounts on a production
    database without manual SQL. Must run inside an app context.
    """
    import config
    from .audit_logger import log_info
    changed = False
    for name in getattr(config, 'ADMIN_USERS', []):
        u = User.query.filter_by(username=name).first()
        if u and not u.is_admin:
            u.is_admin = True
            changed = True
            log_info("Admin granted via ADMIN_USERS", user=name)
    if changed:
        db.session.commit()

def register_socket_session(user_id, socket_sid, user_agent=None):
    """
    Register a SocketIO session for a user.

    Args:
        user_id: User ID
        socket_sid: SocketIO session ID
        user_agent: Browser user agent string

    Returns:
        SocketSession object
    """
    SocketSession.query.filter_by(socket_sid=socket_sid).delete()

    socket_session = SocketSession(
        user_id=user_id,
        socket_sid=socket_sid,
        user_agent=user_agent
    )
    db.session.add(socket_session)
    db.session.commit()
    return socket_session

def get_user_from_socket(socket_sid):
    """
    Get user associated with a SocketIO session.

    Args:
        socket_sid: SocketIO session ID

    Returns:
        User object or None
    """
    socket_session = SocketSession.query.filter_by(socket_sid=socket_sid).first()
    if socket_session:
        user = socket_session.user
        if user is None or user.is_locked:
            return None
        import time as _time
        now = datetime.now(timezone.utc)
        last = socket_session.last_activity
        needs_update = not last
        if not needs_update and last:
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            needs_update = (now - last).total_seconds() > 30
        if needs_update:
            socket_session.last_activity = now
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()
        return user
    return None

def cleanup_inactive_socket_sessions(timeout_minutes=30):
    """
    Remove inactive socket sessions based on timeout.

    Args:
        timeout_minutes: Number of minutes of inactivity before cleanup
    """
    timeout = datetime.now(timezone.utc) - timedelta(minutes=timeout_minutes)
    deleted = SocketSession.query.filter(SocketSession.last_activity < timeout).delete()
    db.session.commit()
    return deleted
