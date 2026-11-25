import ipaddress
import re

import bcrypt
import config
from contextlib import contextmanager
from threading import Lock
from flask_login import LoginManager
from datetime import datetime, timedelta, timezone
from sqlalchemy import text
from .login_devices import (
    FAILURE_BUDGET,
    FAILURE_WINDOW_SECONDS,
    failure_budget_key,
    username_digest,
)
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
user_creation_lock = Lock()
_NEW_USERNAME_PATTERN = re.compile(r'[A-Za-z0-9_]+')


@contextmanager
def user_creation_transaction():
    """Serialize account-name checks and writes across SQLite connections."""
    with user_creation_lock:
        db.session.rollback()
        db.session.execute(text('BEGIN IMMEDIATE'))
        try:
            yield
        finally:
            if db.session().in_transaction():
                db.session.rollback()


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

def rate_limit_address(address):
    """Return the source bucket used to rate limit ``address``.

    An IPv6 client usually controls at least a whole /64 and can rotate
    through it freely, so IPv6 addresses share one bucket per network of
    the prefix length set in the admin sign-in protection settings (default
    /64). IPv4 and IPv4-mapped IPv6
    addresses keep one bucket per address. Values that are not an IP
    address are returned unchanged.
    """
    value = str(address if address is not None else 'unknown')
    try:
        parsed = ipaddress.ip_address(value.strip())
    except ValueError:
        return value
    if parsed.version == 6:
        if parsed.ipv4_mapped is not None:
            return str(parsed.ipv4_mapped)
        from .app_settings import ratelimit_ipv6_prefix
        prefix = ratelimit_ipv6_prefix()
        host_bits = 128 - prefix
        network = (int(parsed) >> host_bits) << host_bits
        return str(ipaddress.IPv6Network((network, prefix)))
    return str(parsed)


def check_rate_limit(ip_address, endpoint, limit_str):
    """Return True if request should be blocked."""
    limit, window = parse_rate_limit(limit_str)
    key = f'{endpoint}:{rate_limit_address(ip_address)}'
    return not _get_rate_limiter().allow(key, limit, window)


def reserve_login_username_attempt(
    username, source, endpoint, limit_str, global_limit_str,
    *, device_nonce=None,
):
    """Reserve one password attempt for ``username``.

    Returns ``(limited, reservation)``. ``limit_str`` applies per submitted
    name and source bucket, so one source cannot spend another source's
    attempts on the same name. ``global_limit_str`` is a much higher ceiling
    per name across all sources that only slows distributed guessing; it is
    not a lockout, but a sender spread over enough sources can still hold a
    name at it while it keeps sending.

    The attempt is reserved before the password is checked, so concurrent
    guesses cannot overrun the limit, and only failed attempts keep their
    reservation: pass the reservation to
    :func:`release_login_username_attempt` after a successful login.

    ``device_nonce`` comes from a valid known-device cookie for this name
    (see :mod:`app.login_devices`). Such a request skips only the global
    ceiling, while its failures spend the cookie's own small budget; once
    that is used up the cookie is treated like no cookie.

    Buckets are keyed by the normalized name whether or not an account
    exists, so the answer does not reveal which accounts exist. The name is
    replaced by a keyed digest that bounds the key size and keeps it out of
    the limiter store.
    """
    if not str(username or '').strip():
        return False, ()
    digest = username_digest(username)
    limiter = _get_rate_limiter()
    source_key = f'{endpoint}:username:{digest}:{rate_limit_address(source)}'
    global_key = f'{endpoint}:username:{digest}'
    limit, window = parse_rate_limit(limit_str, default_limit=10)
    source_token = limiter.reserve(source_key, limit, window)
    if source_token is None:
        return True, ()
    if device_nonce:
        device_key = failure_budget_key(endpoint, device_nonce)
        device_token = limiter.reserve(
            device_key, FAILURE_BUDGET, FAILURE_WINDOW_SECONDS,
        )
        if device_token is not None:
            return False, (
                (source_key, source_token), (device_key, device_token),
            )
    global_limit, global_window = parse_rate_limit(
        global_limit_str, default_limit=100,
    )
    global_token = limiter.reserve(global_key, global_limit, global_window)
    if global_token is None:
        limiter.release(source_key, source_token)
        return True, ()
    return False, ((source_key, source_token), (global_key, global_token))


def release_login_username_attempt(reservation):
    """Return a reservation after the password was accepted."""
    limiter = _get_rate_limiter()
    for key, token in reservation or ():
        limiter.release(key, token)

def check_socket_rate_limit(user_id, endpoint, limit_str):
    """Return True if a per-user socket action should be blocked.

    Keyed by user_id (not IP), so it throttles the authenticated user behind
    an event regardless of source address. Every call counts toward the limit,
    so both successful and failed attempts are rate-limited.
    """
    limit, window = parse_rate_limit(limit_str)
    key = f'{endpoint}:{user_id}'
    return not _get_rate_limiter().allow(key, limit, window)


def check_user_rate_limit(user_id, endpoint, limit_str, cost=1):
    """Return True when the account exceeded ``limit_str``; ``cost`` units are charged.

    For authenticated features without credentials, where a shared source
    address (NAT, a proxy without TRUSTED_PROXIES) must not let one account
    exhaust the budget of everyone else.
    """
    limit, window = parse_rate_limit(limit_str)
    limiter = _get_rate_limiter()
    return not all(limiter.allow(f'{endpoint}:user:{int(user_id)}', limit, window) for _ in range(max(1, int(cost))))


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
        f'{endpoint}:ip:{rate_limit_address(ip_address or "unknown")}',
        limit,
        window,
    )
    return not (user_allowed and ip_allowed)


@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login."""
    raw_identifier = str(user_id)
    identifier_parts = raw_identifier.split(':', 2)
    raw_user_id = identifier_parts[0]
    raw_generation = (
        identifier_parts[1] if len(identifier_parts) > 1 else '0'
    )
    auth_session_token = (
        identifier_parts[2] if len(identifier_parts) > 2 else None
    )
    try:
        parsed_user_id = int(raw_user_id)
        parsed_generation = int(raw_generation)
    except (TypeError, ValueError):
        return None
    if parsed_user_id <= 0 or parsed_generation < 0:
        return None

    user = db.session.get(User, parsed_user_id)
    if user is None or user.is_locked or (
        user.is_admin and (user.is_ldap_managed or user.is_github_managed)
    ):
        return None
    if int(user.auth_generation or 0) != parsed_generation:
        return None
    if auth_session_token is not None:
        from flask import session
        from .auth_assurance import authentication_session_for_token

        if authentication_session_for_token(
            auth_session_token,
            user.id,
            parsed_generation,
        ) is None:
            return None
        session['_auth_session'] = auth_session_token
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

    # ASCII only: Unicode letters allow look-alike names such as a Cyrillic
    # "admin". Existing accounts keep their names; only new ones are checked.
    if not _NEW_USERNAME_PATTERN.fullmatch(username):
        return "Username can only contain letters, numbers, and underscores"

    normalized_username = username.casefold()
    existing_names = User.query.with_entities(User.username).all()
    if any(row.username.casefold() == normalized_username for row in existing_names):
        return "Username already exists"

    if not password or len(password) < 8:
        return "Password must be at least 8 characters"

    if password_exceeds_bcrypt_limit(password):
        return (
            f"Password must not exceed {config.MAX_PASSWORD_LENGTH} bytes "
            "when encoded as UTF-8"
        )

    return None


def register_user(username, password, *, first_user_only=False):
    """
    Register a user, granting administrator rights only to the first account.

    ``first_user_only`` atomically closes browser bootstrap registration as
    soon as any account exists. Administrative and explicitly enabled normal
    registration keep the default behavior.
    Returns:
        tuple: (User object, error message) - one will be None
    """
    with user_creation_transaction():
        is_first_user = User.query.order_by(User.id).first() is None
        if first_user_only and not is_first_user:
            return None, 'Registration is currently disabled.'

        error = validate_new_user(username, password)
        if error:
            return None, error

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


def is_bootstrap_registration_available():
    """Return whether the one-time browser bootstrap is still unclaimed."""
    if not config.BOOTSTRAP_REGISTRATION_ENABLED:
        return False
    return User.query.with_entities(User.id).order_by(User.id).first() is None


def ensure_initial_admin():
    """Return an existing admin or promote the oldest user if none exists."""
    with user_creation_lock:
        existing_admin = (
            User.query
            .filter_by(is_admin=True)
            .filter(~User.ldap_identity.has())
            .filter(~User.github_identity.has(provisioned_by_github=True))
            .order_by(User.id)
            .first()
        )
        if existing_admin is not None:
            return existing_admin

        oldest_user = (
            User.query
            .filter(~User.ldap_identity.has())
            .filter(~User.github_identity.has(provisioned_by_github=True))
            .order_by(User.id)
            .first()
        )
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
    password_matches = user.check_password(password)
    # A directory-managed identity must never silently fall back to the local
    # password database. Keep this boundary in the shared authenticator so it
    # also protects reauthentication and future password-based entry points.
    if user.ldap_identity is not None or user.is_github_managed:
        return None, "Invalid username or password"
    # A locked account answers like a wrong password. A distinct message after
    # a correct password would let anyone keep guessing it while it is locked.
    if password_matches and not getattr(user, 'is_locked', False):
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
    from .audit_logger import log_warning
    for name in getattr(config, 'ADMIN_USERS', []):
        u = User.query.filter_by(username=name).first()
        if u is None:
            # Whoever registers this name later would become admin on the next start.
            log_warning("ADMIN_USERS lists an account that does not exist; remove it or create the account", user=name)
            continue
        if (
            not u.is_admin
            and not u.is_locked
            and not u.is_ldap_managed
            and not u.is_github_managed
        ):
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
    from flask import has_request_context
    from .auth_assurance import current_authentication_session
    auth = current_authentication_session() if has_request_context() else None
    SocketSession.query.filter_by(socket_sid=socket_sid).delete()

    socket_session = SocketSession(
        user_id=user_id,
        socket_sid=socket_sid,
        user_agent=user_agent,
        authentication_session_id=auth.id if auth and auth.user_id == user_id else None,
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
