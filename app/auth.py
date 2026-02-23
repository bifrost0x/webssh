from flask import request
from flask_login import LoginManager
from datetime import datetime, timedelta, timezone
from collections import deque
from .models import db, User, SocketSession

login_manager = LoginManager()

class RateLimiter:
    """
    Simple in-memory rate limiter.

    SECURITY NOTE: This rate limiter is per-process only. In multi-worker
    deployments (e.g., Gunicorn with multiple workers), rate limits can be
    bypassed by distributing requests across workers.

    For production deployments, either:
    1. Use a single worker (recommended for this app due to WebSocket state)
    2. Use Redis-based rate limiting (flask-limiter with Redis backend)

    The application is designed for single-worker deployment due to
    WebSocket session state management requirements.
    """
    MAX_KEYS = 10000

    def __init__(self):
        self.events = {}

    def allow(self, key, limit, window_seconds):
        now = datetime.now(timezone.utc).timestamp()
        window_start = now - window_seconds
        queue = self.events.get(key)
        if queue is None:
            queue = deque()
            self.events[key] = queue

        while queue and queue[0] < window_start:
            queue.popleft()

        if len(queue) >= limit:
            return False

        queue.append(now)

        if len(self.events) > 50:
            stale = [k for k, q in self.events.items() if not q]
            for k in stale:
                del self.events[k]

        if len(self.events) > self.MAX_KEYS:
            cutoff = now - 3600
            expired = [k for k, q in self.events.items()
                       if not q or q[-1] < cutoff]
            for k in expired:
                del self.events[k]

        return True

_rate_limiter = RateLimiter()

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
    return not _rate_limiter.allow(key, limit, window)

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login."""
    return User.query.get(int(user_id))

def init_auth(app):
    """Initialize authentication system."""
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message = 'Please log in to access this page.'

def register_user(username, password):
    """
    Register a new user.
    Returns:
        tuple: (User object, error message) - one will be None
    """
    if not username or len(username) < 3 or len(username) > 32:
        return None, "Username must be between 3 and 32 characters"

    if not username.replace('_', '').isalnum():
        return None, "Username can only contain letters, numbers, and underscores"

    if User.query.filter_by(username=username).first():
        return None, "Username already exists"

    if not password or len(password) < 8:
        return None, "Password must be at least 8 characters"

    if len(password) > 72:
        return None, "Password must not exceed 72 characters"

    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    user.get_data_dir()
    return user, None

def authenticate_user(username, password):
    """
    Authenticate user credentials.

    Returns:
        tuple: (User object, error message) - one will be None
    """
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        user.last_login = datetime.now(timezone.utc)
        db.session.commit()
        return user, None
    return None, "Invalid username or password"

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
        return socket_session.user
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
