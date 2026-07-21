from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timezone
import bcrypt
from pathlib import Path

db = SQLAlchemy()

class User(db.Model, UserMixin):
    """User model for authentication."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    is_locked = db.Column(db.Boolean, nullable=False, default=False)

    socket_sessions = db.relationship('SocketSession', backref='user', cascade='all, delete-orphan', lazy='dynamic')
    ssh_sessions = db.relationship('SSHSession', backref='user', cascade='all, delete-orphan', lazy='dynamic')

    def set_password(self, password):
        """Hash and set user password using bcrypt."""
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        """Verify password against stored hash."""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    def get_data_dir(self):
        """Get user-specific data directory."""
        import config
        user_dir = config.DATA_DIR / 'users' / f"user_{self.id}"
        user_dir.mkdir(parents=True, exist_ok=True)
        return user_dir

    def __repr__(self):
        return f'<User {self.username}>'


def ensure_user_columns():
    """Additive, idempotent schema migration for the users table.

    db.create_all() only creates missing TABLES, never missing COLUMNS, so new
    columns (is_admin, is_locked) added above would be absent on an existing
    production database. This adds them in place via ALTER TABLE without touching
    existing rows. Must run inside an app context, after db.create_all().
    """
    from sqlalchemy import text, inspect
    inspector = inspect(db.engine)
    if 'users' not in inspector.get_table_names():
        return  # fresh DB: create_all() already made the table with all columns
    existing = {c['name'] for c in inspector.get_columns('users')}
    added_is_admin = 'is_admin' not in existing
    additions = []
    if added_is_admin:
        additions.append("ALTER TABLE users ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT 0")
    if 'is_locked' not in existing:
        additions.append("ALTER TABLE users ADD COLUMN is_locked BOOLEAN NOT NULL DEFAULT 0")
    for stmt in additions:
        db.session.execute(text(stmt))
    # First-time migration of an existing install: there was no role separation
    # before. Grant admin ONLY to the oldest account (lowest id) instead of every
    # user, so upgrading a multi-user install does not silently make everyone an
    # admin. Runs once — on later starts the column already exists, so this block
    # is skipped. (New installs seed their first admin via auth bootstrap.)
    if added_is_admin:
        result = db.session.execute(text(
            "UPDATE users SET is_admin = 1 "
            "WHERE id = (SELECT id FROM users ORDER BY id LIMIT 1)"
        ))
        try:
            from .audit_logger import log_info
            log_info("Schema migration: granted admin to the oldest pre-existing user",
                     count=getattr(result, 'rowcount', None))
        except Exception:
            pass
    if additions:
        db.session.commit()

class SocketSession(db.Model):
    """Tracks SocketIO sessions for users (browser connections)."""
    __tablename__ = 'socket_sessions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    socket_sid = db.Column(db.String(128), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_activity = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    user_agent = db.Column(db.String(256))

    def __repr__(self):
        return f'<SocketSession user_id={self.user_id} sid={self.socket_sid[:8]}...>'

class SSHSession(db.Model):
    """Tracks SSH connections for users (persistent across browser reconnects)."""
    __tablename__ = 'ssh_sessions'

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(36), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    host = db.Column(db.String(256), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(128), nullable=False)
    connected = db.Column(db.Boolean, default=True, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_activity = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    # Persistent tmux session support
    is_persistent = db.Column(db.Boolean, default=False, index=True)
    key_id = db.Column(db.String(64), nullable=True)
    auth_type = db.Column(db.String(16), nullable=False, default='password')
    tmux_session_name = db.Column(db.String(256), nullable=True)
    display_name = db.Column(db.String(128), nullable=True)

    def __repr__(self):
        return f'<SSHSession id={self.session_id[:8]}... {self.username}@{self.host}:{self.port}>'


def ensure_ssh_session_columns():
    """Additive schema migration for persistent SSH session columns."""
    from sqlalchemy import text, inspect
    inspector = inspect(db.engine)
    if 'ssh_sessions' not in inspector.get_table_names():
        return
    existing = {c['name'] for c in inspector.get_columns('ssh_sessions')}
    additions = []
    if 'is_persistent' not in existing:
        additions.append("ALTER TABLE ssh_sessions ADD COLUMN is_persistent BOOLEAN NOT NULL DEFAULT 0")
    if 'key_id' not in existing:
        additions.append("ALTER TABLE ssh_sessions ADD COLUMN key_id VARCHAR(64)")
    added_auth_type = 'auth_type' not in existing
    if added_auth_type:
        additions.append(
            "ALTER TABLE ssh_sessions ADD COLUMN auth_type VARCHAR(16) "
            "NOT NULL DEFAULT 'password'"
        )
    if 'tmux_session_name' not in existing:
        additions.append("ALTER TABLE ssh_sessions ADD COLUMN tmux_session_name VARCHAR(256)")
    if 'display_name' not in existing:
        additions.append("ALTER TABLE ssh_sessions ADD COLUMN display_name VARCHAR(128)")
    for stmt in additions:
        db.session.execute(text(stmt))
    if added_auth_type:
        db.session.execute(text(
            "UPDATE ssh_sessions SET auth_type = 'key' WHERE key_id IS NOT NULL"
        ))
    if additions:
        db.session.commit()
