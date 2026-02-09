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

    def __repr__(self):
        return f'<SSHSession id={self.session_id[:8]}... {self.username}@{self.host}:{self.port}>'
