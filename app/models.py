from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timezone
import bcrypt

db = SQLAlchemy()


def as_naive_utc(value):
    """Normalize a datetime for database columns that store naive UTC."""
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


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
    auth_generation = db.Column(db.Integer, nullable=False, default=0)

    socket_sessions = db.relationship('SocketSession', backref='user', cascade='all, delete-orphan', lazy='dynamic')
    ssh_sessions = db.relationship('SSHSession', backref='user', cascade='all, delete-orphan', lazy='dynamic')
    webauthn_credentials = db.relationship(
        'WebAuthnCredential',
        backref='user',
        cascade='all, delete-orphan',
        lazy='dynamic',
    )
    recovery_codes = db.relationship(
        'RecoveryCode',
        backref='user',
        cascade='all, delete-orphan',
        lazy='dynamic',
    )
    oidc_identities = db.relationship(
        'OIDCIdentity',
        backref='user',
        cascade='all, delete-orphan',
        lazy='dynamic',
    )
    ldap_identity = db.relationship(
        'LDAPIdentity',
        backref='user',
        cascade='all, delete-orphan',
        uselist=False,
    )

    def set_password(self, password):
        """Hash and set user password using bcrypt."""
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        """Verify password against stored hash."""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    def get_id(self):
        """Bind Flask-Login sessions to the current authentication boundary."""
        return f'{self.id}:{int(self.auth_generation or 0)}'

    @property
    def is_ldap_managed(self):
        """Return whether this account is exclusively directory-managed."""
        return self.ldap_identity is not None

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
    columns added above would be absent on an existing
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
    if 'auth_generation' not in existing:
        additions.append(
            "ALTER TABLE users ADD COLUMN auth_generation "
            "INTEGER NOT NULL DEFAULT 0"
        )
    for stmt in additions:
        db.session.execute(text(stmt))
    # First-time migration of an existing install: there was no role separation
    # before. Grant admin ONLY to the oldest account (lowest id) instead of every
    # user, so upgrading a multi-user install does not silently make everyone an
    # admin. Runs once — on later starts the column already exists, so this block
    # is skipped. On fresh installs, the first registered user becomes admin.
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


class WebAuthnCredential(db.Model):
    """A verified passkey bound to one local account."""

    __tablename__ = 'webauthn_credentials'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id'),
        nullable=False,
        index=True,
    )
    credential_id = db.Column(db.LargeBinary, unique=True, nullable=False)
    public_key = db.Column(db.LargeBinary, nullable=False)
    sign_count = db.Column(db.Integer, nullable=False, default=0)
    transports = db.Column(db.Text, nullable=False, default='[]')
    name = db.Column(db.String(80), nullable=False, default='Passkey')
    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_used_at = db.Column(db.DateTime)


class WebAuthnChallenge(db.Model):
    """Short-lived, one-use server-side WebAuthn ceremony state."""

    __tablename__ = 'webauthn_challenges'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id'),
        nullable=True,
        index=True,
    )
    purpose = db.Column(db.String(16), nullable=False, index=True)
    session_binding_hash = db.Column(
        db.String(64),
        nullable=False,
        index=True,
    )
    challenge = db.Column(db.LargeBinary, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)


class RecoveryCode(db.Model):
    """A single-use, domain-separated account recovery verifier."""

    __tablename__ = 'recovery_codes'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id'),
        nullable=False,
        index=True,
    )
    code_hash = db.Column(db.LargeBinary(32), nullable=False, index=True)
    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class OIDCIdentity(db.Model):
    """Administrator-approved stable external identity mapping."""

    __tablename__ = 'oidc_identities'
    __table_args__ = (
        db.UniqueConstraint(
            'issuer',
            'subject',
            name='uq_oidc_issuer_subject',
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id'),
        nullable=False,
        index=True,
    )
    issuer = db.Column(db.String(512), nullable=False)
    subject = db.Column(db.String(512), nullable=False)
    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class OIDCLoginState(db.Model):
    """Short-lived server-side OIDC state, nonce, and PKCE verifier."""

    __tablename__ = 'oidc_login_states'

    id = db.Column(db.Integer, primary_key=True)
    state_hash = db.Column(db.String(64), unique=True, nullable=False)
    session_binding_hash = db.Column(db.String(64), nullable=False, index=True)
    nonce = db.Column(db.String(128), nullable=False)
    code_verifier = db.Column(db.String(128), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)


class LDAPIdentity(db.Model):
    """Administrator-approved stable LDAP identity mapping."""

    __tablename__ = 'ldap_identities'
    __table_args__ = (
        db.UniqueConstraint(
            'provider',
            'subject',
            name='uq_ldap_provider_subject',
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id'),
        nullable=False,
        unique=True,
        index=True,
    )
    provider = db.Column(db.String(64), nullable=False)
    subject = db.Column(db.String(512), nullable=False)
    directory_username = db.Column(db.String(256), nullable=False)
    distinguished_name = db.Column(db.String(2048), nullable=False)
    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_verified_at = db.Column(db.DateTime)

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
