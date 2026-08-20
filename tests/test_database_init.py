from sqlalchemy import inspect, text


SECURITY_TABLES = {
    'authentication_sessions',
    'pending_authentications',
    'security_feature_states',
    'step_up_grants',
    'totp_authenticators',
    'totp_enrollments',
}


def test_fresh_database_initializes_authentication_assurance_schema(app):
    from app.models import db

    with app.app_context():
        inspector = inspect(db.engine)
        tables = set(inspector.get_table_names())
        user_columns = {
            column['name'] for column in inspector.get_columns('users')
        }

        assert SECURITY_TABLES <= tables
        assert 'mfa_enabled' in user_columns


def test_legacy_user_schema_adds_disabled_mfa_idempotently(app):
    from app.models import db, ensure_security_columns

    with app.app_context():
        db.drop_all()
        db.session.execute(text(
            'CREATE TABLE users ('
            'id INTEGER PRIMARY KEY, '
            'username VARCHAR(80) NOT NULL UNIQUE, '
            'password_hash VARCHAR(128) NOT NULL, '
            'is_admin BOOLEAN NOT NULL DEFAULT 0, '
            'is_locked BOOLEAN NOT NULL DEFAULT 0, '
            'auth_generation INTEGER NOT NULL DEFAULT 0'
            ')'
        ))
        db.session.execute(text(
            "INSERT INTO users (id, username, password_hash) "
            "VALUES (1, 'legacy-user', 'unused')"
        ))
        db.session.commit()

        ensure_security_columns()
        ensure_security_columns()

        row = db.session.execute(text(
            'SELECT username, mfa_enabled FROM users WHERE id = 1'
        )).one()
        assert row == ('legacy-user', 0)
