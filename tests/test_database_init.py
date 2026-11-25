from datetime import datetime, timedelta, timezone
import hashlib

from sqlalchemy import inspect, text


SECURITY_TABLES = {
    'authentication_sessions',
    'pending_authentications',
    'security_feature_states',
    'step_up_grants',
    'step_up_intents',
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
        assert 'settings_default_generation' in user_columns


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
            'SELECT username, mfa_enabled, settings_default_generation, '
            'mfa_failed_attempts, mfa_last_failed_at, '
            'mfa_step_up_failed_attempts, mfa_step_up_last_failed_at '
            'FROM users WHERE id = 1'
        )).one()
        assert row == ('legacy-user', 0, 0, 0, None, 0, None)


def test_legacy_oidc_state_adds_assurance_intent_columns_idempotently(app):
    from sqlalchemy import inspect, text
    from app.models import db, ensure_security_columns

    with app.app_context():
        db.session.execute(text('DROP TABLE oidc_login_states'))
        db.session.execute(text(
            'CREATE TABLE oidc_login_states ('
            'id INTEGER PRIMARY KEY, '
            'state_hash VARCHAR(64) NOT NULL UNIQUE, '
            'session_binding_hash VARCHAR(64) NOT NULL, '
            'nonce VARCHAR(128) NOT NULL, '
            'code_verifier VARCHAR(128) NOT NULL, '
            'expires_at DATETIME NOT NULL'
            ')'
        ))
        db.session.execute(
            text(
                'INSERT INTO oidc_login_states '
                '(state_hash, session_binding_hash, nonce, code_verifier, '
                'expires_at) VALUES '
                '(:state_hash, :binding_hash, :nonce, :verifier, :expires_at)'
            ),
            {
                'state_hash': hashlib.sha256(
                    b'legacy-login-state'
                ).hexdigest(),
                'binding_hash': hashlib.sha256(
                    b'legacy-browser-binding'
                ).hexdigest(),
                'nonce': 'legacy-nonce',
                'verifier': 'legacy-verifier',
                'expires_at': datetime.now(timezone.utc).replace(
                    tzinfo=None
                ) + timedelta(minutes=5),
            },
        )
        db.session.commit()

        ensure_security_columns()
        ensure_security_columns()

        columns = {
            column['name']
            for column in inspect(db.engine).get_columns('oidc_login_states')
        }
        assert {
            'purpose',
            'continuation',
            'requested_acr',
            'step_up_action',
            'step_up_target_hash',
            'step_up_intent_id',
            'user_id',
            'auth_generation',
            'authentication_session_id',
        } <= columns
        from app.oidc_service import consume_login_state

        intent = consume_login_state(
            state='legacy-login-state',
            session_binding='legacy-browser-binding',
        )
        assert intent.purpose == 'login'
        assert intent.continuation == '/'
        assert intent.user_id is None
        assert intent.auth_generation is None
        assert intent.authentication_session_id is None


def test_schema_upgrade_from_oldest_layout_adds_all_columns(app, monkeypatch):
    from sqlalchemy import event
    from app import audit_logger
    from app.models import (
        db,
        ensure_security_columns,
        ensure_ssh_session_columns,
    )

    migration_logs = []
    original_log_info = audit_logger.log_info

    def record_log_info(message, **kwargs):
        if message.startswith('Schema migration'):
            migration_logs.append(message)
        return original_log_info(message, **kwargs)

    monkeypatch.setattr(audit_logger, 'log_info', record_log_info)

    with app.app_context():
        db.drop_all()
        db.session.execute(text(
            'CREATE TABLE users ('
            'id INTEGER PRIMARY KEY, '
            'username VARCHAR(80) NOT NULL UNIQUE, '
            'password_hash VARCHAR(128) NOT NULL'
            ')'
        ))
        db.session.execute(text(
            'CREATE TABLE oidc_login_states ('
            'id INTEGER PRIMARY KEY, '
            'state_hash VARCHAR(64) NOT NULL UNIQUE'
            ')'
        ))
        db.session.execute(text(
            'CREATE TABLE ssh_sessions ('
            'id INTEGER PRIMARY KEY, '
            'session_id VARCHAR(36) NOT NULL UNIQUE, '
            'user_id INTEGER NOT NULL, '
            'host VARCHAR(256) NOT NULL, '
            'port INTEGER NOT NULL, '
            'username VARCHAR(128) NOT NULL'
            ')'
        ))
        db.session.execute(text(
            "INSERT INTO users (id, username, password_hash) VALUES "
            "(2, 'oldest', 'unused'), (5, 'second', 'unused')"
        ))
        db.session.execute(text(
            "INSERT INTO ssh_sessions "
            "(session_id, user_id, host, port, username) "
            "VALUES ('legacy-session', 2, 'example.test', 22, 'root')"
        ))
        db.session.commit()

        statements = []

        def record(conn, cursor, statement, parameters, context, executemany):
            if statement.startswith(('ALTER', 'UPDATE')):
                statements.append(statement)

        event.listen(db.engine, 'before_cursor_execute', record)
        try:
            ensure_security_columns()
            ensure_ssh_session_columns()
            first_run = list(statements)
            first_admins = db.session.execute(text(
                'SELECT id, is_admin FROM users ORDER BY id'
            )).all()
            # A later start must neither add columns nor re-grant admin.
            db.session.execute(text('UPDATE users SET is_admin = 0'))
            db.session.commit()
            statements.clear()
            ensure_security_columns()
            ensure_ssh_session_columns()
            second_run = [
                statement for statement in statements
                if statement != 'UPDATE users SET is_admin = 0'
            ]
        finally:
            event.remove(db.engine, 'before_cursor_execute', record)

        assert first_run == [
            "ALTER TABLE users ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT 0",
            "ALTER TABLE users ADD COLUMN is_locked BOOLEAN NOT NULL DEFAULT 0",
            "ALTER TABLE users ADD COLUMN auth_generation "
            "INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE users ADD COLUMN mfa_enabled "
            "BOOLEAN NOT NULL DEFAULT 0",
            "ALTER TABLE users ADD COLUMN settings_default_generation "
            "INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE users ADD COLUMN mfa_failed_attempts "
            "INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE users ADD COLUMN mfa_last_failed_at DATETIME",
            "ALTER TABLE users ADD COLUMN mfa_step_up_failed_attempts "
            "INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE users ADD COLUMN mfa_step_up_last_failed_at DATETIME",
            "UPDATE users SET is_admin = 1 "
            "WHERE id = (SELECT id FROM users ORDER BY id LIMIT 1)",
            "ALTER TABLE oidc_login_states ADD COLUMN purpose "
            "VARCHAR(24) NOT NULL DEFAULT 'login'",
            "ALTER TABLE oidc_login_states ADD COLUMN continuation "
            "VARCHAR(512) NOT NULL DEFAULT '/'",
            "ALTER TABLE oidc_login_states ADD COLUMN requested_acr "
            "VARCHAR(512)",
            "ALTER TABLE oidc_login_states ADD COLUMN step_up_action "
            "VARCHAR(96)",
            "ALTER TABLE oidc_login_states ADD COLUMN step_up_target_hash "
            "VARCHAR(64)",
            "ALTER TABLE oidc_login_states ADD COLUMN step_up_intent_id "
            "INTEGER",
            "ALTER TABLE oidc_login_states ADD COLUMN user_id INTEGER",
            "ALTER TABLE oidc_login_states ADD COLUMN auth_generation INTEGER",
            "ALTER TABLE oidc_login_states ADD COLUMN "
            "authentication_session_id INTEGER",
            "ALTER TABLE ssh_sessions ADD COLUMN is_persistent "
            "BOOLEAN NOT NULL DEFAULT 0",
            "ALTER TABLE ssh_sessions ADD COLUMN key_id VARCHAR(64)",
            "ALTER TABLE ssh_sessions ADD COLUMN auth_type VARCHAR(16) "
            "NOT NULL DEFAULT 'password'",
            "ALTER TABLE ssh_sessions ADD COLUMN tmux_session_name "
            "VARCHAR(256)",
            "ALTER TABLE ssh_sessions ADD COLUMN display_name VARCHAR(128)",
            "ALTER TABLE ssh_sessions ADD COLUMN jump_host_id VARCHAR(64)",
            "ALTER TABLE ssh_sessions ADD COLUMN socks_proxy_id VARCHAR(64)",
            "ALTER TABLE ssh_sessions ADD COLUMN via_socks "
            "BOOLEAN NOT NULL DEFAULT 0",
            "ALTER TABLE ssh_sessions ADD COLUMN profile_id VARCHAR(128)",
            "ALTER TABLE ssh_sessions ADD COLUMN via_jump VARCHAR(256)",
            "ALTER TABLE ssh_sessions ADD COLUMN reconnect_route_known "
            "BOOLEAN NOT NULL DEFAULT 0",
            "UPDATE ssh_sessions SET auth_type = 'key' "
            "WHERE key_id IS NOT NULL",
        ]
        assert first_admins == [(2, 1), (5, 0)]
        assert second_run == []
        assert migration_logs == [
            'Schema migration: granted admin to the oldest pre-existing user'
        ]

        inspector = inspect(db.engine)
        for statement in first_run:
            if statement.startswith('ALTER'):
                table, column = statement.split()[2], statement.split()[5]
                columns = {c['name'] for c in inspector.get_columns(table)}
                assert column in columns, (table, column)

        assert db.session.execute(text(
            'SELECT id, is_admin FROM users ORDER BY id'
        )).all() == [(2, 0), (5, 0)]
        assert db.session.execute(text(
            'SELECT auth_type, is_persistent, via_socks, '
            'reconnect_route_known FROM ssh_sessions'
        )).one() == ('password', 0, 0, 0)
