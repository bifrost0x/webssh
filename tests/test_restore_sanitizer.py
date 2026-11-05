import sqlite3
import pytest


TRANSIENT_TABLES = (
    'factor_bootstrap_tokens',
    'github_oauth_states',
    'oidc_login_states',
    'step_up_grants',
    'step_up_intents',
    'authentication_sessions',
    'pending_authentications',
    'webauthn_challenges',
    'totp_enrollments',
    'socket_sessions',
    'ssh_sessions',
)


@pytest.mark.parametrize('schema', [
    'CREATE TRIGGER replay AFTER DELETE ON authentication_sessions '
    'BEGIN UPDATE users SET auth_generation = 99; END',
    'CREATE VIEW imported_view AS SELECT * FROM users',
    'CREATE VIRTUAL TABLE imported_search USING fts5(body)',
])
def test_sanitizer_rejects_executable_schema_without_mutating_rows(tmp_path, schema):
    from app.restore_sanitizer import sanitize_restored_authentication_state

    database = tmp_path / 'app.db'
    with sqlite3.connect(database) as connection:
        connection.execute('CREATE TABLE users (id INTEGER, auth_generation INTEGER)')
        connection.execute('INSERT INTO users VALUES (1, 7)')
        connection.execute('CREATE TABLE authentication_sessions (id INTEGER)')
        connection.execute('INSERT INTO authentication_sessions VALUES (1)')
        connection.execute(schema)
    with pytest.raises(sqlite3.DatabaseError, match='unsupported schema'):
        sanitize_restored_authentication_state(database)
    with sqlite3.connect(database) as connection:
        assert connection.execute('SELECT auth_generation FROM users').fetchone() == (7,)
        assert connection.execute('SELECT count(*) FROM authentication_sessions').fetchone() == (1,)


def test_restore_trigger_cannot_query_fts_during_cleanup(tmp_path):
    from app.restore_sanitizer import sanitize_restored_authentication_state

    database = tmp_path / 'app.db'
    with sqlite3.connect(database) as connection:
        connection.executescript('''
            CREATE TABLE users (id INTEGER, auth_generation INTEGER);
            INSERT INTO users VALUES (1, 7);
            CREATE TABLE authentication_sessions (id INTEGER);
            INSERT INTO authentication_sessions VALUES (1);
            CREATE VIRTUAL TABLE probe_fts USING fts5(body);
            INSERT INTO probe_fts VALUES ('harmless probe');
            CREATE TABLE probe_log (count INTEGER);
            CREATE TRIGGER imported_trigger AFTER DELETE ON authentication_sessions
            BEGIN
                INSERT INTO probe_log SELECT count(*) FROM probe_fts
                WHERE probe_fts MATCH 'harmless';
            END;
        ''')
    with pytest.raises(sqlite3.DatabaseError, match='unsupported schema'):
        sanitize_restored_authentication_state(database)
    with sqlite3.connect(database) as connection:
        assert connection.execute('SELECT * FROM probe_log').fetchall() == []
        assert connection.execute('SELECT * FROM authentication_sessions').fetchall() == [(1,)]
        assert connection.execute('SELECT auth_generation FROM users').fetchone() == (7,)


def test_sanitizer_rejects_virtual_schema_with_alternate_sql_encoding(tmp_path):
    from app.restore_sanitizer import sanitize_restored_authentication_state

    database = tmp_path / 'app.db'
    with sqlite3.connect(database) as connection:
        connection.execute('CREATE VIRTUAL TABLE imported_search USING fts5(body)')
        connection.execute('PRAGMA writable_schema=ON')
        connection.execute(
            'UPDATE sqlite_master SET sql = ? WHERE name = ?',
            ('CREATE \ufeff VIRTUAL TABLE imported_search USING fts5(body)', 'imported_search'),
        )
    with pytest.raises(sqlite3.DatabaseError, match='unsupported schema'):
        sanitize_restored_authentication_state(database)


def test_restore_sanitizer_removes_transient_rows_and_preserves_durable_state(
    tmp_path,
):
    from app.restore_sanitizer import sanitize_restored_authentication_state

    database = tmp_path / 'app.db'
    connection = sqlite3.connect(database)
    connection.execute(
        'CREATE TABLE users (id INTEGER PRIMARY KEY, auth_generation INTEGER)'
    )
    connection.execute(
        'CREATE TABLE webauthn_credentials (id INTEGER PRIMARY KEY)'
    )
    connection.execute(
        'CREATE TABLE totp_authenticators (id INTEGER PRIMARY KEY)'
    )
    connection.execute('CREATE TABLE recovery_codes (id INTEGER PRIMARY KEY)')
    for table in TRANSIENT_TABLES:
        connection.execute(f'CREATE TABLE "{table}" (id INTEGER PRIMARY KEY)')
    connection.execute('INSERT INTO users VALUES (1, 7)')
    for table in (
        'webauthn_credentials',
        'totp_authenticators',
        'recovery_codes',
        *TRANSIENT_TABLES,
    ):
        connection.execute(f'INSERT INTO "{table}" VALUES (1)')
    connection.commit()
    connection.close()

    deleted = sanitize_restored_authentication_state(database)

    connection = sqlite3.connect(database)
    try:
        assert set(deleted) == set(TRANSIENT_TABLES)
        assert all(deleted[table] == 1 for table in TRANSIENT_TABLES)
        assert connection.execute(
            'SELECT auth_generation FROM users'
        ).fetchone() == (8,)
        for table in TRANSIENT_TABLES:
            assert connection.execute(
                f'SELECT COUNT(*) FROM "{table}"'
            ).fetchone() == (0,)
        for table in (
            'webauthn_credentials',
            'totp_authenticators',
            'recovery_codes',
        ):
            assert connection.execute(
                f'SELECT COUNT(*) FROM "{table}"'
            ).fetchone() == (1,)
    finally:
        connection.close()


def test_restore_sanitizer_accepts_older_schema_without_transient_tables(
    tmp_path,
):
    from app.restore_sanitizer import sanitize_restored_authentication_state

    database = tmp_path / 'legacy.db'
    connection = sqlite3.connect(database)
    connection.execute(
        'CREATE TABLE users (id INTEGER PRIMARY KEY, auth_generation INTEGER)'
    )
    connection.execute('INSERT INTO users VALUES (1, 0)')
    connection.commit()
    connection.close()

    assert sanitize_restored_authentication_state(database) == {}
    connection = sqlite3.connect(database)
    try:
        assert connection.execute(
            'SELECT auth_generation FROM users'
        ).fetchone() == (1,)
    finally:
        connection.close()


def test_restore_sanitizer_accepts_users_table_before_auth_generation(
    tmp_path,
):
    from app.restore_sanitizer import sanitize_restored_authentication_state

    database = tmp_path / 'older-users.db'
    connection = sqlite3.connect(database)
    connection.execute(
        'CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)'
    )
    connection.execute('INSERT INTO users VALUES (1, "legacy")')
    connection.commit()
    connection.close()

    assert sanitize_restored_authentication_state(database) == {}
