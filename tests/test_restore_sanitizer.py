import sqlite3


TRANSIENT_TABLES = (
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
