"""Fail-closed cleanup for replayable state after persistent-state restore."""

from pathlib import Path
import sqlite3


_TRANSIENT_TABLES = (
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


def sanitize_restored_authentication_state(database_path: Path):
    """Remove replayable runtime credentials from one restored database.

    Older compatible backups may not contain every current transient table,
    so the sanitizer deletes the intersection present in the restored schema.
    Durable users, provider identities, MFA authenticators, and recovery codes
    are intentionally preserved.
    """
    connection = sqlite3.connect(str(database_path), timeout=30)
    try:
        connection.execute('BEGIN IMMEDIATE')
        present = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        deleted = {}
        for table in _TRANSIENT_TABLES:
            if table not in present:
                continue
            cursor = connection.execute(f'DELETE FROM "{table}"')
            deleted[table] = max(0, int(cursor.rowcount or 0))
        user_columns = (
            {
                row[1]
                for row in connection.execute('PRAGMA table_info("users")')
            }
            if 'users' in present
            else set()
        )
        if 'auth_generation' in user_columns:
            connection.execute(
                'UPDATE users SET auth_generation = '
                'COALESCE(auth_generation, 0) + 1'
            )
        connection.commit()
        return deleted
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
