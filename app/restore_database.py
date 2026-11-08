"""Schema boundary for portable WebSSH database imports."""

import sqlite3


SQLITE_SIDECARS = frozenset({'app.db-wal', 'app.db-shm', 'app.db-journal'})


def harden_imported_database(connection):
    """Reject executable schema not produced by WebSSH before using its data."""
    connection.execute('PRAGMA trusted_schema = OFF')
    if connection.execute('PRAGMA trusted_schema').fetchone() != (0,):
        raise sqlite3.DatabaseError('database schema protection is unavailable')
    if connection.execute(
        "SELECT 1 FROM main.sqlite_master WHERE type IN ('trigger', 'view') LIMIT 1"
    ).fetchone():
        raise sqlite3.DatabaseError('database contains unsupported schema')
    # Use SQLite's parsed classification, not SQL-text matching: imported
    # schema text can contain alternate whitespace and comments.
    tables = connection.execute('PRAGMA main.table_list').fetchall()
    if not tables:
        raise sqlite3.DatabaseError('database schema inspection is unavailable')
    if any(row[2] != 'table' for row in tables):
        raise sqlite3.DatabaseError('database contains unsupported schema')
