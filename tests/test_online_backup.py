import sqlite3
import threading
import time
import zipfile

import pytest

from app.backup_coordination import (
    OperationBusyError,
    ensure_backup_temp_dir,
    operation_lock,
    persistent_write,
    snapshot_barrier,
)
from app.backup_manager import verify_backup
from app.online_backup import create_online_backup


def _configure_temp_root(monkeypatch, tmp_path):
    import config

    root = tmp_path / 'operations'
    monkeypatch.setattr(config, 'BACKUP_TEMP_DIR', root)
    monkeypatch.setattr(config, 'BACKUP_OPERATION_TIMEOUT', 2)
    return root


def test_backup_temp_root_is_namespaced_by_data_directory(
    tmp_path, monkeypatch
):
    import config

    configured_root = tmp_path / 'operations'
    first_data_dir = tmp_path / 'first-data'
    second_data_dir = tmp_path / 'second-data'
    monkeypatch.setattr(config, 'BACKUP_TEMP_DIR', configured_root)

    monkeypatch.setattr(config, 'DATA_DIR', first_data_dir)
    first_root = ensure_backup_temp_dir()
    monkeypatch.setattr(config, 'DATA_DIR', second_data_dir)
    second_root = ensure_backup_temp_dir()

    assert first_root != second_root
    assert first_root.parent == configured_root.resolve()
    assert second_root.parent == configured_root.resolve()


def test_online_backup_uses_valid_sqlite_snapshot_and_discards_worktree(
    tmp_path, monkeypatch
):
    operation_root = _configure_temp_root(monkeypatch, tmp_path)
    data_dir = tmp_path / 'data'
    data_dir.mkdir()
    database = sqlite3.connect(data_dir / 'app.db')
    database.execute('PRAGMA journal_mode=WAL')
    database.execute(
        'CREATE TABLE users ('
        'id INTEGER PRIMARY KEY, '
        'username TEXT NOT NULL, '
        'password_hash TEXT NOT NULL'
        ')'
    )
    database.execute('CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT)')
    database.executemany(
        'INSERT INTO records(value) VALUES (?)',
        ((f'value-{index}',) for index in range(2000)),
    )
    database.commit()
    database.close()
    (data_dir / 'settings.json').write_text('{"enabled":true}', encoding='utf-8')
    (data_dir / 'logs').mkdir()
    (data_dir / 'logs' / 'audit.log').write_text('excluded', encoding='utf-8')
    (data_dir / 'tmp').mkdir()
    (data_dir / 'tmp' / 'upload.bin').write_bytes(b'excluded')
    archive = tmp_path / 'backup.zip'

    manifest = create_online_backup(data_dir, archive)

    assert manifest == verify_backup(archive)
    assert not tuple(operation_root.glob('snapshot-*'))
    assert 'settings.json' in {item.path for item in manifest.files}
    assert not any(item.path.startswith(('logs/', 'tmp/')) for item in manifest.files)
    extracted_database = tmp_path / 'snapshot.db'
    with zipfile.ZipFile(archive) as backup:
        extracted_database.write_bytes(backup.read('data/app.db'))
    snapshot = sqlite3.connect(extracted_database)
    try:
        assert snapshot.execute('PRAGMA quick_check').fetchone() == ('ok',)
        assert snapshot.execute('SELECT COUNT(*) FROM records').fetchone() == (2000,)
    finally:
        snapshot.close()


def test_snapshot_barrier_waits_for_persistent_writes():
    entered = threading.Event()
    finished = threading.Event()

    def writer():
        with persistent_write():
            entered.set()
        finished.set()

    with snapshot_barrier():
        thread = threading.Thread(target=writer)
        thread.start()
        assert not entered.wait(0.1)
    assert finished.wait(1)
    thread.join(timeout=1)


def test_sqlalchemy_commit_waits_for_online_snapshot(app):
    from app.models import User, db

    committed = threading.Event()

    def database_writer():
        with app.app_context():
            db.session.add(User(
                username='snapshot-writer',
                password_hash='not-used-in-this-test',
            ))
            db.session.commit()
            committed.set()

    with snapshot_barrier():
        thread = threading.Thread(target=database_writer)
        thread.start()
        assert not committed.wait(0.1)
    assert committed.wait(2)
    thread.join(timeout=1)


def test_process_operation_lock_rejects_concurrent_operation(
    tmp_path, monkeypatch
):
    _configure_temp_root(monkeypatch, tmp_path)
    outcome = []

    def contender():
        try:
            with operation_lock(timeout=0.1):
                outcome.append('acquired')
        except OperationBusyError:
            outcome.append('busy')

    with operation_lock():
        thread = threading.Thread(target=contender)
        thread.start()
        thread.join(timeout=1)
    assert outcome == ['busy']


def test_online_backup_rejects_destination_inside_data_dir(
    tmp_path, monkeypatch
):
    _configure_temp_root(monkeypatch, tmp_path)
    data_dir = tmp_path / 'data'
    data_dir.mkdir()
    sqlite3.connect(data_dir / 'app.db').close()

    with pytest.raises(ValueError, match='outside DATA_DIR'):
        create_online_backup(data_dir, data_dir / 'backup.zip')
