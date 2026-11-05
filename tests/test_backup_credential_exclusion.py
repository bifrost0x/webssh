"""Export boundaries must not compromise the private restore rollback path."""
import sqlite3
import zipfile
from pathlib import Path

import pytest

from app import backup_manager, online_backup


PRIVATE_FILES = (
    'users/user_1/credentials.json',
    'users/user_1/.credentials.json.interrupted.tmp',
    'users/user_1/credentials.json.bak',
    'users/user_1/automation-vault.json',
    'users/user_1/.automation-vault.json.interrupted.tmp',
    'users/user_1/keys/keys.json',
    'users/user_1/keys/key.pem',
    'keys/legacy.pem',
    'deleted_users/user_2/credentials.json',
)


def seed(root):
    root.mkdir()
    with sqlite3.connect(root / 'app.db') as db:
        db.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT)')
    for name in PRIVATE_FILES:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'encrypted-remote-secret')
    (root / 'secret_key').write_bytes(b'application-secret')
    (root / 'users/user_1/profiles.json').write_bytes(b'{"profiles":[]}')
    return snapshot(root)


def snapshot(root):
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob('*') if p.is_file()}


@pytest.mark.parametrize('online', [False, True])
def test_export_excludes_remote_credentials_and_preserves_live_data(tmp_path, monkeypatch, online):
    import config
    monkeypatch.setattr(config, 'BACKUP_TEMP_DIR', tmp_path / 'operations')
    source = tmp_path / 'source'
    before = seed(source)
    archive = tmp_path / 'export.zip'
    create = online_backup.create_online_backup if online else backup_manager.create_backup
    manifest = create(source, archive)
    assert not set(PRIVATE_FILES).intersection(item.path for item in manifest.files)
    with zipfile.ZipFile(archive) as exported:
        assert not any('encrypted-remote-secret' in exported.read(name).decode(errors='replace') for name in exported.namelist())
    assert snapshot(source) == before
    restored = tmp_path / 'restored'
    backup_manager.restore_backup(archive, restored)
    assert snapshot(restored) == {k: v for k, v in before.items() if k not in PRIVATE_FILES}


def test_legacy_restore_drops_credentials_but_private_recovery_preserves_them(tmp_path, monkeypatch):
    import config
    monkeypatch.setattr(config, 'BACKUP_TEMP_DIR', tmp_path / 'operations')
    source = tmp_path / 'source'
    original = seed(source)
    archive = tmp_path / 'private-recovery.zip'
    backup_manager._create_recovery_snapshot(source, archive)
    destination = tmp_path / 'restored'
    seed(destination)
    backup_manager.restore_backup(archive, destination)
    assert snapshot(destination) == {k: v for k, v in original.items() if k not in PRIVATE_FILES}
    backup_manager._restore_recovery_snapshot(archive, destination)
    assert snapshot(destination) == original


def test_online_recovery_preserves_credentials(tmp_path, monkeypatch):
    import config
    monkeypatch.setattr(config, 'BACKUP_TEMP_DIR', tmp_path / 'operations')
    source = tmp_path / 'source'
    before = seed(source)
    archive = tmp_path / 'recovery.zip'
    manifest = online_backup._create_online_recovery_snapshot(source, archive)
    assert set(PRIVATE_FILES).issubset(item.path for item in manifest.files)
    backup_manager._restore_recovery_snapshot(archive, tmp_path / 'restored')
    assert snapshot(tmp_path / 'restored') == before


def test_failed_restore_recovers_credentials_already_removed(tmp_path, monkeypatch):
    import config
    monkeypatch.setattr(config, 'BACKUP_TEMP_DIR', tmp_path / 'operations')
    source = tmp_path / 'source'
    seed(source)
    archive = tmp_path / 'export.zip'
    backup_manager.create_backup(source, archive)
    destination = tmp_path / 'restored'
    before = seed(destination)
    original_unlink = Path.unlink
    removed = []

    def fail_after_removal(path, *args, **kwargs):
        result = original_unlink(path, *args, **kwargs)
        if path.is_relative_to(destination) and path.relative_to(destination).as_posix() in PRIVATE_FILES:
            removed.append(path)
            if len(removed) == 2:
                raise OSError('injected credential removal failure')
        return result

    monkeypatch.setattr(Path, 'unlink', fail_after_removal)
    with pytest.raises(OSError, match='injected credential removal failure'):
        backup_manager.restore_backup(archive, destination)
    assert len(removed) == 2
    assert snapshot(destination) == before
