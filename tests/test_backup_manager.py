import json
import os
from pathlib import Path
import zipfile

import pytest

from app.backup_manager import (
    BackupIntegrityError,
    create_backup,
    restore_backup,
    verify_backup,
)


def _write_representative_data(data_dir):
    files = {
        'app.db': b'SQLite format 3\x00representative database',
        'app_settings.json': b'{"registration_enabled": false}',
        'known_hosts': b'ssh.example ssh-ed25519 AAAA-test\n',
        'secret_key': b'persisted-secret\n',
        'users/user_1/profiles.json': b'{"schema_version": 1, "profiles": []}',
        'users/user_1/keys/keys.json': (
            b'{"schema_version": 1, "keys": []}'
        ),
        'users/user_1/keys/key.pem': b'encrypted-private-key',
    }
    for relative_path, payload in files.items():
        path = data_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    return files


def _snapshot(directory):
    return {
        path.relative_to(directory).as_posix(): path.read_bytes()
        for path in directory.rglob('*')
        if path.is_file()
    }


def _corrupt_archive_member(source, destination, member):
    with zipfile.ZipFile(source, 'r') as source_zip:
        entries = {
            info.filename: source_zip.read(info)
            for info in source_zip.infolist()
        }
    entries[f'data/{member}'] += b'-corrupt'
    with zipfile.ZipFile(destination, 'w') as destination_zip:
        for name, payload in entries.items():
            destination_zip.writestr(name, payload)


def test_create_verify_and_restore_round_trip(tmp_path):
    data_dir = tmp_path / 'data'
    data_dir.mkdir()
    expected_files = _write_representative_data(data_dir)
    archive = tmp_path / 'backups' / 'webssh.zip'

    created = create_backup(data_dir, archive)
    verified = verify_backup(archive)

    assert created == verified
    assert created.format_version == 1
    assert tuple(item.path for item in created.files) == tuple(
        sorted(expected_files)
    )
    assert archive.is_file()

    restored_dir = tmp_path / 'restored'
    restore_backup(archive, restored_dir)
    assert _snapshot(restored_dir) == expected_files


def test_backup_excludes_logs_and_transfer_temporary_files(tmp_path):
    data_dir = tmp_path / 'data'
    data_dir.mkdir()
    expected_files = _write_representative_data(data_dir)
    (data_dir / 'logs').mkdir()
    (data_dir / 'logs' / 'webssh.log').write_bytes(b'active log')
    (data_dir / 'tmp').mkdir()
    (data_dir / 'tmp' / 'partial-upload').write_bytes(b'partial')
    archive = tmp_path / 'backup.zip'

    manifest = create_backup(data_dir, archive)
    restored_dir = tmp_path / 'restored'
    restore_backup(archive, restored_dir)

    assert tuple(item.path for item in manifest.files) == tuple(
        sorted(expected_files)
    )
    assert _snapshot(restored_dir) == expected_files


def test_corrupt_member_fails_before_restore_writes_anything(tmp_path):
    source_dir = tmp_path / 'source'
    source_dir.mkdir()
    _write_representative_data(source_dir)
    archive = tmp_path / 'valid.zip'
    create_backup(source_dir, archive)
    corrupt_archive = tmp_path / 'corrupt.zip'
    _corrupt_archive_member(archive, corrupt_archive, 'app.db')

    restore_dir = tmp_path / 'restore'
    restore_dir.mkdir()
    sentinel = restore_dir / 'keep.txt'
    sentinel.write_bytes(b'must remain unchanged')
    before = _snapshot(restore_dir)

    with pytest.raises(BackupIntegrityError, match='checksum'):
        verify_backup(corrupt_archive)
    with pytest.raises(BackupIntegrityError, match='checksum'):
        restore_backup(corrupt_archive, restore_dir)

    assert _snapshot(restore_dir) == before


def test_verify_rejects_path_traversal_member(tmp_path):
    archive = tmp_path / 'traversal.zip'
    manifest = {
        'format_version': 1,
        'files': [
            {
                'path': '../outside',
                'sha256': '0' * 64,
                'size': 0,
            },
        ],
    }
    with zipfile.ZipFile(archive, 'w') as backup:
        backup.writestr(
            'manifest.json',
            json.dumps(manifest, sort_keys=True, separators=(',', ':')),
        )
        backup.writestr('data/../outside', b'')

    with pytest.raises(BackupIntegrityError, match='unsafe'):
        verify_backup(archive)


def test_create_rejects_symlinks_without_publishing_archive(tmp_path):
    data_dir = tmp_path / 'data'
    data_dir.mkdir()
    target = tmp_path / 'outside'
    target.write_bytes(b'outside')
    link = data_dir / 'linked'
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip('symlinks are unavailable in this environment')
    archive = tmp_path / 'backup.zip'

    with pytest.raises(BackupIntegrityError, match='symbolic link'):
        create_backup(data_dir, archive)

    assert not archive.exists()


def test_create_rejects_destination_inside_data_directory(tmp_path):
    data_dir = tmp_path / 'data'
    data_dir.mkdir()
    _write_representative_data(data_dir)

    with pytest.raises(ValueError, match='outside'):
        create_backup(data_dir, data_dir / 'backup.zip')


def test_create_does_not_overwrite_existing_archive(tmp_path):
    data_dir = tmp_path / 'data'
    data_dir.mkdir()
    _write_representative_data(data_dir)
    archive = tmp_path / 'existing.zip'
    archive.write_bytes(b'operator-owned-existing-backup')

    with pytest.raises(FileExistsError, match='already exists'):
        create_backup(data_dir, archive)

    assert archive.read_bytes() == b'operator-owned-existing-backup'


def test_create_does_not_clobber_archive_created_during_staging(
    tmp_path,
    monkeypatch,
):
    from app import backup_manager

    data_dir = tmp_path / 'data'
    data_dir.mkdir()
    _write_representative_data(data_dir)
    archive = tmp_path / 'raced.zip'
    original_write_archive = backup_manager._write_archive

    def create_competing_archive(*args, **kwargs):
        original_write_archive(*args, **kwargs)
        archive.write_bytes(b'competing-process-backup')

    monkeypatch.setattr(
        backup_manager,
        '_write_archive',
        create_competing_archive,
    )

    with pytest.raises(FileExistsError, match='already exists'):
        create_backup(data_dir, archive)

    assert archive.read_bytes() == b'competing-process-backup'


def test_create_rejects_symlinked_data_directory(tmp_path):
    real_data_dir = tmp_path / 'real-data'
    real_data_dir.mkdir()
    _write_representative_data(real_data_dir)
    linked_data_dir = tmp_path / 'linked-data'
    try:
        linked_data_dir.symlink_to(real_data_dir, target_is_directory=True)
    except OSError:
        pytest.skip('directory symlinks are unavailable in this environment')
    archive = tmp_path / 'backup.zip'

    with pytest.raises(BackupIntegrityError, match='real directory'):
        create_backup(linked_data_dir, archive)

    assert not archive.exists()


def test_restore_rejects_symlinked_data_directory(tmp_path):
    source_dir = tmp_path / 'source'
    source_dir.mkdir()
    _write_representative_data(source_dir)
    archive = tmp_path / 'backup.zip'
    create_backup(source_dir, archive)
    real_restore_dir = tmp_path / 'real-restore'
    real_restore_dir.mkdir()
    linked_restore_dir = tmp_path / 'linked-restore'
    try:
        linked_restore_dir.symlink_to(
            real_restore_dir,
            target_is_directory=True,
        )
    except OSError:
        pytest.skip('directory symlinks are unavailable in this environment')

    with pytest.raises(BackupIntegrityError, match='real directory'):
        restore_backup(archive, linked_restore_dir)

    assert _snapshot(real_restore_dir) == {}


def test_restore_commit_failure_rolls_back_every_original_file(
    tmp_path,
    monkeypatch,
):
    from app import backup_manager

    source_dir = tmp_path / 'source'
    source_dir.mkdir()
    source_files = _write_representative_data(source_dir)
    archive = tmp_path / 'backup.zip'
    create_backup(source_dir, archive)

    restore_dir = tmp_path / 'restore'
    restore_dir.mkdir()
    for relative_path in source_files:
        path = restore_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'original-' + relative_path.encode('utf-8'))
    before = _snapshot(restore_dir)

    original_write = backup_manager.atomic_write_bytes
    writes = 0

    def fail_second_commit(path, payload, mode=0o600):
        nonlocal writes
        if Path(path).is_relative_to(restore_dir):
            writes += 1
            if writes == 2:
                raise OSError('forced restore commit failure')
        return original_write(path, payload, mode)

    monkeypatch.setattr(
        backup_manager,
        'atomic_write_bytes',
        fail_second_commit,
    )

    with pytest.raises(OSError, match='forced restore commit failure'):
        restore_backup(archive, restore_dir)

    assert _snapshot(restore_dir) == before


def test_restore_removes_stale_persistent_files_but_keeps_runtime_files(
    tmp_path,
):
    source_dir = tmp_path / 'source'
    source_dir.mkdir()
    expected = _write_representative_data(source_dir)
    archive = tmp_path / 'backup.zip'
    create_backup(source_dir, archive)

    restore_dir = tmp_path / 'restore'
    stale = restore_dir / 'users/user_99/profiles.json'
    stale.parent.mkdir(parents=True)
    stale.write_bytes(b'stale persistent state')
    log = restore_dir / 'logs/webssh.log'
    log.parent.mkdir()
    log.write_bytes(b'keep current runtime log')
    temporary = restore_dir / 'tmp/active-transfer'
    temporary.parent.mkdir()
    temporary.write_bytes(b'keep active temp state')

    restore_backup(archive, restore_dir)

    assert not stale.exists()
    assert log.read_bytes() == b'keep current runtime log'
    assert temporary.read_bytes() == b'keep active temp state'
    persistent_snapshot = {
        path: payload
        for path, payload in _snapshot(restore_dir).items()
        if path.split('/', 1)[0] not in {'logs', 'tmp'}
    }
    assert persistent_snapshot == expected


def test_restore_reverifies_staged_bytes_before_active_writes(
    tmp_path,
    monkeypatch,
):
    from app import backup_manager

    source_dir = tmp_path / 'source'
    source_dir.mkdir()
    _write_representative_data(source_dir)
    archive = tmp_path / 'backup.zip'
    create_backup(source_dir, archive)
    replacement = tmp_path / 'replacement.zip'
    _corrupt_archive_member(archive, replacement, 'app.db')

    restore_dir = tmp_path / 'restore'
    restore_dir.mkdir()
    (restore_dir / 'keep.txt').write_bytes(b'unchanged')
    before = _snapshot(restore_dir)
    original_validate = backup_manager._validate_restore_targets

    def replace_after_initial_verification(data_dir, manifest):
        original_validate(data_dir, manifest)
        replacement.replace(archive)

    monkeypatch.setattr(
        backup_manager,
        '_validate_restore_targets',
        replace_after_initial_verification,
    )

    with pytest.raises(BackupIntegrityError, match='checksum'):
        restore_backup(archive, restore_dir)

    assert _snapshot(restore_dir) == before


def test_backup_cli_create_verify_and_restore_real_archive(
    app,
    tmp_path,
    monkeypatch,
):
    import config

    source_dir = Path(app.config['DATA_DIR'])
    source_dir.mkdir(exist_ok=True)
    (source_dir / 'operator-setting.json').write_bytes(b'{"safe": true}')
    archive = tmp_path / 'cli-backup.zip'
    runner = app.test_cli_runner()

    create_result = runner.invoke(
        args=[
            'backup',
            'create',
            '--destination',
            str(archive),
            '--confirm-offline',
        ],
    )
    assert create_result.exit_code == 0
    assert archive.is_file()

    verify_result = runner.invoke(
        args=['backup', 'verify', str(archive)],
    )
    assert verify_result.exit_code == 0
    assert 'verified' in verify_result.output.lower()

    restore_dir = tmp_path / 'cli-restored'
    monkeypatch.setattr(config, 'DATA_DIR', restore_dir)
    restore_result = runner.invoke(
        args=[
            'backup',
            'restore',
            str(archive),
            '--confirm-offline',
        ],
    )
    assert restore_result.exit_code == 0
    assert (restore_dir / 'operator-setting.json').read_bytes() == (
        b'{"safe": true}'
    )


@pytest.mark.skipif(
    os.name != 'nt',
    reason='Windows blocks atomic replacement while SQLite is pooled',
)
def test_backup_cli_restores_active_data_dir_with_pooled_sqlite_handle(
    app,
    tmp_path,
):
    from app import db

    data_dir = Path(app.config['DATA_DIR'])
    marker = data_dir / 'operator-setting.json'
    marker.write_bytes(b'{"state": "before"}')
    archive = tmp_path / 'active-data-dir.zip'
    runner = app.test_cli_runner()

    create_result = runner.invoke(args=[
        'backup',
        'create',
        '--destination',
        str(archive),
        '--confirm-offline',
    ])
    assert create_result.exit_code == 0

    with app.app_context():
        with db.engine.connect() as connection:
            connection.exec_driver_sql('SELECT 1')
    marker.write_bytes(b'{"state": "mutated"}')

    restore_result = runner.invoke(args=[
        'backup',
        'restore',
        str(archive),
        '--confirm-offline',
    ])

    assert restore_result.exit_code == 0, restore_result.output
    assert marker.read_bytes() == b'{"state": "before"}'


def test_backup_cli_refuses_mutating_operations_without_offline_ack(
    app,
    tmp_path,
):
    archive = tmp_path / 'must-not-exist.zip'

    result = app.test_cli_runner().invoke(
        args=['backup', 'create', '--destination', str(archive)],
    )

    assert result.exit_code != 0
    assert 'confirm-offline' in result.output
    assert not archive.exists()
