import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


def test_importing_scanner_does_not_initialize_application_package(tmp_path):
    """The read-only scanner must not import app logging or create app files."""
    env = os.environ.copy()
    env.update({
        'SECRET_KEY': 'readiness-import-isolation-secret',
        'DATA_DIR': str(tmp_path),
    })
    completed = subprocess.run(
        [
            sys.executable,
            '-c',
            (
                'import sys; '
                'import scripts.check_paramiko5_readiness; '
                "raise SystemExit(1 if {'app', 'config'} & sys.modules.keys() else 0)"
            ),
        ],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert list(tmp_path.rglob('*')) == []


def store_key(data_dir, user_id, key_id, key_content, metadata_type,
              filename=None):
    from app.key_encryption import encrypt_key_content

    keys_dir = data_dir / 'users' / f'user_{user_id}' / 'keys'
    keys_dir.mkdir(parents=True, exist_ok=True)
    filename = filename or f'{key_id}.pem'
    key_path = keys_dir / filename
    key_path.write_bytes(encrypt_key_content(str(user_id), key_content))
    return {
        'id': key_id,
        'name': f'name-{key_id}',
        'filename': filename,
        'key_type': metadata_type,
    }


def write_metadata(data_dir, user_id, entries):
    keys_dir = data_dir / 'users' / f'user_{user_id}' / 'keys'
    keys_dir.mkdir(parents=True, exist_ok=True)
    keys_file = keys_dir / 'keys.json'
    keys_file.write_text(
        json.dumps({'keys': entries}),
        encoding='utf-8',
    )
    return keys_file


def file_state(root):
    state = {}
    for path in sorted(p for p in root.rglob('*') if p.is_file()):
        relative = path.relative_to(root).as_posix()
        state[relative] = {
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'mtime_ns': path.stat().st_mtime_ns,
        }
    return state


def test_ready_for_real_rsa_ed25519_and_ecdsa_keys(
        tmp_path, rsa_private_key_pem, ed25519_private_key_pem,
        ecdsa_private_key_pem):
    from scripts.check_paramiko5_readiness import (
        audit_data_dir,
        readiness_exit_code,
    )

    entries = [
        store_key(tmp_path, 1, 'rsa-id', rsa_private_key_pem, 'RSA'),
        store_key(
            tmp_path,
            1,
            'ed25519-id',
            ed25519_private_key_pem,
            'RSA',
        ),
        store_key(tmp_path, 1, 'ecdsa-id', ecdsa_private_key_pem, 'ECDSA'),
    ]
    write_metadata(tmp_path, 1, entries)

    results = audit_data_dir(tmp_path)

    assert [item['actual_type'] for item in results] == [
        'RSA',
        'Ed25519',
        'ECDSA',
    ]
    assert all(item['compatible'] for item in results)
    assert readiness_exit_code(results) == 0
    assert results[1]['metadata_type'] == 'RSA'


def test_dsa_blocks_readiness(
        tmp_path, dsa_private_key_pem):
    from scripts.check_paramiko5_readiness import (
        audit_data_dir,
        readiness_exit_code,
    )

    entry = store_key(tmp_path, 2, 'dsa-id', dsa_private_key_pem, 'DSA')
    write_metadata(tmp_path, 2, [entry])

    results = audit_data_dir(tmp_path)

    assert results == [{
        'user_id': 2,
        'key_id': 'dsa-id',
        'metadata_type': 'DSA',
        'actual_type': 'DSA',
        'compatible': False,
    }]
    assert readiness_exit_code(results) == 2


def test_unparseable_key_blocks_readiness_without_leaking_content(tmp_path):
    from scripts.check_paramiko5_readiness import (
        audit_data_dir,
        readiness_exit_code,
    )

    marker = 'unparseable-private-marker'
    entry = store_key(tmp_path, 3, 'broken-id', marker, 'RSA')
    write_metadata(tmp_path, 3, [entry])

    results = audit_data_dir(tmp_path)
    serialized = json.dumps(results)

    assert results[0]['actual_type'] == 'UNPARSEABLE'
    assert results[0]['compatible'] is False
    assert marker not in serialized
    assert readiness_exit_code(results) == 2


def test_passphrase_encrypted_supported_key_passes_readiness(
        tmp_path, encrypted_rsa_private_key_pem):
    from scripts.check_paramiko5_readiness import (
        audit_data_dir,
        readiness_exit_code,
    )

    entry = store_key(
        tmp_path,
        4,
        'encrypted-id',
        encrypted_rsa_private_key_pem,
        'RSA',
    )
    write_metadata(tmp_path, 4, [entry])

    results = audit_data_dir(tmp_path)

    assert results[0]['actual_type'] == 'PASSPHRASE_ENCRYPTED'
    assert results[0]['compatible'] is True
    assert readiness_exit_code(results) == 0


def test_scan_does_not_change_key_bytes_or_metadata(
        tmp_path, rsa_private_key_pem):
    from scripts.check_paramiko5_readiness import audit_data_dir

    entry = store_key(tmp_path, 5, 'rsa-id', rsa_private_key_pem, 'RSA')
    write_metadata(tmp_path, 5, [entry])
    before = file_state(tmp_path)

    audit_data_dir(tmp_path)

    assert file_state(tmp_path) == before


def test_report_omits_names_filenames_paths_key_material_and_secret(
        tmp_path, rsa_private_key_pem, monkeypatch):
    from scripts.check_paramiko5_readiness import audit_data_dir

    secret_marker = 'readiness-secret-marker'
    import config
    original_secret = config.SECRET_KEY
    config.SECRET_KEY = secret_marker
    monkeypatch.setenv('SECRET_KEY', secret_marker)
    try:
        entry = store_key(tmp_path, 6, 'safe-id', rsa_private_key_pem, 'RSA')
        entry['name'] = 'configured-name-marker'
        entry['id'] = 'unsafe key-id marker'
        entry['key_type'] = 'metadata-secret-marker'
        entry['filename'] = 'filename-marker.pem'
        keys_dir = tmp_path / 'users' / 'user_6' / 'keys'
        original_key_path = keys_dir / 'safe-id.pem'
        renamed_key_path = keys_dir / entry['filename']
        original_key_path.rename(renamed_key_path)
        write_metadata(tmp_path, 6, [entry])

        serialized = json.dumps(audit_data_dir(tmp_path))
    finally:
        config.SECRET_KEY = original_secret

    assert 'configured-name-marker' not in serialized
    assert 'unsafe key-id marker' not in serialized
    assert 'metadata-secret-marker' not in serialized
    assert 'filename-marker.pem' not in serialized
    assert str(tmp_path) not in serialized
    assert 'BEGIN RSA PRIVATE KEY' not in serialized
    assert secret_marker not in serialized


def test_unsafe_parent_path_blocks_without_reading_outside_file(
        tmp_path, monkeypatch):
    import scripts.check_paramiko5_readiness as readiness

    sentinel = tmp_path / 'users' / 'user_7' / 'outside.pem'
    sentinel.parent.mkdir(parents=True)
    sentinel.write_text('outside-private-marker', encoding='utf-8')
    entry = {
        'id': 'unsafe-id',
        'name': 'unsafe-name',
        'filename': '../outside.pem',
        'key_type': 'RSA',
    }
    write_metadata(tmp_path, 7, [entry])
    read_paths = []
    original_reader = readiness.read_without_migration

    def recording_reader(user_id, key_path):
        read_paths.append(Path(key_path))
        return original_reader(user_id, key_path)

    monkeypatch.setattr(readiness, 'read_without_migration', recording_reader)

    results = readiness.audit_data_dir(tmp_path)

    assert results[0]['actual_type'] == 'READ_ERROR'
    assert results[0]['compatible'] is False
    assert read_paths == []
    assert 'outside-private-marker' not in json.dumps(results)
    assert readiness.readiness_exit_code(results) == 2


def test_symlinked_key_blocks_without_following_target(
        tmp_path, rsa_private_key_pem):
    from scripts.check_paramiko5_readiness import (
        audit_data_dir,
        readiness_exit_code,
    )

    keys_dir = tmp_path / 'users' / 'user_8' / 'keys'
    keys_dir.mkdir(parents=True)
    outside = tmp_path / 'outside-key.pem'
    outside.write_text(rsa_private_key_pem, encoding='utf-8')
    link = keys_dir / 'linked.pem'
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip('symlinks are unavailable in this test environment')
    write_metadata(tmp_path, 8, [{
        'id': 'linked-id',
        'name': 'linked-name',
        'filename': 'linked.pem',
        'key_type': 'RSA',
    }])

    results = audit_data_dir(tmp_path)

    assert results[0]['actual_type'] == 'READ_ERROR'
    assert results[0]['compatible'] is False
    assert readiness_exit_code(results) == 2


def test_malformed_metadata_is_a_blocker(tmp_path):
    from scripts.check_paramiko5_readiness import (
        audit_data_dir,
        readiness_exit_code,
    )

    keys_dir = tmp_path / 'users' / 'user_9' / 'keys'
    keys_dir.mkdir(parents=True)
    (keys_dir / 'keys.json').write_text('{invalid-json', encoding='utf-8')

    results = audit_data_dir(tmp_path)

    assert results[0]['user_id'] == 9
    assert results[0]['actual_type'] == 'READ_ERROR'
    assert results[0]['compatible'] is False
    assert results[0]['error_type'] == 'JSONDecodeError'
    assert readiness_exit_code(results) == 2
