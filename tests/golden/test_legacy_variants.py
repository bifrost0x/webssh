"""3.3.x behaviour for the exclusive variants and the 3.3.x-written backups."""

import base64
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from tests.golden import runtime
from tests.golden.legacy.harness import (
    EXTENDED, MAIN, MANIFEST, ROOT, apply_overlay, decode, extract, started,
)

VARIANTS = MANIFEST['variants']
BACKUPS = MANIFEST['backups']
SECRET = MANIFEST['secret_key']['value']
# The entrypoint of the Python release (tests/conftest.py, WEBSSH_PYTHON_ROOT).
ENTRYPOINT = Path(os.environ['WEBSSH_PYTHON_ROOT']) / 'entrypoint.sh'


@pytest.fixture
def data_dir(tmp_path):
    return extract('datadir-extended.tar', tmp_path)


@pytest.mark.parametrize('name', ['recovery_check_malformed', 'recovery_check_oversized'])
def test_recovery_check_variants_are_treated_as_absent(name, data_dir, tmp_path):
    apply_overlay(data_dir, VARIANTS[name])
    with started(data_dir, tmp_path):
        from app.customer_workflows import _restore_marker
        assert _restore_marker() is VARIANTS[name]['expected']['restore_marker']


def test_app_settings_schema_1_is_migrated(data_dir, tmp_path):
    apply_overlay(data_dir, VARIANTS['app_settings_schema_1'])
    with started(data_dir, tmp_path):
        from app.app_settings import is_support_links_enabled
        assert is_support_links_enabled() is False
    assert json.loads((data_dir / 'app_settings.json').read_text())['schema_version'] == 2


def test_database_trigger_and_view(data_dir, tmp_path):
    variant = VARIANTS['database_trigger_and_view']
    connection = sqlite3.connect(data_dir / 'app.db')
    for statement in variant['sql']:
        connection.execute(statement)
    connection.commit()
    connection.close()
    with started(data_dir, tmp_path):
        from app.auth import authenticate_user
        from app.backup_manager import BackupIntegrityError, create_backup
        users = MAIN['values']['users']
        assert authenticate_user('local_user', users['local_user']['password'])[0] is not None
        with pytest.raises(BackupIntegrityError, match=variant['expected']['create_backup_error']):
            create_backup(data_dir, tmp_path / 'refused.zip')


def test_admin_users_naming_a_missing_account(data_dir, tmp_path):
    variant = VARIANTS['admin_users_missing_account']
    with started(data_dir, tmp_path, variant['environment']):
        from app.models import User
        assert User.query.filter_by(username='ghost_admin').first() is None
        assert User.query.filter_by(username='cfg_admin').one().is_admin


def _entrypoint(data_dir, tmp_path, environment, legacy_file=None):
    script = ENTRYPOINT.read_text(encoding='utf-8')
    if legacy_file is not None:
        # Only the constant changes; the resolution logic is the release's.
        script = script.replace('LEGACY_SECRET_KEY_FILE="/app/data/secret_key"',
                                f'LEGACY_SECRET_KEY_FILE="{legacy_file}"')
    path = tmp_path / 'entrypoint.sh'
    path.write_text(script, encoding='utf-8')
    env = {'PATH': f'{Path(sys.executable).parent}:/usr/bin:/bin', 'HOME': str(tmp_path),
           'DATA_DIR': str(data_dir)}
    env.update({k: v for k, v in environment.items() if v is not None})
    resolved = tmp_path / 'resolved-secret'
    result = subprocess.run(['bash', str(path), 'python', '-c',
                             'import os, sys; open(sys.argv[1], "wb").write(os.environ["SECRET_KEY"].encode())',
                             str(resolved)], env=env, capture_output=True)
    result.secret = resolved.read_bytes() if resolved.exists() else None
    return result


@pytest.mark.parametrize('name', ['secret_key_crlf', 'secret_key_placeholder_env', 'secret_key_empty_file'])
def test_secret_key_resolution(name, data_dir, tmp_path):
    variant = VARIANTS[name]
    apply_overlay(data_dir, variant)
    result = _entrypoint(data_dir, tmp_path, variant['environment'])
    assert result.returncode == 0, result.stderr
    expected = decode(variant['expected']['entrypoint_secret_key_b64'])
    assert result.secret == expected
    if 'data_decrypts' in variant['expected']:
        from cryptography.fernet import Fernet, InvalidToken
        key_file = next((data_dir / f"users/user_{MAIN['values']['users']['local_user']['id']}/keys").glob('*.pem'))
        derived = hashlib.pbkdf2_hmac('sha256', f"{expected.decode()}:{MAIN['values']['users']['local_user']['id']}".encode(),
                                      b'webssh_key_encryption_v1', 600000, 32)
        fernet = Fernet(base64.urlsafe_b64encode(derived))
        try:
            fernet.decrypt(key_file.read_bytes())
            decrypts = True
        except InvalidToken:
            decrypts = False
        assert decrypts is variant['expected']['data_decrypts']
    if variant['expected'].get('python_starts') is False:
        env = dict(os.environ, SECRET_KEY=expected.decode(), DEBUG='false', DATA_DIR=str(data_dir))
        started_ok = subprocess.run([sys.executable, '-c', 'import config'], env=env,
                                    cwd=ENTRYPOINT.parent, capture_output=True)
        assert started_ok.returncode != 0 and b'SECRET_KEY' in started_ok.stderr


def test_secret_key_conflicting_legacy_path(data_dir, tmp_path):
    variant = VARIANTS['secret_key_conflicting_legacy_path']
    legacy = tmp_path / 'app-data' / 'secret_key'
    legacy.parent.mkdir()
    legacy.write_bytes(decode(variant['legacy_secret_key_file']))
    result = _entrypoint(data_dir, tmp_path, variant['environment'], legacy_file=legacy)
    assert result.returncode == variant['expected']['entrypoint_exit']
    assert variant['expected']['stderr'] in result.stderr.decode()


@pytest.mark.parametrize('state', sorted(EXTENDED['restore_status']['documents']))
def test_restore_status_states(state, data_dir, tmp_path):
    template = EXTENDED['restore_status']
    with started(data_dir, tmp_path):
        from app import maintenance_mode
        from app.backup_coordination import ensure_backup_temp_dir
        document = dict(template['documents'][state])
        if document.get('data_fingerprint') == '{DATA_FINGERPRINT}':
            document['data_fingerprint'] = maintenance_mode._data_fingerprint()
        (ensure_backup_temp_dir() / 'restore-status.json').write_text(json.dumps(document))
        maintenance_mode._state = maintenance_mode._state_path = None
        try:
            assert maintenance_mode.is_active() is template['expected'][state]['maintenance_active']
        finally:
            (ensure_backup_temp_dir() / 'restore-status.json').unlink()
            maintenance_mode._state = maintenance_mode._state_path = None


def _members(name):
    with zipfile.ZipFile(ROOT / 'backups' / name) as archive:
        return set(archive.namelist())


def test_python_backups_verify_and_restore(tmp_path):
    from app.backup_manager import restore_backup, verify_backup
    cases = {'with-go-dir.zip': 'data/go/webssh.db', 'with-logs-members.zip': 'data/logs/app.log',
             'outdated-secret-key.zip': 'data/secret_key'}
    for name, member in cases.items():
        assert member in _members(name), name
        target = tmp_path / name / 'data'
        target.mkdir(parents=True, mode=0o700)
        (target / 'logs').mkdir(mode=0o700)
        (target / 'logs' / 'app.log').write_text('existing\n')
        with started(target, tmp_path / name):
            manifest = verify_backup(ROOT / 'backups' / name)
            expected = BACKUPS[f'backups/{name}']
            assert [f.path for f in manifest.files] == [f['path'] for f in expected['files']]
            restore_backup(ROOT / 'backups' / name, target)
        # Restore never replaces the audit trail with archived log files.
        log = (target / 'logs' / 'app.log').read_text()
        assert log.startswith('existing\n') and 'edited archive' not in log
        if name == 'with-go-dir.zip':
            assert (target / 'go' / 'webssh.db').is_file()
        if name == 'outdated-secret-key.zip':
            assert (target / 'secret_key').read_text().strip() == expected['archived_secret_key']
            assert expected['archived_secret_key'] != SECRET
        shutil.rmtree(target.parent)
    assert runtime.secret_key() == SECRET
