"""3.3.x reads the DATA_DIRs and the backup written by older releases.

The archives come from the releases themselves (tests/golden/legacy/build.py
runs 2fcd38a, v1.0.0 and 8c41517 in their own virtualenvs). Expected values
are the legacy manifest's; every check goes through 3.3.x functions.
"""

import hashlib
import zipfile

import pytest

from tests.golden.legacy.harness import (
    MAIN, MANIFEST, PASSWORDS, ROOT, decode, extract, release_values, started,
)
from tests.golden.legacy.old_driver import BULK_COMMANDS, BULK_SET_STEPS, KEY_PASSPHRASE, LONG_NAME, NOTEPAD

INITIAL = release_values('datadir-2fcd38a.tar')
UPGRADE = release_values('datadir-v1.0.0.tar')
BACKUP = MANIFEST['backups']['backups/backup-v1-8c41517.zip']


def test_main_manifest_holds_the_vault_passphrase():
    from tests.golden.stores import VAULT_PASSPHRASE
    assert MAIN['values']['vault_passphrase'] == VAULT_PASSPHRASE
    assert MANIFEST['secret_key']['value'] == MAIN['secret_key']['value']


def test_legacy_inventory_and_releases():
    for entry in MANIFEST['files']:
        content = (ROOT / entry['path']).read_bytes()
        assert len(content) == entry['size'], entry['path']
        assert hashlib.sha256(content).hexdigest() == entry['sha256'], entry['path']
    listed = {e['path'] for e in MANIFEST['files']}
    present = {p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*')
               if p.is_file() and p.name != 'manifest.json'}
    assert listed == present
    commits = {name: info['commit'][:7] for name, info in MANIFEST['releases'].items()}
    assert commits == {'initial': '2fcd38a', 'v1.0.0': '9e73b60', 'backup_v1': '8c41517'}


@pytest.fixture
def initial(tmp_path):
    data_dir = extract('datadir-2fcd38a.tar', tmp_path)
    with started(data_dir, tmp_path) as application:
        yield application, data_dir


@pytest.fixture
def upgraded(tmp_path):
    data_dir = extract('datadir-v1.0.0.tar', tmp_path)
    with started(data_dir, tmp_path) as application:
        yield application, data_dir


def test_initial_release_accounts_gain_role_columns(initial):
    from app.auth import authenticate_user
    from app.models import User
    users = {u.username: u for u in User.query.order_by(User.id)}
    assert set(users) == set(INITIAL['users'])
    # ensure_user_columns: only the oldest pre-existing account becomes admin.
    assert users['pioneer_admin'].is_admin and not users['pioneer_user'].is_admin
    for name, user in users.items():
        assert authenticate_user(name, PASSWORDS[name])[0] == user


def test_initial_release_profiles_get_startup_mode(initial):
    from app.profile_manager import load_profiles
    owner = INITIAL['users']['pioneer_user']['id']
    profiles = {p['id']: p for p in load_profiles(owner)}
    assert set(profiles) == set(INITIAL['profiles'].values())
    assert {p['startup_mode'] for p in profiles.values()} == {'none'}
    long_profile = profiles[INITIAL['profiles']['long_name']]
    assert long_profile['name'] == LONG_NAME and len(long_profile['name']) == 200
    assert profiles[INITIAL['profiles']['key']]['port'] == 2222


def test_initial_release_keys_decrypt_and_unsupported_keys_stay_listed(initial):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from app.key_encryption import read_key_content
    from app.key_manager import load_keys
    from app.ssh_key_loader import load_private_key
    _, data_dir = initial
    owner = INITIAL['users']['pioneer_user']['id']
    listed = {k['id']: k for k in load_keys(owner)}
    assert set(listed) == {k['key_id'] for k in INITIAL['keys'].values()}
    errors = {}
    for label, key in INITIAL['keys'].items():
        plaintext = decode(key['plaintext_b64']).decode()
        stored = data_dir.parent / key['stored_file']
        assert read_key_content(owner, str(stored), migrate_legacy=False) == plaintext
        assert listed[key['key_id']]['key_type'] == key['key_type']
        try:
            load_private_key(plaintext)
        except Exception as error:  # noqa: BLE001 - the message is the contract
            errors[label] = str(error)
    assert errors == {
        'dsa_pem': 'DSA private keys are not supported; use Ed25519, ECDSA, or RSA',
        'rsa_pem_passphrase': 'Passphrase-encrypted private keys are not supported',
        'ed25519_pkcs8': 'Unsupported or invalid private key format',
    }
    protected = decode(INITIAL['keys']['rsa_pem_passphrase']['plaintext_b64'])
    assert load_pem_private_key(protected, KEY_PASSPHRASE.encode()).key_size == 2048


def test_initial_release_notepad_and_commands(initial):
    from app.command_manager import load_user_commands
    from app.user_settings import get_user_settings
    owner = INITIAL['users']['pioneer_user']['id']
    settings = get_user_settings(owner)
    assert settings['notepad'] == NOTEPAD and settings['theme'] == 'retro'
    assert [c['id'] for c in load_user_commands(owner)] == [INITIAL['command']]


def test_upgraded_release_stores_and_limits(upgraded):
    from app.app_settings import is_registration_enabled
    from app.command_manager import load_user_commands
    from app.command_set_manager import load_command_sets
    from app.jump_host_manager import load_jump_hosts
    from app.profile_manager import load_profiles
    owner = INITIAL['users']['pioneer_user']['id']
    profiles = {p['id']: p for p in load_profiles(owner)}
    free_text = profiles[UPGRADE['profiles']['free_text']]
    assert free_text['startup_mode'] == 'free_text' and free_text['startup_commands'] == 'cd /srv\nls -la'
    via_set = profiles[UPGRADE['profiles']['command_set']]
    assert via_set['startup_mode'] == 'command_set' and via_set['jump_host_id'] == UPGRADE['jump_host']
    assert profiles[UPGRADE['profiles']['tailscale']]['auth_type'] == 'tailscale'
    assert [j['id'] for j in load_jump_hosts(owner)] == [UPGRADE['jump_host']]
    bulk = UPGRADE['users']['bulk_user']['id']
    # Above COMMAND_MAX_RECORDS (500) and COMMAND_SET_MAX_STEPS (64): still read.
    assert len(load_user_commands(bulk)) == BULK_COMMANDS
    sets, error = load_command_sets(bulk)
    assert error is None and len(sets[0]['steps']) == BULK_SET_STEPS
    assert is_registration_enabled() is False


def test_upgraded_release_persistent_tmux_row(upgraded):
    from app.models import SSHSession
    expected = UPGRADE['ssh_session']
    rows = SSHSession.query.filter_by(user_id=expected['user_id'], is_persistent=True,
                                      connected=False).all()
    assert [(r.session_id, r.tmux_session_name, r.display_name) for r in rows] == [
        (expected['session_id'], expected['tmux_session_name'], expected['display_name'])]
    assert rows[0].via_socks is False and rows[0].reconnect_route_known is False


def test_backup_format_1_verifies_and_restores(tmp_path):
    from app.backup_manager import evaluate_backup_compatibility, restore_backup, verify_backup
    archive = ROOT / 'backups' / 'backup-v1-8c41517.zip'
    with zipfile.ZipFile(archive) as backup:
        assert b'"format_version":1' in backup.read('manifest.json')
    target = tmp_path / 'restored'
    target.mkdir(mode=0o700)
    with started(target, tmp_path):
        manifest = verify_backup(archive)
        assert manifest.format_version == 1 and manifest.data_schema_version == 0
        assert [f.path for f in manifest.files] == [f['path'] for f in BACKUP['values']['files']]
        compatibility = evaluate_backup_compatibility(manifest)
        assert compatibility.compatible and compatibility.legacy
        restore_backup(archive, target)
    with started(target, tmp_path / 'second'):
        from app.auth import authenticate_user
        from app.profile_manager import load_profiles
        from app.models import User
        assert {u.username for u in User.query} == set(PASSWORDS)
        assert authenticate_user('release_user', PASSWORDS['release_user'])[0] is not None
        owner = UPGRADE['users']['release_user']['id']
        assert BACKUP['values']['profile'] in {p['id'] for p in load_profiles(owner)}
