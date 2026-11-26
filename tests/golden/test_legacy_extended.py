"""3.3.x reads every boundary case of the extended DATA_DIR correctly.

datadir-extended.tar is the golden DATA_DIR plus the cases of
migration-spec 8.2 (see legacy manifest ``cases``).
"""

import datetime as dt
import json

import pytest

from tests.golden.legacy.harness import EXTENDED, MAIN, extract, started

USERS = MAIN['values']['users']
OWNER = USERS['local_user']['id']


@pytest.fixture(scope='module')
def extended(tmp_path_factory):
    work = tmp_path_factory.mktemp('extended')
    data_dir = extract('datadir-extended.tar', work)
    with started(data_dir, work) as application:
        yield application, data_dir


def test_notepad_presets_and_tour_state(extended):
    from app.user_settings import get_user_settings
    settings = get_user_settings(OWNER)
    for key, value in EXTENDED['account_settings'].items():
        assert settings[key] == value, key
    assert settings['notepad'].startswith('Globaler Notizblock')


def test_store_files_at_schema_1_and_commands_object_form(extended):
    from app.command_manager import load_user_commands
    from app.command_set_manager import load_command_sets
    from app.jump_host_manager import load_jump_hosts
    from app.key_manager import load_keys
    from app.profile_manager import load_profiles
    from app.smb_share_manager import load_smb_shares
    from app.socks_proxy_manager import load_socks_proxies
    from app.user_settings import get_user_settings
    case = EXTENDED['legacy_stores']
    uid = case['user_id']
    assert load_profiles(uid) == case['profiles']
    assert [k['id'] for k in load_keys(uid)] == [case['key_id']]
    assert [c['id'] for c in load_user_commands(uid)] == [case['command_id']]
    assert len(load_command_sets(uid)[0]) == 1
    assert len(load_jump_hosts(uid)) == len(load_socks_proxies(uid)) == len(load_smb_shares(uid)) == 1
    assert get_user_settings(uid)['theme'] == 'paper'


def test_profiles_schema_2_drop_tailscale_authorized(extended):
    from app.profile_manager import load_profiles
    case = EXTENDED['profiles_schema_2']
    profiles = load_profiles(case['user_id'])
    assert profiles == case['profiles']
    assert all('tailscale_authorized' not in p for p in profiles)


def test_vault_version_1_unlocks_read_only(extended):
    application, data_dir = extended
    from app.profile_manager import load_profiles
    case = EXTENDED['vault_v1']
    vault = application.extensions['credentials'].vault
    path = vault.path(case['user_id'])
    before = path.read_bytes()
    assert json.loads(before)['version'] == 1
    vault.unlock(case['user_id'], 'golden-lease', case['passphrase'])
    profile = next(p for p in load_profiles(case['user_id']) if p['id'] == case['profile_id'])
    assert vault.password(case['user_id'], 'golden-lease', profile) == case['password']
    vault.lock(case['user_id'])
    assert path.read_bytes() == before
    from app.automation_store import AutomationError
    with pytest.raises(AutomationError):
        vault.unlock(case['user_id'], 'golden-lease', 'a wrong but long passphrase')


def test_created_at_vectors_and_null(extended):
    from app.auth import authenticate_user
    from app.automation_store import incarnation
    from app.browser_identity import connection_history_scope
    from app.models import User, db
    application, _ = extended
    for name, case in EXTENDED['created_at'].items():
        user = db.session.get(User, case['user_id'])
        assert authenticate_user(name, case['password'])[0] == user
        scope = connection_history_scope(user, application.config['SECRET_KEY'])
        assert len(scope) == 64
        if case['incarnation'] is None:
            assert user.created_at is None
            with pytest.raises(AttributeError):
                incarnation(user.id)
        else:
            assert incarnation(user.id) == case['incarnation'], name


def test_interrupted_key_deletions_reconcile(extended, tmp_path):
    from app.key_manager import load_keys
    _, data_dir = extended
    root = data_dir.parent
    case = EXTENDED['interrupted_key_deletions']
    pristine = extract('datadir-extended.tar', tmp_path).parent
    assert (pristine / case['staged_only']['pending_file']).is_file()
    assert not (pristine / case['staged_only']['restored_file']).exists()
    assert (pristine / case['metadata_saved']['pending_file']).is_file()
    keys = {k['id'] for k in load_keys(OWNER)}
    assert case['staged_only']['key_id'] in keys
    assert case['metadata_saved']['key_id'] not in keys
    assert (root / case['staged_only']['restored_file']).is_file()
    assert not (root / case['staged_only']['pending_file']).exists()
    assert not (root / case['metadata_saved']['pending_file']).exists()


def test_stale_claim_and_deleted_account_schedule(extended):
    from app.automation_schedule import AutomationSchedule
    from app.models import db
    application, _ = extended
    service = application.extensions['automation_schedules']
    stale = EXTENDED['schedules']['stale_claim']
    foreign = EXTENDED['schedules']['deleted_account']
    assert foreign['id'] not in {row['id'] for row in service.list(foreign['user_id'])}
    listed = {row['id']: row for row in service.list(OWNER)}
    assert listed[stale['id']]['running'] is True
    service.tick(now=dt.datetime(2026, 11, 2, 10, 30, tzinfo=dt.timezone.utc))
    db.session.expire_all()
    row = db.session.get(AutomationSchedule, stale['id'])
    assert (row.enabled, row.last_status, row.claim_id, row.revision) == (False, 'unknown', None, stale['revision'] + 1)
    assert db.session.get(AutomationSchedule, foreign['id']).enabled is True


def test_host_context_of_deleted_profile_stays_hidden(extended):
    from app.host_context import ContextError, read_context
    _, data_dir = extended
    case = EXTENDED['orphan_host_context']
    stored = json.loads((data_dir / f'users/user_{OWNER}/host_context.json').read_text())
    assert stored['hosts'][case['profile_id']]['notes'] == case['notes']
    with pytest.raises(ContextError):
        read_context(OWNER, case['profile_id'])


def test_persistent_sessions_are_reconnect_candidates(extended):
    from app.models import SSHSession
    rows = SSHSession.query.filter_by(user_id=OWNER, is_persistent=True, connected=False).all()
    expected = [s for s in EXTENDED['persistent_sessions'] if s['is_persistent']]
    assert sorted((r.session_id, r.tmux_session_name, r.display_name) for r in rows) == sorted(
        (s['session_id'], s['tmux_session_name'], s['display_name']) for s in expected)
    assert any('_wg_' in s['tmux_session_name'] for s in expected)


def test_recovery_check_fence_and_cert_authority(extended):
    import config
    from app.customer_workflows import _restore_marker
    from app.host_key_store import HostKeyStore
    from app.ldap_session import ldap_revocation_pending
    application, _ = extended
    case = EXTENDED['trust_and_fences']
    assert _restore_marker() == case['recovery_check']['restored_at']
    assert ldap_revocation_pending(application, case['ldap_fence_user_id'])
    assert not ldap_revocation_pending(application, OWNER)
    assert case['cert_authority_line'] in config.KNOWN_HOSTS_FILE.read_text()
    check = HostKeyStore(OWNER, config.KNOWN_HOSTS_FILE, config.USERS_DIR).trust_checker()
    assert check('bastion.golden.test', 22) and not check('a.ca.golden.test', 22)


def test_foreign_database_objects_and_single_user_paths(extended):
    import sqlite3
    from app.auth import authenticate_user
    from app.command_manager import load_system_commands
    _, data_dir = extended
    assert authenticate_user('local_user', USERS['local_user']['password'])[0] is not None
    connection = sqlite3.connect(data_dir / 'app.db')
    names = {row[0] for row in connection.execute('SELECT name FROM sqlite_master')}
    connection.close()
    assert set(EXTENDED['database_objects']['objects']) <= names
    for path in EXTENDED['legacy_single_user_paths']:
        assert (data_dir.parent / path).is_file()
    assert 'legacy-sys' not in {c.get('id') for c in load_system_commands()}
