"""Boundary cases written into a copy of the golden DATA_DIR by 3.3.x.

Every case uses the application function that produces the state in a real
installation. Where no current function writes it (older store versions,
NULL timestamps, interrupted operations, foreign database objects), the
state is constructed from the written current state with the transformation
the older code or the failure implies; each function says which.
"""

import base64
import json
import os
import sqlite3
from pathlib import Path

LEGACY_VAULT_PASSPHRASE = 'golden legacy vault passphrase v1'
LEGACY_VAULT_PASSWORD = 'legacy-vault-v1-password ✓'
NOTEPAD = 'Globaler Notizblock ✓\n日本語 notes\n\n- item 1\n'
STORE_PASSWORD = 'legacy-stores-password-1'
# Spec section 2 "Incarnation" vectors: stored text -> expected isoformat().
CREATED_AT_VECTORS = {
    'created_vector_a': ('2026-11-02 09:00:00.000000', '2026-11-02T09:00:00'),
    'created_vector_b': ('2026-11-02 09:00:00.250000+00:00', '2026-11-02T09:00:00.250000+00:00'),
    'created_vector_c': ('2026-11-02', '2026-11-02T00:00:00'),
    'created_vector_d': ('2026-11-02 09:00', '2026-11-02T09:00:00'),
    'created_vector_e': ('2026-11-02T09:00:01.5', '2026-11-02T09:00:01.500000'),
}


def _ok(result):
    value, error = result
    if error:
        raise RuntimeError(error)
    return value


def _register(name, password=STORE_PASSWORD):
    from app.auth import register_user
    return _ok(register_user(name, password))


def _read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def _write(path, document):
    # storage_utils.atomic_write_json writes indent=2, sorted keys off.
    from app.storage_utils import atomic_write_json
    atomic_write_json(Path(path), document)


def account_settings(owner_id, profile_ids):
    """Notepad, workspace presets, tour state, recovery review (save_user_settings)."""
    from app.user_settings import get_user_settings, save_user_settings
    presets = [{'id': 'golden-pair', 'name': 'Golden pair ✓', 'layout': 2,
                'profile_ids': profile_ids[:2]},
               {'id': 'golden-single', 'name': 'Single', 'layout': 1, 'profile_ids': []}]
    update = {'notepad': NOTEPAD, 'workspace_presets': presets,
              'intro_tour': 'completed', 'intro_tour_v3_acknowledged': True,
              'recovery_reviewed_at': '2026-11-02T10:00:00+00:00'}
    if not save_user_settings(owner_id, update):
        raise RuntimeError('settings rejected')
    stored = get_user_settings(owner_id)
    return {key: stored[key] for key in update}


def legacy_store_versions(key_content):
    """A user whose stores are at schema 1 and whose commands use the object form.

    No release wrote schema 1 (CURRENT_STORAGE_VERSIONS went from absent to 2
    in 131964f); 3.3.x still migrates it, so it is built from the 3.3.x
    document with ``schema_version`` 1. Profiles additionally lose
    ``startup_mode`` (introduced by migrate_profiles_v1_to_v2). commands.json
    gets the ``{"schema_version": 2, "commands": [...]}`` wrapper that the
    unreleased commits 131964f..973fe54 wrote (_PR_COMMAND_WRAPPER_VERSIONS).
    """
    from app.command_manager import add_user_command
    from app.command_set_manager import upsert_command_set
    from app.jump_host_manager import add_jump_host
    from app.key_manager import save_key
    from app.profile_manager import load_profiles, upsert_profile
    from app.smb_share_manager import upsert_smb_share
    from app.socks_proxy_manager import add_socks_proxy
    from app.user_settings import save_user_settings

    user = _register('legacy_stores')
    uid = user.id
    key = _ok(save_key(uid, 'Legacy schema key', key_content))
    jump = _ok(add_jump_host(uid, 'Legacy bastion', 'lbastion.golden.test', 22,
                             'jumper', 'key', key_id=key['id']))
    socks = _ok(add_socks_proxy(uid, 'Legacy SOCKS', 'lsocks.golden.test', 1080,
                                auth_type='none'))
    _ok(upsert_smb_share(uid, {'name': 'Legacy share', 'host': 'lfiles.golden.test',
                               'share': 'old', 'username': 'smb'}))
    command = add_user_command(uid, 'Legacy df', 'df -h', '', '', ['linux'], 'custom')
    _ok(upsert_command_set(uid, {'name': 'Legacy set', 'steps': [
        {'type': 'library', 'command_id': command['id']}]}))
    profiles = [_ok(upsert_profile(uid, payload)) for payload in (
        dict(name='Legacy password host', host='lpw.golden.test', username='op',
             auth_type='password'),
        dict(name='Legacy key host', host='lkey.golden.test', username='op',
             auth_type='key', key_id=key['id'], jump_host_id=jump['id']),
        dict(name='Legacy socks host', host='lsx.golden.test', username='op',
             auth_type='password', socks_proxy_id=socks['id']),
    )]
    save_user_settings(uid, {'theme': 'paper'})
    expected_profiles = load_profiles(uid)
    root = user.get_data_dir()
    for name in ('jump_hosts.json', 'socks_proxies.json', 'smb_shares.json',
                 'command_sets.json', 'settings.json', 'keys/keys.json'):
        document = _read(root / name)
        document['schema_version'] = 1
        _write(root / name, document)
    document = _read(root / 'profiles.json')
    document['schema_version'] = 1
    for profile in document['profiles']:
        profile.pop('startup_mode', None)
    _write(root / 'profiles.json', document)
    _write(root / 'commands.json', {'schema_version': 2, 'commands': _read(root / 'commands.json')})
    return uid, {'user_id': uid, 'username': 'legacy_stores', 'password': STORE_PASSWORD,
                 'key_id': key['id'], 'profiles': expected_profiles,
                 'command_id': command['id']}, profiles[0]


def profiles_schema_2(clock):
    """profiles.json at schema 2 with ``tailscale_authorized`` (v1.1.0 to v2.2.1)."""
    from app.profile_manager import load_profiles, upsert_profile
    user = _register('legacy_profiles_v2')
    _ok(upsert_profile(user.id, dict(name='Authorized v2 host', host='v2.golden.test',
                                     username='op', auth_type='password')))
    expected = load_profiles(user.id)
    path = user.get_data_dir() / 'profiles.json'
    document = _read(path)
    document['schema_version'] = 2
    for profile in document['profiles']:
        profile['tailscale_authorized'] = True
    _write(path, document)
    return {'user_id': user.id, 'username': 'legacy_profiles_v2',
            'password': STORE_PASSWORD, 'profiles': expected}


def vault_version_1(user_id, profile, stream):
    """automation-vault.json version 1: no ``generation``, AAD prefix v1.

    No release wrote version 1 (automation_vault.py entered in 960e84a
    writing version 2). Built from the 3.3.x reader (_valid, _decrypt, _aad).
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from app.automation_store import incarnation, profile_fingerprint, user_path
    from app.storage_utils import atomic_write_bytes
    salt, nonce = stream.read(16), stream.read(12)
    key = Scrypt(salt=salt, length=32, n=131072, r=8, p=1).derive(
        LEGACY_VAULT_PASSPHRASE.encode('utf-8'))
    records = {profile['id']: {'fingerprint': profile_fingerprint(profile),
                               'password': LEGACY_VAULT_PASSWORD}}
    aad = f'webssh-automation-vault-v1:{user_id}:{incarnation(user_id)}'.encode()
    ciphertext = AESGCM(key).encrypt(nonce, json.dumps(records, separators=(',', ':')).encode(), aad)
    encode = lambda value: base64.b64encode(value).decode('ascii')  # noqa: E731
    document = dict(version=1, kdf='scrypt-131072-8-1', salt=encode(salt),
                    nonce=encode(nonce), ciphertext=encode(ciphertext))
    atomic_write_bytes(user_path(user_id, 'automation-vault.json'),
                       json.dumps(document, separators=(',', ':')).encode())
    return {'user_id': user_id, 'passphrase': LEGACY_VAULT_PASSPHRASE,
            'aad': aad.decode(), 'profile_id': profile['id'],
            'password': LEGACY_VAULT_PASSWORD}


def created_at_accounts():
    """users.created_at NULL and the text vectors of spec section 2.

    No 3.3.x path writes these; databases imported from other tools or edited
    by hand hold them. The rows are created by register_user and the column
    is then set with SQL, as such a database stores it.
    """
    from sqlalchemy import text
    from app.models import db
    result = {}
    for name, (stored, expected) in {**CREATED_AT_VECTORS, 'created_null': (None, None)}.items():
        user = _register(name)
        db.session.execute(text('UPDATE users SET created_at = :v WHERE id = :i'),
                           {'v': stored, 'i': user.id})
        db.session.commit()
        result[name] = {'user_id': user.id, 'password': STORE_PASSWORD,
                        'created_at_text': stored, 'incarnation': expected}
    db.session.expire_all()
    return result


def interrupted_key_deletions(owner_id, key_content):
    """Both crash points of key_manager.delete_key.

    ``staged_only``: the file was renamed to ``.delete-<hex>-<file>``
    (_stage_key_deletion) and keys.json still lists it; the next load moves
    it back. ``metadata_saved``: keys.json no longer lists the key and the
    staged file was not removed (_remove_pending_key_entry did not run); the
    next load deletes it.
    """
    from app import key_manager
    staged = _ok(key_manager.save_key(owner_id, 'Interrupted delete (staged)', key_content))
    saved = _ok(key_manager.save_key(owner_id, 'Interrupted delete (saved)', key_content))
    keys_dir = key_manager.get_user_keys_dir(owner_id)
    original = key_manager._remove_pending_key_entry
    key_manager._remove_pending_key_entry = lambda *_a, **_k: False
    try:
        if not key_manager.delete_key(owner_id, saved['id']):
            raise RuntimeError('delete_key failed')
    finally:
        key_manager._remove_pending_key_entry = original
    # Staged last: every keys.json read reconciles pending entries.
    pending_staged = key_manager._stage_key_deletion(keys_dir, keys_dir / staged['filename'])
    pending_saved = next(p for p in keys_dir.iterdir()
                         if p.name.startswith('.delete-') and p.name.endswith(saved['filename']))
    rel = lambda p: f'data/users/user_{owner_id}/keys/{Path(p).name}'  # noqa: E731
    return {'staged_only': {'key_id': staged['id'], 'pending_file': rel(pending_staged),
                            'restored_file': rel(keys_dir / staged['filename'])},
            'metadata_saved': {'key_id': saved['id'], 'pending_file': rel(pending_saved)}}


def schedules(owner_id, deleted_former_id, deleted_incarnation, clock):
    """A stale claim and a schedule of a deleted account (copies of a real row).

    A worker killed after tick() claimed a slot leaves claim_id/claimed_at;
    a schedule survives delete_user_account because automation_schedules has
    no foreign key. Both rows are copies of the fixture's active schedule.
    """
    import copy
    from app.automation_schedule import AutomationSchedule
    from app.models import db
    source = AutomationSchedule.query.filter_by(user_id=owner_id, enabled=True).one()
    stale_at = clock.now.timestamp() - 7200
    rows = {
        'stale_claim': dict(id='00000000-0000-4000-8000-00000000c1a1', user_id=owner_id,
                            claim_id='c' * 48, claimed_at=stale_at, last_status='running',
                            grant=copy.deepcopy(source.grant)),
        'deleted_account': dict(id='00000000-0000-4000-8000-0000000de1e7',
                                user_id=deleted_former_id, claim_id=None, claimed_at=None,
                                last_status='waiting', grant=dict(
                                    copy.deepcopy(source.grant),
                                    account=[deleted_incarnation, 1, source.grant['account'][2]])),
    }
    for values in rows.values():
        db.session.add(AutomationSchedule(revision=source.revision, enabled=True,
                                          cron=source.cron, timezone=source.timezone,
                                          next_at=source.next_at, **values))
    db.session.commit()
    return {name: {'id': v['id'], 'user_id': v['user_id'], 'revision': source.revision,
                   'claimed_at': v['claimed_at'], 'account': v['grant']['account']}
            for name, v in rows.items()}


def orphan_host_context(owner_id, command_set_id):
    """Host context of a deleted profile: delete_profile does not prune it."""
    from app.host_context import write_context
    from app.profile_manager import delete_profile, upsert_profile
    profile = _ok(upsert_profile(owner_id, dict(name='Context orphan', host='orphan.golden.test',
                                                username='o', auth_type='password')))
    write_context(owner_id, profile['id'], {'notes': 'Orphaned notes ✓',
                                            'directories': ['/srv/orphan'],
                                            'command_sets': [command_set_id]}, 0)
    deleted = delete_profile(owner_id, profile['id'])
    if (deleted[0] if isinstance(deleted, tuple) else deleted) is not True:
        raise RuntimeError(f'delete_profile failed: {deleted!r}')
    return {'profile_id': profile['id'], 'notes': 'Orphaned notes ✓'}


def persistent_sessions(owner_id, stream):
    """ssh_sessions rows as socket_events stores tmux sessions (no live tmux)."""
    import uuid
    from app.models import SSHSession, db
    from app.ssh_gateway import tmux_name
    rows = [
        dict(host='pw.golden.test', port=22, username='operator', auth_type='password',
             is_persistent=True, display_name='Golden tmux ✓ 日本',
             tmux_session_name=f'webssh_operator_pw_golden_test_22_{uuid.uuid4().hex[:8]}'),
        dict(host='inner.golden.test', port=22, username='deploy:root', auth_type='key',
             is_persistent=True, display_name=None, via_jump='bastion.golden.test',
             tmux_session_name=tmux_name('webssh', 'inner.golden.test', 22, 'deploy:root', owner_id)),
        dict(host='min.golden.test', port=22, username='m', auth_type='password',
             is_persistent=False, display_name='Not persistent', tmux_session_name=None),
    ]
    result = []
    for values in rows:
        row = SSHSession(session_id=str(uuid.uuid4()), user_id=owner_id, connected=False, **values)
        db.session.add(row)
        result.append({'session_id': row.session_id, **values})
    db.session.commit()
    return result


def global_trust_and_fences(application, ldap_user_id, ca_line):
    """recovery-check.json, an LDAP revocation fence, an @cert-authority line."""
    import config
    from app.customer_workflows import mark_restore_recovery
    mark_restore_recovery(config.DATA_DIR)
    application.extensions['ldap_revocation_fence'].mark(ldap_user_id)
    # add_file_entry refuses @cert-authority; operators add such lines by hand.
    with open(config.KNOWN_HOSTS_FILE, 'a', encoding='utf-8') as handle:
        handle.write(ca_line + '\n')
    return {'recovery_check': _read(config.DATA_DIR / 'recovery-check.json'),
            'ldap_fence_user_id': ldap_user_id, 'cert_authority_line': ca_line}


def legacy_single_user_paths(data_dir, key_content):
    """Root-level stores of pre-multi-user installs (config.PROFILES_FILE etc.)."""
    data_dir = Path(data_dir)
    for name in ('commands', 'keys'):
        (data_dir / name).mkdir(mode=0o700, exist_ok=True)
    files = {
        'profiles.json': json.dumps({'profiles': [{'id': 'single-user-profile', 'name': 'Single user',
                                                    'host': 'single.golden.test', 'port': 22,
                                                    'username': 'root', 'auth_type': 'password'}]}, indent=2),
        'keys/keys.json': json.dumps({'keys': [{'id': 'single-user-key', 'name': 'Single key',
                                                 'filename': 'single-user-key.pem', 'key_type': 'ED25519'}]}, indent=2),
        'keys/single-user-key.pem': key_content,
        'commands/system_commands.json': json.dumps([{'id': 'legacy-sys', 'name': 'Legacy system',
                                                       'command': 'uname -a', 'os': ['linux']}], indent=2),
    }
    for name, content in files.items():
        path = data_dir / name
        path.write_text(content, encoding='utf-8')
        os.chmod(path, 0o600)
    return sorted(f'data/{name}' for name in files)


# 3.3.x refuses triggers and views in any database it backs up or restores
# (restore_database.harden_imported_database), so they are a variant.
TRIGGER_AND_VIEW = [
    'CREATE TRIGGER operator_users_touch AFTER UPDATE OF last_login ON users '
    'BEGIN UPDATE operator_notes SET note = note WHERE id = 1; END',
    'CREATE VIEW operator_admins AS SELECT id, username FROM users WHERE is_admin = 1',
]


def database_objects(database):
    """Objects 3.3.x never creates: statistics, an extra index, an unknown table."""
    statements = [
        'ANALYZE',
        'CREATE INDEX operator_users_last_login ON users (last_login)',
        'CREATE TABLE operator_notes (id INTEGER PRIMARY KEY, note TEXT)',
        "INSERT INTO operator_notes (note) VALUES ('added by an operator')",
    ]
    connection = sqlite3.connect(database)
    try:
        for statement in statements:
            connection.execute(statement)
        connection.commit()
    finally:
        connection.close()
    return {'statements': statements,
            'objects': ['sqlite_stat1', 'operator_users_last_login', 'operator_notes']}
