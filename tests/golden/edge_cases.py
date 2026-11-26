"""Boundary values for every user-created entity type.

Unicode, values at or beyond the documented limits, empty optional fields,
deleted and disabled objects. Each function returns what a migration must
reproduce (or must not resurrect).
"""

UNICODE_NAME = 'Ünïcødé ✓ 服务器 🚀 עברית'
LONG_PROFILE_NAME = 'Ł' * 200  # profile_manager keeps name.strip()[:128]
LONG_PASSWORD = ('pässwört-✓-' * 400).encode('utf-8')[:4096].decode('utf-8', 'ignore')


def _ok(result):
    value, error = result
    if error:
        raise RuntimeError(error)
    return value


def _deleted(result):
    """Delete helpers return a bool or a tuple starting with one."""
    ok = result[0] if isinstance(result, tuple) else result
    if ok is not True:
        raise RuntimeError(f'deletion failed: {result!r}')


def profiles(user_id, key_ids, command_set_id):
    from app.profile_manager import (
        assign_command_set, delete_profile, update_profile_organization,
        upsert_profile,
    )
    unicode_profile = _ok(upsert_profile(user_id, dict(
        name=UNICODE_NAME, host='unicode.golden.test', port=65535,
        username='root', auth_type='key', key_id=key_ids['ed25519'],
        group='Grüppe/日本', favorite=True)))
    long_profile = _ok(upsert_profile(user_id, dict(
        name=LONG_PROFILE_NAME, host='2001:db8::10', port=1,
        username='u', auth_type='password')))
    minimal = _ok(upsert_profile(user_id, dict(
        name='Minimal', host='min.golden.test', username='m',
        auth_type='password')))
    _ok(update_profile_organization(user_id, minimal['id'], {'group': ''}))
    _ok(assign_command_set(user_id, unicode_profile['id'], command_set_id))
    doomed = _ok(upsert_profile(user_id, dict(
        name='Deleted profile', host='gone.golden.test', username='gone',
        auth_type='password')))
    _deleted(delete_profile(user_id, doomed['id']))
    return {'unicode': unicode_profile['id'], 'long_name': long_profile['id'],
            'stored_long_name': LONG_PROFILE_NAME[:128],
            'minimal': minimal['id'], 'deleted': doomed['id']}


def keys(user_id, item):
    from app.key_manager import delete_key, save_key
    unicode_key = _ok(save_key(user_id, ('Schlüssel ✓ ' * 12)[:128], item['content']))
    doomed = _ok(save_key(user_id, 'deleted key', item['content']))
    _deleted(delete_key(user_id, doomed['id']))
    too_long = save_key(user_id, 'x' * 129, item['content'])
    return {'unicode_128_chars': unicode_key['id'], 'deleted': doomed['id'],
            'name_129_chars_error': too_long[1]}


def named_credentials(application, user_id):
    service = application.extensions['credentials']
    unassigned = service.create_named(user_id, dict(
        name=UNICODE_NAME, username='', password=LONG_PASSWORD))
    doomed = service.create_named(user_id, dict(
        name='Deleted credential', username='x', password='deleted-secret'))
    service.delete_named(user_id, doomed['id'])
    return {'unassigned_unicode': {'record_id': unassigned['id'],
                                   'username': '', 'password': LONG_PASSWORD},
            'deleted': doomed['id']}


def vault_long_password(application, user_id, auth_id, profile, passphrase):
    vault = application.extensions['credentials'].vault
    vault.unlock(user_id, auth_id, passphrase)
    vault.put(user_id, auth_id, profile, LONG_PASSWORD)
    vault.lock(user_id)
    return {'profile_id': profile['id'], 'password': LONG_PASSWORD}


def automation(application, user_id, auth_id, profile, clock):
    from app.automation_store import delete_runbook, save_runbook
    big = save_runbook(user_id, dict(
        name=UNICODE_NAME,
        steps=[dict(name=f'Schritt {i} ✓', command=f'echo {i}',
                    timeout=300 if i == 19 else 1, sudo=i % 2 == 0)
               for i in range(20)]))
    doomed = save_runbook(user_id, dict(
        name='Deleted runbook',
        steps=[dict(name='x', command='true', timeout=5, sudo=False)]))
    delete_runbook(user_id, doomed['id'])
    schedules = application.extensions['automation_schedules']
    # Schedules resolve passwords from saved-credential assignments only.
    preview = schedules.prepare(user_id, auth_id, dict(
        runbook_id=big['id'], profile_ids=[profile['id']],
        cron='*/5 * * * *', timezone='UTC'), now=clock.now)
    paused = schedules.apply(user_id, auth_id, preview['intent'], '1',
                             now=clock.now)
    schedules.pause(user_id, paused['id'])
    history = _run_history(application, user_id, big, profile, clock)
    return {'runbook_20_steps': big['id'], 'deleted_runbook': doomed['id'],
            'paused_schedule': paused['id'], 'run_history': history}


def _run_history(application, user_id, book, profile, clock):
    """One finished run as AutomationService._persist stores it."""
    service = application.extensions['automation']
    record = {
        'id': 'golden-run-0001', 'name': book['name'], 'runbook_id': book['id'],
        'created_at': clock.now.isoformat(), 'finished_at': clock.now.isoformat(),
        'status': 'failed',
        'targets': [{
            'id': profile['id'], 'name': profile['name'], 'host': profile['host'],
            'port': profile['port'], 'username': profile['username'],
            'group': None, 'status': 'failed', 'reason': None,
            'steps': [{'name': 'Schritt 0 ✓', 'status': 'failed', 'exit_code': 1,
                       'duration': 0.25, 'reason': None, 'stdout': 'ünïcødé\n',
                       'stderr': 'boom\n', 'output_truncated': False}],
        }],
    }
    service._persist(user_id, record)
    return record


def commands(user_id):
    from app.command_manager import add_user_command, delete_user_command
    from app.command_set_manager import delete_command_set, upsert_command_set
    unicode_command = add_user_command(
        user_id, UNICODE_NAME, 'printf "%s\\n" "ünïcødé"', '', '', ['linux'],
        'custom')
    doomed_command = add_user_command(user_id, 'Deleted command', 'true', '',
                                      '', ['all'], 'custom')
    _deleted(delete_user_command(user_id, doomed_command['id']))
    unicode_set = _ok(upsert_command_set(user_id, {
        'name': UNICODE_NAME, 'description': '',
        'steps': [{'type': 'library', 'command_id': unicode_command['id']}]}))
    doomed_set = _ok(upsert_command_set(user_id, {
        'name': 'Deleted set', 'steps': [{'type': 'inline', 'command': 'true'}]}))
    _deleted(delete_command_set(user_id, doomed_set['id']))
    return {'unicode_command': unicode_command['id'],
            'deleted_command': doomed_command['id'],
            'unicode_set': unicode_set['id'], 'deleted_set': doomed_set['id']}


def routes(user_id, key_id):
    from app.jump_host_manager import add_jump_host, delete_jump_host
    from app.smb_share_manager import delete_smb_share, upsert_smb_share
    from app.socks_proxy_manager import add_socks_proxy
    socks = _ok(add_socks_proxy(user_id, UNICODE_NAME, 'socks2.golden.test',
                                65535, auth_type='password',
                                username='sockenmann', remote_dns=False))
    smb = _ok(upsert_smb_share(user_id, {
        'name': UNICODE_NAME, 'host': 'files2.golden.test',
        'share': 'Dateien', 'username': 'smb'}))
    doomed_jump = _ok(add_jump_host(user_id, 'Deleted bastion',
                                    'gone-bastion.golden.test', 22, 'x',
                                    'key', key_id=key_id))
    _deleted(delete_jump_host(user_id, doomed_jump['id']))
    doomed_smb = _ok(upsert_smb_share(user_id, {
        'name': 'Deleted share', 'host': 'gone.golden.test', 'share': 'x',
        'username': 'x'}))
    _deleted(delete_smb_share(user_id, doomed_smb['id']))
    return {'socks_with_auth': socks['id'], 'smb_unicode_empty_domain': smb['id'],
            'deleted_jump_host': doomed_jump['id'], 'deleted_smb': doomed_smb['id']}


def host_context(user_id, profile_id, command_set_id):
    from app.host_context import write_context
    return write_context(user_id, profile_id, {
        'notes': ('Notizen ✓ 日本語\n' * 200),
        'directories': ['/srv/ünïcødé', '/var/log'],
        'command_sets': [command_set_id],
    }, 0)


def host_key_deletion(user_id):
    import config
    from app.host_key_store import HostKeyStore
    store = HostKeyStore(user_id, config.KNOWN_HOSTS_FILE, config.USERS_DIR)
    entry = next(e for e in store.list_entries() if 'key.golden.test' in str(e))
    store.delete_entry(entry['id'])
    return {'deleted_host': 'key.golden.test'}


def consume_recovery_code(user, codes):
    from app.recovery_service import consume_code
    if not consume_code(user.id, codes[0]):
        raise RuntimeError('recovery code was not accepted')
    return {'consumed': codes[0], 'remaining': codes[1:]}


def delete_passkey(user):
    """Passkey removal deletes the row (app/webauthn_routes.py)."""
    from app.models import WebAuthnCredential, db
    row = WebAuthnCredential.query.filter_by(
        user_id=user.id, name='Golden removed').one()
    removed = {'id': row.id, 'credential_id_hex': bytes(row.credential_id).hex()}
    db.session.delete(row)
    db.session.commit()
    return removed


def deleted_account(application, password, clock):
    """Admin delete: lock, invalidate, then delete_user_account (quarantine)."""
    from app.auth import register_user
    from app.auth_assurance import invalidate_user_authentication
    from app.models import db
    from app.profile_manager import upsert_profile
    from app.user_lifecycle import delete_user_account

    clock.advance(seconds=1)
    user, error = register_user('deleted_user', password)
    if error:
        raise RuntimeError(error)
    _ok(upsert_profile(user.id, dict(name='Orphan', host='orphan.golden.test',
                                     username='o', auth_type='password')))
    user_id = user.id
    user.is_locked = True
    invalidate_user_authentication(user)
    db.session.commit()
    quarantined = delete_user_account(user)
    return {'former_id': user_id,
            'quarantine_dir': str(quarantined.relative_to(quarantined.parents[1]))}


def legacy_unicode_account(clock):
    """A pre-validation account name (new names must be ASCII).

    app/auth.py validate_new_user: existing accounts keep their names; the
    row is written through the model like an old installation did.
    """
    from app.models import User, db
    clock.advance(seconds=1)
    user = User(username='jörg_ünïcødé', is_admin=False)
    user.set_password('legacy-unicode-password-1')
    db.session.add(user)
    db.session.commit()
    user.get_data_dir()
    return {'username': user.username, 'password': 'legacy-unicode-password-1'}


def admin_settings():
    from app.app_settings import update_admin_settings
    return {name: list(change) for name, change in update_admin_settings(
        {'support_links_enabled': False}).items()}
