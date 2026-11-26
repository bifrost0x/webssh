"""Generate the golden WebSSH data directory.

Usage (from the repository root, inside the project virtualenv)::

    python -m tests.golden.generate [--out DIR]

The default output is ``tests/golden/fixture``. An existing output directory
is replaced only if it holds a previous ``manifest.json`` from this tool.
"""

import argparse
import datetime as dt
import os
import shutil
import sys
import tempfile
from pathlib import Path

from . import runtime
from .determinism import Clock, deterministic

_MARKER = '.golden-output-in-progress'
# Written by tests.golden.legacy.build from older releases; a run of this
# generator keeps it.
LEGACY_DIRECTORY = 'legacy'


def _prepare_output(out, keep):
    if out.exists():
        if not any((out / name).is_file() for name in ('manifest.json', _MARKER)):
            raise SystemExit(f'refusing to replace {out}: not a golden output')
        legacy = out / LEGACY_DIRECTORY
        if legacy.is_dir():
            shutil.move(legacy, keep / LEGACY_DIRECTORY)
        shutil.rmtree(out)
    (out / 'artifacts' / 'backups').mkdir(parents=True)
    (out / _MARKER).write_text('in progress\n', encoding='ascii')


def _restore_kept(out, keep):
    if (keep / LEGACY_DIRECTORY).is_dir():
        shutil.move(keep / LEGACY_DIRECTORY, out / LEGACY_DIRECTORY)


def _write_secret_key(data_dir, value):
    # entrypoint.sh: (umask 077; printf '%s\n' "$_sk" > "$SECRET_KEY_FILE")
    path = data_dir / 'secret_key'
    path.write_text(value + '\n', encoding='ascii')
    path.chmod(0o600)


def _generate(out, data_dir, clock, stream):
    from . import accounts, cookies, factors, ssh_keys, stores
    from app.app_settings import set_automation_enabled, set_credentials_enabled
    from app.backup_manager import create_backup
    from app.models import AuthenticationSession, User, db
    from app.online_backup import (
        _create_online_recovery_snapshot, create_online_backup,
    )
    from app.session_epoch import current_epoch, rotate_epoch

    application = runtime.create_application()
    facts = {'epochs': {}}
    with application.app_context():
        facts['epochs']['initial'] = current_epoch()
        users = accounts.create_local_accounts(clock)
        admin = users['golden_admin']
        accounts.activate_security_features(admin.id)
        set_credentials_enabled(True)
        set_automation_enabled(True)
        accounts.create_ldap_account(clock)
        accounts.create_github_accounts(clock)
        accounts.create_oidc_identity(clock)
        facts['github_client_secret'] = accounts.configure_github(admin.id, clock)

        clock.advance(minutes=1)
        facts['totp'] = factors.enroll_totp(users['totp_user'], clock)
        facts['totp_pending'] = factors.pending_totp_enrollment(users['totp_user'])

        clock.advance(minutes=1)
        passkey_user = users['passkey_user']
        credentials = factors.register_passkeys(passkey_user, stream, clock)
        facts['passkey_recovery_codes'] = factors.enable_passkey_mfa(passkey_user)
        facts['webauthn_vectors'] = factors.assertion_vectors(
            passkey_user, credentials, stream)

        clock.advance(minutes=1)
        owner = users['local_user']
        login_before_rotation = cookies.login_cookie(
            application, 'local_user', accounts.PASSWORDS['local_user'])
        auth_id = AuthenticationSession.query.filter_by(
            user_id=owner.id).order_by(AuthenticationSession.id.desc()).first().id

        matrix = ssh_keys.build_matrix(stream)
        stored, rejected = ssh_keys.store_keys(owner.id, matrix)
        facts['ssh_keys'] = {'stored': stored, 'rejected': rejected}
        facts['ssh_keys']['legacy_plaintext'] = ssh_keys.store_legacy_plaintext_key(
            admin.id, next(i for i in matrix if i['label'] == 'ed25519-openssh'))
        key_ids = {item['label'].removesuffix('-openssh'): item['key_id']
                   for item in stored if item['format'] == 'openssh'}

        conn = stores.connections(owner.id, key_ids)
        facts['connections'] = conn
        profiles = conn['profiles']
        facts['host_identity'] = stores.host_identity(
            owner.id, profiles['Key server'], clock)
        facts['named_credential'] = stores.named_credentials(
            application, owner.id, auth_id, profiles['Password server'])
        facts['vault'] = stores.vault(application, owner.id, auth_id, profiles)
        facts['vault_passphrase'] = stores.VAULT_PASSPHRASE
        facts['host_keys'] = stores.host_keys(owner.id, stream)
        facts['automation'] = stores.automation(
            application, owner.id, auth_id, profiles['Password server'], clock)
        facts['commands'] = stores.commands(owner.id)
        facts['user_settings'] = stores.user_settings(owner.id)
        facts['edge_cases'] = _edge_cases(
            application, clock, owner, admin, users, auth_id, key_ids, matrix,
            facts)

        # Session epoch rotation revokes every cookie issued before it.
        clock.advance(minutes=1)
        facts['epochs']['rotated'] = rotate_epoch()
        clock.advance(minutes=1)
        valid = cookies.login_cookie(
            application, 'local_user', accounts.PASSWORDS['local_user'])
        linked = User.query.filter_by(username='github_linked').one()
        generation_cookie = cookies.login_cookie(
            application, 'github_linked', accounts.PASSWORDS['github_linked'])
        from app.auth_assurance import invalidate_user_authentication
        invalidate_user_authentication(linked)
        db.session.commit()

        clock.advance(minutes=3)
        verify_at = clock.now
        lifetime = application.permanent_session_lifetime
        facts['cookies'] = _cookie_set(
            application, clock, cookies, verify_at, lifetime, owner,
            valid=valid, before_rotation=login_before_rotation,
            generation=generation_cookie, admin_id=admin.id)
        facts['cookie_verify_at'] = verify_at

        clock.advance(minutes=1)
        backups = out / 'artifacts' / 'backups'
        facts['backups'] = {
            'export': create_backup(data_dir, backups / 'export.zip'),
            'online': create_online_backup(data_dir, backups / 'online.zip'),
            'recovery_snapshot': _create_online_recovery_snapshot(
                data_dir, backups / 'online-recovery-snapshot.zip'),
        }
        facts['users'] = _user_facts(application, User)
        facts['device_cookies'] = dict(cookies.LAST_DEVICE_COOKIE)
        facts['secret_key'] = application.config['SECRET_KEY']
    runtime.shutdown(application)
    return facts


_KINDS = {
    'golden_admin': 'local, administrator (first account)',
    'cfg_admin': 'local, administrator through ADMIN_USERS',
    'local_user': 'local, owner of all per-user stores',
    'limit_user': 'local, password exactly 72 UTF-8 bytes',
    'locked_user': 'local, locked by an administrator',
    'totp_user': 'local, TOTP MFA',
    'passkey_user': 'local, passkey MFA',
    'oidc_user': 'local with linked OIDC identity',
    'github_linked': 'local with linked GitHub identity; sessions revoked',
    'ldap_user': 'LDAP-managed (directory-provisioned)',
    'octo_golden': 'GitHub-managed (auto-provisioned)',
    'jörg_ünïcødé': 'legacy Unicode name; reuses the id of the deleted account',
}


def _user_facts(application, user_model):
    from . import accounts
    from app.browser_identity import connection_history_scope
    passwords = dict(accounts.PASSWORDS)
    passwords['jörg_ünïcødé'] = 'legacy-unicode-password-1'
    result = {}
    for user in user_model.query.order_by(user_model.id):
        result[user.username] = {
            'id': user.id,
            'kind': _KINDS[user.username],
            'created_at_db': user.created_at.isoformat(),
            'is_admin': bool(user.is_admin),
            'is_locked': bool(user.is_locked),
            'mfa_enabled': bool(user.mfa_enabled),
            'auth_generation': int(user.auth_generation or 0),
            'password': passwords.get(user.username),
            'password_login_allowed': user.username in passwords
                and not user.is_locked and not user.mfa_enabled,
            'connection_history_scope': connection_history_scope(
                user, application.config['SECRET_KEY']),
        }
    return result


def _edge_cases(application, clock, owner, admin, users, auth_id, key_ids,
                matrix, facts):
    from . import accounts, edge_cases, stores
    command_set_id = facts['commands']['command_sets'][0]['id']
    profiles = facts['connections']['profiles']
    ed25519 = next(i for i in matrix if i['label'] == 'ed25519-openssh')
    result = {
        'profiles': edge_cases.profiles(owner.id, key_ids, command_set_id),
        'keys': edge_cases.keys(owner.id, ed25519),
        'named_credentials': edge_cases.named_credentials(application, owner.id),
        'vault_long_password': edge_cases.vault_long_password(
            application, owner.id, auth_id, profiles['Via SOCKS'],
            stores.VAULT_PASSPHRASE),
        'automation': edge_cases.automation(
            application, owner.id, auth_id, profiles['Password server'], clock),
        'commands': edge_cases.commands(owner.id),
        'routes': edge_cases.routes(owner.id, key_ids['ed25519']),
        'host_key_deleted': edge_cases.host_key_deletion(owner.id),
        'recovery_code': edge_cases.consume_recovery_code(
            users['totp_user'], facts['totp']['recovery_codes']),
        'passkey_deleted': edge_cases.delete_passkey(users['passkey_user']),
        'deleted_account': edge_cases.deleted_account(
            application, accounts.PASSWORDS['local_user'], clock),
        'legacy_unicode_account': edge_cases.legacy_unicode_account(clock),
        'admin_settings': edge_cases.admin_settings(),
    }
    result['host_context'] = edge_cases.host_context(
        owner.id, result['profiles']['unicode'], command_set_id)
    return result


def _cookie_set(application, clock, cookies, verify_at, lifetime, owner, *,
                valid, before_rotation, generation, admin_id):
    expired = cookies.resign_at(
        application, valid, clock, verify_at - lifetime - dt.timedelta(seconds=1))
    accept = {'accepted': True}
    return [
        cookies.describe(application, 'valid', valid, accept,
                         'Fresh login after the epoch rotation.'),
        cookies.describe(application, 'expired_signature', expired,
                         {'accepted': False, 'reason': 'signature_age'},
                         'Payload of "valid", signed 8 h + 1 s before verify_at.'),
        cookies.describe(application, 'revoked_epoch', before_rotation,
                         {'accepted': False, 'reason': 'session_epoch'},
                         '_auth_epoch holds the epoch before rotate_epoch().'),
        cookies.describe(application, 'revoked_generation', generation,
                         {'accepted': False, 'reason': 'auth_generation'},
                         'invalidate_user_authentication() ran after login.'),
        cookies.describe(application, 'tampered_signature',
                         cookies.tamper_signature(valid),
                         {'accepted': False, 'reason': 'signature'},
                         'First signature character changed.'),
        cookies.describe(application, 'tampered_payload',
                         cookies.tamper_payload(application, valid,
                                                user_id_prefix=admin_id),
                         {'accepted': False, 'reason': 'signature'},
                         'Payload claims the admin id; original signature kept.'),
        cookies.describe(application, 'foreign_key',
                         cookies.foreign_key(application, valid),
                         {'accepted': False, 'reason': 'signature'},
                         'Signed with a secret that is not the fixture key.'),
    ]


def _ensure_fixed_hash_seed(argv):
    """Re-run with PYTHONHASHSEED=0: set iteration order reaches the schema.

    SQLAlchemy emits CREATE INDEX statements in set order, so the SQLite file
    differs between runs under hash randomization.
    """
    if os.environ.get('PYTHONHASHSEED') == '0':
        return
    environment = dict(os.environ, PYTHONHASHSEED='0')
    arguments = sys.argv[1:] if argv is None else list(argv)
    os.execve(sys.executable,
              [sys.executable, '-m', 'tests.golden.generate', *arguments],
              environment)


def main(argv=None):
    _ensure_fixed_hash_seed(argv)
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--out', type=Path, default=runtime.FIXTURE_ROOT)
    args = parser.parse_args(argv)
    out = args.out.resolve()
    with tempfile.TemporaryDirectory(prefix='webssh-golden-') as work:
        keep = Path(work) / 'kept'
        keep.mkdir()
        _prepare_output(out, keep)
        try:
            data_dir = Path(work) / 'data'
            data_dir.mkdir(mode=0o700)
            runtime.apply_environment(runtime.environment(data_dir, work))
            _write_secret_key(data_dir, runtime.secret_key())
            runtime.import_application_modules()
            clock = Clock(runtime.START)
            with deterministic(runtime.SEED, clock,
                               bcrypt_rounds=runtime.BCRYPT_ROUNDS) as stream:
                facts = _generate(out, data_dir, clock, stream)
            from .manifest import write_manifest
            from .packing import pack_data_dir
            write_manifest(out, facts, data_dir)
            pack_data_dir(data_dir, out / runtime.DATA_ARCHIVE)
        finally:
            out.mkdir(parents=True, exist_ok=True)
            _restore_kept(out, keep)
    (out / _MARKER).unlink()
    return 0


if __name__ == '__main__':
    sys.exit(main())
