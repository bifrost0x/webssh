"""Write legacy data through the functions of an old WebSSH release.

Runs inside the virtual environment and source tree of that release (the
orchestrator ``build.py`` starts it with ``cwd`` = the release checkout)::

    python old_driver.py STAGE DATA_DIR FACTS_JSON [BACKUP_ZIP]

Stages and the release they belong to:

* ``initial`` (2fcd38a, "Initial release", January 2026): accounts without
  role columns, profiles without validation or ``startup_mode``, DSA,
  passphrase-protected and PKCS#8 keys, a filled notepad.
* ``v1.0.0`` (tag v1.0.0): the upgrade of that DATA_DIR; jump host, command
  set, profiles with startup modes, more user commands and set steps than
  3.3.x allows, a persistent tmux row, admin settings without a schema.
* ``backup_v1`` (8c41517, last main commit before #71): start on a copy of
  the upgraded DATA_DIR and write a backup archive in format version 1.

Only the standard library, the release's own dependencies and two helper
modules of the golden data set (loaded by path) are used.
"""

import base64
import importlib.util
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
SEED = 'webssh-golden-legacy-v1'
STARTS = {'initial': (2026, 1, 24, 10, 0, 0), 'v1.0.0': (2026, 7, 24, 10, 0, 0),
          'backup_v1': (2026, 8, 3, 10, 0, 0)}
PASSWORDS = {'pioneer_admin': 'pioneer-admin-password-1',
             'pioneer_user': 'pioneer-user-password-1',
             'release_user': 'release-user-password-1',
             'bulk_user': 'bulk-user-password-1'}
KEY_PASSPHRASE = 'pioneer-key-passphrase'
NOTEPAD = 'Pioneer notepad ✓\nZeile 2: ünïcødé\n'
LONG_NAME = 'Ł' * 200
BULK_COMMANDS = 501   # 3.3.x COMMAND_MAX_RECORDS default is 500
BULK_SET_STEPS = 65   # 3.3.x COMMAND_SET_MAX_STEPS default is 64


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


determinism = _load('_golden_determinism', _HERE.parent / 'determinism.py')
key_material = _load('_golden_key_material', _HERE.parent / 'key_material.py')
old_keys = _load('_golden_old_keys', _HERE / 'old_keys.py')


def _ok(result):
    value, error = result
    if error:
        raise RuntimeError(error)
    return value


def _b64(text):
    return base64.b64encode(text.encode('utf-8')).decode('ascii')


def _initial(clock, stream):
    from app import create_app
    from app.auth import register_user
    from app.command_manager import add_user_command
    from app.key_manager import save_key
    from app.profile_manager import add_profile
    from app.user_settings import save_user_settings

    application = create_app()
    facts = {'users': {}, 'keys': {}, 'profiles': {}}
    with application.app_context():
        for name in ('pioneer_admin', 'pioneer_user'):
            user = _ok(register_user(name, PASSWORDS[name]))
            facts['users'][name] = {'id': user.id, 'password': PASSWORDS[name]}
            clock.advance(minutes=1)
        owner = facts['users']['pioneer_user']['id']
        rsa = key_material.rsa_key(stream, 2048)
        material = {
            'rsa_openssh': old_keys.openssh_pem(rsa),
            'dsa_pem': old_keys.traditional_pem(old_keys.dsa_key(stream)),
            'rsa_pem_passphrase': old_keys.encrypted_traditional_pem(
                key_material.rsa_key(stream, 2048), KEY_PASSPHRASE, stream),
            'ed25519_pkcs8': old_keys.pkcs8_pem(key_material.ed25519_key(stream)),
        }
        for label, content in material.items():
            meta = _ok(save_key(owner, f'Pioneer {label}', content))
            facts['keys'][label] = {
                'key_id': meta['id'], 'filename': meta['filename'],
                'key_type': meta['key_type'], 'plaintext_b64': _b64(content),
                'stored_file': f"data/users/user_{owner}/keys/{meta['filename']}"}
            clock.advance(seconds=10)
        for label, args in (
            ('password', ('Pioneer password', 'pw.pioneer.test', 22, 'operator', 'password')),
            ('key', ('Pioneer key', 'key.pioneer.test', '2222', 'deploy', 'key',
                     facts['keys']['rsa_openssh']['key_id'])),
            ('dsa', ('Pioneer DSA', 'dsa.pioneer.test', 22, 'legacy', 'key',
                     facts['keys']['dsa_pem']['key_id'])),
            ('long_name', (LONG_NAME, 'long.pioneer.test', 22, 'u', 'password')),
        ):
            facts['profiles'][label] = _ok(add_profile(owner, *args))['id']
            clock.advance(seconds=10)
        facts['command'] = add_user_command(owner, 'Pioneer uptime', 'uptime', '',
                                            'Show uptime', ['linux'], 'custom')['id']
        save_user_settings(owner, {'notepad': NOTEPAD, 'theme': 'retro'})
        facts['notepad'] = NOTEPAD
    return facts


def _v100(clock, stream):
    import uuid
    from app import create_app
    from app.app_settings import set_registration_enabled
    from app.auth import register_user
    from app.command_manager import add_user_command
    from app.command_set_manager import upsert_command_set
    from app.jump_host_manager import add_jump_host
    from app.models import SSHSession, User, db
    from app.profile_manager import upsert_profile

    application = create_app()
    facts = {'users': {}, 'profiles': {}}
    with application.app_context():
        owner = User.query.filter_by(username='pioneer_user').one()
        previous = json.loads(Path(sys.argv[3]).with_name('initial.json').read_text())
        keys = previous['keys']
        for name in ('release_user', 'bulk_user'):
            user = _ok(register_user(name, PASSWORDS[name]))
            facts['users'][name] = {'id': user.id, 'password': PASSWORDS[name]}
            clock.advance(minutes=1)
        jump = _ok(add_jump_host(owner.id, 'Pioneer bastion', 'bastion.pioneer.test', 22,
                                 'jumper', 'key', key_id=keys['rsa_openssh']['key_id']))
        facts['jump_host'] = jump['id']
        command_set = _ok(upsert_command_set(owner.id, {
            'name': 'Pioneer set', 'steps': [
                {'type': 'library', 'command_id': previous['command']},
                {'type': 'inline', 'command': 'df -h /'}]}))
        facts['command_set'] = command_set['id']
        for label, payload in (
            ('free_text', dict(name='Release free text', host='ft.release.test',
                               username='op', auth_type='password',
                               startup_commands='cd /srv\nls -la')),
            ('command_set', dict(name='Release set', host='set.release.test',
                                 username='op', auth_type='key',
                                 key_id=keys['rsa_openssh']['key_id'],
                                 jump_host_id=jump['id'],
                                 command_set_id=command_set['id'])),
            ('tailscale', dict(name='Release tailscale', host='ts.release.test',
                               username='op', auth_type='tailscale')),
        ):
            facts['profiles'][label] = _ok(upsert_profile(owner.id, payload))['id']
            clock.advance(seconds=10)
        bulk = facts['users']['bulk_user']['id']
        commands = [add_user_command(bulk, f'Bulk {i:03d}', f'echo {i}', '', '', ['all'], 'custom')['id']
                    for i in range(BULK_COMMANDS)]
        bulk_set = _ok(upsert_command_set(bulk, {
            'name': 'Bulk steps', 'steps': [{'type': 'inline', 'command': f'echo step {i}'}
                                            for i in range(BULK_SET_STEPS)]}))
        facts['bulk'] = {'commands': len(commands), 'command_set': bulk_set['id'],
                         'set_steps': BULK_SET_STEPS}
        # A persistent tmux session row as ssh_manager.create_ssh_connection
        # records it; the remote tmux itself cannot exist in the fixture.
        suffix = uuid.uuid4().hex[:8]
        tmux = f'webssh_pioneer_user_key_pioneer_test_2222_{suffix}'
        row = SSHSession(session_id=str(uuid.uuid4()), user_id=owner.id,
                         host='key.pioneer.test', port=2222, username='deploy',
                         connected=False, is_persistent=True,
                         key_id=keys['rsa_openssh']['key_id'], auth_type='key',
                         tmux_session_name=tmux, display_name='Pioneer tmux ✓')
        db.session.add(row)
        db.session.commit()
        facts['ssh_session'] = {'session_id': row.session_id, 'tmux_session_name': tmux,
                                'display_name': row.display_name, 'user_id': owner.id}
        set_registration_enabled(False)
    return facts


def _backup_v1(clock, stream):
    from app import create_app
    from app.backup_manager import create_backup
    from app.models import User
    from app.profile_manager import upsert_profile

    application = create_app(start_runtime=False)
    with application.app_context():
        owner = User.query.filter_by(username='release_user').one()
        profile = _ok(upsert_profile(owner.id, dict(
            name='Backup era host', host='backup.release.test', username='op',
            auth_type='password')))
        clock.advance(minutes=1)
        manifest = create_backup(Path(sys.argv[2]), Path(sys.argv[4]))
    application.extensions['runtime_lifecycle'].begin_shutdown(1)
    return {'profile': profile['id'], 'format_version': manifest.format_version,
            'files': [dict(path=f.path, sha256=f.sha256, size=f.size) for f in manifest.files]}


STAGES = {'initial': _initial, 'v1.0.0': _v100, 'backup_v1': _backup_v1}


def main():
    import datetime as dt
    stage = sys.argv[1]
    clock = determinism.Clock(dt.datetime(*STARTS[stage], tzinfo=dt.timezone.utc))
    with determinism.deterministic(f'{SEED}:{stage}', clock, bcrypt_rounds=12) as stream:
        # Import the release inside the patched context so that default
        # callables bound at import time (datetime.utcnow) read the clock.
        facts = STAGES[stage](clock, stream)
    Path(sys.argv[3]).write_text(json.dumps(facts, indent=1, sort_keys=True,
                                            ensure_ascii=False) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
