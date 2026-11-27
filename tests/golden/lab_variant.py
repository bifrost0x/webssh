"""Write a 3.3 data directory whose connections point at the test lab.

The Go lab test of the migration (cmd/webssh, build tag lab) migrates it
and connects over the migrated records. Everything is written through the
application's managers, as tests.golden.generate does, but with the real
clock and with hosts, keys and passwords of the shared lab (tests/lab):

    python -m tests.golden.lab_variant --out DIR --lab tests/lab/runtime/lab.json

DIR must not exist. The facts the Go test needs go to stdout as JSON.
"""

import argparse
import json
import sys
import tempfile
from pathlib import Path

from . import cookies, runtime

USERNAME = 'lab_owner'
PASSWORD = 'lab-owner-password-1'


def lab_environment(data_dir, work_dir):
    env = runtime.environment(data_dir, work_dir)
    env.update({
        'BLOCK_INTERNAL_SSH': 'false',
        'PROXY_JUMP_REMOTE_DNS_ALLOWLIST': 'ssh-inner.lab.test',
        'SOCKS_REMOTE_DNS_ALLOWLIST': 'ssh-inner.lab.test',
        'ADMIN_USERS': '',
    })
    return env


def _ok(result):
    value, error = result
    if error:
        raise RuntimeError(error)
    return value


def _host_key(runtime_dir, service):
    import base64

    import paramiko
    path = Path(runtime_dir) / 'ssh' / 'hostkeys' / service / 'ssh_host_ed25519_key.pub'
    _kind, data = path.read_text(encoding='ascii').split()[:2]
    return paramiko.Ed25519Key(data=base64.b64decode(data))


def _generate(lab):
    import config
    from app.app_settings import set_automation_enabled, set_credentials_enabled
    from app.auth import register_user
    from app.host_key_store import HostKeyStore
    from app.jump_host_manager import add_jump_host
    from app.key_manager import save_key
    from app.models import AuthenticationSession
    from app.profile_manager import upsert_profile
    from app.socks_proxy_manager import add_socks_proxy
    from app.automation_store import save_runbook

    services = lab['services']
    runtime_dir = Path(lab['runtime_dir'])
    pw = (runtime_dir / 'secrets' / 'ssh-pwuser').read_text(encoding='utf-8').splitlines()[0]
    key_pem = (runtime_dir / 'ssh' / 'client' / 'ed25519').read_text(encoding='ascii')

    application = runtime.create_application()
    with application.app_context():
        user, error = register_user(USERNAME, PASSWORD)
        if error:
            raise RuntimeError(error)
        set_credentials_enabled(True)
        set_automation_enabled(True)
        cookies.login_cookie(application, USERNAME, PASSWORD)
        auth_id = AuthenticationSession.query.filter_by(
            user_id=user.id).order_by(AuthenticationSession.id.desc()).first().id
        key, error = save_key(user.id, 'lab ed25519', key_pem)
        if error:
            raise RuntimeError(error)

        modern, bastion, socks = services['ssh-modern'], services['ssh-bastion'], services['socks-open']
        jump = _ok(add_jump_host(user.id, 'Lab bastion', bastion['host'], bastion['port'],
                                 'keyuser', 'key', key_id=key['id']))
        proxy = _ok(add_socks_proxy(user.id, 'Lab SOCKS', socks['host'], socks['port'],
                                    auth_type='none', remote_dns=True))
        profiles = {}
        for name, payload in {
            'direct': dict(name='Lab direct', host=modern['host'], port=modern['port'],
                           username='pwuser', auth_type='password'),
            'jump': dict(name='Lab via bastion', host='ssh-inner.lab.test', port=22,
                         username='keyuser', auth_type='key', key_id=key['id'],
                         jump_host_id=jump['id']),
            'socks': dict(name='Lab via SOCKS', host='ssh-inner.lab.test', port=22,
                          username='keyuser', auth_type='key', key_id=key['id'],
                          socks_proxy_id=proxy['id']),
        }.items():
            profiles[name] = _ok(upsert_profile(user.id, payload))

        store = HostKeyStore(user.id, config.KNOWN_HOSTS_FILE, config.USERS_DIR)
        store.record(f"[{modern['host']}]:{modern['port']}", _host_key(runtime_dir, 'ssh-modern'))
        store.record(f"[{bastion['host']}]:{bastion['port']}", _host_key(runtime_dir, 'ssh-bastion'))
        store.record('ssh-inner.lab.test', _host_key(runtime_dir, 'ssh-inner'))

        service = application.extensions['credentials']
        mutation = dict(method='create', resource_id=profiles['direct']['id'], confirm_target=True,
                        name='Lab password', username='pwuser', password=pw)
        token = service.prepare_vault(user.id, auth_id, dict(operation='native', mutation=mutation))['intent']
        service.apply_native_assignment(user.id, auth_id, token, mutation)

        book = save_runbook(user.id, dict(name='Lab identity', stop_on_error=False,
                                          steps=[dict(name='user', command='id -un', timeout=10, sudo=False)]))
        schedules = application.extensions['automation_schedules']
        preview = schedules.prepare(user.id, auth_id, dict(
            # Python runs automation without SOCKS5 (supported_login).
            runbook_id=book['id'], profile_ids=[profiles['direct']['id'], profiles['jump']['id']],
            cron='15 3 * * 1', timezone='Europe/Berlin'))
        schedule = schedules.apply(user.id, auth_id, preview['intent'], '2')
        facts = {
            'user_id': user.id, 'username': USERNAME, 'password': PASSWORD,
            'profiles': {name: p['id'] for name, p in profiles.items()},
            'runbook_id': book['id'], 'schedule_id': schedule['id'],
            'secret_key': application.config['SECRET_KEY'],
        }
    runtime.shutdown(application)
    return facts


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--lab', required=True, type=Path)
    args = parser.parse_args(argv)
    lab = json.loads(args.lab.read_text(encoding='utf-8'))
    data_dir = args.out.resolve()
    data_dir.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory() as work:
        runtime.apply_environment(lab_environment(data_dir, work))
        runtime.reload_config()
        runtime.import_application_modules()
        (data_dir / 'secret_key').write_text(runtime.secret_key() + '\n', encoding='ascii')
        (data_dir / 'secret_key').chmod(0o600)
        facts = _generate(lab)
    json.dump(facts, sys.stdout)


if __name__ == '__main__':
    main()
