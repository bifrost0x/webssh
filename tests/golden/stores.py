"""Connections, saved credentials, vault, automation and host trust.

Everything is written through the application's managers and services. The
logged-in authentication session of the owner supplies the ``auth_id`` that
the credential and vault services bind to.
"""

import datetime as dt

from . import key_material

VAULT_PASSPHRASE = 'golden automation vault passphrase'
NAMED_PASSWORD = 'golden-named-credential-password'
VAULT_PASSWORDS = {
    'Password server': 'golden-vault-password-ssh',
    'Unicode server': 'pässwörd-✓-golden',
}


def _ok(result):
    value, error = result
    if error:
        raise RuntimeError(error)
    return value


def connections(user_id, key_ids):
    """Profiles of every kind plus jump host, SOCKS proxy and SMB share."""
    from app.jump_host_manager import add_jump_host
    from app.profile_manager import upsert_profile
    from app.smb_share_manager import upsert_smb_share
    from app.socks_proxy_manager import add_socks_proxy

    jump = _ok(add_jump_host(user_id, 'Golden bastion', 'bastion.golden.test',
                             22, 'jumper', 'key', key_id=key_ids['ed25519']))
    socks = _ok(add_socks_proxy(user_id, 'Golden SOCKS', 'socks.golden.test',
                                1080, auth_type='none'))
    smb = _ok(upsert_smb_share(user_id, {
        'name': 'Golden share', 'host': 'files.golden.test',
        'share': 'public', 'domain': 'GOLDEN', 'username': 'smbuser',
    }))
    profiles = {}
    for payload in (
        dict(name='Password server', host='pw.golden.test', port=22,
             username='operator', auth_type='password'),
        dict(name='Unicode server', host='uni.golden.test', port=2222,
             username='op.erator-2', auth_type='password'),
        dict(name='Key server', host='key.golden.test', port=22,
             username='deploy', auth_type='key', key_id=key_ids['rsa2048']),
        dict(name='Via bastion', host='inner.golden.test', port=22,
             username='deploy', auth_type='key', key_id=key_ids['ecdsa-p256'],
             jump_host_id=jump['id']),
        dict(name='Via SOCKS', host='proxied.golden.test', port=22,
             username='deploy', auth_type='password',
             socks_proxy_id=socks['id']),
    ):
        profiles[payload['name']] = _ok(upsert_profile(user_id, payload))
    return {'profiles': profiles, 'jump_host': jump, 'socks_proxy': socks,
            'smb_share': smb}


def host_identity(user_id, profile, clock):
    """Detected host facts cached on a profile after an identity probe."""
    from app import host_platform
    from app.profile_manager import cache_detected_facts
    identity = {'state': 'detected', 'platform': 'debian', 'family': None,
                'os_id': None, 'os_version': '13', 'virt': 'vm',
                'graphical': False, 'guests': None,
                'services': ['docker', 'nextcloud'], 'container_access': 'ok'}
    cache_detected_facts(user_id, profile['id'], host_platform.endpoint(profile),
                         identity=identity, now=clock.now)
    return identity


def named_credentials(application, user_id, auth_id, profile):
    """Saved password record assigned to a profile (native intent flow)."""
    service = application.extensions['credentials']
    mutation = dict(method='create', resource_id=profile['id'],
                    confirm_target=True, name='Golden saved password',
                    username='operator', password=NAMED_PASSWORD)
    token = service.prepare_vault(
        user_id, auth_id, dict(operation='native', mutation=mutation),
    )['intent']
    service.apply_native_assignment(user_id, auth_id, token, mutation)
    document = service.named.read(user_id)
    record_id = document['assignments'][profile['id']]['credential_id']
    return {'record_id': record_id, 'resource_id': profile['id'],
            'password': NAMED_PASSWORD}


def vault(application, user_id, auth_id, profiles):
    vault_service = application.extensions['credentials'].vault
    vault_service.setup(user_id, auth_id, VAULT_PASSPHRASE)
    for name, password in VAULT_PASSWORDS.items():
        vault_service.put(user_id, auth_id, profiles[name], password)
    vault_service.lock(user_id)
    return {name: {'profile_id': profiles[name]['id'], 'password': password}
            for name, password in VAULT_PASSWORDS.items()}


def automation(application, user_id, auth_id, profile, clock):
    from app.automation_store import save_runbook
    book = save_runbook(user_id, dict(
        name='Golden check',
        steps=[dict(name='Identity', command='id', timeout=5, sudo=False),
               dict(name='Disk', command='df -h /', timeout=30, sudo=True)],
        stop_on_error=False,
    ))
    schedules = application.extensions['automation_schedules']
    preview = schedules.prepare(user_id, auth_id, dict(
        runbook_id=book['id'], profile_ids=[profile['id']],
        cron='15 3 * * 1', timezone='Europe/Berlin',
    ), now=clock.now)
    schedule = schedules.apply(user_id, auth_id, preview['intent'], '1',
                               now=clock.now)
    return {'runbook': book, 'schedule_id': schedule['id']}


def commands(user_id):
    from app.command_manager import add_user_command
    from app.command_set_manager import upsert_command_set
    command = add_user_command(user_id, 'Golden uptime', 'uptime', '',
                               'Show uptime', ['all'], 'custom')
    plain = _ok(upsert_command_set(user_id, {
        'name': 'Golden bootstrap',
        'steps': [{'type': 'inline', 'command': 'uptime'}],
    }))
    parameterized = _ok(upsert_command_set(user_id, {
        'name': 'Golden inspect path', 'parameters': [{'name': 'path'}],
        'steps': [{'type': 'argv', 'argv': ['ls', '-la', '{{path}}']}],
    }))
    return {'user_command': command, 'command_sets': [plain, parameterized]}


def _paramiko_key(private_key):
    from cryptography.hazmat.primitives import serialization as ser
    from app.ssh_key_loader import load_private_key
    pem = private_key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.OpenSSH,
                                    ser.NoEncryption()).decode('ascii')
    return load_private_key(pem)


def host_keys(user_id, stream):
    """Per-user trusted keys plus global trust including a revoked entry."""
    import config
    from app.host_key_store import HostKeyStore

    store = HostKeyStore(user_id, config.KNOWN_HOSTS_FILE, config.USERS_DIR)
    keys = {
        'ed25519': key_material.ed25519_key(stream),
        'ecdsa': key_material.ec_key(stream, 'nistp256'),
        'rsa': key_material.rsa_key(stream, 2048),
    }
    paramiko_keys = {name: _paramiko_key(key) for name, key in keys.items()}
    user_entries = [('pw.golden.test', 'ed25519'),
                    ('[uni.golden.test]:2222', 'ecdsa'),
                    ('key.golden.test', 'rsa')]
    for hostname, name in user_entries:
        store.record(hostname, paramiko_keys[name])
    global_lines = [
        f'bastion.golden.test {paramiko_keys["ed25519"].get_name()} '
        f'{paramiko_keys["ed25519"].get_base64()}',
        f'@revoked compromised.golden.test {paramiko_keys["rsa"].get_name()} '
        f'{paramiko_keys["rsa"].get_base64()}',
    ]
    for line in global_lines:
        _ok(HostKeyStore.add_file_entry(
            config.KNOWN_HOSTS_FILE, line, scope='global', owner_id=None,
            lock_key='host_keys:global',
        ))
    return {
        'user_entries': [
            {'host': h, 'key_type': paramiko_keys[n].get_name(),
             'fingerprint_sha256': paramiko_keys[n].fingerprint}
            for h, n in user_entries
        ],
        'global_lines': global_lines,
    }


def user_settings(user_id):
    from app.user_settings import get_user_settings, save_user_settings
    settings = dict(get_user_settings(user_id))
    settings['start_page'] = 'overview'
    settings['confirm_session_close'] = True
    save_user_settings(user_id, settings)
    return get_user_settings(user_id)


def now_iso(clock):
    return clock.now.astimezone(dt.timezone.utc).isoformat()
