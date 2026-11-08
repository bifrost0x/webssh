#!/usr/bin/env python3
"""Upgrade a real 2.x container data volume to a candidate image and back.

The check seeds a data volume with the published previous image, then starts
the candidate on the same volume three ways: with the old example Compose
environment, with the current example Compose environment, and again with the
previous image (rollback). Each stage verifies readiness, the effective Admin
switches and that hosts, jump hosts and SSH keys survive and still decrypt.

Usage:
    python scripts/check_container_upgrade.py --old-image IMAGE --new-image IMAGE
"""
import argparse
import json
import re
import secrets
import subprocess
import sys
import time

# Environment of the example Compose shipped with 2.x.
LEGACY_ENVIRONMENT = {'TMUX_ENABLED': 'true', 'TMUX_DEFAULT': 'false', 'SFTP_CHMOD_ENABLED': 'true'}
BASE_ENVIRONMENT = {'DEPLOYMENT_PROFILE': 'homelab', 'SESSION_COOKIE_SECURE': 'false'}
SEED_PASSWORD = 'Upgrade-Check-' + secrets.token_hex(8)

SEED = r'''
import os, sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from app import create_app, db
from app.models import User
app = create_app()
with app.app_context():
    from app import key_manager, profile_manager, jump_host_manager
    from app.app_settings import set_registration_enabled
    user = User(username='upgrade', is_admin=True)
    user.set_password(os.environ['SEED_PASSWORD'])
    db.session.add(user)
    db.session.commit()
    user.get_data_dir()
    pem = ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption()).decode()
    key_manager.save_key(user.id, 'upgrade-key', pem)
    key_id = key_manager.load_keys(user.id)[0]['id']
    jump_host_manager.add_jump_host(user.id, 'bastion', '10.0.0.1', 22, 'ops', 'key', key_id)
    jump_id = jump_host_manager.load_jump_hosts(user.id)[0]['id']
    profile_manager.add_profile(user.id, 'web', '10.0.0.10', 22, 'root', 'key', key_id, jump_id)
    profile_manager.add_profile(user.id, 'db', '10.0.0.11', 2222, 'pg', 'password')
    set_registration_enabled(False)
print('SEEDED', flush=True)
os._exit(0)
'''

INSPECT = r'''
import json, os
from app import create_app
app = create_app()
with app.app_context():
    from app import key_manager, profile_manager, jump_host_manager
    from app.models import User
    user = User.query.filter_by(username='upgrade').one()
    keys = key_manager.load_keys(user.id)
    content, error = key_manager.read_key_content(user.id, keys[0]['id'])
    result = dict(
        profiles=sorted(p['name'] for p in profile_manager.load_profiles(user.id)),
        jump_hosts=[j['name'] for j in jump_host_manager.load_jump_hosts(user.id)],
        key_decrypts=error is None and 'OPENSSH PRIVATE KEY' in (content or ''),
        password_ok=user.check_password(os.environ['SEED_PASSWORD']),
    )
    try:
        from app.app_settings import RUNTIME_FEATURES, runtime_feature_status, is_registration_enabled
        result['switches'] = {name: runtime_feature_status(name) for name in RUNTIME_FEATURES}
        result['registration'] = is_registration_enabled()
    except ImportError:
        from app.app_settings import is_registration_enabled
        result['registration'] = is_registration_enabled()
print('INSPECT ' + json.dumps(result), flush=True)
os._exit(0)
'''

EXPECTED_DATA = dict(profiles=['db', 'web'], jump_hosts=['bastion'], key_decrypts=True, password_ok=True)


def docker(*arguments, check=True, input_text=None, timeout=300):
    completed = subprocess.run(
        ['docker', *arguments], input=input_text, capture_output=True, text=True,
        encoding='utf-8', errors='replace', timeout=timeout, check=False,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(f"docker {' '.join(arguments[:2])} failed: {completed.stderr.strip()[-2000:]}")
    return completed


def env_arguments(environment):
    arguments = []
    for key, value in {**BASE_ENVIRONMENT, **environment}.items():
        arguments += ['--env', f'{key}={value}']
    return arguments


def run_python(image, volume, environment, script, marker):
    result = docker(
        'run', '--rm', '-i', '--volume', f'{volume}:/app/data',
        *env_arguments(dict(environment, SEED_PASSWORD=SEED_PASSWORD)),
        image, 'python', '-', input_text=script,
    )
    lines = [line for line in result.stdout.splitlines() if line.startswith(marker)]
    if not lines:
        raise RuntimeError(f'{marker} missing: {result.stdout[-2000:]} {result.stderr[-2000:]}')
    return lines[-1][len(marker):].strip()


def wait_ready(image, volume, environment, label):
    slug = re.sub(r'[^a-z0-9]+', '-', label.lower()).strip('-')
    name = f'webssh-upgrade-{slug}-{secrets.token_hex(4)}'
    docker('run', '--detach', '--name', name, '--label', 'webssh.upgrade-check=1',
           '--volume', f'{volume}:/app/data', *env_arguments(environment), image)
    try:
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            probe = docker('exec', name, 'python', '-c',
                           "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/ready', timeout=2).read(1)",
                           check=False, timeout=30)
            if probe.returncode == 0:
                return
            time.sleep(2)
        logs = docker('logs', name, check=False).stdout[-4000:]
        raise RuntimeError(f'{label}: container did not become ready\n{logs}')
    finally:
        docker('stop', '--time', '40', name, check=False)
        docker('rm', '--force', name, check=False)


def inspect(image, volume, environment, label):
    wait_ready(image, volume, environment, label)
    data = json.loads(run_python(image, volume, environment, INSPECT, 'INSPECT'))
    for key, expected in EXPECTED_DATA.items():
        if data.get(key) != expected:
            raise RuntimeError(f'{label}: {key} is {data.get(key)!r}, expected {expected!r}')
    if data.get('registration') is not False:
        raise RuntimeError(f'{label}: registration reopened')
    return data


def switch(data, name):
    status = data['switches'][name]
    return status['enabled'], status['locked']


def require(label, actual, expected):
    if actual != expected:
        raise RuntimeError(f'{label}: {actual!r} != {expected!r}')
    print(f'ok: {label}')


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--old-image', required=True)
    parser.add_argument('--new-image', required=True)
    options = parser.parse_args()
    volume = f'webssh-upgrade-{secrets.token_hex(6)}'
    docker('volume', 'create', '--label', 'webssh.upgrade-check=1', volume)
    try:
        run_python(options.old_image, volume, LEGACY_ENVIRONMENT, SEED, 'SEEDED')
        inspect(options.old_image, volume, LEGACY_ENVIRONMENT, 'previous release')
        print('ok: previous release seeded and ready')

        unchanged = inspect(options.new_image, volume, LEGACY_ENVIRONMENT, 'old Compose')
        require('old Compose keeps tmux on and locked', switch(unchanged, 'tmux_enabled'), (True, True))
        require('old Compose keeps tmux preselection off', switch(unchanged, 'tmux_default'), (False, True))
        require('old Compose keeps file permissions on', switch(unchanged, 'sftp_chmod_enabled'), (True, True))
        require('server operations stay off', switch(unchanged, 'server_operations_enabled'), (False, False))

        replaced = inspect(options.new_image, volume, {}, 'new Compose')
        require('new Compose keeps tmux on, editable', switch(replaced, 'tmux_enabled'), (True, False))
        require('new Compose keeps the stored file permission choice', switch(replaced, 'sftp_chmod_enabled'), (True, False))
        require('new Compose keeps tmux preselection off, editable', switch(replaced, 'tmux_default'), (False, False))
        require('new Compose keeps server operations off', switch(replaced, 'server_operations_enabled'), (False, False))

        inspect(options.old_image, volume, LEGACY_ENVIRONMENT, 'rollback')
        print('ok: rollback to the previous release keeps every record')
    finally:
        docker('volume', 'rm', '--force', volume, check=False)
    print('container upgrade check passed')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:  # report the failing stage without a traceback wall
        print(f'container upgrade check failed: {error}', file=sys.stderr)
        sys.exit(1)
