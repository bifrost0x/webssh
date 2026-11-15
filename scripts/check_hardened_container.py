"""Exercise production compatibility, opt-in restrictions and the Unraid runtime
identity using disposable containers."""

import argparse
import json
import subprocess
import time
import urllib.error
import urllib.request
from uuid import uuid4


PROBE = r'''
import errno
import os
from pathlib import Path
import tempfile
from app.online_backup import create_online_backup
from app.storage_utils import atomic_write_json

hardened = __HARDENED__
runtime_id = __RUNTIME_ID__
# The application root is root-owned in every profile; read-only adds EROFS.
probe = Path('/app/.hardening-probe')
try:
    probe.write_text('must not succeed')
except OSError as error:
    assert error.errno == (errno.EROFS if hardened else errno.EACCES), error
else:
    raise AssertionError('Application root is writable')
status = Path('/proc/self/status').read_text()
if hardened:
    assert 'CapEff:\t0000000000000000' in status
    assert 'NoNewPrivs:\t1' in status
if runtime_id is not None:
    # An arbitrary numeric user without a passwd entry or writable home, as
    # Unraid runs it: the server and this probe use exactly that identity.
    uid, gid = runtime_id
    for process in ('self', '1'):
        status = Path(f'/proc/{process}/status').read_text()
        assert f'Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n' in status, status
        assert f'Gid:\t{gid}\t{gid}\t{gid}\t{gid}\n' in status, status
        assert 'CapEff:\t0000000000000000' in status, status
    for path in (Path('/app/data'), Path('/app/recovery')):
        metadata = path.stat()
        assert (metadata.st_uid, metadata.st_gid, metadata.st_mode & 0o777) == (uid, gid, 0o700)
    server = dict(line.split('=', 1) for line in
                  Path('/proc/1/environ').read_text().split('\0') if '=' in line)
    runtime = Path(server['XDG_RUNTIME_DIR'])
    assert runtime.parent == Path('/tmp') and runtime.name.startswith('webssh-runtime.')
    metadata = runtime.stat()
    assert (metadata.st_uid, metadata.st_mode & 0o777) == (uid, 0o700)
with tempfile.TemporaryFile() as handle:
    handle.write(b'temporary upload/export data')
    handle.seek(0)
    assert handle.read() == b'temporary upload/export data'
# Exercise a configured transfer scratch path above the former 128 MiB ceiling.
import config
scratch = Path(config.TRANSFER_TEMP_DIR)
scratch.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryFile(dir=scratch) as handle:
    chunk = b'x' * (1024 * 1024)
    for _ in range(160):
        handle.write(chunk)
    handle.flush()
    assert os.fstat(handle.fileno()).st_size == 160 * 1024 * 1024

data = Path('/app/data')
assert len((data / 'secret_key').read_text().strip()) >= 64
atomic_write_json(data / 'hardening-probe.json', {'state': 'before'})
(data / 'tmp').mkdir(exist_ok=True)
atomic_write_json(data / 'tmp' / 'transfer-probe.json', {'temporary': True})
create_online_backup(data, Path('/app/recovery/hardening.zip'))
print('Filesystem, process restrictions, 160 MiB scratch write and online backup passed')
'''

RESTORE = r'''
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
from app.backup_coordination import ensure_backup_temp_dir
from app.backup_manager import restore_backup, verify_backup
from app.storage_utils import atomic_write_json

# Run the documented CLI, including its default destination, while stopped.
result = subprocess.run(
    [sys.executable, '-m', 'flask', '--app', 'start:app',
     'backup', 'create', '--confirm-offline'],
    capture_output=True, text=True, check=False,
)
assert result.returncode == 0, result.stdout + result.stderr
# The service cannot write the parent of DATA_DIR, so the CLI falls back to
# its private recovery namespace instead of the container's writable layer.
expected = ensure_backup_temp_dir()
assert not list(Path('/app').glob('webssh-backup-*.zip'))
archives = list(expected.glob('webssh-backup-*.zip'))
assert len(archives) == 1, result.stdout
verify_backup(archives[0])
assert str(archives[0]) in result.stdout
print('Offline CLI backup and default destination passed')

data = Path('/app/data')
atomic_write_json(data / 'hardening-probe.json', {'state': 'changed'})
(data / 'extra-after-backup.txt').write_text('remove during restore')
restore_backup(archives[0], data)
assert json.loads((data / 'hardening-probe.json').read_text()) == {'state': 'before'}
assert not (data / 'extra-after-backup.txt').exists()
assert (data / 'tmp' / 'transfer-probe.json').exists()
with sqlite3.connect(data / 'app.db') as database:
    assert database.execute('PRAGMA quick_check').fetchone() == ('ok',)
print('Offline restore and SQLite verification passed')
'''


def docker(*args, capture=True):
    result = subprocess.run(['docker', *args], check=True, text=True,
                            capture_output=capture)
    return result.stdout.strip() if capture else ''


def wait_ready(container):
    binding = docker('port', container, '5000/tcp').splitlines()[0]
    url = f"http://127.0.0.1:{binding.rsplit(':', 1)[1]}/ready"
    for _ in range(90):
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(1)
    raise RuntimeError('Hardened container did not become ready')


def check_image(image, revision, platform, profile='hardened'):
    owner = uuid4().hex
    label = 'webssh.hardening-test'
    containers = []
    hardened = profile not in {'compatible', 'unraid'}
    runtime_id = 1234 if profile == 'hardened-custom' else 1000
    restrictions = ['--platform', platform, '--label', f'{label}={owner}']
    if hardened:
        tmp_size = '256m' if profile == 'hardened-custom' else '128m'
        restrictions.extend([
            '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges:true', '--pids-limit', '512',
            '--memory', '2g', '--tmpfs',
            f'/tmp:rw,noexec,nosuid,nodev,size={tmp_size},mode=1777',
            '--tmpfs', f'/run/webssh:rw,noexec,nosuid,nodev,size=1m,uid={runtime_id},gid={runtime_id},mode=700',
        ])
    if profile == 'hardened-custom':
        restrictions.extend(['--user', f'{runtime_id}:{runtime_id}'])
    environment = []
    for key, value in {
        'DEPLOYMENT_PROFILE': 'production', 'CORS_ORIGINS': 'https://localhost',
        'ALLOW_CORS_WILDCARD': 'false', 'SESSION_COOKIE_SECURE': 'true',
        'REGISTRATION_ENABLED': 'false', 'BOOTSTRAP_REGISTRATION_ENABLED': 'false',
        'BLOCK_INTERNAL_SSH': 'true', 'TRUSTED_PROXIES': '1',
        'BACKUP_TEMP_DIR': '/app/recovery', 'BACKUP_RECOVERY_DURABLE': 'true',
    }.items():
        environment.extend(['--env', f'{key}={value}'])
    if hardened:
        environment.extend(['--env', 'XDG_RUNTIME_DIR=/run/webssh'])
    if profile in {'compatible', 'hardened-custom'}:
        environment.extend(['--env', 'TRANSFER_TEMP_DIR=/tmp/custom-transfers'])
    unraid_id = None
    volumes = ['--volume', '/app/recovery']
    provision = None
    if profile == 'hardened-custom':
        # Provision only this test's fresh anonymous volumes for its custom
        # identity, just as an operator provisions a bind/named mount.
        provision = (runtime_id, runtime_id, None,
                     ['/app/data', '/app/data/logs', '/app/data/keys', '/app/recovery'])
    if profile == 'unraid':
        # The Unraid template runs --user 99:100 on appdata folders that Unraid
        # creates empty with mode 0777 and owner nobody:users.
        unraid_id = (99, 100)
        restrictions.extend(['--user', '99:100'])
        volumes = [
            '--mount', 'type=volume,target=/app/data,volume-nocopy=true',
            '--mount', 'type=volume,target=/app/recovery,volume-nocopy=true',
        ]
        provision = (*unraid_id, 0o777, ['/app/data', '/app/recovery'])
    probe_script = (PROBE.replace('__HARDENED__', repr(hardened))
                    .replace('__RUNTIME_ID__', repr(unraid_id)))
    restore_script = RESTORE
    try:
        container = docker('create', *restrictions, *environment,
                           *volumes, '--publish', '127.0.0.1::5000', image)
        containers.append(container)
        actual_revision = docker('inspect', '--format',
                                 '{{ index .Config.Labels "org.opencontainers.image.revision" }}', container)
        if actual_revision != revision:
            raise ValueError('Hardened runtime candidate has the wrong revision')
        if provision is not None:
            uid, gid, mode, paths = provision
            chmod = f'os.chmod(path, {mode:#o}), ' if mode is not None else ''
            provisioner = docker(
                'create', '--platform', platform, '--label', f'{label}={owner}',
                '--network', 'none', '--read-only', '--user', '0:0',
                '--cap-drop', 'ALL', '--cap-add', 'CHOWN', '--cap-add', 'DAC_OVERRIDE',
                '--cap-add', 'FOWNER', '--security-opt', 'no-new-privileges:true',
                '--volumes-from', container, '--entrypoint', 'python', image,
                '-c', "import os; from pathlib import Path; "
                f"paths = {paths!r}; "
                f"[(os.chown(path, {uid}, {gid}), {chmod}) for path in paths if Path(path).exists()]",
            )
            containers.append(provisioner)
            docker('start', '--attach', provisioner, capture=False)
            if docker('inspect', '--format', '{{.State.ExitCode}}', provisioner) != '0':
                raise RuntimeError('Could not provision custom-identity test volumes')
        docker('start', container)
        wait_ready(container)
        if unraid_id is not None:
            logs = subprocess.run(['docker', 'logs', container], capture_output=True,
                                  text=True, check=True)
            if 'Control server error' in logs.stdout + logs.stderr:
                raise RuntimeError('Gunicorn could not create its control socket')
        docker('exec', container, '/app/entrypoint.sh', 'python', '-c', probe_script, capture=False)
        docker('stop', '--time', '35', container)
        if docker('inspect', '--format', '{{.State.ExitCode}}', container) != '0':
            raise RuntimeError('Hardened container did not shut down cleanly')

        # Restore against the real data volume only after its server stopped.
        restore = docker('create', *restrictions, *environment,
                         '--volumes-from', container, image, 'python', '-c', restore_script)
        containers.append(restore)
        docker('start', '--attach', restore, capture=False)
        if docker('inspect', '--format', '{{.State.ExitCode}}', restore) != '0':
            raise RuntimeError('Offline restore failed under production restrictions')
        docker('start', container)
        wait_ready(container)
        docker('stop', '--time', '35', container)
        if docker('inspect', '--format', '{{.State.ExitCode}}', container) != '0':
            raise RuntimeError('Restored container did not shut down cleanly')
        print(f'Startup, backup, restore, restart and shutdown passed: {platform} / {profile}')
    except Exception:
        for container in containers:
            subprocess.run(['docker', 'logs', '--tail', '40', container], check=False)
        raise
    finally:
        for container in reversed(containers):
            actual_owner = docker('inspect', '--format',
                                 '{{ index .Config.Labels "' + label + '" }}', container)
            if actual_owner != owner:
                raise RuntimeError('Refusing cleanup of an unrelated container')
            docker('rm', '--force', '--volumes', container)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--platform', default='linux/amd64', choices=('linux/amd64', 'linux/arm64'))
    parser.add_argument('--profile', default='all',
                        choices=('all', 'compatible', 'hardened', 'hardened-custom', 'unraid'))
    args = parser.parse_args()
    profiles = ('compatible', 'hardened', 'hardened-custom', 'unraid') if args.profile == 'all' else (args.profile,)
    for profile in profiles:
        check_image(args.image, args.revision, args.platform, profile)


if __name__ == '__main__':
    main()
