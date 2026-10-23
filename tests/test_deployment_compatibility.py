"""Production upgrades preserve existing deployments; hardening is explicit."""
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


def compose(files, environment=None):
    docker = shutil.which('docker')
    if docker is None:
        pytest.skip('Docker Compose CLI is unavailable')
    args = [docker, 'compose']
    for file in files:
        args += ['-f', str(file)]
    merged_environment = dict(os.environ, WEBSSH_ORIGIN='https://ssh.example.com')
    merged_environment.update(environment or {})
    result = subprocess.run(
        args + ['config', '--format', 'json'], cwd=ROOT,
        env=merged_environment, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)['services']['webssh']


@pytest.mark.parametrize('production', [False, True])
def test_tmux_is_available_but_not_preselected_in_compose(production):
    files = ['docker-compose.yml']
    if production:
        files.append('docker-compose.production.yml')
    environment = compose(files)['environment']
    assert environment['TMUX_ENABLED'] == 'true'
    assert environment['TMUX_DEFAULT'] == 'false'


@pytest.mark.parametrize('ldap', [False, True])
def test_production_upgrade_does_not_silently_restrict_existing_resources(ldap):
    files = ['docker-compose.yml']
    if ldap:
        files += ['docker-compose.ldap.yml']
    files += ['docker-compose.production.yml']
    service = compose(files)
    assert not service.get('read_only', False)
    assert not service.get('cap_drop')
    assert not service.get('pids_limit')
    assert not service.get('mem_limit')
    assert not service.get('tmpfs')
    assert 'XDG_RUNTIME_DIR' not in service['environment']
    assert service['environment']['SESSION_COOKIE_SECURE'] == 'true'
    assert service['environment']['BLOCK_INTERNAL_SSH'] == 'true'
    assert service['ports'][0]['host_ip'] == '127.0.0.1'


def test_existing_custom_limits_paths_and_runtime_are_preserved(tmp_path):
    custom = tmp_path / 'custom.yml'
    custom.write_text("""services:
  webssh:
    user: '1234:1234'
    mem_limit: 4g
    pids_limit: 1024
    environment:
      TRANSFER_TEMP_DIR: /custom/transfers
      XDG_RUNTIME_DIR: /custom/runtime
    volumes:
      - custom_store:/custom
volumes:
  custom_store:
""")
    service = compose(['docker-compose.yml', custom, 'docker-compose.production.yml'])
    assert int(service['mem_limit']) == 4 * 1024 ** 3
    assert service['pids_limit'] == 1024
    assert service['user'] == '1234:1234'
    assert service['environment']['TRANSFER_TEMP_DIR'] == '/custom/transfers'
    assert service['environment']['XDG_RUNTIME_DIR'] == '/custom/runtime'
    assert any(v['target'] == '/custom' for v in service['volumes'])


def test_explicit_hardening_supports_custom_capacity_and_runtime_owner():
    service = compose(['docker-compose.yml', 'docker-compose.production.yml',
                       'docker-compose.hardened.yml'], {
        'WEBSSH_MEMORY_LIMIT': '4g', 'WEBSSH_PIDS_LIMIT': '1024',
        'WEBSSH_TMPFS_SIZE': '768m', 'WEBSSH_RUNTIME_UID': '1234',
        'WEBSSH_RUNTIME_GID': '1234',
    })
    assert service['read_only'] is True
    assert service['cap_drop'] == ['ALL']
    assert service['security_opt'] == ['no-new-privileges:true']
    assert int(service['mem_limit']) == 4 * 1024 ** 3
    assert service['pids_limit'] == 1024
    assert any(m.startswith('/tmp:') and 'size=768m' in m for m in service['tmpfs'])
    assert any(m.startswith('/run/webssh:') and 'uid=1234' in m and 'gid=1234' in m
               for m in service['tmpfs'])
