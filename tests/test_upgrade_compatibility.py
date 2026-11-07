"""Upgrade matrix for switches that moved from Compose into Administration.

Every start runs in a fresh interpreter, because ``config`` reads the
environment once at import. Scenarios follow the documented upgrade paths:
new installation, existing installation with its old Compose unchanged, and
existing installation that replaced its Compose before or after the first 3.0
start. See docs/webssh-3.md, "Configuration ownership during upgrades".
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SWITCH_KEYS = (
    'TMUX_ENABLED', 'TMUX_DEFAULT', 'SFTP_CHMOD_ENABLED',
    'SERVER_OPERATIONS_ENABLED', 'AUTOMATION_ENABLED', 'REGISTRATION_ENABLED',
)
# Environment of the example Compose shipped with 2.x (docker-compose.yml).
LEGACY_COMPOSE = {'TMUX_ENABLED': 'true', 'TMUX_DEFAULT': 'false'}
# Active switch lines of the 2.x .env.example used by source installations.
LEGACY_ENV_EXAMPLE = {
    'REGISTRATION_ENABLED': 'False', 'TMUX_ENABLED': 'false',
    'TMUX_DEFAULT': 'false', 'SFTP_CHMOD_ENABLED': 'false',
}

PROBE = r'''
import json, os, sys
from app import create_app
app = create_app()
with app.app_context():
    from app.app_settings import (RUNTIME_FEATURES, runtime_feature_status,
        is_registration_enabled, is_automation_enabled, native_setting_sources,
        get_automation_policy_revision)
    sources = native_setting_sources()
    result = {name: runtime_feature_status(name) for name in RUNTIME_FEATURES}
    result['registration'] = dict(sources['registration_enabled'], enabled=is_registration_enabled())
    result['automation'] = dict(sources['automation_enabled'], enabled=is_automation_enabled(),
                                revision=get_automation_policy_revision())
sys.stdout.write('UPGRADE-RESULT ' + json.dumps(result) + '\n')
sys.stdout.flush()
os._exit(0)
'''


def new_compose_switches():
    """Uncommented switch values of the current example Compose file."""
    values = {}
    for line in (ROOT / 'docker-compose.yml').read_text(encoding='utf-8').splitlines():
        match = re.match(r'^\s+-\s+([A-Z0-9_]+)=(.*)$', line)
        if match and match.group(1) in SWITCH_KEYS:
            values[match.group(1)] = match.group(2)
    return values


@pytest.fixture
def start(tmp_path):
    if (ROOT / '.env').exists():
        pytest.skip('a local .env would leak values into the upgrade matrix')
    data_dir = tmp_path / 'data'
    data_dir.mkdir()

    def run(environment):
        env = {key: value for key, value in os.environ.items() if key not in SWITCH_KEYS}
        env.update({
            'DATA_DIR': str(data_dir),
            'SECRET_KEY': 'upgrade-matrix-secret-key-with-enough-entropy-0123456789',
            'DEPLOYMENT_PROFILE': 'homelab',
            'DEBUG': 'False',
            'BACKUP_TEMP_DIR': str(tmp_path / 'operations'),
            'TRANSFER_TEMP_DIR': str(tmp_path / 'transfers'),
            'PYTHONIOENCODING': 'utf-8',
        })
        env.update(environment)
        completed = subprocess.run(
            [sys.executable, '-c', PROBE], cwd=ROOT, env=env,
            capture_output=True, text=True, encoding='utf-8', errors='replace',
            timeout=120, check=False,
        )
        lines = [line for line in completed.stdout.splitlines() if line.startswith('UPGRADE-RESULT ')]
        assert completed.returncode == 0 and lines, completed.stderr[-4000:]
        return json.loads(lines[-1][len('UPGRADE-RESULT '):])

    run.data_dir = data_dir
    return run


def seed_v2_install(data_dir, **saved):
    """Settings as written by 2.x: only registration and audit choices existed."""
    (data_dir / 'users').mkdir(exist_ok=True)
    if saved:
        (data_dir / 'app_settings.json').write_text(json.dumps(dict(schema_version=2, **saved)), encoding='utf-8')


def effective(result):
    return {
        'tmux': (result['tmux_enabled']['enabled'], result['tmux_enabled']['locked']),
        'tmux_default': (result['tmux_default']['enabled'], result['tmux_default']['locked']),
        'chmod': (result['sftp_chmod_enabled']['enabled'], result['sftp_chmod_enabled']['locked']),
        'server_operations': (result['server_operations_enabled']['enabled'], result['server_operations_enabled']['locked']),
        'registration': (result['registration']['enabled'], result['registration']['locked']),
        'automation': (result['automation']['enabled'], result['automation']['locked']),
    }


NEW_INSTALL_DEFAULTS = {
    'tmux': (True, False), 'tmux_default': (False, False), 'chmod': (False, False),
    'server_operations': (False, False), 'registration': (False, False), 'automation': (False, False),
}


def test_example_compose_leaves_every_moved_switch_to_administration():
    assert new_compose_switches() == {}


def test_new_installation_uses_editable_product_defaults(start):
    result = start(new_compose_switches())
    assert effective(result) == NEW_INSTALL_DEFAULTS
    assert result['tmux_enabled']['source'] == 'default'


def test_existing_installation_with_unchanged_old_compose(start):
    seed_v2_install(start.data_dir)
    first = start(LEGACY_COMPOSE)
    assert effective(first) == dict(NEW_INSTALL_DEFAULTS, tmux=(True, True), tmux_default=(False, True))
    assert first['tmux_enabled']['source'] == 'compose'
    assert first['tmux_enabled']['saved_value'] is True
    assert first['tmux_default']['saved_value'] is False
    settings = start.data_dir / 'app_settings.json'
    stored = settings.read_bytes()
    second = start(LEGACY_COMPOSE)
    assert effective(second) == effective(first)
    assert settings.read_bytes() == stored, 'an unchanged restart must not rewrite settings'


def test_old_compose_with_enabled_optional_features_stays_identical(start):
    seed_v2_install(start.data_dir)
    environment = dict(LEGACY_COMPOSE, SFTP_CHMOD_ENABLED='true', SERVER_OPERATIONS_ENABLED='true')
    result = start(environment)
    assert effective(result)['chmod'] == (True, True)
    assert effective(result)['server_operations'] == (True, True)


def test_new_compose_before_the_first_start_keeps_tmux_behavior(start):
    seed_v2_install(start.data_dir)
    result = start(new_compose_switches())
    assert effective(result) == NEW_INSTALL_DEFAULTS


def test_new_compose_after_the_first_start_keeps_every_value_and_unlocks(start):
    seed_v2_install(start.data_dir)
    start(dict(LEGACY_COMPOSE, SFTP_CHMOD_ENABLED='true', SERVER_OPERATIONS_ENABLED='false'))
    result = start(new_compose_switches())
    assert effective(result) == dict(NEW_INSTALL_DEFAULTS, chmod=(True, False))
    assert result['tmux_enabled']['source'] == 'admin'
    assert result['sftp_chmod_enabled']['migrated'] is True


def test_source_installation_with_old_env_example_keeps_its_values(start):
    seed_v2_install(start.data_dir)
    result = start(LEGACY_ENV_EXAMPLE)
    assert effective(result) == dict(
        NEW_INSTALL_DEFAULTS, tmux=(False, True), tmux_default=(False, True), chmod=(False, True),
    )


@pytest.mark.parametrize('value', ['', '   '])
def test_empty_values_count_as_not_supplied(start, value):
    result = start({key: value for key in SWITCH_KEYS})
    assert effective(result) == NEW_INSTALL_DEFAULTS
    assert not (start.data_dir / 'app_settings.json').read_text(encoding='utf-8').count('runtime_feature_migration')


@pytest.mark.parametrize('saved,env,expected', [
    (False, 'true', False),   # an administrator closed registration in 2.x
    (True, 'false', True),    # an administrator opened it in 2.x
    (None, 'true', True),     # no saved choice: the environment is the initial value
    (None, None, False),
])
def test_registration_keeps_the_2x_precedence(start, saved, env, expected):
    seed_v2_install(start.data_dir, **({} if saved is None else {'registration_enabled': saved}))
    result = start({} if env is None else {'REGISTRATION_ENABLED': env})
    assert result['registration']['enabled'] is expected
    assert result['registration']['locked'] is False


def test_changing_an_override_later_wins_until_removed(start):
    seed_v2_install(start.data_dir)
    start({'TMUX_ENABLED': 'true'})
    changed = start({'TMUX_ENABLED': 'false'})
    assert effective(changed)['tmux'] == (False, True)
    assert changed['tmux_enabled']['saved_value'] is True
    removed = start({})
    assert effective(removed)['tmux'] == (True, False)


def test_environment_toggles_of_automation_revoke_approvals(start):
    enabled = start({'AUTOMATION_ENABLED': 'true'})
    assert enabled['automation']['enabled'] is True and enabled['automation']['locked'] is True
    same = start({'AUTOMATION_ENABLED': 'true'})
    assert same['automation']['revision'] == enabled['automation']['revision']
    disabled = start({'AUTOMATION_ENABLED': 'false'})
    assert disabled['automation']['revision'] != enabled['automation']['revision']
    again = start({'AUTOMATION_ENABLED': 'true'})
    assert again['automation']['revision'] not in {enabled['automation']['revision'], disabled['automation']['revision']}


def test_written_settings_stay_readable_by_2x(start):
    """2.x validated only known keys; every stored value keeps its 2.x type."""
    seed_v2_install(start.data_dir, registration_enabled=False, audit_backup_count=7)
    start(dict(LEGACY_COMPOSE, SFTP_CHMOD_ENABLED='true'))
    data = json.loads((start.data_dir / 'app_settings.json').read_text(encoding='utf-8'))
    assert data['schema_version'] == 2
    assert data['registration_enabled'] is False
    assert data['audit_backup_count'] == 7
