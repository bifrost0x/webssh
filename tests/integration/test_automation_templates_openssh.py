"""Template execution on the disposable Debian OpenSSH lab, never user hosts.

Requires paramiko5/Dockerfile.templates and Node in the test client. Keep this
suite separate from the minimal SSH lab: it executes apt updates/upgrades on the
throwaway target. The standard disposable-target guards remain mandatory.
"""
import json
import os
import subprocess

import pytest

from app.automation_transport import connect_profile, execute_step
from tests.integration.test_automation_openssh import peer, trust, PASSWORD

pytestmark = pytest.mark.skipif(os.environ.get('PARAMIKO5_INTEGRATION') != '1', reason='requires disposable OpenSSH lab')


@pytest.fixture
def catalog():
    script = "const c=require('./static/js/automation-templates.js');process.stdout.write(JSON.stringify(c.list().map(x=>c.create(x.id))))"
    return json.loads(subprocess.check_output(['node', '-e', script], text=True))


def test_all_templates_have_valid_shell_and_report_missing_prerequisites(peer, catalog):
    uid, profile = peer
    trust(uid)
    with connect_profile(uid, profile, PASSWORD, lambda: False) as transport:
        for template in catalog:
            import shlex
            for step in template['steps']:
                # Parse only: writes and platform-specific commands are not executed here.
                check = dict(command='printf %s ' + shlex.quote(step['command']) + ' | sh -n', timeout=5, sudo=False)
                result = execute_step(transport, check, lambda: False)
                assert result['status'] == 'succeeded', (template['id'], step['name'], result)
            # A restricted PATH leaves uname available for the OS check but no
            # template dependencies; the diagnostic must be explicit and nonzero.
            command = 'PATH=/nonexistent; uname() { printf "Linux\\n"; }; ' + template['steps'][0]['command']
            result = execute_step(transport, dict(command=command, timeout=5, sudo=False), lambda: False)
            assert result['status'] == 'failed', (template['id'], result)
            assert 'missing:' in result['stderr'] or 'requires Darwin' in result['stderr']


@pytest.mark.parametrize('template_id', ['inventory', 'disk', 'memory', 'cpu', 'processes', 'network', 'listeners', 'links', 'apt-list', 'apt-upgrade', 'maintenance'])
def test_linux_template_executes_on_supported_disposable_host(peer, catalog, template_id):
    uid, profile = peer
    trust(uid)
    template = next(item for item in catalog if item['id'] == template_id)
    with connect_profile(uid, profile, PASSWORD, lambda: False) as transport:
        for step in template['steps']:
            result = execute_step(transport, step, lambda: False)
            assert result['status'] == 'succeeded' and result['exit_code'] == 0, (step['name'], result)


@pytest.mark.parametrize('exit_code', [0, 7])
def test_real_openssh_large_output_retains_exit_and_stderr(peer, exit_code):
    uid, profile = peer
    trust(uid)
    with connect_profile(uid, profile, PASSWORD, lambda: False) as transport:
        # Exceeds the capture limit, finishes quickly, and puts the diagnostic
        # after stdout so the reader must continue draining after truncation.
        command = "head -c 2097152 /dev/zero | tr '\\000' x; printf 'final diagnostic' >&2; exit " + str(exit_code)
        result = execute_step(transport, dict(command=command, timeout=10, sudo=False), lambda: False)
        assert result['exit_code'] == exit_code
        assert result['status'] == ('succeeded' if exit_code == 0 else 'failed')
        assert result['stderr'] == 'final diagnostic'
        assert result['output_truncated']
        assert len(result['stdout'].encode()) + len(result['stderr'].encode()) <= 8192
        following = execute_step(transport, dict(command='printf next-step', timeout=5, sudo=False), lambda: False)
        assert following['status'] == 'succeeded' and following['stdout'] == 'next-step'
