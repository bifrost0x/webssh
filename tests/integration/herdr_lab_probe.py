"""Read and reset the Herdr session of the disposable lab for browser tests.

Prints one JSON document. Every command is fixed; only a validated workspace
label is passed through.
"""
import json
import os
import re
import sys

import paramiko

HOST = '127.0.0.1'
PORT = 2225
USERNAME = 'agentuser'
PASSWORD = 'Paramiko5-Test-Only!'
HERDR = '$HOME/.local/bin/herdr'


def run(client, command):
    _, stdout, stderr = client.exec_command(command, timeout=15)
    output = stdout.read().decode('utf-8', 'replace')
    stderr.read()
    return stdout.channel.recv_exit_status(), output


def snapshot(client):
    status, output = run(client, f'{HERDR} api snapshot')
    if status != 0:
        return {'running': False}
    state = json.loads(output)['result']['snapshot']
    return {
        'running': True,
        'panes': len(state['panes']),
        'tabs': len(state['tabs']),
        'workspaces': [workspace.get('label') for workspace in state['workspaces']],
        'focused': state.get('focused_pane_id'),
    }


def main(action, *args):
    if os.environ.get('PARAMIKO5_DISPOSABLE_LAB') != '1':
        raise SystemExit('This probe requires the disposable OpenSSH lab')
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, port=PORT, username=USERNAME, password=PASSWORD,
                   allow_agent=False, look_for_keys=False, timeout=10)
    try:
        if action == 'reset':
            run(client, f'{HERDR} server stop >/dev/null 2>&1; rm -rf "$HOME/.config/herdr"')
            result = {'running': snapshot(client)['running']}
        elif action == 'snapshot':
            result = snapshot(client)
        elif action == 'split':
            # The probe is not inside a pane, so it names the focused one.
            focused = snapshot(client).get('focused') or ''
            if not re.fullmatch(r'[A-Za-z0-9:_-]{1,64}', focused):
                raise SystemExit('No focused pane')
            status, _ = run(client, f'{HERDR} pane split {focused} --direction right >/dev/null')
            result = {'split': status == 0, **snapshot(client)}
        elif action == 'workspace':
            label = args[0] if args else ''
            if not re.fullmatch(r'[a-z0-9-]{1,32}', label):
                raise SystemExit('Invalid workspace label')
            status, _ = run(client, f'{HERDR} workspace create --label {label} --no-focus >/dev/null')
            result = {'created': status == 0, **snapshot(client)}
        else:
            raise SystemExit(f'Unknown action: {action}')
    finally:
        client.close()
    print(json.dumps(result))


if __name__ == '__main__':
    main(*sys.argv[1:])
