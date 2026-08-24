"""Run the isolated SMB security lab and always remove its resources."""

from __future__ import annotations

import secrets
import subprocess
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
COMPOSE_FILE = 'tests/integration/smb/docker-compose.yml'


def _run(command):
    return subprocess.run(command, cwd=PROJECT_ROOT, check=False).returncode


def main():
    project = f'webssh-smb-{secrets.token_hex(6)}'
    compose = [
        'docker',
        'compose',
        '-f',
        COMPOSE_FILE,
        '--project-name',
        project,
    ]
    try:
        startup = _run([*compose, 'up', '-d', '--build', '--wait', 'samba'])
        if startup:
            return startup
        return _run([*compose, 'run', '--rm', '--build', 'client'])
    finally:
        _run([*compose, 'down', '--volumes', '--remove-orphans'])


if __name__ == '__main__':
    raise SystemExit(main())
