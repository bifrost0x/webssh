"""Verify Docker's actual context filtering with disposable, harmless canaries.

Uses a scratch export only: no base-image download, app startup or real secrets.
Run alongside the ordinary image/readiness smoke test.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--container', help='Verify files in the already running CI container')
    args = parser.parse_args()
    paths = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT)
    paths = [name.decode('utf-8') for name in paths.split(b'\0') if name]
    required = [name for name in paths if (
        name.startswith(('app/', 'templates/', 'static/', 'deployment/'))
        and not name.endswith('.md')
        and not (name.startswith('static/images/theme-backgrounds/') and name.endswith('.png'))
    )] + ['requirements.txt', 'config.py', 'start.py', 'entrypoint.sh', 'LICENSE']
    if args.container:
        manifest = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in required}
        probe = '''import hashlib, json, sys
from pathlib import Path
root = Path('/app')
for name, digest in json.load(sys.stdin).items():
    assert (root / name).is_file(), f'Missing runtime file: {name}'
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest, f'Changed runtime file: {name}'
for name in ['site', 'assets', 'docs', 'tests', 'scripts', '.git']:
    assert not (root / name).exists(), f'Unexpected repository-only path: {name}'
assert not list(root.glob('static/images/theme-backgrounds/*.png'))
print('Packaged runtime files match the tested source; repository-only assets excluded.')
'''
        subprocess.run(['docker', 'exec', '-i', args.container, 'python', '-c', probe],
                       input=json.dumps(manifest), text=True, check=True)
        return 0
    with tempfile.TemporaryDirectory(prefix='webssh-context-check-') as temporary:
        directory = Path(temporary)
        context = directory / 'context'
        context.mkdir()
        for name in paths:
            source = ROOT / name
            if source.is_symlink() or not source.is_file():
                raise RuntimeError(f'Expected a regular tracked file: {name}')
            target = context / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        probes = [
            '.env', '.env.staging', 'loose.pem', 'loose.key', 'secret_key',
            'secrets/password.txt', 'server.sqlite3', 'server.sqlite3-wal',
            'server.db-shm', 'data/profiles.json', 'instance/private.json',
            'app/.env.staging', 'app/secrets/password.txt', 'app/loose.pem',
            'app/data/profiles.json', 'app/instance/private.json',
            'static/loose.key', 'templates/secret_key', 'static/.ssh/id_ed25519',
            'app/leftover.log', 'app/copy.backup', 'app/.git/config',
        ]
        for name in probes:
            target = context / name
            if target.exists():
                raise RuntimeError(f'Canary would overwrite a tracked file: {name}')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('HARMLESS_CONTEXT_CANARY\n')
        output = directory / 'export'
        subprocess.run([
            'docker', 'buildx', 'build', '--network=none', '--file', '-',
            '--output', f'type=local,dest={output}', str(context),
        ], input='FROM scratch\nCOPY . /payload\n', text=True, check=True)
        payload = output / 'payload'
        for name in probes:
            if (payload / name).exists():
                raise RuntimeError(f'Docker included a private-file canary: {name}')
        for name in ['site', 'assets', 'docs', 'tests', 'scripts']:
            if (payload / name).exists():
                raise RuntimeError(f'Docker included repository-only files: {name}')
        if list(payload.glob('static/images/theme-backgrounds/*.png')):
            raise RuntimeError('Docker included authoring PNGs.')
        # Check every runtime input, not only a few representative filenames.
        for name in required:
            if not (payload / name).is_file() or (payload / name).read_bytes() != (ROOT / name).read_bytes():
                raise RuntimeError(f'Docker omitted or changed a runtime input: {name}')
        print(f'Docker context passed: {len(probes)} canaries excluded; {len(required)} runtime inputs preserved.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
