"""Scan tracked working-tree files, with canaries proving exceptions stay narrow.

Gitleaks is a pinned CI tool, never an application dependency. No file content
is uploaded; diagnostics are redacted and temporary reports are removed.
"""

import argparse
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def scan(binary, config, directory, report):
    return subprocess.run([
        binary, 'dir', str(directory), '--config', str(config),
        '--no-banner', '--redact=100', '--ignore-gitleaks-allow',
        '--gitleaks-ignore-path', str(report.parent / '.unused-ignore'),
        '--report-format', 'json', '--report-path', str(report),
    ], capture_output=True, text=True, check=False)


def check_canaries(binary, config, directory):
    # Generate nonfunctional token-shaped strings at runtime, never commit them.
    paths = [
        'app/step_up.py', 'static/js/app.js',
        'static/vendor/xterm/xterm.js',
        'site/vendor/vis-network-9.1.6/vis-network.min.js',
        'tests/test_key_encryption.py', 'tests/test_key_manager.py',
    ]
    for name in paths:
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('token = "' + 'ghp_' + secrets.token_hex(18) + '"\n')
    # PEM-shaped blocks must also be detected inside both synthetic-key tests.
    key_paths = ['tests/test_key_encryption.py', 'tests/test_key_manager.py']
    for name in key_paths:
        pem = directory / name
        pem.write_text(pem.read_text() + '-----BEGIN ' + 'RSA PRIVATE KEY-----\n'
                       + 'M' * 64 + '\n-----END RSA PRIVATE KEY-----\n')
    report = directory.parent / 'canary-report.json'
    result = scan(binary, config, directory, report)
    if result.returncode != 1 or not report.is_file():
        raise RuntimeError('Secret scanner failed to reject the generated canaries.')
    findings = json.loads(report.read_text())
    detected = {Path(item['File']).relative_to(directory).as_posix() for item in findings}
    private_keys = {Path(item['File']).relative_to(directory).as_posix()
                    for item in findings if item['RuleID'] == 'private-key'}
    if not set(paths) <= detected or not set(key_paths) <= private_keys:
        raise RuntimeError('Secret scanner exceptions hide one or more canaries.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gitleaks', default='gitleaks')
    args = parser.parse_args()
    config = ROOT / '.gitleaks.toml'
    with tempfile.TemporaryDirectory(prefix='webssh-secret-check-') as temporary:
        directory = Path(temporary)
        canaries = directory / 'canaries'
        canaries.mkdir()
        check_canaries(args.gitleaks, config, canaries)
        snapshot = directory / 'source'
        snapshot.mkdir()
        tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT)
        paths = [path.decode('utf-8') for path in tracked.split(b'\0') if path]
        for name in paths:
            source = ROOT / name
            if source.is_symlink() or not source.is_file():
                raise RuntimeError(f'Expected a regular tracked file: {name}')
            target = snapshot / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        result = scan(args.gitleaks, config, snapshot, directory / 'report.json')
        if result.returncode:
            print(result.stderr)
            return result.returncode
        print(f'Secret scan passed for {len(paths)} tracked files; all detection canaries passed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
