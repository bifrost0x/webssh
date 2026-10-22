"""Run the disposable OpenSSH integration environment and its tests."""

import os
import argparse
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from subprocess import run


PROJECT_ROOT = Path(__file__).resolve().parent.parent
COMPOSE_FILE = "tests/integration/paramiko5/docker-compose.yml"
KEY_GENERATOR = "tests/integration/paramiko5/generate_keys.py"
RUNTIME_DIR = PROJECT_ROOT / "tests/integration/paramiko5/runtime"
INTEGRATION_MODULES = [
    "tests/integration/test_paramiko5_openssh.py",
    "tests/integration/test_paramiko5_socketio.py",
]


def returncode(result):
    """Return a subprocess result code while keeping the runner testable."""
    return result if isinstance(result, int) else result.returncode


def cleanup_runtime():
    """Remove the disposable private keys without following an unsafe path."""
    expected = PROJECT_ROOT / "tests/integration/paramiko5/runtime"
    runtime_dir = Path(os.path.abspath(RUNTIME_DIR))
    expected = Path(os.path.abspath(expected))
    if os.path.normcase(runtime_dir) != os.path.normcase(expected):
        raise RuntimeError(
            "Refusing to remove outside the fixture runtime directory"
        )
    if runtime_dir.is_symlink():
        raise RuntimeError(
            "Refusing to remove a runtime symlink or reparse point"
        )
    try:
        metadata = runtime_dir.lstat()
    except FileNotFoundError:
        return
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if getattr(metadata, "st_file_attributes", 0) & reparse_flag:
        raise RuntimeError(
            "Refusing to remove a runtime symlink or reparse point"
        )
    if not runtime_dir.is_dir():
        raise RuntimeError("Refusing to remove a non-directory runtime path")
    shutil.rmtree(runtime_dir)


def main(*, browser=False) -> int:
    browser_cli = PROJECT_ROOT / 'node_modules/playwright/cli.js'
    node = shutil.which('node') if browser else None
    if browser and (node is None or not browser_cli.is_file()):
        print('Browser integration requires Node.js, npm ci and npx playwright install chromium.', file=sys.stderr)
        return 2
    try:
        key_generation = run(
            [sys.executable, KEY_GENERATOR],
            cwd=PROJECT_ROOT,
        )
        if returncode(key_generation):
            return returncode(key_generation)

        compose = [
            "docker",
            "compose",
            "-f",
            COMPOSE_FILE,
            "--project-name",
            "webssh-paramiko5-integration",
        ]
        environment = os.environ.copy()
        environment.update({
            "PARAMIKO5_INTEGRATION": "1",
            "PARAMIKO5_DISPOSABLE_LAB": "1",
            "PARAMIKO5_TARGET_HOST": "127.0.0.1",
            "PARAMIKO5_TARGET_PORT": "2223",
            "PARAMIKO5_PROXY_TARGET_HOST": "target",
            "PARAMIKO5_PROXY_TARGET_PORT": "22",
            "PROXY_JUMP_REMOTE_DNS_ALLOWLIST": "target",
            "PARAMIKO5_BASTION_HOST": "127.0.0.1",
            "PARAMIKO5_BASTION_PORT": "2222",
            "PARAMIKO5_CHANGED_HOST": "127.0.0.1",
            "PARAMIKO5_CHANGED_PORT": "2224",
        })

        try:
            startup = run(
                [*compose, "up", "-d", "--build", "--wait"],
                cwd=PROJECT_ROOT,
            )
            if returncode(startup):
                return returncode(startup)

            with tempfile.TemporaryDirectory(prefix='webssh-ssh-integration-') as temporary:
                state = Path(temporary)
                for name in ('backups', 'transfers'):
                    (state / name).mkdir(mode=0o700)
                environment.update({
                    'PYTHON': sys.executable,
                    'WEBSSH_E2E_PORT': environment.get('WEBSSH_E2E_PORT', '4184'),
                    'WEBSSH_E2E_TIMING_FILE': str(PROJECT_ROOT / 'test-results/e2e-timing-ssh-browser.json'),
                    'BACKUP_TEMP_DIR': str(state / 'backups'),
                    'TRANSFER_TEMP_DIR': str(state / 'transfers'),
                })
                tests = run(
                    [sys.executable, '-m', 'pytest', f'--basetemp={state / "pytest"}', *INTEGRATION_MODULES],
                    cwd=PROJECT_ROOT,
                    env=environment,
                )
                if returncode(tests) or not browser:
                    return returncode(tests)
                return returncode(run(
                    [node, str(browser_cli), 'test', '--config',
                     'tests/integration/playwright.file-mutations.config.js', '--forbid-only'],
                    cwd=PROJECT_ROOT,
                    env=environment,
                ))
        finally:
            run([*compose, "down", "-v"], cwd=PROJECT_ROOT)
    finally:
        cleanup_runtime()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--browser', action='store_true',
                        help='Also run the real file-mutation browser lifecycle against the same lab.')
    raise SystemExit(main(browser=parser.parse_args().browser))
