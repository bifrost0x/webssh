"""Run the three owned protocol/release labs together without skipping failures."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import subprocess
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
GROUPS = {
    'ssh': (
        ('bash', 'scripts/install_ci_test_system_deps.sh'),
        ('uv', 'pip', 'install', '--python', sys.executable, '--require-hashes', '-r', 'requirements-test.txt'),
        ('npm', 'ci'),
        ('node', 'scripts/install-ci-chromium.js'),
        (sys.executable, 'scripts/run_integration_tests.py', '--browser'),
    ),
    'smb': ((sys.executable, 'scripts/run_smb_integration_tests.py'),),
    'release': ((sys.executable, 'scripts/check_release_promotion.py'),),
}


def _run_group(name, commands, run):
    for command in commands:
        result = run(command, cwd=PROJECT_ROOT, check=False)
        if result.returncode != 0:
            print(f'{name}: command failed with exit code {result.returncode}', flush=True)
            return False
    print(f'{name}: all checks passed', flush=True)
    return True


def main(*, run=subprocess.run):
    success = True
    with ThreadPoolExecutor(max_workers=3) as executor:
        pending = {
            executor.submit(_run_group, name, commands, run): name
            for name, commands in GROUPS.items()
        }
        for future in as_completed(pending):
            try:
                if not future.result():
                    success = False
            except Exception as error:
                print(f'{pending[future]}: unexpected {type(error).__name__}', file=sys.stderr, flush=True)
                success = False
    return 0 if success else 1


if __name__ == '__main__':
    raise SystemExit(main())
