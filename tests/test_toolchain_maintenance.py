"""Regression coverage for reproducible tool selection and lock preservation."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tomllib

import pytest


ROOT = Path(__file__).resolve().parents[1]


def test_container_update_jobs_have_a_manifest_for_their_ecosystem():
    text = (ROOT / '.github/dependabot.yml').read_text(encoding='utf-8')
    blocks = re.split(r'^  - package-ecosystem:\s*', text, flags=re.M)[1:]
    for block in blocks:
        ecosystem = block.splitlines()[0].strip().strip('"')
        if ecosystem not in {'docker', 'docker-compose'}:
            continue
        directory = re.search(r'^\s+directory:\s*"([^"]+)"', block, re.M).group(1)
        target = ROOT / directory.lstrip('/')
        candidates = ('Dockerfile',) if ecosystem == 'docker' else (
            'compose.yml', 'compose.yaml', 'docker-compose.yml', 'docker-compose.yaml',
        )
        assert any((target / name).is_file() for name in candidates), (ecosystem, directory)


def test_every_uv_setup_consumes_the_same_required_version():
    config = tomllib.loads((ROOT / 'uv.toml').read_text(encoding='utf-8'))
    assert re.fullmatch(r'==\d+\.\d+\.\d+', config['required-version'])
    setups = []
    for path in (ROOT / '.github/workflows').glob('*.yml'):
        for block in re.split(r'\n\s+- (?:name:|uses:)', path.read_text(encoding='utf-8')):
            if 'astral-sh/setup-uv@' in block:
                assert 'version-file: uv.toml' in block, path
                assert not re.search(r'^\s+version:', block, re.M), path
                setups.append(path)
    assert len(setups) == 7


def test_scanner_fallbacks_use_the_same_pinned_release_images():
    """Images that stand in for failing release downloads carry the exact pinned version."""
    tests = (ROOT / '.github/workflows/tests.yml').read_text(encoding='utf-8')
    security = (ROOT / '.github/workflows/security.yml').read_text(encoding='utf-8')
    gitleaks = re.search(r'gitleaks/releases/download/(v\d+\.\d+\.\d+)/', tests).group(1)
    assert re.search(r'docker create ghcr\.io/gitleaks/gitleaks@sha256:[0-9a-f]{64}\)', tests)
    assert f'test "${{version#v}}" = "{gitleaks.lstrip("v")}"' in tests
    syft = re.search(r"syft-version:\s*['\"]?v(\d+\.\d+\.\d+)", security).group(1)
    assert re.search(r'docker create ghcr\.io/anchore/syft@sha256:[0-9a-f]{64}\)', security)
    assert f'tool="$RUNNER_TOOL_CACHE/syft/{syft}/x64"' in security
    assert f'print $2}}\')" = "{syft}"' in security
    assert security.index('Provide the pinned Syft release') < security.index('anchore/sbom-action@')


def test_security_scanners_select_explicit_engines_independent_of_action_defaults():
    engines = {'aquasecurity/trivy-action': 'version', 'anchore/sbom-action': 'syft-version'}
    selected = {name: set() for name in engines}
    for path in (ROOT / '.github/workflows').glob('*.yml'):
        for block in re.split(r'\n\s+- (?:name:|uses:)', path.read_text(encoding='utf-8')):
            for action, key in engines.items():
                if action + '@' not in block:
                    continue
                match = re.search(r'^\s+' + key + r":\s*['\"]?(v?\d+\.\d+\.\d+)['\"]?\s*$", block, re.M)
                assert match, (path, action)
                selected[action].add(match.group(1))
    assert all(len(versions) == 1 for versions in selected.values())


@pytest.mark.parametrize('mode', ['late-failure', 'check', 'conflicting-options'])
def test_lock_generator_preserves_existing_files_without_a_successful_update(tmp_path, mode):
    """A late resolver failure or read-only invocation cannot replace any lock."""
    pwsh = shutil.which('pwsh')
    if not pwsh:
        pytest.skip('PowerShell is required to exercise the real lock generator')
    scripts = tmp_path / 'scripts'
    scripts.mkdir()
    shutil.copyfile(ROOT / 'scripts/lock_requirements.ps1', scripts / 'lock_requirements.ps1')
    names = ('requirements', 'requirements-test', 'requirements-graph')
    for name in names:
        (tmp_path / (name + '.in')).write_text('example==1\n', encoding='utf-8')
        (tmp_path / (name + '.txt')).write_bytes(b'--require-hashes\nexample==1\n')
    original = {name: (tmp_path / (name + '.txt')).read_bytes() for name in names}
    runner = tmp_path / 'run.ps1'
    runner.write_text('''$global:lockTestCalls = 0
function global:uv {
    $global:lockTestCalls += 1
    if ($env:LOCK_TEST_MODE -eq 'conflicting-options') { throw 'resolver must not run' }
    if ($env:LOCK_TEST_MODE -eq 'late-failure' -and $global:lockTestCalls -eq 3) {
        $global:LASTEXITCODE = 1
        return
    }
    $outputIndex = [array]::IndexOf($args, '--output-file') + 1
    [System.IO.File]::WriteAllText($args[$outputIndex], "example==1`n")
    $global:LASTEXITCODE = 0
}
try {
    if ($env:LOCK_TEST_MODE -eq 'check') { & ./scripts/lock_requirements.ps1 -Check }
    elseif ($env:LOCK_TEST_MODE -eq 'conflicting-options') { & ./scripts/lock_requirements.ps1 -Check -Upgrade }
    else { & ./scripts/lock_requirements.ps1 -Upgrade }
    exit 0
} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }
''', encoding='utf-8')
    result = subprocess.run([pwsh, '-NoProfile', '-File', str(runner)], cwd=tmp_path,
                            env={**os.environ, 'LOCK_TEST_MODE': mode}, capture_output=True,
                            text=True, encoding='utf-8', timeout=30)
    assert result.returncode == (0 if mode == 'check' else 1), result.stderr
    if mode == 'late-failure':
        assert 'could not compile requirements-graph.in' in result.stderr
    if mode == 'conflicting-options':
        assert '-Check and -Upgrade cannot be used together' in result.stderr
        assert 'resolver must not run' not in result.stderr
    assert {name: (tmp_path / (name + '.txt')).read_bytes() for name in names} == original


def test_lock_generator_never_seeds_the_resolver_with_committed_hashes(tmp_path):
    """uv keeps seeded hash lines unverified, so -Check could not detect added hashes."""
    pwsh = shutil.which('pwsh')
    if not pwsh:
        pytest.skip('PowerShell is required to exercise the real lock generator')
    scripts = tmp_path / 'scripts'
    scripts.mkdir()
    shutil.copyfile(ROOT / 'scripts/lock_requirements.ps1', scripts / 'lock_requirements.ps1')
    names = ('requirements', 'requirements-test', 'requirements-graph')
    bogus = '--hash=sha256:' + 'ab' * 32
    for name in names:
        (tmp_path / (name + '.in')).write_text('example==1\n', encoding='utf-8')
        (tmp_path / (name + '.txt')).write_text(
            '--require-hashes\n'
            "example==1 ; sys_platform == 'win32' \\\n"
            f'    {bogus} \\\n'
            f'    {bogus}\n'
            '    # via -r requirements.in\n',
            encoding='utf-8',
        )
    seeds = tmp_path / 'seeds'
    seeds.mkdir()
    runner = tmp_path / 'run.ps1'
    runner.write_text('''function global:uv {
    $outputIndex = [array]::IndexOf($args, '--output-file') + 1
    $output = $args[$outputIndex]
    Copy-Item -LiteralPath $output -Destination (Join-Path $env:LOCK_TEST_SEEDS (Split-Path $output -Leaf))
    [System.IO.File]::WriteAllText($output, "example==1`n")
    $global:LASTEXITCODE = 0
}
try { & ./scripts/lock_requirements.ps1 -Check; exit 0 }
catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }
''', encoding='utf-8')
    result = subprocess.run([pwsh, '-NoProfile', '-File', str(runner)], cwd=tmp_path,
                            env={**os.environ, 'LOCK_TEST_SEEDS': str(seeds)},
                            capture_output=True, text=True, encoding='utf-8', timeout=30)
    assert result.returncode == 1
    assert 'requirements.txt is out of date' in result.stderr
    seed = (seeds / 'requirements.txt').read_text(encoding='utf-8')
    assert seed.splitlines() == [
        '--require-hashes',
        "example==1 ; sys_platform == 'win32'",
        '    # via -r requirements.in',
    ]
