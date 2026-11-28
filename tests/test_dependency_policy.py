import json
import re
from pathlib import Path

import pytest

from packaging.version import Version


APPROVED_PIP_INSTALL_COMMAND = (
    "python -m pip install --require-hashes -r requirements-test.txt"
)
APPROVED_UV_INSTALL_COMMAND = (
    'uv pip install --python "$(command -v python)" --require-hashes -r requirements-test.txt'
)
APPROVED_INSTALL_COMMANDS = {APPROVED_PIP_INSTALL_COMMAND, APPROVED_UV_INSTALL_COMMAND}
# "pipefail" contains "pip"; the exact strict-mode line installs nothing.
ALLOWED_PIP_LINES = {"cache: pip", "set -euo pipefail", *APPROVED_INSTALL_COMMANDS}
MINIMUM_PYTHON = "3.11"
PYTHON_INPUTS = ("requirements-test.in", "requirements-graph.in")
PYTHON_LOCKS = ("requirements-test.txt", "requirements-graph.txt")


def pip_policy_allows(workflow):
    pip_lines = [
        line.strip()
        for line in workflow.splitlines()
        if line.strip() and ("pip" in line.casefold() or re.search(r'\buv\s+', line, re.IGNORECASE))
    ]
    return (
        bool(APPROVED_INSTALL_COMMANDS.intersection(pip_lines))
        and all(line in ALLOWED_PIP_LINES for line in pip_lines)
    )


def locked_version(path, package_name):
    prefix = f"{package_name}=="
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.startswith(prefix):
            return Version(line.removeprefix(prefix).split()[0])
    raise AssertionError(f"{package_name} is not locked in {path}")


@pytest.mark.parametrize("path", PYTHON_LOCKS)
def test_python_tool_locks_are_hashed(path):
    text = Path(path).read_text(encoding="utf-8")

    assert "--require-hashes" in text
    assert re.search(r"--hash=sha256:[0-9a-f]{64}", text)


@pytest.mark.parametrize("path", PYTHON_LOCKS)
def test_lock_files_do_not_repeat_hashes_within_a_requirement(path):
    """A regenerated requirement must list each approved artifact only once."""
    requirement = None
    hashes = set()

    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line and not line.startswith((" ", "#", "-")):
            requirement = line.removesuffix(" \\")
            hashes = set()

        match = re.search(r"--hash=sha256:([0-9a-f]{64})", line)
        if not match:
            continue

        digest = match.group(1)
        assert digest not in hashes, f"duplicate hash for {requirement} in {path}"
        hashes.add(digest)


@pytest.mark.parametrize("path", PYTHON_INPUTS)
def test_every_direct_version_range_has_an_adjacent_compatibility_reason(path):
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    undocumented = []

    for index, line in enumerate(lines):
        requirement = line.strip()
        if not requirement or requirement.startswith(("#", "-")):
            continue
        if "==" in requirement or not any(
            operator in requirement for operator in ("<", ">", "~=", "!=")
        ):
            continue
        previous = lines[index - 1].strip() if index else ""
        if not previous.startswith("# Compatibility: "):
            undocumented.append(requirement)

    assert undocumented == []


def test_lock_generator_compiles_universal_locks():
    script = Path("scripts/lock_requirements.ps1").read_text(encoding="utf-8")
    assert '"pip", "compile", $InputFile' in script
    assert '"--universal"' in script
    assert f'"--python-version", "{MINIMUM_PYTHON}"' in script


def test_lock_generator_reuses_committed_pins_unless_upgrade_is_explicit():
    script = Path("scripts/lock_requirements.ps1").read_text(encoding="utf-8")

    assert "[switch]$Upgrade" in script
    assert "[System.IO.File]::ReadAllLines($committedLock)" in script
    assert "[System.IO.File]::WriteAllLines($temporaryLock, [string[]]$seedLines" in script
    assert "Where-Object { $_ -notmatch '^\\s*--hash=' }" in script
    assert 'if ($Upgrade)' in script
    assert '$compileArguments += "--upgrade"' in script


def test_lock_generator_compares_text_independent_of_checkout_line_endings():
    script = Path("scripts/lock_requirements.ps1").read_text(encoding="utf-8")

    assert "function Test-TextEqual" in script
    assert '.Replace("`r`n", "`n")' in script
    assert "Test-ByteEqual" not in script


def test_tool_lock_excludes_vulnerable_cryptography_versions():
    """CVE-2026-69247 affects cryptography 44 through 49."""
    assert locked_version("requirements-test.txt", "cryptography") >= Version("50.0.0")


def test_ci_installs_only_hash_checked_python_dependencies():
    workflow = Path(".github/workflows/tests.yml").read_text(encoding="utf-8")

    assert pip_policy_allows(workflow)


def test_browser_test_runner_is_not_a_frontend_runtime_dependency():
    package = json.loads(Path('package.json').read_text(encoding='utf-8'))

    assert 'playwright' not in package.get('dependencies', {})
    assert package.get('devDependencies', {}).get('playwright')


def test_graph_dependencies_are_hash_locked_and_generated_with_other_locks():
    graph_input = Path('requirements-graph.in').read_text(encoding='utf-8')
    graph_lock = Path('requirements-graph.txt').read_text(encoding='utf-8')
    lock_script = Path('scripts/lock_requirements.ps1').read_text(
        encoding='utf-8'
    )

    assert 'graphifyy==0.9.105' in graph_input
    assert '--require-hashes' in graph_lock
    assert 'graphifyy==0.9.105' in graph_lock
    assert 'requirements-graph.in' in lock_script
    assert 'requirements-graph.txt' in lock_script


def test_graph_pages_build_is_unprivileged_and_deploy_only_is_privileged():
    workflow = Path('.github/workflows/graph-pages.yml').read_text(
        encoding='utf-8'
    )
    build = workflow.split('\n  build:', 1)[1].split('\n  deploy:', 1)[0]
    deploy = workflow.split('\n  deploy:', 1)[1]

    assert 'permissions:\n  contents: read' in workflow
    assert 'permissions:\n      contents: read' in build
    assert 'pages: write' not in build
    assert 'id-token: write' not in build
    assert 'uv pip install --require-hashes -r requirements-graph.txt' in build
    assert 'needs: build' in deploy
    assert 'permissions:\n      pages: write\n      id-token: write' in deploy
    assert 'graphify update .' not in deploy


@pytest.mark.parametrize(
    ("lines", "allowed"),
    [
        ([APPROVED_PIP_INSTALL_COMMAND], True),
        (["cache: pip", APPROVED_PIP_INSTALL_COMMAND], True),
        ([APPROVED_PIP_INSTALL_COMMAND, "pip3 install -r requirements-test.txt"], False),
        (
            [
                APPROVED_PIP_INSTALL_COMMAND,
                "PIP_MODULE=pip",
                "$PIP_MODULE install -r requirements-test.txt",
            ],
            False,
        ),
        (
            [
                APPROVED_PIP_INSTALL_COMMAND,
                "python -m pip --isolated install -r requirements-unhashed.txt",
            ],
            False,
        ),
        ([APPROVED_PIP_INSTALL_COMMAND, "uv pip install -r requirements-test.txt"], False),
        (
            [
                APPROVED_PIP_INSTALL_COMMAND,
                "python -m pip install --no-require-hashes -r requirements-test.txt",
            ],
            False,
        ),
        (
            [
                APPROVED_PIP_INSTALL_COMMAND,
                "python -m pip install --require-hashes -r requirements-unhashed.txt",
            ],
            False,
        ),
        (
            [
                APPROVED_PIP_INSTALL_COMMAND,
                "python -m pip " + "\\",
                "install --require-hashes -r requirements-test.txt",
            ],
            False,
        ),
    ],
)
def test_pip_policy_allows_only_explicit_workflow_lines(lines, allowed):
    workflow = "\n".join(lines)

    assert pip_policy_allows(workflow) is allowed


@pytest.mark.parametrize('lines,allowed', [
    (['uv pip install --python "$(command -v python)" --require-hashes -r requirements-test.txt'], True),
    (['cache: pip', 'uv pip install --python "$(command -v python)" --require-hashes -r requirements-test.txt'], True),
    (['cache: pip'], False),
    ([], False),
    (['uv pip install --python "$(command -v python)" -r requirements-test.txt'], False),
    (['uv pip install --python "$(command -v python)" --require-hashes -r requirements.in'], False),
    (['uv pip install --python "$(command -v python)" --require-hashes -r requirements-test.txt requests'], False),
    (['uv pip install --python "$(command -v python)" --require-hashes -r requirements-test.txt --no-deps'], False),
    (['uv pip sync --python "$(command -v python)" --require-hashes -r requirements-test.txt'], False),
    ([APPROVED_PIP_INSTALL_COMMAND, 'uv add requests'], False),
    ([APPROVED_PIP_INSTALL_COMMAND, 'uv sync'], False),
    # Strict shell mode is not an install; anything appended to it still is.
    ([APPROVED_PIP_INSTALL_COMMAND, 'set -euo pipefail'], True),
    (['set -euo pipefail'], False),
    ([APPROVED_PIP_INSTALL_COMMAND, 'set -euo pipefail; pip install requests'], False),
    ([APPROVED_PIP_INSTALL_COMMAND, 'set -euo pipefail && python -m pip install requests'], False),
])
def test_uv_installer_policy_is_exact_and_keeps_all_hash_requirements(lines, allowed):
    assert pip_policy_allows('\n'.join(lines)) is allowed


def test_every_host_test_environment_sets_up_the_reviewed_uv_before_installing():
    workflow = Path('.github/workflows/tests.yml').read_text(encoding='utf-8')
    setup = 'astral-sh/setup-uv@68559e99cc807c1eb7e9238fd43a15bba460eec2'
    install = APPROVED_UV_INSTALL_COMMAND
    jobs = re.split(r'\n  (?=[a-z][a-z0-9-]*:\n)', workflow.split('\njobs:\n', 1)[1])
    installing = [job for job in jobs if install in job]

    assert [job.split(':', 1)[0].strip() for job in installing] == ['lint']
    for job in installing:
        assert job.index(setup) < job.index(install)
        assert "version-file: uv.toml" in job
