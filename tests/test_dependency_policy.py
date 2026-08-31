import json
import re
from pathlib import Path

import pytest

from packaging.utils import canonicalize_name
from packaging.version import Version


APPROVED_PIP_INSTALL_COMMAND = (
    "python -m pip install --require-hashes -r requirements-test.txt"
)
ALLOWED_PIP_LINES = {"cache: pip", APPROVED_PIP_INSTALL_COMMAND}
MINIMUM_PYTHON = "3.11"
PRODUCTION_PYTHON = "3.14"


def pip_policy_allows(workflow):
    pip_lines = [
        line.strip()
        for line in workflow.splitlines()
        if line.strip() and "pip" in line.casefold()
    ]
    return (
        APPROVED_PIP_INSTALL_COMMAND in pip_lines
        and all(line in ALLOWED_PIP_LINES for line in pip_lines)
    )


def workflow_job(workflow, job_name):
    marker = f"\n  {job_name}:\n"
    _, separator, remainder = workflow.partition(marker)
    assert separator, f"missing workflow job: {job_name}"

    next_job = re.search(r"(?m)^  [a-zA-Z0-9_-]+:\s*$", remainder)
    return remainder[:next_job.start()] if next_job else remainder


def normalized_names(path):
    return {
        canonicalize_name(line.split("=", 1)[0].split("<", 1)[0].split(">", 1)[0])
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line and not line.startswith(("#", "-"))
    }


def locked_version(path, package_name):
    prefix = f"{package_name}=="
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.startswith(prefix):
            return Version(line.removeprefix(prefix).split()[0])
    raise AssertionError(f"{package_name} is not locked in {path}")


def lock_provenance(path, package_name):
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    prefix = f"{package_name}=="
    start = next(
        index for index, line in enumerate(lines) if line.startswith(prefix)
    )
    end = next(
        (index for index in range(start + 1, len(lines))
        if lines[index] and not lines[index].startswith((" ", "#"))),
        len(lines),
    )
    return "\n".join(lines[start:end])


def lock_provenance_set(block):
    return {
        line.partition("# via ")[2].strip()
        for line in block.splitlines()
        if "# via " in line
    }


def test_greenlet_provenance_parser_returns_exact_dependency_set():
    block = "greenlet==3.5.4 \\\n+    # via sqlalchemy\n"

    assert lock_provenance_set(block) == {"sqlalchemy"}


@pytest.mark.parametrize("path", ["requirements.txt", "requirements-test.txt"])
def test_runtime_locks_are_hashed_and_exclude_eventlet(path):
    """A resolver must not silently restore the superseded Eventlet runtime."""
    text = Path(path).read_text(encoding="utf-8")

    assert "--require-hashes" in text
    assert "eventlet" not in normalized_names(path)


@pytest.mark.parametrize(
    "path",
    ["requirements.txt", "requirements-test.txt", "requirements-graph.txt"],
)
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


@pytest.mark.parametrize("path", ["requirements.txt", "requirements-test.txt"])
def test_greenlet_lock_is_only_sqlalchemy_transitive_provenance(path):
    """Greenlet is SQLAlchemy's platform-marked dependency, not Eventlet runtime."""
    direct = normalized_names("requirements.in")

    assert "greenlet" not in direct
    assert "sqlalchemy" not in direct
    assert lock_provenance_set(lock_provenance(path, "greenlet")) == {"sqlalchemy"}


def test_runtime_artifacts_do_not_select_cooperative_runtime():
    """A stale Eventlet import or greenthread reference would change scheduling."""
    runtime_artifacts = (
        "requirements.in",
        "Dockerfile",
        "docker-compose.yml",
        "docker-compose.ldap.yml",
        "config.py",
        "start.py",
    )

    runtime_paths = [Path(artifact) for artifact in runtime_artifacts]
    runtime_paths.extend(Path("app").rglob("*.py"))

    for artifact in runtime_paths:
        text = artifact.read_text(encoding="utf-8").casefold()
        assert "eventlet" not in text
        assert "greenthread" not in text
        assert "greenlet" not in text


@pytest.mark.parametrize("path", ["requirements.txt", "requirements-test.txt"])
def test_runtime_locks_resolve_reviewed_gunicorn_26(path):
    """Gunicorn 25 would retain the superseded runtime baseline."""
    version = locked_version(path, "gunicorn")

    assert Version("26") <= version < Version("27")


def test_direct_requirements_do_not_hide_transitive_packages():
    direct = normalized_names("requirements.in")
    assert "sqlalchemy" not in direct
    assert "python-engineio" not in direct


def test_every_direct_version_range_has_an_adjacent_compatibility_reason():
    lines = Path("requirements.in").read_text(encoding="utf-8").splitlines()
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
    assert "Copy-Item -LiteralPath $committedLock -Destination $temporaryLock" in script
    assert 'if ($Upgrade)' in script
    assert '$compileArguments += "--upgrade"' in script


def test_lock_generator_compares_text_independent_of_checkout_line_endings():
    script = Path("scripts/lock_requirements.ps1").read_text(encoding="utf-8")

    assert "function Test-TextEqual" in script
    assert '.Replace("`r`n", "`n")' in script
    assert "Test-ByteEqual" not in script


@pytest.mark.parametrize("path", ["requirements.txt", "requirements-test.txt"])
def test_runtime_locks_exclude_vulnerable_cryptography_versions(path):
    """CVE-2026-69247 affects cryptography 44 through 49."""
    assert locked_version(path, "cryptography") >= Version("50.0.0")


@pytest.mark.parametrize("path", ["requirements.txt", "requirements-test.txt"])
def test_runtime_locks_include_reviewed_mfa_libraries(path):
    """TOTP verification and local SVG provisioning require reviewed APIs."""
    pyotp_version = locked_version(path, "pyotp")
    qrcode_version = locked_version(path, "qrcode")

    assert Version("2.10") <= pyotp_version < Version("3")
    assert Version("8.2") <= qrcode_version < Version("9")


def test_frontend_lock_excludes_vulnerable_socket_io_parser_versions():
    """CVE-2026-69185 affects socket.io-parser 4.0.0 through 4.2.6."""
    package_lock = json.loads(Path("package-lock.json").read_text(encoding="utf-8"))
    parser = package_lock["packages"]["node_modules/socket.io-parser"]

    assert Version(parser["version"]) >= Version("4.2.7")


def test_python_runtime_contract_stays_synchronized():
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    workflow = Path(".github/workflows/tests.yml").read_text(encoding="utf-8")
    readme = Path("README.md").read_text(encoding="utf-8")

    pytest_job = workflow_job(workflow, "pytest")
    matrix_entries = re.findall(
        r"- python_version: '([^']+)'\s+check_name: ([^\n]+)",
        pytest_job,
    )

    assert dockerfile.startswith(
        f"FROM python:{PRODUCTION_PYTHON}-slim@sha256:"
    )
    assert matrix_entries == [
        (PRODUCTION_PYTHON, "pytest"),
        (MINIMUM_PYTHON, f"pytest (Python {MINIMUM_PYTHON} minimum)"),
    ]
    assert "python-version: ${{ matrix.python_version }}" in pytest_job

    for job_name in ("ssh-integration", "browser-e2e"):
        assert (
            f"python-version: '{PRODUCTION_PYTHON}'"
            in workflow_job(workflow, job_name)
        )

    assert f"python-{MINIMUM_PYTHON}+" in readme


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

    assert 'graphifyy==0.9.51' in graph_input
    assert '--require-hashes' in graph_lock
    assert 'graphifyy==0.9.51' in graph_lock
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
