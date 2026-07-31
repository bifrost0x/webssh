"""Policy checks for immutable CI and container build inputs."""

from datetime import date
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / '.github' / 'workflows'
FULL_SHA = re.compile(r'[0-9a-f]{40}')
IMAGE_DIGEST = re.compile(r'@sha256:[0-9a-f]{64}(?:\s|$)')
PINNED_ACTIONS = {
    'actions/checkout': (
        '3d3c42e5aac5ba805825da76410c181273ba90b1',
        'v7',
    ),
    'actions/deploy-pages': (
        'cd2ce8fcbc39b97be8ca5fce6e763baed58fa128',
        'v5',
    ),
    'actions/setup-node': (
        '249970729cb0ef3589644e2896645e5dc5ba9c38',
        'v6',
    ),
    'actions/setup-python': (
        'ece7cb06caefa5fff74198d8649806c4678c61a1',
        'v6',
    ),
    'actions/upload-artifact': (
        'ea165f8d65b6e75b540449e92b4886f43607fa02',
        'v4',
    ),
    'actions/upload-pages-artifact': (
        'fc324d3547104276b827a68afc52ff2a11cc49c9',
        'v5',
    ),
    'anchore/sbom-action': (
        'e22c389904149dbc22b58101806040fa8d37a610',
        'v0.24.0',
    ),
    'aquasecurity/trivy-action': (
        'ed142fd0673e97e23eac54620cfb913e5ce36c25',
        'v0.36.0',
    ),
    'astral-sh/setup-uv': (
        '94527f2e458b27549849d47d273a16bec83a01e9',
        'v7',
    ),
    'docker/build-push-action': (
        '53b7df96c91f9c12dcc8a07bcb9ccacbed38856a',
        'v7',
    ),
    'docker/login-action': (
        'dbcb813823bdd20940b903addbd779551569679f',
        'v4',
    ),
    'docker/metadata-action': (
        'dc802804100637a589fabce1cb79ff13a1411302',
        'v6',
    ),
    'docker/setup-buildx-action': (
        'bb05f3f5519dd87d3ba754cc423b652a5edd6d2c',
        'v4',
    ),
    'docker/setup-qemu-action': (
        '96fe6ef7f33517b61c61be40b68a1882f3264fb8',
        'v4',
    ),
}


def _workflow_texts():
    return {
        path.name: path.read_text(encoding='utf-8')
        for pattern in ('*.yml', '*.yaml')
        for path in WORKFLOWS.glob(pattern)
    }


def test_remote_actions_are_immutable_and_keep_version_comments():
    remote_actions = []
    for workflow, text in _workflow_texts().items():
        for line_number, line in enumerate(text.splitlines(), start=1):
            match = re.search(r'\buses:\s*([^\s#]+)(?:\s+#\s*(\S+))?', line)
            if match is None or match.group(1).startswith('./'):
                continue
            reference = match.group(1)
            action, separator, revision = reference.rpartition('@')
            assert separator and FULL_SHA.fullmatch(revision), (
                f'{workflow}:{line_number} has mutable action {reference}'
            )
            version_comment = match.group(2)
            assert action and version_comment and version_comment.startswith('v'), (
                f'{workflow}:{line_number} must retain a human-readable version'
            )
            assert action in PINNED_ACTIONS, (
                f'{workflow}:{line_number} uses unreviewed action {action}'
            )
            assert (revision, version_comment) == PINNED_ACTIONS[action], (
                f'{workflow}:{line_number} has an unreviewed pin/version pair'
            )
            remote_actions.append(reference)
    assert remote_actions


def test_container_build_inputs_and_ci_services_are_digest_pinned():
    dockerfiles = [
        ROOT / 'Dockerfile',
        ROOT / 'tests' / 'integration' / 'paramiko5' / 'Dockerfile',
    ]
    for dockerfile in dockerfiles:
        from_lines = [
            line.strip()
            for line in dockerfile.read_text(encoding='utf-8').splitlines()
            if line.lstrip().startswith('FROM ')
        ]
        assert from_lines
        assert all(IMAGE_DIGEST.search(line) for line in from_lines), dockerfile

    tests_workflow = (WORKFLOWS / 'tests.yml').read_text(encoding='utf-8')
    redis_references = re.findall(r'redis:[78]-alpine[^\s#]*', tests_workflow)
    assert len(redis_references) >= 3
    assert all(IMAGE_DIGEST.search(reference) for reference in redis_references)


def test_security_workflow_gates_publish_and_preserves_scan_evidence():
    security = (WORKFLOWS / 'security.yml').read_text(encoding='utf-8')
    publish = (WORKFLOWS / 'docker-publish.yml').read_text(encoding='utf-8')

    assert 'workflow_call:' in security
    assert 'schedule:' in security
    assert re.search(r'permissions:\s*\n\s+contents:\s+read\b', security)
    assert not re.search(r'^\s+\w[\w-]*:\s+write\b', security, re.MULTILINE)
    assert 'docker/setup-qemu-action@' in security
    assert re.search(r'platforms:\s*linux/amd64\b', security)
    assert re.search(r'platforms:\s*linux/arm64\b', security)
    assert (
        'outputs: type=docker,dest=/tmp/webssh-arm64.tar'
        in security
    )

    assert 'anchore/sbom-action@' in security
    assert re.search(r'format:\s*[\'"]?spdx-json', security)
    assert re.search(r'output-file:\s*[\'"]?webssh\.spdx\.json', security)

    assert security.count('aquasecurity/trivy-action@') == 2
    assert re.search(r'exit-code:\s*[\'"]?1', security)
    assert re.search(r'ignore-unfixed:\s*[\'"]?true', security)
    assert re.search(r'severity:\s*[\'"]?CRITICAL,HIGH', security)
    assert 'output: trivy-results-amd64.json' in security
    assert 'input: /tmp/webssh-arm64.tar' in security
    assert 'output: trivy-results-arm64.json' in security
    assert 'trivyignores: .trivyignore.yaml' in security
    assert re.search(
        r'if:\s*\$\{\{\s*always\(\)\s*\}\}.*?'
        r'actions/upload-artifact@',
        security,
        re.DOTALL,
    )

    assert re.search(
        r'security-scan:\s*\n\s+uses:\s+\./\.github/workflows/security\.yml',
        publish,
    )
    assert re.search(
        r'build-and-push:.*?\n\s+needs:\s+security-scan\b',
        publish,
        re.DOTALL,
    )
    assert re.search(r'\n\s+sbom:\s+true\b', publish)
    assert re.search(r'\n\s+provenance:\s+mode=max\b', publish)


def test_publish_records_and_verifies_the_immutable_image_identity():
    publish = (WORKFLOWS / 'docker-publish.yml').read_text(encoding='utf-8')

    assert re.search(
        r'- name: Build and push Docker image\s+id:\s+build\b',
        publish,
    )
    assert 'VCS_REF=${{ github.sha }}' in publish
    assert 'IMAGE_DIGEST: ${{ steps.build.outputs.digest }}' in publish
    assert 'docker buildx imagetools inspect "$immutable_ref"' in publish
    assert 'name: image-release-${{ github.sha }}' in publish
    assert 'path: image-release.json' in publish


def test_docker_image_declares_the_source_revision_label():
    dockerfile = (ROOT / 'Dockerfile').read_text(encoding='utf-8')

    assert 'ARG VCS_REF=unknown' in dockerfile
    assert 'LABEL org.opencontainers.image.revision=$VCS_REF' in dockerfile


def test_trivy_suppressions_are_justified_and_expire():
    policy = json.loads(
        (ROOT / '.trivyignore.yaml').read_text(encoding='utf-8')
    )
    assert set(policy) == {'vulnerabilities'}
    assert isinstance(policy['vulnerabilities'], list)
    for suppression in policy['vulnerabilities']:
        assert set(suppression) == {'id', 'statement', 'expired_at'}
        assert re.fullmatch(r'(?:CVE|GHSA)-[A-Za-z0-9-]+', suppression['id'])
        assert suppression['statement'].strip()
        assert date.fromisoformat(suppression['expired_at']) >= date.today()


def test_dependabot_tracks_pinned_docker_bases():
    config = (ROOT / '.github' / 'dependabot.yml').read_text(encoding='utf-8')
    docker_blocks = re.findall(
        r'- package-ecosystem:\s*"docker"\s+(.*?)(?=\n\s+- package-ecosystem:|\Z)',
        config,
        re.DOTALL,
    )
    assert len(docker_blocks) == 2
    directories = {
        re.search(r'directory:\s*"([^"]+)"', block).group(1)
        for block in docker_blocks
    }
    assert directories == {'/', '/tests/integration/paramiko5'}


def test_graph_pages_toolchain_versions_are_explicit():
    workflow = (WORKFLOWS / 'graph-pages.yml').read_text(encoding='utf-8')
    graph_input = (ROOT / 'requirements-graph.in').read_text(encoding='utf-8')
    graph_lock = (ROOT / 'requirements-graph.txt').read_text(encoding='utf-8')

    assert re.search(r'with:\s*\n\s+version:\s*[\'"]?0\.12\.0', workflow)
    assert 'uv pip install --require-hashes -r requirements-graph.txt' in workflow
    assert 'graphifyy==0.9.30' in graph_input
    assert '--require-hashes' in graph_lock
    assert 'graphifyy==0.9.30' in graph_lock


def test_workflows_use_an_explicit_runner_release():
    for workflow, text in _workflow_texts().items():
        assert 'ubuntu-latest' not in text, workflow
        for runner in re.findall(r'runs-on:\s*(\S+)', text):
            assert runner == 'ubuntu-24.04', f'{workflow}: {runner}'


def test_browser_ci_runs_javascript_units_before_playwright():
    workflow = (WORKFLOWS / 'tests.yml').read_text(encoding='utf-8')
    browser_job = workflow.split('  browser-e2e:', 1)[1].split(
        '\n  container-threading-smoke:',
        1,
    )[0]

    unit_step = browser_job.index('run: npm run test:js')
    browser_step = browser_job.index('run: npm run test:e2e')

    assert unit_step < browser_step
