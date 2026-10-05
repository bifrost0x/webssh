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
    'actions/download-artifact': (
        '3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c',
        'v8.0.1',
    ),
    'actions/deploy-pages': (
        '368f82528645a54fb793d4d04e342629a3f51346',
        'v5',
    ),
    'actions/setup-node': (
        '820762786026740c76f36085b0efc47a31fe5020',
        'v7.0.0',
    ),
    'actions/setup-python': (
        '5fda3b95a4ea91299a34e894583c3862153e4b97',
        'v7.0.0',
    ),
    'actions/upload-artifact': (
        '043fb46d1a93c77aae656e7c1c64a875d1fc6a0a',
        'v7.0.1',
    ),
    'actions/upload-pages-artifact': (
        'fc324d3547104276b827a68afc52ff2a11cc49c9',
        'v5',
    ),
    'anchore/sbom-action': (
        '3ad7283483fc7af8ff2b4ea19663c2d5ca935e26',
        'v0.24.2',
    ),
    'aquasecurity/trivy-action': (
        'ed142fd0673e97e23eac54620cfb913e5ce36c25',
        'v0.36.0',
    ),
    'astral-sh/setup-uv': (
        'c18668ad3cf93ea998bef934396af7bb5c839dc7',
        'v10.2.0',
    ),
    'docker/build-push-action': (
        'c3c9e263c25d99ce0380d002d59b67737d91b0dc',
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
        'f87e5991a6d7451dcb8d9637bfbc97413f497069',
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


def test_node_workflows_use_current_lts():
    node_workflows = (
        WORKFLOWS / 'tests.yml',
        WORKFLOWS / 'dependabot-vendor.yml',
    )
    for workflow in node_workflows:
        text = workflow.read_text(encoding='utf-8')
        assert "node-version: '24'" in text, workflow
        assert "node-version: '22'" not in text, workflow


def test_wiki_sync_is_main_only_and_uses_the_repository_token():
    workflow = (WORKFLOWS / 'wiki-sync.yml').read_text(encoding='utf-8')

    assert 'pull_request:' not in workflow
    assert re.search(r'push:\s*\n\s+branches:\s*\n\s+- main\b', workflow)
    assert "if: github.ref == 'refs/heads/main'" in workflow
    assert re.search(r'permissions:\s*\n\s+contents:\s+write\b', workflow)
    assert re.search(r'concurrency:.*?queue:\s+max\b', workflow, re.DOTALL)
    assert 'persist-credentials: false' in workflow
    assert 'actions/setup-python@' in workflow
    assert "python-version: '3.11'" in workflow
    assert 'GH_TOKEN: ${{ github.token }}' in workflow
    assert 'secrets.' not in workflow
    assert 'scripts/wiki_sync.py' in workflow
    assert re.search(
        r'^\s*git -C "\$RUNNER_TEMP/webssh-wiki" add --all\s*$',
        workflow,
        re.MULTILINE,
    )
    assert 'add --all --' not in workflow
    assert workflow.count('git/ref/heads/main') >= 3
    assert '${{ runner.temp }}' not in workflow
    assert '"$RUNNER_TEMP/webssh-wiki"' in workflow
    assert 'push origin HEAD' in workflow

    publish = workflow.split('- name: Publish changed Wiki pages', 1)[1]
    commit = publish.index(' commit -m ')
    final_main_check = publish.rindex('git/ref/heads/main')
    push = publish.index(' push origin HEAD')
    assert commit < final_main_check < push


def test_container_build_inputs_and_ci_services_are_digest_pinned():
    dockerfiles = [
        ROOT / 'Dockerfile',
        ROOT / 'tests' / 'integration' / 'paramiko5' / 'Dockerfile',
        ROOT / 'tests' / 'integration' / 'smb' / 'Dockerfile',
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
    assert len(redis_references) == 2
    assert all(IMAGE_DIGEST.search(reference) for reference in redis_references)


def test_container_build_applies_available_base_image_security_updates():
    dockerfile = (ROOT / 'Dockerfile').read_text(encoding='utf-8')

    assert dockerfile.count('apt-get update') == 2
    assert dockerfile.count('apt-get upgrade --yes') == 2


def test_scanned_and_published_images_refresh_os_packages_per_ci_attempt():
    """A cached apt upgrade must not hide newly available security updates."""
    dockerfile = (ROOT / 'Dockerfile').read_text(encoding='utf-8')
    stages = re.split(r'^FROM ', dockerfile, flags=re.MULTILINE)[1:]
    assert len(stages) == 2
    for stage in stages:
        assert stage.index('ARG OS_PACKAGE_REFRESH=local') < stage.index(
            'RUN apt-get update'
        )

    refresh = 'OS_PACKAGE_REFRESH=${{ github.run_id }}-${{ github.run_attempt }}'
    for filename, expected_builds in [('security.yml', 2), ('docker-publish.yml', 1)]:
        workflow = (WORKFLOWS / filename).read_text(encoding='utf-8')
        builds = re.split(r'uses: docker/build-push-action@', workflow)[1:]
        assert len(builds) == expected_builds
        for build in builds:
            step = re.split(r'\n      - ', build)[0]
            assert re.search(r'build-args:\s*\|\n(?:[^\n]*\n)*?\s+'
                             + re.escape(refresh), step)


def test_security_workflow_gates_publish_and_preserves_scan_evidence():
    security = (WORKFLOWS / 'security.yml').read_text(encoding='utf-8')
    publish = (WORKFLOWS / 'docker-publish.yml').read_text(encoding='utf-8')

    assert 'workflow_call:' in security
    assert 'schedule:' in security
    assert re.search(r'permissions:\s*\n\s+contents:\s+read\b', security)
    assert not re.search(r'^\s+\w[\w-]*:\s+write\b', security, re.MULTILINE)
    assert 'docker/setup-qemu-action@' not in security
    assert 'runs-on: ubuntu-24.04-arm' in security
    assert 'image-security-amd64:' in security
    assert 'image-security-arm64:' in security
    assert re.search(
        r'image-security:\s*\n\s+needs:\s*'
        r'\[change-scope, image-security-amd64, image-security-arm64\]',
        security,
    )
    assert 'GATE_KIND: images' in security
    assert 'python scripts/check_release_gates.py' in security
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
        r'build-and-push:.*?\n\s+needs:\s+\[release-tests, build-candidate\]',
        publish,
        re.DOTALL,
    )
    assert re.search(
        r'build-and-push:.*?\n\s+needs:\s+\[release-tests, build-candidate\]\s*\n'
        r"\s+if:\s+github\.event_name\s+!=\s+'pull_request'",
        publish,
        re.DOTALL,
    )
    assert re.search(r'\n\s+sbom:\s+true\b', publish)
    assert re.search(r'\n\s+provenance:\s+mode=max\b', publish)


def test_publish_records_and_verifies_the_immutable_image_identity():
    publish = (WORKFLOWS / 'docker-publish.yml').read_text(encoding='utf-8')

    assert re.search(
        r'- name: Build immutable native candidate\s+id:\s+build\b',
        publish,
    )
    assert 'VCS_REF=${{ github.sha }}' in publish
    assert 'IMAGE_DIGEST: ${{ steps.build.outputs.digest }}' in publish
    assert 'python scripts/release_image.py inspect-platform' in publish
    assert 'python scripts/release_image.py assemble' in publish
    assert 'python scripts/release_image.py promote' in publish
    assert 'name: image-release-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}' in publish
    assert 'path: image-release.json' in publish


def test_docker_image_declares_the_source_revision_label():
    dockerfile = (ROOT / 'Dockerfile').read_text(encoding='utf-8')

    assert 'ARG VCS_REF=unknown' in dockerfile
    assert 'LABEL org.opencontainers.image.revision=$VCS_REF' in dockerfile


def test_runtime_image_excludes_repository_only_tooling():
    ignored = {
        line.strip()
        for line in (ROOT / '.dockerignore').read_text(
            encoding='utf-8'
        ).splitlines()
        if line.strip() and not line.lstrip().startswith('#')
    }

    assert {
        '.agents/',
        '.codex/',
        '.env.example',
        '.trivyignore.yaml',
        'AGENTS.md',
        'design-qa.md',
        'docker-compose*.yml',
        'package*.json',
        'playwright.config.js',
        'requirements-graph.*',
        'requirements-test.*',
        'requirements.in',
        'scripts/',
    } <= ignored


def test_runtime_image_removes_python_packaging_tooling():
    dockerfile = (ROOT / 'Dockerfile').read_text(encoding='utf-8')

    assert 'python -m pip uninstall --yes pip' in dockerfile
    assert 'rm -rf /usr/local/lib/python*/ensurepip' in dockerfile


def test_ci_rejects_stale_vendored_frontend_assets():
    package = json.loads((ROOT / 'package.json').read_text(encoding='utf-8'))
    workflow = (WORKFLOWS / 'tests.yml').read_text(encoding='utf-8')

    assert package['scripts']['vendor:check'] == (
        'node scripts/vendor.js --check'
    )
    assert re.search(
        r'Install locked Node dependencies.*?npm ci.*?'
        r'Check vendored frontend assets.*?npm run vendor:check.*?'
        r'Run JavaScript unit tests',
        workflow,
        re.DOTALL,
    )


def test_dependabot_vendor_refresh_uses_a_separate_validated_write_workflow():
    workflow = (WORKFLOWS / 'dependabot-vendor.yml').read_text(
        encoding='utf-8'
    )
    tests_workflow = (WORKFLOWS / 'tests.yml').read_text(encoding='utf-8')

    assert 'workflow_run:' in workflow
    assert 'workflows: [Tests]' in workflow
    assert 'contents: write' in workflow
    assert 'pull-requests: read' in workflow
    assert 'actions: write' in workflow
    assert 'pull_request_target' not in workflow
    assert 'scripts/dependabot_vendor.py validate' in workflow
    assert '--jobs' in workflow
    assert 'npm ci --ignore-scripts' in workflow
    assert 'node scripts/vendor.js' in workflow
    assert 'node scripts/vendor.js --check' in workflow
    assert 'npm run vendor:check' not in workflow
    assert 'persist-credentials: false' in workflow
    assert 'gh auth setup-git' in workflow
    assert '[dependabot skip]' in workflow
    assert (
        'cp scripts/dependabot_vendor.py "$RUNNER_TEMP/dependabot_vendor.py"'
        in workflow
    )
    assert 'python "$RUNNER_TEMP/dependabot_vendor.py" stage' in workflow
    assert 'gh workflow run tests.yml' in workflow
    assert '-f expected_sha="$EXPECTED_SHA"' in workflow
    assert 'EXPECTED_SHA: ${{ inputs.expected_sha }}' in tests_workflow
    assert 'workflow_dispatch:' in tests_workflow


def test_dependabot_vendor_refresh_checks_out_validated_head_before_generation():
    workflow = (WORKFLOWS / 'dependabot-vendor.yml').read_text(
        encoding='utf-8'
    )

    validation = workflow.index('Fetch and validate Dependabot context')
    checkout = workflow.index('Checkout validated Dependabot head')
    generation = workflow.index('Generate vendor assets from locked dependencies')

    assert validation < checkout < generation
    assert 'git checkout --detach FETCH_HEAD' in workflow
    assert '> package.json' not in workflow
    assert '> package-lock.json' not in workflow


def test_dependabot_vendor_refresh_executes_only_trusted_automation_scripts():
    workflow = (WORKFLOWS / 'dependabot-vendor.yml').read_text(
        encoding='utf-8'
    )

    snapshot = workflow.index(
        'sha256sum scripts/vendor.js scripts/dependabot_vendor.py'
    )
    checkout = workflow.index('git checkout --detach FETCH_HEAD')
    verification = workflow.index(
        'sha256sum --check "$RUNNER_TEMP/trusted-script-checksums"'
    )
    generation = workflow.index('node scripts/vendor.js')

    assert snapshot < checkout < verification < generation


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
    assert len(docker_blocks) == 3
    directories = {
        re.search(r'directory:\s*"([^"]+)"', block).group(1)
        for block in docker_blocks
    }
    assert directories == {
        '/',
        '/tests/integration/paramiko5',
        '/tests/integration/smb',
    }


def test_graph_pages_toolchain_versions_are_explicit():
    workflow = (WORKFLOWS / 'graph-pages.yml').read_text(encoding='utf-8')
    graph_input = (ROOT / 'requirements-graph.in').read_text(encoding='utf-8')
    graph_lock = (ROOT / 'requirements-graph.txt').read_text(encoding='utf-8')

    assert re.search(r'with:\s*\n\s+version:\s*[\'"]?0\.12\.3', workflow)
    assert 'uv pip install --require-hashes -r requirements-graph.txt' in workflow
    assert 'graphifyy==0.9.73' in graph_input
    assert '--require-hashes' in graph_lock
    assert 'graphifyy==0.9.73' in graph_lock


def test_workflows_use_an_explicit_runner_release():
    allowed = {'ubuntu-24.04', 'ubuntu-24.04-arm'}
    for workflow, text in _workflow_texts().items():
        assert 'ubuntu-latest' not in text, workflow
        for runner in re.findall(r'runs-on:\s*([^\n]+)', text):
            if runner.strip() == '${{ matrix.runner }}':
                values = re.findall(r'^\s+runner:\s*(\S+)', text, re.MULTILINE)
                assert values and set(values) <= allowed, workflow
            else:
                assert runner.strip() in allowed, f'{workflow}: {runner}'


def test_browser_ci_runs_javascript_units_before_playwright():
    workflow = (WORKFLOWS / 'tests.yml').read_text(encoding='utf-8')
    browser_job = workflow.split('  browser-e2e-shards:', 1)[1].split(
        '\n  browser-e2e:',
        1,
    )[0]

    unit_step = browser_job.index('run: npm run test:js')
    browser_step = browser_job.index('run: npm run test:e2e')

    assert unit_step < browser_step


def test_slow_test_gates_are_sharded_without_duplicate_redis_unit_runs():
    workflow = (WORKFLOWS / 'tests.yml').read_text(encoding='utf-8')
    playwright = (ROOT / 'playwright.config.js').read_text(encoding='utf-8')

    assert '--ignore=tests/integration' in workflow
    assert '-n 2' in workflow
    assert '--dist=loadscope' in workflow
    assert '--durations=30' in workflow
    assert workflow.count(
        'tests/test_rate_limiter.py::'
        'test_real_redis_does_not_store_denied_requests'
    ) == 1
    assert 'name: browser-e2e (${{ matrix.shard }}/2)' in workflow
    assert 'npm run test:e2e:ci -- --shard=${{ matrix.shard }}/2' in workflow
    assert re.search(
        r'\n  browser-e2e:\s*\n\s+needs:\s+\[dispatch-integrity, browser-e2e-shards\]',
        workflow,
    )
    assert 'test "$SHARD_RESULT" = success' in workflow
    assert 'fullyParallel: true' in playwright


def test_release_only_promotes_the_candidate_after_exact_sha_tests_and_scans():
    publish = (WORKFLOWS / 'docker-publish.yml').read_text(encoding='utf-8')
    assert 'uses: ./.github/workflows/tests.yml' in publish
    assert 'expected_sha: ${{ github.sha }}' in publish
    candidate = publish.split('\n  build-candidate:', 1)[1].split('\n  build-and-push:', 1)[0]
    publisher = publish.split('\n  build-and-push:', 1)[1]
    # Candidate work can overlap tests, but no public tag write can bypass either gate.
    assert not re.search(r'^    needs:', candidate, re.MULTILINE)
    assert 'needs: [release-tests, build-candidate]' in publisher
    assert 'push-by-digest=true,name-canonical=true,push=true' in candidate
    assert publish.count('uses: docker/build-push-action@') == 1
    build = candidate.split('- name: Build immutable native candidate', 1)[1].split('- name:', 1)[0]
    assert 'tags:' not in build
    assert 'platforms: linux/${{ matrix.arch }}' in build
    for arch, runner in (('amd64', 'ubuntu-24.04'), ('arm64', 'ubuntu-24.04-arm')):
        assert re.search(r'arch: ' + arch + r'\s+runner: ' + re.escape(runner) + r'\s', candidate)
    inspect = candidate.index('python scripts/release_image.py inspect-platform')
    scan = candidate.index('image-ref: ${{ env.RUNTIME_REF }}')
    runtime = candidate.index('python scripts/check_hardened_container.py')
    handoff = candidate.index('- name: Upload verified native identity')
    assert inspect < scan < runtime < handoff
    identity_step = candidate[handoff:].split('- name:', 2)[1]
    assert 'if: always()' not in identity_step
    assert 'image-candidate.json' in identity_step
    assert publisher.index('python scripts/release_image.py assemble') < publisher.index('python scripts/release_image.py promote')
    assert 'docker/build-push-action@' not in publisher
    assert 'continue-on-error:' not in publish
    assert 'cancel-in-progress: false' in publisher


def test_reusable_tests_preserve_standalone_and_fail_closed_contracts():
    from scripts.check_release_gates import REQUIRED
    workflow = (WORKFLOWS / 'tests.yml').read_text(encoding='utf-8')
    assert workflow.startswith('name: Tests\n')
    assert all(trigger + ':' in workflow for trigger in ('pull_request', 'workflow_call', 'workflow_dispatch'))
    assert not re.search(r'^  push:', workflow, re.MULTILINE)
    assert 'github.run_id' in workflow.split('jobs:', 1)[0]
    assert "[ -n \"$EXPECTED_SHA\" ]" in workflow
    gate = workflow.split('  all-tests:', 1)[1]
    needs = re.search(r'needs: \[(.*?)\]', gate).group(1)
    assert set(needs.split(', ')) == REQUIRED
    assert 'if: ${{ always() }}' in gate
    assert 'GATE_RESULTS: ${{ toJSON(needs) }}' in gate
    assert 'python scripts/check_release_gates.py' in gate
    assert (ROOT / 'scripts/check_release_promotion.py').is_file()


def test_opt_in_hardening_preserves_restrictions_and_ldap_mounts():
    import os
    import shutil
    import subprocess
    import pytest

    docker = shutil.which('docker')
    if docker is None:
        pytest.skip('Docker Compose CLI is unavailable')
    environment = dict(os.environ, WEBSSH_ORIGIN='https://ssh.example.com',
                       WEBSSH_PIDS_LIMIT='768', WEBSSH_MEMORY_LIMIT='3g')
    for ldap in (False, True):
        arguments = [docker, 'compose', '-f', 'docker-compose.yml']
        if ldap:
            arguments.extend(['-f', 'docker-compose.ldap.yml'])
        arguments.extend(['-f', 'docker-compose.production.yml',
                          '-f', 'docker-compose.hardened.yml', 'config', '--format', 'json'])
        result = subprocess.run(arguments, cwd=ROOT, env=environment,
                                capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stderr
        service = json.loads(result.stdout)['services']['webssh']
        assert service['read_only'] is True
        assert service['cap_drop'] == ['ALL']
        assert service['security_opt'] == ['no-new-privileges:true']
        assert int(service['pids_limit']) == 768
        assert int(service['mem_limit']) == 3 * 1024 ** 3
        assert service['environment']['XDG_RUNTIME_DIR'] == '/run/webssh'
        assert service['ports'][0]['host_ip'] == '127.0.0.1'
        assert len(service['ports']) == 1
        for mount in service['tmpfs']:
            assert all(option in mount for option in ('noexec', 'nosuid', 'nodev', 'size='))
        assert any(mount.startswith('/tmp:') for mount in service['tmpfs'])
        assert any(mount.startswith('/run/webssh:') and 'mode=700' in mount
                   for mount in service['tmpfs'])
        volumes = {volume['target']: volume for volume in service['volumes']}
        assert not volumes['/app/data'].get('read_only', False)
        assert not volumes['/app/recovery'].get('read_only', False)
        if ldap:
            assert service['environment']['LDAP_ENABLED'] == 'true'
            assert volumes['/run/webssh-auth']['read_only'] is True
        else:
            assert '/run/webssh-auth' not in volumes


def test_publish_queues_releases_and_guards_only_main_promotion():
    publish = (WORKFLOWS / 'docker-publish.yml').read_text(encoding='utf-8')
    concurrency = publish.split('    concurrency:', 1)[1].split('    permissions:', 1)[0]
    assert 'queue: max' in concurrency
    assert 'cancel-in-progress: false' in concurrency
    step = publish.split('- name: Promote the verified index without rebuilding', 1)[1].split('- name:', 1)[0]
    assert 'if [ "$GITHUB_REF" = "refs/heads/main" ]; then' in step
    assert 'promotion_args+=(--require-current-main)' in step
    assert '\"${promotion_args[@]}\"' in step


def test_docs_selection_is_job_level_and_keeps_both_required_aggregates():
    tests = (WORKFLOWS / 'tests.yml').read_text(encoding='utf-8')
    images = (WORKFLOWS / 'security.yml').read_text(encoding='utf-8')
    for workflow in (tests, images):
        assert 'paths-ignore:' not in workflow
        assert 'paths:' not in workflow
        assert 'fetch-depth: 0' in workflow
        assert 'run: python scripts/ci_change_scope.py' in workflow
        assert 'mode: ${{ steps.scope.outputs.mode }}' in workflow
        assert 'if: ${{ always() }}' in workflow
    assert "CI_FORCE_FULL: ${{ inputs.expected_sha != '' }}" in tests
    assert 'python -m unittest discover -s tests -p test_documentation_surface.py -v' in tests
    assert '--ignore=tests/test_documentation_surface.py' in tests
    from scripts.check_release_gates import REQUIRED
    for name in REQUIRED - {'dispatch-integrity', 'browser-e2e'}:
        job = re.split(r'\n  [a-z][a-z-]*:', tests.split('\n  ' + name + ':', 1)[1], maxsplit=1)[0]
        assert 'needs: dispatch-integrity' in job
        assert "if: needs.dispatch-integrity.outputs.mode == 'full'" in job
    for arch in ('amd64', 'arm64'):
        job = re.split(r'\n  [a-z][a-z0-9-]*:', images.split('\n  image-security-' + arch + ':', 1)[1], maxsplit=1)[0]
        assert 'needs: change-scope' in job
        assert "if: needs.change-scope.outputs.mode == 'full'" in job
