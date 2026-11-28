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
        '9000827ccba6bdab643e8b6fd33ac0654aef8333',
        'v8.0.2',
    ),
    'actions/deploy-pages': (
        '368f82528645a54fb793d4d04e342629a3f51346',
        'v5',
    ),
    'actions/setup-go': (
        'd8cbb8045d7f43706b9177cceb36c1f91a6644d5',
        'v7.1.0',
    ),
    'actions/setup-node': (
        '949feb2413d6458794dcd2491c4babbbce0c15c1',
        'v7.1.0',
    ),
    'actions/setup-python': (
        '6d4fd22b20465ccc0f7354476588e8df7c9ca0e0',
        'v7.1.0',
    ),
    'actions/upload-artifact': (
        'cf430e030ddbb5b0abf93d22962f4752f3646cd9',
        'v7.0.2',
    ),
    'actions/upload-pages-artifact': (
        'fc324d3547104276b827a68afc52ff2a11cc49c9',
        'v5',
    ),
    'anchore/sbom-action': (
        '66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c',
        'v0.24.3',
    ),
    'aquasecurity/trivy-action': (
        'ed142fd0673e97e23eac54620cfb913e5ce36c25',
        'v0.36.0',
    ),
    'astral-sh/setup-uv': (
        '68559e99cc807c1eb7e9238fd43a15bba460eec2',
        'v10.3.3',
    ),
    'docker/build-push-action': (
        'c3c9e263c25d99ce0380d002d59b67737d91b0dc',
        'v7',
    ),
    'docker/login-action': (
        '81c6f93d4bc991e510b342a00b419b3bb4efc5c6',
        'v4.7.0',
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


def _job(workflow, name):
    jobs = re.split(r'\n  (?=[a-z][a-z0-9-]*:\n)', workflow.split('\njobs:\n', 1)[1])
    return next(job for job in jobs if job.startswith(f'{name}:\n'))


def _dockerfile_stages(dockerfile):
    """Map each FROM line of a Dockerfile to the stage names defined before it."""
    stages, names = [], []
    for line in dockerfile.read_text(encoding='utf-8').splitlines():
        match = re.match(r'FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?', line.strip())
        if match:
            stages.append((line.strip(), match.group(1), tuple(names)))
            if match.group(2):
                names.append(match.group(2))
    return stages


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
        ROOT / 'tests' / 'integration' / 'herdr' / 'Dockerfile',
        *sorted((ROOT / 'tests' / 'lab' / 'images').glob('*/Dockerfile')),
    ]
    for dockerfile in dockerfiles:
        stages = _dockerfile_stages(dockerfile)
        assert stages, dockerfile
        for line, image, earlier in stages:
            # scratch and earlier stages (possibly selected by a build
            # argument such as herdr-${TARGETARCH}) pull nothing.
            local = image == 'scratch' or any(
                re.fullmatch(re.sub(r'\\\$\\\{[A-Z_]+\\\}', '.+', re.escape(image)), name)
                for name in earlier
            )
            assert local or IMAGE_DIGEST.search(line), (dockerfile, line)

    check = (ROOT / 'tests' / 'image' / 'check.sh').read_text(encoding='utf-8')
    references = re.findall(r'^[A-Z_]+=([a-z0-9./-]+:[^\s@]+@\S+)$', check, re.MULTILINE)
    assert len(references) == 2
    assert all(IMAGE_DIGEST.search(reference) for reference in references)


def test_images_built_inside_workflows_are_digest_pinned():
    # Dockerfiles written inline in a run step, such as the netns tools.
    found = []
    for workflow in sorted(WORKFLOWS.glob('*.yml')):
        text = workflow.read_text(encoding='utf-8')
        for match in re.finditer(r'FROM ([^\s\\]+)', text):
            found.append(match.group(1))
            assert re.search(r'@sha256:[0-9a-f]{64}$', match.group(1)), (workflow.name, match.group(1))
    assert found


def test_container_build_applies_available_base_image_security_updates():
    """The CA bundle is the only distribution package that reaches the image."""
    dockerfile = (ROOT / 'Dockerfile').read_text(encoding='utf-8')

    assert dockerfile.count('apk upgrade --no-cache ca-certificates-bundle') == 1
    assert not re.search(r'\b(?:apt-get|apk add|pip3? install)\b', dockerfile)


def test_scanned_and_published_images_refresh_os_packages_per_ci_attempt():
    """A cached package upgrade must not hide newly available security updates."""
    dockerfile = (ROOT / 'Dockerfile').read_text(encoding='utf-8')
    stages = [
        stage for stage in re.split(r'^FROM ', dockerfile, flags=re.MULTILINE)[1:]
        if 'apk upgrade' in stage
    ]
    assert len(stages) == 1
    assert stages[0].index('ARG OS_PACKAGE_REFRESH=local') < stages[0].index(
        'RUN apk upgrade'
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

    runtime = dockerfile.split('\nFROM scratch AS runtime\n', 1)[1].split('\nFROM ', 1)[0]
    label = re.search(r'^LABEL (?:.*\\\n)*.*$', runtime, re.MULTILINE).group(0)

    assert 'ARG VCS_REF=unknown' in runtime
    assert re.search(r'\borg\.opencontainers\.image\.revision=\$VCS_REF\b', label)


def test_runtime_image_excludes_repository_only_tooling():
    """The build context is an allowlist; every COPY source must be on it."""
    lines = [
        line.strip()
        for line in (ROOT / '.dockerignore').read_text(encoding='utf-8').splitlines()
        if line.strip() and not line.lstrip().startswith('#')
    ]
    allowed = {line[1:].rstrip('/') for line in lines if line.startswith('!')}

    assert lines[0] == '*'
    assert allowed == {
        'go.mod',
        'go.sum',
        'cmd',
        'internal',
        'static',
        'third_party/go-smb2',
        'scripts/stage-webassets.sh',
        'LICENSE',
        'NOTICE',
        'THIRD-PARTY-NOTICES',
    }
    # Exclusions after the allowlist win over it.
    last_include = max(index for index, line in enumerate(lines) if line.startswith('!'))
    assert {
        '**/.env',
        '**/.env.*',
        '**/*.db',
        '**/*.sqlite*',
        '**/*.pem',
        '**/*.key',
    } <= set(lines[last_include + 1:])

    dockerfile = (ROOT / 'Dockerfile').read_text(encoding='utf-8')
    assert not re.search(r'^COPY\s+\.\s', dockerfile, re.MULTILINE)
    copies = re.findall(r'^COPY\s+(?!--from=)((?:--\S+\s+)*)(.+)$', dockerfile, re.MULTILINE)
    assert copies
    for _flags, arguments in copies:
        for source in arguments.split()[:-1]:
            source = source.removeprefix('./').rstrip('/')
            assert any(source == entry or source.startswith(entry + '/') for entry in allowed), source


def test_runtime_image_is_scratch_without_shell_or_package_manager():
    dockerfile = (ROOT / 'Dockerfile').read_text(encoding='utf-8')

    assert re.search(r'^FROM scratch AS runtime$', dockerfile, re.MULTILINE)
    assert re.search(r'^FROM runtime AS release$', dockerfile, re.MULTILINE)
    assert dockerfile.rstrip().splitlines()[-1] == 'FROM runtime AS release'
    release = dockerfile.split('\nFROM runtime AS release\n', 1)[1]
    assert 'COPY' not in release and 'RUN' not in release
    assert 'USER 1000:1000' in dockerfile


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


def _dependabot_job(name):
    workflow = (WORKFLOWS / 'dependabot-vendor.yml').read_text(encoding='utf-8')
    jobs = re.split(r'^  (?=[a-z-]+:\n)', workflow.split('\njobs:\n', 1)[1], flags=re.M)
    return next(job for job in jobs if job.startswith(f'{name}:\n'))


def test_dependabot_workflow_grants_write_access_per_job_only():
    workflow = (WORKFLOWS / 'dependabot-vendor.yml').read_text(encoding='utf-8')
    header = workflow.split('\njobs:\n', 1)[0]

    assert re.search(r'^permissions: \{\}$', header, re.MULTILINE)
    for name, ecosystem, prefix in (
        ('refresh-vendor', 'npm', 'dependabot/npm_and_yarn/'),
        ('refresh-python-locks', 'pip', 'dependabot/pip/'),
    ):
        job = _dependabot_job(name)
        assert re.search(
            r'permissions:\n\s+contents: write\n\s+pull-requests: read\n\s+actions: write\n',
            job,
        ), name
        assert "github.event.workflow_run.actor.login == 'dependabot[bot]'" in job
        assert "github.event.workflow_run.conclusion == 'failure'" in job
        assert "github.event.workflow_run.event == 'pull_request'" in job
        assert (
            'github.event.workflow_run.head_repository.full_name == github.repository'
            in job
        )
        assert f"startsWith(github.event.workflow_run.head_branch, '{prefix}')" in job
        assert f'--ecosystem {ecosystem}' in job
        assert job.count('--ecosystem ') == 2, name
        assert 'persist-credentials: false' in job
        assert 'secrets.' not in job


def test_dependabot_python_lock_refresh_runs_only_trusted_generators():
    job = _dependabot_job('refresh-python-locks')

    setup_uv = job.index('astral-sh/setup-uv@')
    validation = job.index('scripts/dependabot_vendor.py validate')
    snapshot = job.index(
        'sha256sum scripts/lock_requirements.ps1 scripts/dependabot_vendor.py uv.toml'
    )
    checkout = job.index('git checkout --detach FETCH_HEAD')
    verification = job.index('sha256sum --check "$RUNNER_TEMP/trusted-script-checksums"')
    copy = job.index('cp scripts/dependabot_vendor.py "$RUNNER_TEMP/dependabot_vendor.py"')
    inputs = job.index('python "$RUNNER_TEMP/dependabot_vendor.py" check-python-inputs')
    generation = job.index('-File scripts/lock_requirements.ps1\n')
    check = job.index('-File scripts/lock_requirements.ps1 -Check')
    stage = job.index('python "$RUNNER_TEMP/dependabot_vendor.py" stage')
    remote_check = job.index('git ls-remote origin')
    credentials = job.index('gh auth setup-git')
    push = job.index('git push origin "HEAD:refs/heads/${HEAD_REF}"')

    assert setup_uv < validation < snapshot < checkout < verification < copy
    assert copy < inputs < generation < check < stage < remote_check < credentials < push
    assert 'version-file: uv.toml' in job
    assert 'enable-cache: false' in job
    assert "UV_NO_BUILD: '1'" in job
    assert "python-version: '3.11'" in job
    assert '-Upgrade' not in job
    assert 'pip install' not in job
    assert '[dependabot skip]' in job
    assert 'gh workflow run tests.yml --ref "$HEAD_REF" -f expected_sha="$EXPECTED_SHA"' in job

    generate = job.split('- name: Regenerate Python locks', 1)[1].split('- name:', 1)[0]
    assert 'GH_TOKEN' not in generate
    assert 'github.token' not in generate


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
    directories = {
        re.search(r'directory:\s*"([^"]+)"', block).group(1): block
        for block in docker_blocks
    }
    # The bases of the release image live in the root Dockerfile on the
    # default branch.
    assert '/' in directories
    assert 'target-branch:' not in directories['/']


def test_graph_pages_toolchain_versions_are_explicit():
    workflow = (WORKFLOWS / 'graph-pages.yml').read_text(encoding='utf-8')
    graph_input = (ROOT / 'requirements-graph.in').read_text(encoding='utf-8')
    graph_lock = (ROOT / 'requirements-graph.txt').read_text(encoding='utf-8')

    assert 'version-file: uv.toml' in workflow
    assert 'uv pip install --require-hashes -r requirements-graph.txt' in workflow
    assert 'graphifyy==0.9.105' in graph_input
    assert '--require-hashes' in graph_lock
    assert 'graphifyy==0.9.105' in graph_lock


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


def test_every_workflow_job_with_steps_has_a_timeout():
    for path in WORKFLOWS.glob('*.yml'):
        jobs = path.read_text(encoding='utf-8').split('\njobs:\n', 1)[1]
        for job in re.split(r'\n  (?=[a-z][a-z0-9-]*:\s*\n)', '\n' + jobs)[1:]:
            name = job.split(':', 1)[0]
            if re.search(r'^    runs-on:', job, re.MULTILINE):
                assert re.search(r'^    timeout-minutes: \d+$', job, re.MULTILINE), (path.name, name)


def test_static_checks_run_once_in_the_lint_job():
    workflow = (WORKFLOWS / 'tests.yml').read_text(encoding='utf-8')
    lint_job = _job(workflow, 'lint')
    browser_job = _job(workflow, 'browser-e2e-shards')

    for command in (
        'run: python -m ruff check --output-format=github .',
        'run: npm run vendor:check',
        'run: npm run lint:js',
        'run: npm run test:js',
    ):
        assert command in lint_job
        assert command not in browser_job
    assert 'timeout-minutes:' in lint_job
    assert 'needs:' not in lint_job
    assert 'if:' not in lint_job


def test_browser_gate_is_sharded_and_aggregated():
    workflow = (WORKFLOWS / 'tests.yml').read_text(encoding='utf-8')
    playwright = (ROOT / 'playwright.config.js').read_text(encoding='utf-8')

    assert 'name: browser-e2e (${{ matrix.group }}/8)' in workflow
    assert 'node scripts/run-e2e-ci-parallel.js --group=${{ matrix.group }}/8 --lanes=4' in workflow
    assert 'group: [1, 2, 3, 4, 5, 6, 7, 8]' in workflow
    assert re.search(
        r'\n  browser-e2e:\s*\n\s+needs:\s+\[dispatch-integrity, browser-e2e-shards, browser-fonts\]',
        workflow,
    )
    assert 'test "$SHARD_RESULT" = success' in workflow
    assert 'fullyParallel: true' in playwright


def assert_pinned_remote_font_browsers(fonts):
    """Firefox/WebKit run in the exact prebuilt Playwright version, without apt."""
    assert 'timeout-minutes: 35' in fonts
    assert 'runs-on: ubuntu-24.04' in fonts
    assert 'container:' not in fonts
    assert 'PW_TEST_CONNECT_WS_ENDPOINT: \'ws://127.0.0.1:4355/\'' in fonts
    assert '--network host --user pwuser' in fonts
    assert '--mount "type=bind,source=$PWD/node_modules,target=/work/node_modules,readonly"' in fonts
    assert 'node /work/node_modules/playwright/cli.js run-server --host 127.0.0.1 --port 4355' in fonts
    assert 'node -e \'if (require("playwright/package.json").version !== "1.65.1") process.exit(1)\'' in fonts
    # Image version is locked to package-lock.json; the digest prevents tag drift.
    lock = json.loads((ROOT / 'package-lock.json').read_text(encoding='utf-8'))
    assert lock['packages']['node_modules/playwright']['version'] == '1.65.1'
    assert ('mcr.microsoft.com/playwright:v1.65.1-noble@sha256:'
            '1507cbfc550a63a6b7396791ca4f00df17beb56342d2447b3f106c306f525579') in fonts
    assert 'install-deps' not in fonts and 'apt-get' not in fonts
    assert 'Stop pinned browser server' in fonts
    assert 'if: always()' in fonts
    assert 'webssh.ci-run=$GITHUB_RUN_ID' in fonts
    assert 'docker rm --force --volumes "$WEBSSH_FONT_BROWSER_CONTAINER"' in fonts
    assert 'Refusing to remove container without matching CI ownership label' in fonts

def test_font_browsers_are_a_required_parallel_gate():
    workflow = (WORKFLOWS / 'tests.yml').read_text(encoding='utf-8')
    fonts = workflow.split('\n  browser-fonts:', 1)[1].split('\n  browser-e2e:', 1)[0]
    assert 'matrix:' not in fonts
    assert "WEBSSH_E2E_FAST_HASHING: '1'" in fonts
    assert_pinned_remote_font_browsers(fonts)
    for browser, port in (('firefox', '4173'), ('webkit', '4174')):
        assert 'WEBSSH_E2E_PORT=' + port in fonts
        assert '--browser=' + browser in fonts
        assert '--output="test-results/font-' + browser + '"' in fonts
        assert 'WEBSSH_E2E_TIMING_FILE="test-results/e2e-fonts-' + browser + '.json"' in fonts
        assert browser + '_pid=$!' in fonts
        assert 'wait "$' + browser + '_pid" || ' + browser + '_status=$?' in fonts
        assert 'test "$' + browser + '_status" -eq 0' in fonts
    assert fonts.index('firefox_pid=$!') < fonts.index('webkit_pid=$!') < fonts.index('wait "$firefox_pid"')
    assert fonts.index('wait "$firefox_pid"') < fonts.index('wait "$webkit_pid"') < fonts.index('test "$firefox_status" -eq 0')
    assert '--grep=' in fonts and 'font changes preserve|failed font downloads' in fonts
    assert fonts.count('tests/e2e/terminal-appearance.spec.js') == 2
    assert fonts.count('overview defers terminal fonts|restored terminals load their saved fonts') == 2
    assert 'FONT_RESULT: ${{ needs.browser-fonts.result }}' in workflow
    assert 'test "$FONT_RESULT" = success' in workflow


def test_font_job_uses_hosted_runtime_and_locked_browser_launch_checks():
    workflow = (WORKFLOWS / 'tests.yml').read_text(encoding='utf-8')
    fonts = workflow.split('\n  browser-fonts:', 1)[1].split('\n  browser-e2e:', 1)[0]
    assert 'runs-on: ubuntu-24.04' in fonts
    assert 'container:' not in fonts
    assert 'PLAYWRIGHT_BROWSERS_PATH:' not in fonts
    assert 'actions/setup-python@' not in fonts
    assert "node-version: '24'" in fonts
    assert 'go-version-file: go.mod' in fonts
    assert 'run: npm ci' in fonts
    assert_pinned_remote_font_browsers(fonts)


def test_ci_setup_keeps_safe_dependency_fallbacks():
    workflow = (WORKFLOWS / 'tests.yml').read_text(encoding='utf-8')
    oracles = (WORKFLOWS / 'python-oracles.yml').read_text(encoding='utf-8')
    assert 'bash scripts/install_ci_test_system_deps.sh' in oracles
    assert 'node scripts/install-ci-chromium.js' in workflow
    browser = (ROOT / 'scripts/install-ci-chromium.js').read_text(encoding='utf-8')
    assert "runCli(['install-deps', browserName])" in browser
    assert 'await launchProbe()' in browser


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
    runtime = candidate.index('BUILD=0 IMG="$RUNTIME_REF" tests/image/check.sh')
    runtime_step = candidate[:runtime].rsplit('- name:', 1)[1]
    assert 'REVISION: ${{ github.sha }}' in runtime_step
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
        assert service['ports'][0]['host_ip'] == '127.0.0.1'
        assert len(service['ports']) == 1
        for mount in service['tmpfs']:
            assert all(option in mount for option in ('noexec', 'nosuid', 'nodev', 'size='))
        assert any(mount.startswith('/tmp:') for mount in service['tmpfs'])
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
    from scripts.check_release_gates import REQUIRED
    from scripts.check_release_gates import ALWAYS_RUN
    for name in REQUIRED - ALWAYS_RUN - {'dispatch-integrity', 'browser-e2e'}:
        job = re.split(r'\n  [a-z][a-z-]*:', tests.split('\n  ' + name + ':', 1)[1], maxsplit=1)[0]
        assert 'needs: dispatch-integrity' in job
        assert "if: needs.dispatch-integrity.outputs.mode == 'full'" in job
    for arch in ('amd64', 'arm64'):
        job = re.split(r'\n  [a-z][a-z0-9-]*:', images.split('\n  image-security-' + arch + ':', 1)[1], maxsplit=1)[0]
        assert 'needs: change-scope' in job
        assert "if: needs.change-scope.outputs.mode == 'full'" in job


def test_security_images_require_native_runtime_acceptance_before_success():
    workflow = (WORKFLOWS / 'security.yml').read_text(encoding='utf-8')
    for arch, machine in [('amd64', 'x86_64'), ('arm64', 'aarch64')]:
        job = re.split(r'\n  [a-z][a-z0-9-]*:', workflow.split('\n  image-security-' + arch + ':', 1)[1], maxsplit=1)[0]
        runtime = job.split('- name: Verify native runtime acceptance', 1)[1].split('- name:', 1)[0]
        assert 'if:' not in runtime
        assert f'test "$(uname -m)" = "{machine}"' in runtime
        assert 'docker image inspect --format' in runtime
        assert f'--target debug --platform linux/{arch}' in runtime
        assert ('BUILD=0 IMG="webssh-security:$GITHUB_SHA" '
                'DEBUG_IMG="webssh-security-debug:$GITHUB_SHA" REVISION="$GITHUB_SHA"') in runtime
        assert 'tests/image/check.sh' in runtime
        assert 'continue-on-error' not in job
        assert 'setup-qemu' not in job
    arm = workflow.split('  image-security-arm64:', 1)[1].split('  image-security:', 1)[0]
    assert 'docker load --input /tmp/webssh-arm64.tar' in arm
    assert 'tags: webssh-security:${{ github.sha }}' in arm


def test_pr_image_scans_use_native_builder_without_skipping_security_gates():
    workflow = (WORKFLOWS / 'security.yml').read_text(encoding='utf-8')
    for arch in ('amd64', 'arm64'):
        job = re.split(r'\n  [a-z][a-z0-9-]*:', workflow.split('\n  image-security-' + arch + ':', 1)[1], maxsplit=1)[0]
        assert "if: github.event_name == 'pull_request'\n        run: bash scripts/build_pr_scan_image.sh " + arch in job
        for action in ('docker/setup-buildx-action@', 'docker/build-push-action@'):
            assert "if: github.event_name != 'pull_request'\n        uses: " + action in job
        assert 'aquasecurity/trivy-action@' in job
        assert "exit-code: '1'" in job
        assert 'OS_PACKAGE_REFRESH=${{ github.run_id }}-${{ github.run_attempt }}' in job
    assert 'anchore/sbom-action@' in workflow
