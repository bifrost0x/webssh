"""Behavior tests for the privileged Dependabot vendor gate."""

import json
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts' / 'dependabot_vendor.py'
HEAD_SHA = 'a' * 40


def _payloads():
    event = {
        'action': 'completed',
        'repository': {
            'full_name': 'bifrost0x/webssh',
            'default_branch': 'main',
        },
        'workflow_run': {
            'id': 123456,
            'name': 'Tests',
            'event': 'pull_request',
            'conclusion': 'failure',
            'head_branch': 'dependabot/npm_and_yarn/npm-minor-and-patch-123',
            'head_sha': HEAD_SHA,
            'head_repository': {'full_name': 'bifrost0x/webssh'},
            'actor': {'login': 'dependabot[bot]'},
            'pull_requests': [{'number': 81}],
        },
    }
    pull_request = {
        'number': 81,
        'state': 'open',
        'user': {'login': 'dependabot[bot]'},
        'head': {
            'ref': 'dependabot/npm_and_yarn/npm-minor-and-patch-123',
            'sha': HEAD_SHA,
            'repo': {'full_name': 'bifrost0x/webssh'},
        },
        'base': {'ref': 'main'},
        'changed_files': 2,
    }
    files = [
        {'filename': 'package.json', 'status': 'modified'},
        {'filename': 'package-lock.json', 'status': 'modified'},
    ]
    jobs = {
        'jobs': [
            {
                'name': 'browser-e2e',
                'conclusion': 'failure',
                'steps': [
                    {
                        'name': 'Check vendored frontend assets',
                        'conclusion': 'failure',
                    }
                ],
            }
        ]
    }
    return event, pull_request, files, jobs


def _run_validator(tmp_path, mutate=None, ecosystem=None):
    event, pull_request, files, jobs = _payloads()
    if mutate is not None:
        mutate(event, pull_request, files, jobs)

    inputs = {}
    for name, payload in (
        ('event', event),
        ('pull-request', pull_request),
        ('files', files),
        ('jobs', jobs),
    ):
        path = tmp_path / f'{name}.json'
        path.write_text(json.dumps(payload), encoding='utf-8')
        inputs[name] = path

    output = tmp_path / 'github-output.txt'
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            'validate',
            *(['--ecosystem', ecosystem] if ecosystem else []),
            '--event',
            str(inputs['event']),
            '--pull-request',
            str(inputs['pull-request']),
            '--files',
            str(inputs['files']),
            '--jobs',
            str(inputs['jobs']),
            '--github-output',
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return result, output


def test_valid_dependabot_npm_run_emits_sanitized_push_coordinates(tmp_path):
    result, output = _run_validator(tmp_path)

    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding='utf-8').splitlines() == [
        'head_ref=dependabot/npm_and_yarn/npm-minor-and-patch-123',
        f'head_sha={HEAD_SHA}',
        'pr_number=81',
    ]


def test_valid_sharded_browser_job_is_accepted(tmp_path):
    def mutate(_event, _pull_request, _files, jobs):
        jobs['jobs'][0]['name'] = 'browser-e2e (1/2)'

    result, output = _run_validator(tmp_path, mutate)

    assert result.returncode == 0, result.stderr
    assert output.exists()


def test_gate_rejects_pr_code_outside_manifests_and_generated_vendor(tmp_path):
    def add_untrusted_script(_event, pull_request, files, _jobs):
        files.append({'filename': 'scripts/vendor.js', 'status': 'modified'})
        pull_request['changed_files'] = len(files)

    result, output = _run_validator(tmp_path, add_untrusted_script)

    assert result.returncode == 1
    assert 'scripts/vendor.js' in result.stderr
    assert not output.exists()


def test_gate_rejects_mismatched_workflow_and_live_pr_heads(tmp_path):
    def change_pr_head(_event, pull_request, _files, _jobs):
        pull_request['head']['sha'] = 'b' * 40

    result, output = _run_validator(tmp_path, change_pr_head)

    assert result.returncode == 1
    assert 'head SHA' in result.stderr
    assert not output.exists()


@pytest.mark.parametrize(
    ('mutate', 'message'),
    [
        (
            lambda event, _pr, _files, _jobs: event['workflow_run']['actor'].update(
                login='octocat'
            ),
            'actor',
        ),
        (
            lambda _event, pr, _files, _jobs: pr['user'].update(login='octocat'),
            'author',
        ),
        (
            lambda event, _pr, _files, _jobs: event['workflow_run'].update(
                head_branch='feature/not-dependabot'
            ),
            'branch',
        ),
        (
            lambda _event, pr, _files, _jobs: pr['base'].update(ref='release'),
            'default branch',
        ),
    ],
)
def test_gate_rejects_non_dependabot_or_cross_context_runs(
    tmp_path,
    mutate,
    message,
):
    result, output = _run_validator(tmp_path, mutate)

    assert result.returncode == 1
    assert message in result.stderr.lower()
    assert not output.exists()


@pytest.mark.parametrize('conclusion', ['success', 'cancelled', 'skipped'])
def test_gate_rejects_runs_without_a_failed_vendor_check(tmp_path, conclusion):
    def change_conclusion(event, _pull_request, _files, jobs):
        event['workflow_run']['conclusion'] = conclusion
        jobs['jobs'][0]['steps'][0]['conclusion'] = conclusion

    result, output = _run_validator(tmp_path, change_conclusion)

    assert result.returncode == 1
    assert 'vendor' in result.stderr.lower() or 'conclusion' in result.stderr.lower()
    assert not output.exists()


def test_stage_captures_added_modified_and_removed_vendor_files_only(tmp_path):
    repository = tmp_path / 'repository'
    vendor = repository / 'static' / 'vendor'
    vendor.mkdir(parents=True)
    (vendor / 'modified.js').write_text('old', encoding='utf-8')
    (vendor / 'removed.js').write_text('remove', encoding='utf-8')
    subprocess.run(['git', 'init'], cwd=repository, check=True, capture_output=True)
    subprocess.run(
        ['git', 'add', 'static/vendor'],
        cwd=repository,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            'git',
            '-c',
            'user.name=Test',
            '-c',
            'user.email=test@example.invalid',
            'commit',
            '-m',
            'fixture',
        ],
        cwd=repository,
        check=True,
        capture_output=True,
    )

    (vendor / 'modified.js').write_text('new', encoding='utf-8')
    (vendor / 'removed.js').unlink()
    (vendor / 'added.js').write_text('added', encoding='utf-8')
    (repository / 'outside.txt').write_text('never stage', encoding='utf-8')
    output = tmp_path / 'stage-output.txt'

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            'stage',
            '--root',
            str(repository),
            '--github-output',
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding='utf-8').splitlines() == ['changed=true']
    staged = subprocess.run(
        ['git', 'diff', '--cached', '--name-only'],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    assert staged == [
        'static/vendor/added.js',
        'static/vendor/modified.js',
        'static/vendor/removed.js',
    ]
    assert 'outside.txt' not in staged


PIP_BRANCH = 'dependabot/pip/python-minor-and-patch-34c4db8fb1'
PYTHON_INPUTS = ('requirements.in', 'requirements-test.in', 'requirements-graph.in')
PYTHON_LOCKS = ('requirements.txt', 'requirements-test.txt', 'requirements-graph.txt')


def _pip_mutation(event, pull_request, files, jobs):
    event['workflow_run']['head_branch'] = PIP_BRANCH
    pull_request['head']['ref'] = PIP_BRANCH
    files[:] = [
        {'filename': 'requirements.in', 'status': 'modified'},
        {'filename': 'requirements.txt', 'status': 'modified'},
        {'filename': 'requirements-test.txt', 'status': 'modified'},
    ]
    pull_request['changed_files'] = len(files)
    jobs['jobs'] = [
        {
            'name': 'dependency-locks',
            'conclusion': 'failure',
            'steps': [
                {'name': 'Check dependency locks', 'conclusion': 'failure'},
            ],
        }
    ]


def _run_pip_validator(tmp_path, mutate=None):
    def combined(event, pull_request, files, jobs):
        _pip_mutation(event, pull_request, files, jobs)
        if mutate is not None:
            mutate(event, pull_request, files, jobs)

    return _run_validator(tmp_path, combined, ecosystem='pip')


def _set_branch(name):
    def mutate(event, pull_request, _files, _jobs):
        event['workflow_run']['head_branch'] = name
        pull_request['head']['ref'] = name

    return mutate


def _replace_files(*entries):
    def mutate(_event, pull_request, files, _jobs):
        files[:] = [{'filename': name, 'status': status} for name, status in entries]
        pull_request['changed_files'] = len(files)

    return mutate


def test_valid_dependabot_pip_run_emits_sanitized_push_coordinates(tmp_path):
    result, output = _run_pip_validator(tmp_path)

    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding='utf-8').splitlines() == [
        f'head_ref={PIP_BRANCH}',
        f'head_sha={HEAD_SHA}',
        'pr_number=81',
    ]


@pytest.mark.parametrize(
    ('mutate', 'message'),
    [
        (
            lambda event, _pr, _files, _jobs: event['workflow_run']['actor'].update(
                login='octocat'
            ),
            'actor',
        ),
        (
            lambda _event, pr, _files, _jobs: pr['user'].update(login='octocat'),
            'author',
        ),
        (_set_branch('dependabot/npm_and_yarn/npm-minor-and-patch-1'), 'branch'),
        (_set_branch('dependabot/pip/../main'), 'branch'),
        (_set_branch('feature/dependabot/pip/x'), 'branch'),
        (
            lambda event, _pr, _files, _jobs: event['workflow_run'][
                'head_repository'
            ].update(full_name='attacker/webssh'),
            'head repository',
        ),
        (
            _replace_files(('requirements.txt', 'modified'), ('uv.toml', 'modified')),
            'uv.toml',
        ),
        (
            _replace_files(
                ('requirements.txt', 'modified'),
                ('scripts/lock_requirements.ps1', 'modified'),
            ),
            'lock_requirements.ps1',
        ),
        (
            _replace_files(
                ('requirements.txt', 'modified'),
                ('scripts/dependabot_vendor.py', 'modified'),
            ),
            'dependabot_vendor.py',
        ),
        (
            _replace_files(
                ('requirements.txt', 'modified'),
                ('.github/workflows/tests.yml', 'modified'),
            ),
            'tests.yml',
        ),
        (
            _replace_files(('requirements.txt', 'modified'), ('package-lock.json', 'modified')),
            'package-lock.json',
        ),
        (_replace_files(('requirements-dev.txt', 'added')), 'requirements-dev.txt'),
        (_replace_files(('docs/requirements.txt', 'modified')), 'docs/requirements.txt'),
        (_replace_files(('requirements.txt', 'removed')), 'status'),
        (_replace_files(('requirements.txt', 'renamed')), 'status'),
        (_replace_files(('requirements.in', 'modified')), 'was changed'),
        (
            lambda _event, _pr, _files, jobs: jobs['jobs'][0]['steps'][0].update(
                conclusion='success'
            ),
            'did not fail',
        ),
        (
            lambda _event, _pr, _files, jobs: jobs['jobs'][0].update(name='pytest'),
            'did not fail',
        ),
    ],
)
def test_pip_gate_rejects_untrusted_context_and_files(tmp_path, mutate, message):
    result, output = _run_pip_validator(tmp_path, mutate)

    assert result.returncode == 1
    assert message in result.stderr
    assert not output.exists()


def test_npm_gate_rejects_pip_branches(tmp_path):
    result, output = _run_validator(tmp_path, _pip_mutation, ecosystem='npm')

    assert result.returncode == 1
    assert 'branch' in result.stderr
    assert not output.exists()


def test_pip_gate_rejects_npm_manifests(tmp_path):
    result, output = _run_pip_validator(
        tmp_path,
        _replace_files(('package.json', 'modified'), ('package-lock.json', 'modified')),
    )

    assert result.returncode == 1
    assert 'package.json' in result.stderr
    assert not output.exists()


def _check_inputs(root):
    return subprocess.run(
        [sys.executable, str(SCRIPT), 'check-python-inputs', '--root', str(root)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_repository_python_inputs_pass_the_input_gate():
    result = _check_inputs(ROOT)

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    'line',
    [
        '--index-url https://evil.invalid/simple',
        '--extra-index-url https://evil.invalid/simple',
        '-i https://evil.invalid/simple',
        '--find-links https://evil.invalid/',
        'paramiko @ https://evil.invalid/paramiko-5.1.0.tar.gz',
        'git+https://evil.invalid/paramiko.git',
        '-e .',
        '-r ../outside.in',
        '-r requirements-graph.in',
        '-c /etc/constraints.txt',
        'paramiko[all]==5.1.0',
        "paramiko==5.1.0 ; python_version < '3.12'",
        'paramiko==5.1.0 --hash=sha256:' + '0' * 64,
    ],
)
def test_python_input_gate_rejects_resolution_overrides(tmp_path, line):
    for name in PYTHON_INPUTS:
        (tmp_path / name).write_text(
            (ROOT / name).read_text(encoding='utf-8'), encoding='utf-8'
        )
    target = tmp_path / 'requirements-graph.in'
    target.write_text(target.read_text(encoding='utf-8') + line + '\n', encoding='utf-8')

    result = _check_inputs(tmp_path)

    assert result.returncode == 1
    assert 'requirements-graph.in' in result.stderr


def test_python_input_gate_rejects_missing_inputs(tmp_path):
    (tmp_path / 'requirements.in').write_text('Flask==3.1.3\n', encoding='utf-8')

    result = _check_inputs(tmp_path)

    assert result.returncode == 1
    assert 'requirements-test.in' in result.stderr


def _git(repository, *args):
    return subprocess.run(
        ['git', *args], cwd=repository, check=True, capture_output=True, text=True
    ).stdout


def _commit_fixture(repository, names, content):
    repository.mkdir()
    for name in names:
        (repository / name).write_text(content, encoding='utf-8')
    _git(repository, 'init')
    _git(repository, 'add', '.')
    _git(
        repository,
        '-c', 'user.name=Test',
        '-c', 'user.email=test@example.invalid',
        'commit', '-m', 'fixture',
    )


def _stage_pip(repository, output):
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            'stage',
            '--ecosystem',
            'pip',
            '--root',
            str(repository),
            '--github-output',
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_pip_stage_captures_only_regenerated_lock_files(tmp_path):
    repository = tmp_path / 'repository'
    tracked = (*PYTHON_INPUTS, *PYTHON_LOCKS, 'uv.toml')
    _commit_fixture(repository, tracked, 'old\n')
    for name in tracked:
        (repository / name).write_text('new\n', encoding='utf-8')
    (repository / 'requirements-extra.txt').write_text('never stage\n', encoding='utf-8')
    output = tmp_path / 'stage-output.txt'

    result = _stage_pip(repository, output)

    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding='utf-8').splitlines() == ['changed=true']
    staged = _git(repository, 'diff', '--cached', '--name-only').splitlines()
    assert staged == sorted(PYTHON_LOCKS)


def test_pip_stage_reports_unchanged_locks(tmp_path):
    repository = tmp_path / 'repository'
    _commit_fixture(repository, PYTHON_LOCKS, 'same\n')
    output = tmp_path / 'stage-output.txt'

    result = _stage_pip(repository, output)

    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding='utf-8').splitlines() == ['changed=false']
