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
            'name': 'Tests',
            'event': 'pull_request',
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
    return event, pull_request, files


def _run_validator(tmp_path, mutate=None):
    event, pull_request, files = _payloads()
    if mutate is not None:
        mutate(event, pull_request, files)

    inputs = {}
    for name, payload in (
        ('event', event),
        ('pull-request', pull_request),
        ('files', files),
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
            '--event',
            str(inputs['event']),
            '--pull-request',
            str(inputs['pull-request']),
            '--files',
            str(inputs['files']),
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


def test_gate_rejects_pr_code_outside_manifests_and_generated_vendor(tmp_path):
    def add_untrusted_script(_event, pull_request, files):
        files.append({'filename': 'scripts/vendor.js', 'status': 'modified'})
        pull_request['changed_files'] = len(files)

    result, output = _run_validator(tmp_path, add_untrusted_script)

    assert result.returncode == 1
    assert 'scripts/vendor.js' in result.stderr
    assert not output.exists()


def test_gate_rejects_mismatched_workflow_and_live_pr_heads(tmp_path):
    def change_pr_head(_event, pull_request, _files):
        pull_request['head']['sha'] = 'b' * 40

    result, output = _run_validator(tmp_path, change_pr_head)

    assert result.returncode == 1
    assert 'head SHA' in result.stderr
    assert not output.exists()


@pytest.mark.parametrize(
    ('mutate', 'message'),
    [
        (
            lambda event, _pr, _files: event['workflow_run']['actor'].update(
                login='octocat'
            ),
            'actor',
        ),
        (
            lambda _event, pr, _files: pr['user'].update(login='octocat'),
            'author',
        ),
        (
            lambda event, _pr, _files: event['workflow_run'].update(
                head_branch='feature/not-dependabot'
            ),
            'branch',
        ),
        (
            lambda _event, pr, _files: pr['base'].update(ref='release'),
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
