"""Validate the trust boundary for automated Dependabot vendor updates."""

import argparse
import json
from pathlib import Path
import re
import sys


DEPENDABOT = 'dependabot[bot]'
BRANCH = re.compile(
    r'dependabot/npm_and_yarn/[A-Za-z0-9][A-Za-z0-9._/-]{0,199}'
)
SHA = re.compile(r'[0-9a-f]{40}')
ALLOWED_STATUSES = {'added', 'modified', 'removed'}
MANIFESTS = {'package.json', 'package-lock.json'}


def _load(path, expected_type):
    try:
        value = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f'cannot read {path}: {exc}') from exc
    if not isinstance(value, expected_type):
        raise ValueError(f'{path} has an unexpected JSON shape')
    return value


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _allowed_filename(filename):
    if filename in MANIFESTS:
        return True
    return (
        filename.startswith('static/vendor/')
        and '..' not in filename.split('/')
        and not filename.endswith('/')
    )


def validate(event, pull_request, files):
    run = event.get('workflow_run', {})
    repository = event.get('repository', {})
    repo_name = repository.get('full_name')
    default_branch = repository.get('default_branch')
    head_ref = run.get('head_branch')
    head_sha = run.get('head_sha')

    _require(event.get('action') == 'completed', 'workflow run is not completed')
    _require(run.get('name') == 'Tests', 'unexpected workflow name')
    _require(run.get('event') == 'pull_request', 'workflow was not a pull request run')
    _require(run.get('actor', {}).get('login') == DEPENDABOT, 'unexpected workflow actor')
    _require(isinstance(repo_name, str) and repo_name, 'missing repository identity')
    _require(
        run.get('head_repository', {}).get('full_name') == repo_name,
        'workflow head repository does not match the base repository',
    )
    _require(
        isinstance(head_ref, str)
        and BRANCH.fullmatch(head_ref)
        and '..' not in head_ref,
        'workflow head branch is not an npm Dependabot branch',
    )
    _require(isinstance(head_sha, str) and SHA.fullmatch(head_sha), 'invalid head SHA')

    run_prs = run.get('pull_requests')
    _require(isinstance(run_prs, list) and len(run_prs) == 1, 'expected one pull request')
    pr_number = pull_request.get('number')
    _require(
        isinstance(pr_number, int)
        and pr_number > 0
        and run_prs[0].get('number') == pr_number,
        'pull request number does not match the workflow run',
    )
    _require(pull_request.get('state') == 'open', 'pull request is not open')
    _require(
        pull_request.get('user', {}).get('login') == DEPENDABOT,
        'pull request author is not Dependabot',
    )
    _require(
        pull_request.get('head', {}).get('repo', {}).get('full_name') == repo_name,
        'pull request head repository does not match',
    )
    _require(
        pull_request.get('head', {}).get('ref') == head_ref,
        'pull request head branch does not match the workflow run',
    )
    _require(
        pull_request.get('head', {}).get('sha') == head_sha,
        'pull request head SHA does not match the workflow run',
    )
    _require(
        isinstance(default_branch, str)
        and pull_request.get('base', {}).get('ref') == default_branch,
        'pull request does not target the default branch',
    )

    changed_files = pull_request.get('changed_files')
    _require(
        isinstance(changed_files, int)
        and 0 < changed_files <= 20
        and changed_files == len(files),
        'changed-file count is incomplete or outside the safe limit',
    )
    filenames = []
    for item in files:
        _require(isinstance(item, dict), 'changed-file entry has an invalid shape')
        filename = item.get('filename')
        _require(
            isinstance(filename, str) and _allowed_filename(filename),
            f'disallowed changed file: {filename}',
        )
        _require(
            item.get('status') in ALLOWED_STATUSES,
            f'disallowed change status for {filename}',
        )
        filenames.append(filename)
    _require(len(filenames) == len(set(filenames)), 'duplicate changed-file entries')
    _require('package-lock.json' in filenames, 'package-lock.json was not changed')

    return head_ref, head_sha, pr_number


def main(argv=None):
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command', required=True)
    validate_parser = subparsers.add_parser('validate')
    validate_parser.add_argument('--event', required=True)
    validate_parser.add_argument('--pull-request', required=True)
    validate_parser.add_argument('--files', required=True)
    validate_parser.add_argument('--github-output', required=True)
    args = parser.parse_args(argv)

    try:
        event = _load(args.event, dict)
        pull_request = _load(args.pull_request, dict)
        files = _load(args.files, list)
        head_ref, head_sha, pr_number = validate(event, pull_request, files)
        with Path(args.github_output).open('a', encoding='utf-8', newline='\n') as output:
            output.write(f'head_ref={head_ref}\n')
            output.write(f'head_sha={head_sha}\n')
            output.write(f'pr_number={pr_number}\n')
    except ValueError as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
