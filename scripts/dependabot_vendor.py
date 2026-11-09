"""Validate the trust boundary for automated Dependabot follow-up commits.

Two Dependabot ecosystems need generated files that Dependabot cannot produce
itself: npm updates need refreshed ``static/vendor`` assets, and pip updates
need lock files from ``scripts/lock_requirements.ps1``. Each ecosystem has a
fixed profile; nothing outside a profile's files is ever accepted or staged.
"""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Callable, NamedTuple


DEPENDABOT = 'dependabot[bot]'
SHA = re.compile(r'[0-9a-f]{40}')
MANIFESTS = {'package.json', 'package-lock.json'}
PYTHON_INPUTS = ('requirements.in', 'requirements-test.in', 'requirements-graph.in')
PYTHON_LOCKS = ('requirements.txt', 'requirements-test.txt', 'requirements-graph.txt')
_SPECIFIER = r'(?:===|==|~=|!=|<=|>=|<|>)\s*[A-Za-z0-9.*+!]+'
# Plain names with version specifiers only: no URLs, extras, markers, options
# or index overrides that could redirect resolution away from the default index.
PYTHON_REQUIREMENT = re.compile(
    r'[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?'
    rf'(?:\s*{_SPECIFIER}(?:\s*,\s*{_SPECIFIER})*)?'
)
PYTHON_INCLUDE = re.compile(r'-r ([a-z.-]+)')


def _vendor_filename(filename):
    if filename in MANIFESTS:
        return True
    return (
        filename.startswith('static/vendor/')
        and '..' not in filename.split('/')
        and not filename.endswith('/')
    )


def _vendor_staged(filename):
    return filename.startswith('static/vendor/') and '..' not in filename.split('/')


class Profile(NamedTuple):
    branch: re.Pattern
    allowed_file: Callable[[str], bool]
    allowed_statuses: frozenset
    required_files: frozenset
    failed_job: re.Pattern
    failed_step: str
    stage_command: tuple
    staged_file: Callable[[str], bool]


PROFILES = {
    'npm': Profile(
        branch=re.compile(r'dependabot/npm_and_yarn/[A-Za-z0-9][A-Za-z0-9._/-]{0,199}'),
        allowed_file=_vendor_filename,
        allowed_statuses=frozenset({'added', 'modified', 'removed'}),
        required_files=frozenset({'package-lock.json'}),
        failed_job=re.compile(r'browser-e2e(?: \([1-9][0-9]*/[1-9][0-9]*\))?'),
        failed_step='Check vendored frontend assets',
        stage_command=('git', 'add', '--all', '--', 'static/vendor'),
        staged_file=_vendor_staged,
    ),
    'pip': Profile(
        branch=re.compile(r'dependabot/pip/[A-Za-z0-9][A-Za-z0-9._/-]{0,199}'),
        allowed_file=frozenset(PYTHON_INPUTS + PYTHON_LOCKS).__contains__,
        allowed_statuses=frozenset({'modified'}),
        required_files=frozenset(PYTHON_LOCKS),
        failed_job=re.compile(r'dependency-locks'),
        failed_step='Check dependency locks',
        stage_command=('git', 'add', '--', *PYTHON_LOCKS),
        staged_file=frozenset(PYTHON_LOCKS).__contains__,
    ),
}


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


def validate(event, pull_request, files, jobs, ecosystem='npm'):
    profile = PROFILES[ecosystem]
    run = event.get('workflow_run', {})
    repository = event.get('repository', {})
    repo_name = repository.get('full_name')
    default_branch = repository.get('default_branch')
    head_ref = run.get('head_branch')
    head_sha = run.get('head_sha')

    _require(event.get('action') == 'completed', 'workflow run is not completed')
    _require(run.get('name') == 'Tests', 'unexpected workflow name')
    _require(run.get('event') == 'pull_request', 'workflow was not a pull request run')
    _require(run.get('conclusion') == 'failure', 'workflow conclusion was not failure')
    _require(run.get('actor', {}).get('login') == DEPENDABOT, 'unexpected workflow actor')
    _require(isinstance(repo_name, str) and repo_name, 'missing repository identity')
    _require(
        run.get('head_repository', {}).get('full_name') == repo_name,
        'workflow head repository does not match the base repository',
    )
    _require(
        isinstance(head_ref, str)
        and profile.branch.fullmatch(head_ref)
        and '..' not in head_ref,
        f'workflow head branch is not a Dependabot {ecosystem} branch',
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
            isinstance(filename, str) and profile.allowed_file(filename),
            f'disallowed changed file: {filename}',
        )
        _require(
            item.get('status') in profile.allowed_statuses,
            f'disallowed change status for {filename}',
        )
        filenames.append(filename)
    _require(len(filenames) == len(set(filenames)), 'duplicate changed-file entries')
    _require(
        profile.required_files.intersection(filenames),
        f'none of {", ".join(sorted(profile.required_files))} was changed',
    )

    job_items = jobs.get('jobs')
    _require(isinstance(job_items, list), 'workflow jobs have an invalid shape')
    failed_check = any(
        profile.failed_job.fullmatch(str(job.get('name', '')))
        and job.get('conclusion') == 'failure'
        and any(
            step.get('name') == profile.failed_step
            and step.get('conclusion') == 'failure'
            for step in job.get('steps', [])
            if isinstance(step, dict)
        )
        for job in job_items
        if isinstance(job, dict)
    )
    _require(failed_check, f'{profile.failed_step!r} did not fail')

    return head_ref, head_sha, pr_number


def check_python_inputs(root):
    """Reject lock inputs that could change where or what uv resolves."""
    root = Path(root)
    for name in PYTHON_INPUTS:
        path = root / name
        _require(path.is_file() and not path.is_symlink(), f'{name} is not a regular file')
        for number, raw in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            include = PYTHON_INCLUDE.fullmatch(line)
            _require(
                PYTHON_REQUIREMENT.fullmatch(line)
                or (include and include.group(1) in PYTHON_INPUTS and include.group(1) != name),
                f'{name}:{number} is not a plain pinned requirement',
            )


def stage(root, ecosystem='npm'):
    profile = PROFILES[ecosystem]
    root = Path(root).resolve()
    _require((root / '.git').exists(), 'stage root is not a Git repository')
    subprocess.run(
        list(profile.stage_command),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    result = subprocess.run(
        ['git', 'diff', '--cached', '--name-only', '-z'],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    staged = [name for name in result.stdout.split('\0') if name]
    _require(
        all(profile.staged_file(name) for name in staged),
        'staged changes escaped the generated files',
    )
    return bool(staged)


def main(argv=None):
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command', required=True)
    validate_parser = subparsers.add_parser('validate')
    validate_parser.add_argument('--ecosystem', choices=sorted(PROFILES), default='npm')
    validate_parser.add_argument('--event', required=True)
    validate_parser.add_argument('--pull-request', required=True)
    validate_parser.add_argument('--files', required=True)
    validate_parser.add_argument('--jobs', required=True)
    validate_parser.add_argument('--github-output', required=True)
    inputs_parser = subparsers.add_parser('check-python-inputs')
    inputs_parser.add_argument('--root', required=True)
    stage_parser = subparsers.add_parser('stage')
    stage_parser.add_argument('--ecosystem', choices=sorted(PROFILES), default='npm')
    stage_parser.add_argument('--root', required=True)
    stage_parser.add_argument('--github-output', required=True)
    args = parser.parse_args(argv)

    try:
        if args.command == 'check-python-inputs':
            check_python_inputs(args.root)
            return 0
        if args.command == 'validate':
            event = _load(args.event, dict)
            pull_request = _load(args.pull_request, dict)
            files = _load(args.files, list)
            jobs = _load(args.jobs, dict)
            head_ref, head_sha, pr_number = validate(
                event,
                pull_request,
                files,
                jobs,
                args.ecosystem,
            )
            lines = [
                f'head_ref={head_ref}',
                f'head_sha={head_sha}',
                f'pr_number={pr_number}',
            ]
        else:
            lines = [f'changed={str(stage(args.root, args.ecosystem)).lower()}']
        with Path(args.github_output).open('a', encoding='utf-8', newline='\n') as output:
            output.write('\n'.join(lines) + '\n')
    except (OSError, UnicodeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
