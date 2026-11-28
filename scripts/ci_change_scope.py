#!/usr/bin/env python3
"""Select a documentation-only PR check only when its complete diff is safe."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys


_SHA = re.compile(r'[0-9a-fA-F]{40}')
_PR_MERGE_REF = re.compile(r'refs/pull/[1-9][0-9]*/merge')
_MEDIA_SUFFIXES = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.html')
_GIT_ERRORS = (OSError, subprocess.SubprocessError)


def _git(repo: Path, *args: str) -> bytes:
    return subprocess.run(
        ['git', *args], cwd=repo, check=True, capture_output=True, timeout=60,
    ).stdout


def _valid_sha(value) -> bool:
    return isinstance(value, str) and bool(_SHA.fullmatch(value)) and value != '0' * 40


def _documentation_path(path: str) -> bool:
    if '\\' in path or any(ord(char) < 32 or ord(char) == 127 for char in path):
        return False
    parts = path.split('/')
    if any(part in {'', '.', '..'} for part in parts):
        return False
    if path == 'README.md':
        return True
    if len(parts) < 2 or parts[0] != 'docs':
        return False
    return path.endswith('.md') or (
        len(parts) >= 3 and parts[1] == 'media' and path.endswith(_MEDIA_SUFFIXES)
    )


def _container_excludes_documentation(repo: Path, sha: str) -> bool:
    try:
        # A Dockerfile-specific ignore file takes precedence over .dockerignore.
        if _git(repo, 'ls-tree', '--name-only', '-z', sha, '--', 'Dockerfile.dockerignore'):
            return False
        content = _git(repo, 'show', f'{sha}:.dockerignore').decode('utf-8')
    except (*_GIT_ERRORS, UnicodeError):
        return False
    lines = [
        line.strip() for line in content.splitlines()
        if line.strip() and not line.lstrip().startswith('#')
    ]
    if lines and lines[0] == '*':
        # An allowlist: everything is excluded unless a later pattern names
        # it. Only literal re-includes outside the documentation are safe.
        return all(
            _literal_non_documentation(pattern[1:])
            for pattern in lines if pattern.startswith('!')
        )
    patterns = set(lines)
    return {'README.md', 'docs/'} <= patterns and not any(
        pattern.startswith('!') for pattern in patterns
    )


def _literal_non_documentation(pattern: str) -> bool:
    path = pattern.strip().strip('/')
    if not path or any(char in path for char in '*?[\\'):
        return False
    return path.split('/')[0] not in {'docs', 'README.md', '.', '..'}


def classify_changes(
    repo: Path, event_name: str, event: dict, sha: str, ref: str,
    force_full: bool = False,
) -> dict:
    """Classify a verified checkout; uncertain comparisons always require full CI."""
    if not _valid_sha(sha):
        raise ValueError('The checkout identity requires a complete nonzero commit SHA.')
    sha = sha.lower()
    try:
        actual = _git(repo, 'rev-parse', '--verify', 'HEAD^{commit}').decode('ascii').strip()
    except (*_GIT_ERRORS, UnicodeError) as exc:
        raise ValueError('The checkout commit identity could not be verified.') from exc
    if actual != sha:
        raise ValueError('The checkout commit does not match the requested SHA.')

    result = {'mode': 'full'}
    if force_full:
        return {**result, 'reason': 'Full CI was explicitly requested.'}
    if event_name != 'pull_request' or not _PR_MERGE_REF.fullmatch(ref or ''):
        return {**result, 'reason': 'Only pull request merge revisions can use documentation-only CI.'}
    pull_request = event.get('pull_request') if isinstance(event, dict) else None
    base_data = pull_request.get('base') if isinstance(pull_request, dict) else None
    base = base_data.get('sha') if isinstance(base_data, dict) else None
    if not _valid_sha(base):
        return {**result, 'reason': 'The pull request base commit is missing or invalid.'}
    base = base.lower()
    result['base'] = base
    try:
        _git(repo, 'cat-file', '-e', f'{base}^{{commit}}')
        _git(repo, 'merge-base', '--is-ancestor', base, sha)
        changed = _git(repo, 'diff', '--name-only', '--no-renames', '-z', base, sha, '--')
    except _GIT_ERRORS:
        return {**result, 'reason': 'The base commit or its ancestry could not be verified.'}
    if not changed:
        return {**result, 'reason': 'The comparison contains no changed paths.'}
    try:
        # NUL separators preserve filenames containing whitespace or newlines.
        if not changed.endswith(b'\0'):
            return {**result, 'reason': 'The changed path list is incomplete.'}
        files = [path.decode('utf-8') for path in changed[:-1].split(b'\0')]
    except UnicodeError:
        return {**result, 'reason': 'The changed path list could not be decoded safely.'}
    result['files'] = files
    if not all(_documentation_path(path) for path in files):
        return {**result, 'reason': 'The diff includes a runtime, build, test, or unrecognized path.'}
    if not _container_excludes_documentation(repo, sha):
        return {**result, 'reason': 'Documentation exclusions from the container context are uncertain.'}
    return {**result, 'mode': 'docs', 'reason': 'Every changed path is approved documentation excluded from the container context.'}


def main() -> int:
    try:
        event_path = os.environ.get('GITHUB_EVENT_PATH', '')
        try:
            event = json.loads(Path(event_path).read_text(encoding='utf-8'))
        except (OSError, ValueError):
            event = {}
        result = classify_changes(
            Path.cwd(), os.environ.get('GITHUB_EVENT_NAME', ''), event,
            os.environ.get('GITHUB_SHA', ''), os.environ.get('GITHUB_REF', ''),
            force_full=os.environ.get('CI_FORCE_FULL') == 'true',
        )
        mode = result['mode']
        summary = f"CI scope: **{mode}**. {result['reason']}"
        if 'files' in result:
            summary += f" Compared {len(result['files'])} changed paths."
        print(summary)
        if output_path := os.environ.get('GITHUB_OUTPUT'):
            with Path(output_path).open('a', encoding='utf-8') as output:
                output.write(f'mode={mode}\n')
        if summary_path := os.environ.get('GITHUB_STEP_SUMMARY'):
            with Path(summary_path).open('a', encoding='utf-8') as output:
                output.write(summary + '\n')
    except (OSError, ValueError):
        print('CI scope classification failed: checkout identity or output could not be verified.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
