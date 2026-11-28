"""Reject private development artifacts from the public repository."""

from __future__ import annotations

import argparse
import json
import os
import re
import hashlib
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]

FORBIDDEN_NAMES = frozenset({
    '.cursorrules',
    '.clinerules',
    '.roorules',
    '.windsurfrules',
    'agents.md',
    'agent-instructions.md',
    'ai_instructions.md',
    'claude.md',
    'codex.md',
    'copilot.md',
    'copilot-instructions.md',
    'gemini.md',
    'jules.md',
    'qwen.md',
    'secret_key',
    'known_hosts',
    'id_rsa',
    'id_dsa',
    'id_ecdsa',
    'id_ed25519',
})

FORBIDDEN_DIRECTORIES = frozenset({
    '.agent',
    '.agents',
    '.aider',
    '.ai',
    '.amazonq',
    '.claude',
    '.codex',
    '.continue',
    '.cursor',
    '.gemini',
    '.junie',
    '.impeccable',
    '.pytest_cache',
    '.superpowers',
    '.test-run.tmp',
    '.test-tmp',
    '.windsurf',
    '__pycache__',
    'graphify-out',
    'node_modules',
    'plans',
    'playwright-report',
    'qa-artifacts',
    '.roo',
    'review-artifacts',
    'reviews',
    'test-results',
    'data',
    'instance',
    'secrets',
    '.ssh',
})

DISPOSABLE_SUFFIXES = (
    '.bak', '.db', '.log', '.orig', '.pyc', '.pyo', '.rej', '.sqlite',
    '.sqlite3', '.swp', '.swo', '.backup', '.pem', '.key', '.p12', '.pfx',
)

PUBLIC_REFERENCE_SUFFIXES = frozenset({'.css', '.html', '.js', '.md'})
MEDIA_SUFFIXES = frozenset({
    '.png', '.jpg', '.jpeg', '.webp', '.gif', '.svg', '.mp4', '.webm',
    '.mp3', '.ogg', '.wav', '.vtt', '.woff', '.woff2',
})
TEXT_AUDIT_SUFFIXES = frozenset({'.adoc', '.html', '.md', '.rst', '.txt'})

# Tracked files are sources. Build output such as `go build ./cmd/webssh`
# and other executables, and files above the size limit, stay out of the
# history; reviewed exceptions are listed by path.
MAX_TRACKED_BYTES = 5 * 1024 * 1024
LARGE_FILE_EXCEPTIONS = frozenset({
    # Theme demo of the README and the project site.
    'assets/webssh-themes.gif',
})
MACH_O_MAGICS = frozenset({
    b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe',
    b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
})

# Made-up account names that tests and examples use in absolute paths. A
# path below any other home directory is a workstation path. Add a name
# only for synthetic test data.
SYNTHETIC_HOME_NAMES = frozenset({
    '..', 'agentuser', 'deploy', 'developer', 'dir', 'fixture', 'me',
    'pwuser', 'testuser', 'u', 'user', 'x',
})
HOME_PATH = re.compile(
    r'(?<![\w.~-])(?:/home|/Users)/([A-Za-z0-9._-]+)/'
    r'|\b[A-Za-z]:\\Users\\([^\\\s"\'`]+)\\'
)

AGENT_INSTRUCTION_MARKERS = (
    re.compile(
        r'^\s*#{1,6}\s*(?:(?:ai|coding)\s+)?agents?\s+'
        r'(?:instructions|rules|guidelines)\b',
        re.IGNORECASE | re.MULTILINE,
    ),
    re.compile(
        r'^\s*#{1,6}\s*(?:codex|claude|gemini)\s+'
        r'(?:instructions|rules|guidelines)\b',
        re.IGNORECASE | re.MULTILINE,
    ),
    re.compile(
        r'\byou are (?:an?\s+)?(?:codex|claude|gemini|ai coding agent)\b',
        re.IGNORECASE,
    ),
    re.compile(
        r'<(?:agents|agent_instructions|skills_instructions|developer_instructions)\b',
        re.IGNORECASE,
    ),
)

LOCAL_TOOL_PATH_MARKERS = (
    re.compile(
        r'/(?:home|Users)/[^/\s`"\']+/\.(?:agents|claude|codex|cursor)(?:/|\b)',
        re.IGNORECASE,
    ),
    re.compile(
        r'[A-Z]:\\Users\\[^\\\s`"\']+\\\.(?:agents|claude|codex|cursor)(?:\\|\b)',
        re.IGNORECASE,
    ),
    re.compile(r'/tmp/(?:codex[-_/]|[^/\s`]*?(?:capture|comparison|screenshot)[^/\s`]*)', re.IGNORECASE),
    re.compile(r'https://claude\.ai/code/session_', re.IGNORECASE),
)

INTERNAL_REVIEW_MARKERS = (
    re.compile(
        r'^\s*[-*]\s*(?:source visual truth|browser-rendered implementation|'
        r'combined full-view evidence):',
        re.IGNORECASE | re.MULTILINE,
    ),
)


_ASSISTANT_NAMES = r'(?:claude|codex|copilot|gemini|chatgpt|cursor|aider|devin|jules)'

# Assistant identities are recognized by their account address, never by the
# display name alone: "Jules Martin" or "Devin Smith" are legitimate co-authors.
_ASSISTANT_ADDRESS = (
    r'(?:[^@\s<>]*@(?:[\w-]+\.)*(?:anthropic|openai|cursor)\.com'
    r'|\d+\+copilot@users\.noreply\.github\.com'
    rf'|[^@\s<>]*(?:{_ASSISTANT_NAMES}|github-advanced-security)[^@\s<>]*'
    r'\[bot\]@users\.noreply\.github\.com)'
)

# Tool attribution that coding assistants add to commit messages and PR text.
# Plain mentions such as "ignore .claude/" stay allowed; only attribution forms
# and session links are rejected.
ATTRIBUTION_MARKERS = (
    re.compile(
        rf'^\s*co-authored-by:[^\n<]*<\s*{_ASSISTANT_ADDRESS}\s*>',
        re.IGNORECASE | re.MULTILINE,
    ),
    re.compile(rf'^\s*{_ASSISTANT_NAMES}-session:', re.IGNORECASE | re.MULTILINE),
    re.compile(
        rf'\bgenerated (?:with|by|using)\s+\[?{_ASSISTANT_NAMES}\b',
        re.IGNORECASE,
    ),
    re.compile(r'https?://claude\.ai/code\b', re.IGNORECASE),
    re.compile(r'https?://chatgpt\.com/codex\b', re.IGNORECASE),
    re.compile(r'noreply@(?:anthropic|openai)\.com', re.IGNORECASE),
)

ASSISTANT_EMAIL = re.compile(rf'^{_ASSISTANT_ADDRESS}$', re.IGNORECASE)

# Branch prefixes only for names that cannot be a project topic
# ("cursor" is a terminal concept).
_ASSISTANT_ACCOUNTS = r'(?:claude|codex|copilot|gemini|chatgpt)'
ASSISTANT_BRANCH = re.compile(rf'^{_ASSISTANT_ACCOUNTS}/', re.IGNORECASE)


@dataclass(frozen=True, order=True)
class Violation:
    path: str
    reason: str


def tracked_paths(root: Path = ROOT) -> list[str]:
    result = subprocess.run(
        ['git', 'ls-files', '-z'],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
    )
    return [
        value.decode('utf-8', errors='surrogateescape')
        for value in result.stdout.split(b'\0')
        if value
    ]


def forbidden_path_reason(value: str) -> str | None:
    path = PurePosixPath(value)
    parts = tuple(part.casefold() for part in path.parts)
    name = path.name.casefold()
    if name in FORBIDDEN_NAMES:
        return 'local agent or assistant instruction file'
    if name.startswith('.aider'):
        return 'local agent or assistant configuration file'
    forbidden_component = next(
        (part for part in parts if part in FORBIDDEN_DIRECTORIES),
        None,
    )
    if forbidden_component:
        return f'private or generated directory: {forbidden_component}'
    if '.github' in parts and any(
        part in {'instructions', 'prompts'} for part in parts
    ):
        return 'repository-local AI instruction directory'
    if name == '.env' or (name.startswith('.env.') and name != '.env.example'):
        return 'environment or secret file'
    if re.search(r'\.(?:db|sqlite3?)-(?:wal|shm|journal)$', name):
        return 'database sidecar file'
    if name in {'.ds_store', 'thumbs.db'} or name.endswith(DISPOSABLE_SUFFIXES):
        return 'disposable workstation or runtime artifact'
    if path.suffix.casefold() == '.md' and re.search(
        r'(?:^|[-_])(design[-_])?(?:qa|review)(?:[-_.]|$)',
        name,
        re.IGNORECASE,
    ):
        return 'internal QA or review Markdown'
    return None


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding='utf-8')
    except (OSError, UnicodeError):
        return None


def content_violations(root: Path, paths: list[str]) -> list[Violation]:
    violations: list[Violation] = []
    for value in paths:
        path = PurePosixPath(value)
        if path.suffix.casefold() not in TEXT_AUDIT_SUFFIXES:
            continue
        text = _read_text(root / value)
        if text is None:
            continue
        if any(pattern.search(text) for pattern in AGENT_INSTRUCTION_MARKERS):
            violations.append(Violation(value, 'embedded AI-agent instructions'))
        if any(pattern.search(text) for pattern in LOCAL_TOOL_PATH_MARKERS):
            violations.append(Violation(value, 'workstation-specific AI or QA path'))
        if any(pattern.search(text) for pattern in INTERNAL_REVIEW_MARKERS):
            violations.append(Violation(value, 'internal visual-review evidence'))
    return violations


def asset_violations(root: Path, paths: list[str]) -> list[Violation]:
    public_sources = []
    runtime_sources = []
    for value in paths:
        path = PurePosixPath(value)
        if path.suffix.casefold() not in PUBLIC_REFERENCE_SUFFIXES:
            continue
        if value == 'README.md' or path.parts[0] in {'docs', 'site'}:
            text = _read_text(root / value)
            if text is not None:
                public_sources.append(text)
        if path.parts[0] in {'templates', 'static'} and path.suffix in {'.css', '.html', '.js'}:
            text = _read_text(root / value)
            if text is not None:
                runtime_sources.append(text)
    public_text = '\n'.join(public_sources)
    runtime_text = '\n'.join(runtime_sources)
    violations = []
    seen_media: dict[str, str] = {}
    for value in paths:
        path = PurePosixPath(value)
        if not (value.startswith(('assets/', 'site/assets/', 'static/images/'))
                and path.suffix.casefold() in MEDIA_SUFFIXES):
            continue
        # PNG originals are deliberate authoring inputs, not orphaned UI assets.
        # Only allow an original with a tracked, actually used WebP derivative.
        if (path.parent == PurePosixPath('static/images/theme-backgrounds')
                and path.suffix == '.png'
                and str(path.with_suffix('.webp')) in paths
                and path.with_suffix('.webp').name in runtime_text):
            continue
        references = runtime_text + '\n' + public_text if value.startswith('static/') else public_text
        # A license/caption mentioning its own asset is not a consumer. Sources
        # above include pages, docs and runtime code, never media or test fixtures.
        if path.name not in references and value not in references:
            violations.append(Violation(value, 'asset has no public documentation or site reference'))
        asset = root / value
        if asset.is_file():
            digest = hashlib.sha256(asset.read_bytes()).hexdigest()
            if digest in seen_media:
                violations.append(Violation(value, f'identical media already tracked at {seen_media[digest]}'))
            else:
                seen_media[digest] = value
    return violations


def executable_format(head: bytes) -> str | None:
    """Name the executable format of a file that starts with head."""
    if head.startswith(b'\x7fELF'):
        return 'ELF'
    if head[:4] in MACH_O_MAGICS:
        return 'Mach-O'
    if head.startswith(b'MZ') and len(head) >= 0x40:
        offset = int.from_bytes(head[0x3c:0x40], 'little')
        if head[offset:offset + 4] == b'PE\0\0':
            return 'PE'
    return None


def binary_violations(root: Path, paths: list[str]) -> list[Violation]:
    violations = []
    for value in paths:
        path = root / value
        if path.is_symlink() or not path.is_file():
            continue
        if path.stat().st_size > MAX_TRACKED_BYTES and value not in LARGE_FILE_EXCEPTIONS:
            violations.append(Violation(value, f'file larger than {MAX_TRACKED_BYTES // (1024 * 1024)} MiB'))
        with path.open('rb') as handle:
            head = handle.read(4096)
        if (kind := executable_format(head)) is not None:
            violations.append(Violation(value, f'executable binary ({kind})'))
    return violations


def home_path_violations(root: Path, paths: list[str]) -> list[Violation]:
    violations = []
    for value in paths:
        path = root / value
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_TRACKED_BYTES:
            continue
        data = path.read_bytes()
        if b'\0' in data[:8192]:
            continue
        text = data.decode('utf-8', errors='replace')
        for match in HOME_PATH.finditer(text):
            if (match.group(1) or match.group(2)) not in SYNTHETIC_HOME_NAMES:
                violations.append(Violation(value, 'absolute path into a home directory'))
                break
    return violations


def scan_repository(root: Path = ROOT, paths: list[str] | None = None) -> list[Violation]:
    paths = tracked_paths(root) if paths is None else paths
    violations = [
        Violation(value, reason)
        for value in paths
        if (reason := forbidden_path_reason(value)) is not None
    ]
    violations.extend(content_violations(root, paths))
    violations.extend(asset_violations(root, paths))
    violations.extend(binary_violations(root, paths))
    violations.extend(home_path_violations(root, paths))
    return sorted(set(violations))


def attribution_violations(label: str, text: str) -> list[Violation]:
    if any(pattern.search(text) for pattern in ATTRIBUTION_MARKERS):
        return [Violation(label, 'coding-assistant attribution or session link')]
    return []


def commit_violations(root: Path, revision_range: str) -> list[Violation]:
    """Check author and committer address and message of every commit in the range."""
    if revision_range.startswith('-'):
        raise ValueError(f'invalid revision range: {revision_range}')
    result = subprocess.run(
        ['git', 'log', '-z', '--format=%H%x1f%ae%x1f%ce%x1f%B', revision_range, '--'],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
    )
    violations: list[Violation] = []
    for record in result.stdout.split(b'\0'):
        if not record.strip():
            continue
        fields = record.decode('utf-8', errors='replace').split('\x1f', 3)
        if len(fields) != 4:
            raise ValueError('unexpected git log output')
        sha, author_email, committer_email, message = fields
        label = f'commit {sha[:12]}'
        if any(ASSISTANT_EMAIL.match(email.strip()) for email in (author_email, committer_email)):
            violations.append(Violation(label, 'coding-assistant author or committer identity'))
        violations.extend(attribution_violations(label, message))
    return violations


def pull_request_violations(event: dict) -> list[Violation]:
    pull_request = event.get('pull_request')
    if not isinstance(pull_request, dict):
        raise ValueError('pull_request event without pull_request payload')
    label = f'pull request #{pull_request.get("number")}'
    text = '\n'.join(
        value for value in (pull_request.get('title'), pull_request.get('body'))
        if isinstance(value, str)
    )
    violations = attribution_violations(label, text)
    head_ref = (pull_request.get('head') or {}).get('ref') or ''
    if ASSISTANT_BRANCH.match(head_ref):
        violations.append(Violation(label, f'coding-assistant branch name: {head_ref}'))
    return violations


def pull_request_scan(root: Path, event_path: str) -> list[Violation]:
    event = json.loads(Path(event_path).read_text(encoding='utf-8'))
    violations = pull_request_violations(event)
    base = event['pull_request']['base']['sha']
    head = event['pull_request']['head']['sha']
    for value in (base, head):
        if not re.fullmatch(r'[0-9a-f]{40}', value or ''):
            raise ValueError('pull_request event without commit SHAs')
    violations.extend(commit_violations(root, f'{base}..{head}'))
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--commits',
        metavar='RANGE',
        help='also check commits in this range, e.g. origin/main..HEAD',
    )
    parser.add_argument(
        '--gitleaks',
        metavar='BINARY',
        help='also run the secret scan with its canaries '
             '(scripts/check_repository_secrets.py) with this gitleaks binary',
    )
    args = parser.parse_args(argv)

    if args.gitleaks:
        scan = subprocess.run(
            [sys.executable, str(ROOT / 'scripts' / 'check_repository_secrets.py'), '--gitleaks', args.gitleaks],
            check=False,
        )
        if scan.returncode:
            print('Repository hygiene check failed: the secret scan reported findings or could not run.')
            return scan.returncode

    violations = scan_repository()
    if args.commits:
        violations.extend(commit_violations(ROOT, args.commits))
    event_path = os.environ.get('GITHUB_EVENT_PATH')
    if os.environ.get('GITHUB_EVENT_NAME') == 'pull_request' and event_path:
        violations.extend(pull_request_scan(ROOT, event_path))
    if violations:
        print('Repository hygiene check failed:')
        for violation in sorted(set(violations)):
            print(f'- {violation.path}: {violation.reason}')
        return 1
    print(
        'Repository hygiene check passed: no forbidden paths, internal notes, '
        'orphaned media, binaries, home paths or assistant attribution found.'
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
