import json
import os
import subprocess
from pathlib import Path

import pytest

from scripts.check_repository_hygiene import (
    asset_violations,
    attribution_violations,
    commit_violations,
    content_violations,
    forbidden_path_reason,
    pull_request_scan,
    pull_request_violations,
    scan_repository,
)


@pytest.mark.parametrize('path', [
    'AGENTS.md',
    'docs/CLAUDE.md',
    '.codex/settings.toml',
    '.aider.conf.yml',
    '.cursor/rules/project.mdc',
    '.amazonq/rules/project.md',
    '.windsurfrules',
    'QWEN.md',
    '.github/copilot-instructions.md',
    '.github/instructions/backend.instructions.md',
    'docs/reviews/2026-09-21/README.md',
    'notes/workspace-ux-review.md',
    'graphify-out/graph.html',
    'test-results/failure.png',
    '.env.production',
    'server.sqlite3',
    'app/.env.staging',
    'app/secrets/password.txt',
    'data/profiles.json',
    'instance/users.json',
    'loose.pem',
    'loose.key',
    'secret_key',
    '.ssh/id_ed25519',
    'server.sqlite3-wal',
    'server.db-shm',
])
def test_private_and_generated_paths_are_rejected(path):
    assert forbidden_path_reason(path)


@pytest.mark.parametrize('path', [
    'README.md',
    'SECURITY.md',
    'docs/wiki/Development-and-Testing.md',
    'tests/e2e/review-regressions.spec.js',
    '.env.example',
    'docs/media/diagrams/system-trust-boundaries.svg',
])
def test_public_project_paths_remain_allowed(path):
    assert forbidden_path_reason(path) is None


@pytest.mark.parametrize('content', [
    '# Agent instructions\nAlways run the local tool.',
    'You are Codex. Modify this repository.',
    '<skills_instructions>private workflow</skills_instructions>',
    'Evidence lives at /home/developer/.codex/visualizations/mock.html',
    '- Source visual truth: /tmp/codex-clipboard-image.png',
])
def test_instruction_and_workstation_markers_are_rejected(tmp_path, content):
    target = tmp_path / 'notes.md'
    target.write_text(content, encoding='utf-8')
    assert content_violations(tmp_path, ['notes.md'])


def test_assets_must_have_a_public_reference(tmp_path):
    (tmp_path / 'assets').mkdir()
    (tmp_path / 'assets' / 'public.png').write_bytes(b'png')
    (tmp_path / 'assets' / 'orphan.png').write_bytes(b'other png')
    (tmp_path / 'README.md').write_text('![Product](assets/public.png)', encoding='utf-8')
    violations = asset_violations(
        tmp_path,
        ['README.md', 'assets/public.png', 'assets/orphan.png'],
    )
    assert [(item.path, item.reason) for item in violations] == [
        ('assets/orphan.png', 'asset has no public documentation or site reference'),
    ]


def test_current_tracked_tree_is_public_safe():
    root = Path(__file__).resolve().parents[1]
    assert scan_repository(root) == []


@pytest.mark.parametrize('directory', ['assets', 'site/assets', 'static/images/redesign'])
def test_test_references_and_media_metadata_do_not_keep_orphans_alive(tmp_path, directory):
    paths = [f'{directory}/unused.png', 'tests/test_image.py', f'{directory}/LICENSE.txt']
    for name, content in zip(paths, ['image', 'unused.png', 'Credits for unused.png']):
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    assert [v.path for v in asset_violations(tmp_path, paths)] == [paths[0]]


def test_runtime_references_and_used_authoring_sources_are_retained(tmp_path):
    files = {
        'static/css/style.css': 'background: url(../images/theme-backgrounds/example.webp?v=123)',
        'static/images/theme-backgrounds/example.webp': 'webp',
        'static/images/theme-backgrounds/example.png': 'source',
        'templates/login.html': '<img src="images/logo.svg">',
        'static/images/logo.svg': '<svg/>',
        'site/demo.html': '<a href="assets/tour.vtt">Captions</a>',
        'site/assets/tour.vtt': 'WEBVTT',
    }
    for name, content in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    assert asset_violations(tmp_path, list(files)) == []
    (tmp_path / 'static/css/style.css').write_text('')
    assert {v.path for v in asset_violations(tmp_path, list(files))} == {
        'static/images/theme-backgrounds/example.webp',
        'static/images/theme-backgrounds/example.png',
    }


def test_identical_media_under_different_names_is_reported(tmp_path):
    (tmp_path / 'assets').mkdir()
    for name in ('one.png', 'two.png'):
        (tmp_path / 'assets' / name).write_bytes(b'identical image')
    (tmp_path / 'README.md').write_text('one.png two.png')
    violations = asset_violations(tmp_path, ['assets/one.png', 'assets/two.png', 'README.md'])
    assert len(violations) == 1
    assert violations[0].path == 'assets/two.png'
    assert 'identical media' in violations[0].reason


def test_required_ci_gate_runs_hygiene_before_change_classification():
    root = Path(__file__).resolve().parents[1]
    workflow = (root / '.github' / 'workflows' / 'tests.yml').read_text(
        encoding='utf-8',
    )
    hygiene = workflow.index('python scripts/check_repository_hygiene.py')
    secrets = workflow.index('python scripts/check_repository_secrets.py')
    classification = workflow.index('python scripts/ci_change_scope.py')
    assert hygiene < secrets < classification


@pytest.mark.parametrize('text', [
    'Fix\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>',
    'Fix\n\nCo-authored-by: Cursor Agent <cursoragent@cursor.com>',
    'Fix\n\nCo-authored-by: Copilot Autofix powered by AI '
    '<62310815+github-advanced-security[bot]@users.noreply.github.com>',
    'Fix\n\nCo-authored-by: Copilot <198982749+Copilot@users.noreply.github.com>',
    'Fix\n\nCo-authored-by: devin-ai-integration[bot] '
    '<158243242+devin-ai-integration[bot]@users.noreply.github.com>',
    'Fix\n\nClaude-Session: https://claude.ai/code/session_0123',
    'Summary\n\nhttps://claude.ai/code/session_0123',
    '---\n_Generated by [Claude Code](https://claude.ai/code)_',
    'Generated with Copilot',
    'See https://chatgpt.com/codex/tasks/task_e_0123',
])
def test_assistant_attribution_is_rejected(text):
    assert attribution_violations('commit abc', text)


@pytest.mark.parametrize('text', [
    'Ignore .claude/ and .codex/ worktrees in the hygiene guard',
    'Fix cursor position after resize',
    'Co-authored-by: Jane Doe <jane@example.com>',
    'Co-authored-by: Jules Martin <jules@example.com>',
    'Co-authored-by: Devin Smith <devin@example.com>',
    'Co-authored-by: Claude Dupont <claude.dupont@example.org>',
    'Co-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>',
    'Generated by the release workflow',
])
def test_ordinary_commit_text_is_allowed(text):
    assert attribution_violations('commit abc', text) == []


def _git(root, *args, env=None):
    return subprocess.run(
        ['git', *args], cwd=root, check=True, env=env,
        stdout=subprocess.PIPE, text=True,
    ).stdout.strip()


def _commit(root, message, name='Jane Doe', email='jane@example.com'):
    env = dict(os.environ)
    env.update({
        'GIT_AUTHOR_NAME': name, 'GIT_AUTHOR_EMAIL': email,
        'GIT_COMMITTER_NAME': name, 'GIT_COMMITTER_EMAIL': email,
    })
    _git(root, 'commit', '--allow-empty', '-q', '-m', message, env=env)
    return _git(root, 'rev-parse', 'HEAD')


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, 'init', '-q')
    _git(tmp_path, 'config', 'commit.gpgsign', 'false')
    base = _commit(tmp_path, 'Initial commit')
    return tmp_path, base


def test_commit_range_rejects_assistant_identity_and_trailers(repo):
    root, base = repo
    _commit(root, 'Clean change')
    _commit(root, 'Audit fixes', name='Claude', email='noreply@anthropic.com')
    _commit(root, 'Prune\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>')
    reasons = sorted(v.reason for v in commit_violations(root, f'{base}..HEAD'))
    assert reasons == [
        'coding-assistant attribution or session link',
        'coding-assistant author or committer identity',
    ]


def test_commit_range_outside_the_pull_request_is_not_checked(repo):
    root, _ = repo
    _commit(root, 'Old', name='Claude', email='noreply@anthropic.com')
    head = _commit(root, 'Clean change')
    assert commit_violations(root, f'{head}~1..{head}') == []


def test_commit_range_cannot_inject_git_options(repo):
    root, _ = repo
    with pytest.raises(ValueError):
        commit_violations(root, '--output=/tmp/x')


def test_pull_request_text_and_branch_are_checked():
    event = {'pull_request': {
        'number': 7,
        'title': 'Prune manifests',
        'body': 'Details\n\n_Generated by [Claude Code](https://claude.ai/code)_',
        'head': {'ref': 'claude/code-audit-x1'},
    }}
    reasons = sorted(v.reason for v in pull_request_violations(event))
    assert reasons == [
        'coding-assistant attribution or session link',
        'coding-assistant branch name: claude/code-audit-x1',
    ]
    clean = {'pull_request': {
        'number': 8, 'title': 'Fix cursor blink', 'body': None,
        'head': {'ref': 'fix/cursor-blink'},
    }}
    assert pull_request_violations(clean) == []


def test_pull_request_scan_checks_event_commits(repo):
    root, base = repo
    head = _commit(root, 'Fix\n\nClaude-Session: https://claude.ai/code/session_1')
    event = root / 'event.json'
    event.write_text(json.dumps({'pull_request': {
        'number': 9, 'title': 'Fix', 'body': '',
        'head': {'ref': 'fix/x', 'sha': head},
        'base': {'sha': base},
    }}), encoding='utf-8')
    assert [v.path for v in pull_request_scan(root, str(event))] == [f'commit {head[:12]}']
    payload = json.loads(event.read_text(encoding='utf-8'))
    payload['pull_request']['base']['sha'] = 'main'
    event.write_text(json.dumps(payload), encoding='utf-8')
    with pytest.raises(ValueError):
        pull_request_scan(root, str(event))


def test_human_names_matching_assistant_names_are_not_identities(repo):
    root, base = repo
    _commit(root, 'Fix', name='Claude', email='claude@example.org')
    _commit(root, 'Fix', name='Devin Smith', email='devin@example.com')
    assert commit_violations(root, f'{base}..HEAD') == []
