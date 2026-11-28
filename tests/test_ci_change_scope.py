"""Exercise CI scope decisions against real Git histories and the CLI."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'ci_change_scope.py'


def git(repo, *args):
    env = os.environ.copy()
    env.update({
        'GIT_CONFIG_NOSYSTEM': '1',
        'GIT_CONFIG_GLOBAL': os.devnull,
        'GIT_AUTHOR_NAME': 'CI Tests',
        'GIT_AUTHOR_EMAIL': 'ci-tests@example.invalid',
        'GIT_COMMITTER_NAME': 'CI Tests',
        'GIT_COMMITTER_EMAIL': 'ci-tests@example.invalid',
    })
    result = subprocess.run(
        ['git', '-c', 'core.autocrlf=false', '-c', 'commit.gpgsign=false', *args],
        cwd=repo, env=env, check=True, capture_output=True, text=True,
    )
    return result.stdout.strip()


def commit(repo, changes):
    for name, contents in changes.items():
        path = repo / name
        if contents is None:
            path.unlink()
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding='utf-8')
    git(repo, 'add', '--all')
    git(repo, 'commit', '--allow-empty', '-m', 'Test change')
    return git(repo, 'rev-parse', 'HEAD')


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, 'init', '--initial-branch=main')
    commit(tmp_path, {
        '.dockerignore': 'README.md\ndocs/\n',
        'README.md': 'Original readme\n',
        'app.py': 'print("original")\n',
        'docs/guide.md': 'Original guide\n',
    })
    return tmp_path


def classify(repo, event_name='pull_request', event=None, sha=None,
             ref='refs/pull/7/merge', force_full=False):
    if not SCRIPT.is_file():
        pytest.fail('The CI change classifier has not been implemented')
    spec = importlib.util.spec_from_file_location('ci_change_scope', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if event is None:
        event = {'pull_request': {'base': {'sha': git(repo, 'rev-parse', 'HEAD^')}}}
    return module.classify_changes(
        repo, event_name, event, sha or git(repo, 'rev-parse', 'HEAD'), ref,
        force_full=force_full,
    )


def test_docs_only_changes_use_docs_mode(repo):
    base = git(repo, 'rev-parse', 'HEAD')
    commit(repo, {'README.md': 'Updated readme\n', 'docs/nested/guide.md': 'Guide\n'})
    result = classify(repo)
    assert result['mode'] == 'docs'
    assert result['base'] == base
    assert set(result['files']) == {'README.md', 'docs/nested/guide.md'}
    assert result['reason']


@pytest.mark.parametrize('path', [
    'docs/guide.md', 'docs/nested/guide.md',
    'docs/media/demo.png', 'docs/media/demo.jpg', 'docs/media/demo.jpeg',
    'docs/media/demo.gif', 'docs/media/demo.svg', 'docs/media/demo.webp',
    'docs/media/demo.html', 'docs/media/nested/demo.html',
    'docs/with spaces and ünicode.md',
])
def test_allowed_documentation_paths(repo, path):
    commit(repo, {path: 'Updated content\n'})
    assert classify(repo)['mode'] == 'docs'


@pytest.mark.parametrize('path', [
    'app.py', 'docs/example.py', 'docs/media/demo.js', 'docs/media/demo.PNG',
    'docs/image.png', 'docs/README.MD',
    'other/README.md', '.github/workflows/tests.yml', 'Dockerfile',
    'requirements.txt', 'docs/media2/demo.html',
])
def test_runtime_or_unknown_paths_require_full_ci(repo, path):
    commit(repo, {'README.md': 'Readme change\n', path: 'Changed\n'})
    assert classify(repo)['mode'] == 'full'


@pytest.mark.parametrize('name', ['README.MD', 'readme.md'])
def test_readme_case_rename_requires_full_ci(repo, name):
    git(repo, 'mv', 'README.md', 'temporary-readme')
    git(repo, 'mv', 'temporary-readme', name)
    commit(repo, {})
    result = classify(repo)
    assert result['mode'] == 'full'
    assert set(result['files']) == {'README.md', name}


@pytest.mark.parametrize('path, expected', [('docs/guide.md', 'docs'), ('app.py', 'full')])
def test_deleted_paths_are_classified(repo, path, expected):
    commit(repo, {path: None})
    assert classify(repo)['mode'] == expected


@pytest.mark.parametrize('source, destination', [
    ('app.py', 'docs/moved.md'), ('docs/guide.md', 'app/moved.py'),
])
def test_rename_keeps_both_sides_in_classification(repo, source, destination):
    contents = (repo / source).read_text(encoding='utf-8')
    commit(repo, {source: None, destination: contents})
    result = classify(repo)
    assert result['mode'] == 'full'
    assert set(result['files']) == {source, destination}


@pytest.mark.parametrize('include_runtime, expected', [(False, 'docs'), (True, 'full')])
def test_large_diff_is_not_truncated(repo, include_runtime, expected):
    changes = {f'docs/page-{index:03}.md': 'Page\n' for index in range(305)}
    if include_runtime:
        changes['zz-runtime.py'] = 'print("changed")\n'
    commit(repo, changes)
    result = classify(repo)
    assert result['mode'] == expected
    assert len(result['files']) == (306 if include_runtime else 305)


def test_pull_request_compares_current_base_to_checked_out_merge(repo):
    git(repo, 'checkout', '-b', 'feature')
    commit(repo, {'docs/guide.md': 'Feature documentation\n'})
    git(repo, 'checkout', 'main')
    base = commit(repo, {'app.py': 'print("main advanced")\n'})
    git(repo, 'merge', '--no-ff', 'feature', '-m', 'Merge feature')
    result = classify(
        repo, 'pull_request', {'pull_request': {'base': {'sha': base}}},
        ref='refs/pull/7/merge',
    )
    assert result['mode'] == 'docs'
    assert result['files'] == ['docs/guide.md']


@pytest.mark.parametrize('event_name, ref', [
    ('workflow_dispatch', 'refs/heads/main'), ('schedule', 'refs/heads/main'),
    ('push', 'refs/tags/v3.0.0'), ('push', 'refs/heads/feature'),
    ('push', 'refs/heads/main'),
    ('repository_dispatch', 'refs/heads/main'),
    ('pull_request', 'refs/heads/main'),
])
def test_nonstandard_events_always_require_full_ci(repo, event_name, ref):
    commit(repo, {'README.md': 'Updated\n'})
    assert classify(repo, event_name, ref=ref)['mode'] == 'full'


@pytest.mark.parametrize('base', [None, '', '0' * 40, 'f' * 40, 'HEAD^', 'xyz'])
def test_missing_or_invalid_pull_request_base_requires_full_ci(repo, base):
    commit(repo, {'README.md': 'Updated\n'})
    assert classify(repo, event={'pull_request': {'base': {'sha': base}}})['mode'] == 'full'


@pytest.mark.parametrize('event', [{}, {'pull_request': {}}, {'pull_request': None}])
def test_missing_pull_request_base_requires_full_ci(repo, event):
    commit(repo, {'README.md': 'Updated\n'})
    assert classify(repo, 'pull_request', event, ref='refs/pull/7/merge')['mode'] == 'full'


def test_nonancestor_base_requires_full_ci(repo):
    git(repo, 'checkout', '-b', 'other')
    base = commit(repo, {'docs/guide.md': 'Other branch\n'})
    git(repo, 'checkout', 'main')
    commit(repo, {'README.md': 'Updated\n'})
    assert classify(repo, event={'pull_request': {'base': {'sha': base}}})['mode'] == 'full'



def test_empty_diff_requires_full_ci(repo):
    commit(repo, {})
    assert classify(repo)['mode'] == 'full'


def test_force_full_override(repo):
    commit(repo, {'README.md': 'Updated\n'})
    assert classify(repo, force_full=True)['mode'] == 'full'


@pytest.mark.parametrize('sha', ['HEAD', '0' * 40, 'f' * 40, '1234'])
def test_invalid_checkout_identity_fails_instead_of_skipping(repo, sha):
    commit(repo, {'README.md': 'Updated\n'})
    with pytest.raises(ValueError, match='(?i)(identity|sha|checkout|revision)'):
        classify(repo, sha=sha, force_full=True)


def test_existing_but_wrong_checkout_identity_fails(repo):
    base = git(repo, 'rev-parse', 'HEAD')
    commit(repo, {'README.md': 'Updated\n'})
    with pytest.raises(ValueError, match='(?i)(identity|sha|checkout|revision)'):
        classify(repo, sha=base)


@pytest.mark.parametrize('dockerignore', [
    None, '', 'docs/\n', 'README.md\n',
    'README.md\ndocs/\n!docs/guide.md\n',
    'README.md\ndocs/\n!unrelated.txt\n',
    '# README.md\n# docs/\n',
])
def test_uncertain_container_exclusions_require_full_ci(repo, dockerignore):
    commit(repo, {'.dockerignore': dockerignore})
    commit(repo, {'README.md': 'Updated\n'})
    assert classify(repo)['mode'] == 'full'


def test_allowlist_without_documentation_allows_documentation_ci(repo):
    commit(repo, {'.dockerignore': '# context\n*\n!go.mod\n!cmd/\n!scripts/stage-webassets.sh\n**/testdata/\n'})
    commit(repo, {'README.md': 'Updated\n'})
    assert classify(repo)['mode'] == 'docs'


@pytest.mark.parametrize('reinclude', ['!docs/guide.md', '!README.md', '!*.md', '!docs', '!**', '!./docs/'])
def test_allowlist_that_may_reinclude_documentation_requires_full_ci(repo, reinclude):
    commit(repo, {'.dockerignore': f'*\n!go.mod\n{reinclude}\n'})
    commit(repo, {'README.md': 'Updated\n'})
    assert classify(repo)['mode'] == 'full'


def test_dockerfile_specific_ignore_requires_full_ci(repo):
    commit(repo, {'Dockerfile.dockerignore': 'node_modules/\n'})
    commit(repo, {'README.md': 'Updated\n'})
    assert classify(repo)['mode'] == 'full'


@pytest.mark.skipif(os.name == 'nt', reason='Windows forbids newline filenames')
def test_newline_filename_cannot_spoof_extra_diff_entries(repo):
    name = 'docs/guide.md\napp.py'
    commit(repo, {name: 'Changed\n'})
    result = classify(repo)
    assert result['mode'] == 'full'
    assert result['files'] == [name]


def run_cli(repo, tmp_path, *, sha=None, force_full=False, raw_event=None):
    assert SCRIPT.is_file(), 'The CI change classifier must exist before executing it'
    event_path = tmp_path / 'event.json'
    event_path.write_text(raw_event or json.dumps({
        'pull_request': {'base': {'sha': git(repo, 'rev-parse', 'HEAD^')}},
    }), encoding='utf-8')
    output = tmp_path / 'github-output'
    summary = tmp_path / 'github-summary'
    env = os.environ.copy()
    env.update({
        'GITHUB_EVENT_PATH': str(event_path), 'GITHUB_EVENT_NAME': 'pull_request',
        'GITHUB_SHA': sha or git(repo, 'rev-parse', 'HEAD'),
        'GITHUB_REF': 'refs/pull/7/merge', 'GITHUB_OUTPUT': str(output),
        'GITHUB_STEP_SUMMARY': str(summary),
        'CI_FORCE_FULL': 'true' if force_full else 'false',
    })
    result = subprocess.run(
        [sys.executable, str(SCRIPT)], cwd=repo, env=env,
        capture_output=True, text=True,
    )
    return result, output, summary


@pytest.mark.parametrize('force_full, mode', [(False, 'docs'), (True, 'full')])
def test_cli_writes_mode_and_safe_summary(repo, tmp_path, force_full, mode):
    commit(repo, {'docs/private-name.md': 'Updated\n'})
    result, output, summary = run_cli(repo, tmp_path, force_full=force_full)
    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding='utf-8') == f'mode={mode}\n'
    summary_text = summary.read_text(encoding='utf-8')
    assert mode in summary_text
    if not force_full:
        assert '1' in summary_text
    assert 'private-name' not in result.stdout + result.stderr + summary_text


def test_cli_identity_failure_emits_no_success_output(repo, tmp_path):
    commit(repo, {'README.md': 'Updated\n'})
    result, output, _ = run_cli(repo, tmp_path, sha='f' * 40)
    assert result.returncode != 0
    assert not output.exists() or not output.read_text(encoding='utf-8')


def test_cli_invalid_event_falls_back_to_full_ci(repo, tmp_path):
    commit(repo, {'README.md': 'Updated\n'})
    result, output, _ = run_cli(repo, tmp_path, raw_event='{invalid json')
    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding='utf-8') == 'mode=full\n'
