"""Signed-in users can read the running WebSSH version; anonymous pages cannot."""

from pathlib import Path
import re

import pytest

from app import version
from tests.test_webssh2_shell import _create_login


ROOT = Path(__file__).resolve().parents[1]
REVISION = '0123456789abcdef0123456789abcdef01234567'


def _release_key(path):
    return tuple(int(part) for part in path.stem[1:].split('.'))


def test_version_matches_the_newest_release_notes():
    assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version.VERSION)
    notes = sorted(
        (ROOT / 'docs/releases').glob('v*.*.*.md'), key=_release_key,
    )
    assert notes[-1].name == f'v{version.VERSION}.md'


@pytest.mark.parametrize(('value', 'expected'), [
    (REVISION, f'{version.VERSION} (0123456)'),
    ('', version.VERSION),
    ('unknown', version.VERSION),
    (REVISION[:12], version.VERSION),
    (REVISION.upper(), version.VERSION),
    (REVISION + '\n', version.VERSION),
    ('<script>' + REVISION[8:], version.VERSION),
])
def test_display_version_only_appends_a_full_source_revision(value, expected):
    assert version.display_version({'WEBSSH_REVISION': value}) == expected


def test_display_version_without_revision_variable():
    assert version.display_version({}) == version.VERSION


def test_signed_in_pages_show_the_version(app, client, monkeypatch):
    monkeypatch.setenv('WEBSSH_REVISION', REVISION)
    _create_login(app, client)
    expected = f'{version.VERSION} (0123456)'.encode()
    for route in ('/', '/settings'):
        page = client.get(route)
        assert page.status_code == 200
        assert b'data-i18n="settings.webSshVersion"' in page.data
        assert re.search(
            rb'data-webssh-version>' + re.escape(expected) + rb'<', page.data,
        ), route


def test_anonymous_pages_do_not_reveal_the_version(app, client, monkeypatch):
    monkeypatch.setenv('WEBSSH_REVISION', REVISION)
    _create_login(app, client)
    client.post('/logout')
    app.config['REGISTRATION_ENABLED'] = True
    for route in ('/login', '/register'):
        page = client.get(route)
        assert page.status_code == 200
        assert b'data-webssh-version' not in page.data
        assert b'0123456' not in page.data


def test_image_and_release_build_carry_the_version_contract():
    dockerfile = (ROOT / 'Dockerfile').read_text(encoding='utf-8')
    runtime = dockerfile.split('\nFROM ')[-1]
    assert 'ENV WEBSSH_REVISION=$VCS_REF' in runtime
    # The revision changes every build; keep it below the cached layers.
    tail = runtime.split('ENV WEBSSH_REVISION=$VCS_REF', 1)[1]
    assert not re.search(r'^(RUN|COPY|ADD) ', tail, re.MULTILINE)
    workflow = (ROOT / '.github/workflows/docker-publish.yml').read_text(encoding='utf-8')
    assert '"$GITHUB_REF_NAME" != "v$version"' in workflow
    assert "runpy.run_path('app/version.py')['VERSION']" in workflow
