"""The release version, the newest release notes and the tag guard agree."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def _release_key(path):
    return tuple(int(part) for part in path.stem[1:].split('.'))


def dockerfile_version():
    dockerfile = (ROOT / 'Dockerfile').read_text(encoding='utf-8')
    versions = set(re.findall(r'^ARG VERSION=(\S+)$', dockerfile, re.MULTILINE))
    assert len(versions) == 1, versions
    version, = versions
    return version


def test_dockerfile_stages_share_one_release_version():
    assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', dockerfile_version())


def test_version_matches_the_newest_release_notes():
    notes = sorted((ROOT / 'docs/releases').glob('v*.*.*.md'), key=_release_key)
    assert notes[-1].name == f'v{dockerfile_version()}.md'
    assert not list((ROOT / 'docs').glob('release-notes*.md'))


def test_tag_build_refuses_a_tag_that_differs_from_the_version():
    workflow = (ROOT / '.github/workflows/docker-publish.yml').read_text(encoding='utf-8')
    assert "sed -n 's/^ARG VERSION=//p' Dockerfile | sort -u" in workflow
    assert '"$GITHUB_REF_NAME" != "v$version"' in workflow
