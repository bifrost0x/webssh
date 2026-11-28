"""The Go workflow compiles every build of the Go module, lab builds included."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
GO_WORKFLOW = ROOT / '.github' / 'workflows' / 'go.yml'
# Tags that select a platform, the race detector or a development source of
# the web assets; the plain build covers them.
NOT_A_BUILD = {'linux', 'race', 'devfs', 'container'}
BUILD_LINE = re.compile(r'^//go:build (.+)$', re.MULTILINE)


def build_tags():
    tags = set()
    for source in [*ROOT.glob('cmd/**/*.go'), *ROOT.glob('internal/**/*.go')]:
        if 'webassets' in source.parts:
            continue
        for expression in BUILD_LINE.findall(source.read_text(encoding='utf-8')):
            tags.update(re.findall(r'(?<![!\w])(\w+)', expression))
    return tags - NOT_A_BUILD


def vetted_tags():
    text = GO_WORKFLOW.read_text(encoding='utf-8')
    tags = set()
    for line in text.splitlines():
        if 'go vet' in line:
            tags.update(re.findall(r'-tags\s+"?(\w+)', line))
    # A step that vets several builds in a loop: for tags in a b; do go vet -tags "$tags" ...
    for loop in re.finditer(r'for tags in ([\w ]+); do\n(?:\s*#[^\n]*\n)?\s*go vet -tags "\$tags"', text):
        tags.update(loop.group(1).split())
    return tags


def test_every_build_tag_is_vetted():
    tags = build_tags()
    assert {'e2e', 'lab', 'herdr', 'warpgate'} <= tags
    assert tags <= vetted_tags(), sorted(tags - vetted_tags())
