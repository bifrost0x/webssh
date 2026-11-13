"""Stylesheets must not depend on custom properties that nothing defines."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
DEFINITION = re.compile(r'(--[\w-]+)\s*:')
SCRIPT_DEFINITION = re.compile(r"setProperty\(\s*['\"](--[\w-]+)")
# A var() without a fallback computes to an invalid value when the property
# is undefined, which silently drops the declaration (for example error text
# losing its colour).
UNGUARDED_USE = re.compile(r'var\(\s*(--[\w-]+)\s*\)')


def _sources(*patterns):
    for pattern in patterns:
        yield from sorted(ROOT.glob(pattern))


def test_unguarded_custom_properties_are_defined():
    defined = set()
    for path in _sources('static/css/*.css', 'templates/**/*.html', 'static/js/*.js'):
        text = path.read_text(encoding='utf-8')
        defined.update(DEFINITION.findall(text))
        defined.update(SCRIPT_DEFINITION.findall(text))

    undefined = []
    for path in _sources('static/css/*.css'):
        text = path.read_text(encoding='utf-8')
        for match in UNGUARDED_USE.finditer(text):
            if match.group(1) not in defined:
                line = text.count('\n', 0, match.start()) + 1
                undefined.append(f'{path.relative_to(ROOT)}:{line} {match.group(1)}')
    assert undefined == []
