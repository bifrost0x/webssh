"""Parity of the Go page templates with the Jinja templates.

The Go test TestPagesRenderCases in internal/httpapi renders the cases in
internal/httpapi/testdata/pages/cases.json into the directory named by
WEBSSH_PAGE_PARITY_DIR. This test renders the same cases with the Jinja
templates through the real Flask application and compares both documents
after normalisation: tags, every attribute, text with collapsed
whitespace, JSON blocks by value. Differences are allowed only where
parity-exceptions.json names them with a reason.
"""

import json
import os
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest
from flask import flash, g, render_template

ROOT = Path(__file__).resolve().parent.parent
PAGES = ROOT / 'internal' / 'httpapi' / 'testdata' / 'pages'
CASES = json.loads((PAGES / 'cases.json').read_text(encoding='utf-8'))['cases']
EXCEPTIONS = json.loads((PAGES / 'parity-exceptions.json').read_text(encoding='utf-8'))['exceptions']

TEMPLATES = {
    'login': 'login.html',
    'register': 'register.html',
    'change_password': 'change_password.html',
    'security': 'security.html',
    'index': 'index.html',
    'error': 'error.html',
}
# Values the test passes in place of Flask machinery, or that only Go has.
PARITY_DIR = os.environ.get('WEBSSH_PAGE_PARITY_DIR')
pytestmark = pytest.mark.skipif(
    not PARITY_DIR,
    reason='needs the Go pages; the page-parity job of the Go workflow runs this test',
)
SPECIAL_KEYS = {'script_root', 'csrf_token', 'current_user', 'flashes', 'preview'}
JSON_ATTRIBUTES = {'data-locales', 'data-terminal-appearance'}
VERSION = re.compile(r'\?v=[0-9a-f]{16}')


class _FakeUser:
    def __init__(self, data):
        self.id = data['id']
        self.username = data['username']
        self.is_admin = data['is_admin']
        self.is_authenticated = data['is_authenticated']
        self.is_active = True
        self.is_anonymous = not self.is_authenticated
        self.is_ldap_managed = False
        self.is_github_managed = False
        self.github_identity = None
        self.mfa_enabled = False

    def get_id(self):
        return str(self.id)


def _zero_like(value):
    if isinstance(value, bool):
        return False
    if isinstance(value, str):
        return ''
    return value


def render_jinja(app, case):
    data = case['vars']
    kwargs = {k: v for k, v in data.items() if k not in SPECIAL_KEYS}
    user = data['current_user']
    kwargs.setdefault('username', user['username'])
    kwargs.setdefault('is_admin', user['is_admin'])
    kwargs['csrf_token'] = lambda: data['csrf_token']
    if 'ldap.ldap_login' not in app.view_functions:
        # The test configuration runs without LDAP, so its blueprint is
        # absent; the template still needs the endpoint to build the form.
        app.add_url_rule('/login/ldap', endpoint='ldap.ldap_login', view_func=lambda: '', methods=['POST'])
    base_url = 'http://localhost' + data['script_root']
    with app.test_request_context('/', base_url=base_url):
        g._login_user = _FakeUser(user)
        # Flashes go through the session, because the imported macros of
        # _auth_messages.html read them without the page context.
        for item in data.get('flashes') or []:
            flash(item['message'], item['category'])
        # Context processor values the case does not set take the Go zero
        # value, so both sides start from the same data.
        for processor in app.template_context_processors[None]:
            for key, value in processor().items():
                if key not in kwargs and key not in ('url_for', 'get_flashed_messages', 'config', 'request', 'session', 'g', 'current_user', 'csrf_token'):
                    kwargs[key] = _zero_like(value)
        return render_template(TEMPLATES[case['page']], **kwargs)


class _Normalizer(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.lines = []
        self._json_script = False
        self._buffer = ''

    def _attrs(self, attrs):
        out = []
        for name, value in sorted(attrs, key=lambda a: a[0]):
            value = '' if value is None else VERSION.sub('?v=VERSION', value)
            if name in JSON_ATTRIBUTES and value:
                value = json.dumps(json.loads(value), sort_keys=True)
            out.append(f' {name}={json.dumps(value)}')
        return ''.join(out)

    def handle_starttag(self, tag, attrs):
        self._flush()
        self.lines.append(f'<{tag}{self._attrs(attrs)}>')
        if tag == 'script' and dict(attrs).get('type') == 'application/json':
            self._json_script = True

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        self._flush()
        self.lines.append(f'</{tag}>')

    def handle_data(self, data):
        self._buffer += data

    def handle_decl(self, decl):
        self._flush()
        self.lines.append(f'<!{decl.lower()}>')

    def _flush(self):
        text, self._buffer = VERSION.sub('?v=VERSION', self._buffer), ''
        if self._json_script:
            self._json_script = False
            if text.strip():
                self.lines.append('json:' + json.dumps(json.loads(text), sort_keys=True))
            return
        text = ' '.join(text.split())
        if text:
            self.lines.append('text:' + text)

    def close(self):
        super().close()
        self._flush()


def normalize(document):
    parser = _Normalizer()
    parser.feed(document)
    parser.close()
    return parser.lines


def _applies(exception, case):
    return any(re.fullmatch(p, case['name']) for p in exception['cases'])


def _strip_exceptions(lines, side, case, used):
    kept = []
    drop_script_end = False
    for line in lines:
        if drop_script_end and line == '</script>':
            drop_script_end = False
            continue
        hit = None
        for index, exception in enumerate(EXCEPTIONS):
            if exception['side'] == side and _applies(exception, case) and re.fullmatch(exception['line'], line):
                hit = index
                break
        if hit is None:
            kept.append(line)
        else:
            used.add(hit)
            drop_script_end = drop_script_end or line.startswith('<script')
    return kept


_USED_EXCEPTIONS = set()


@pytest.mark.parametrize('case', CASES, ids=[c['name'] for c in CASES])
def test_go_page_matches_jinja(app, case):
    go_page = Path(PARITY_DIR) / f"{case['name']}.html"
    go_lines = _strip_exceptions(normalize(go_page.read_text(encoding='utf-8')), 'go', case, _USED_EXCEPTIONS)
    jinja_lines = _strip_exceptions(normalize(render_jinja(app, case)), 'jinja', case, _USED_EXCEPTIONS)
    if go_lines != jinja_lines:
        import difflib

        diff = '\n'.join(difflib.unified_diff(jinja_lines, go_lines, 'jinja', 'go', lineterm='', n=2))
        pytest.fail(f"{case['name']}: Go page differs from Jinja\n{diff[:6000]}")


def test_every_exception_is_used(app):
    used = set()
    for case in CASES:
        go_page = Path(PARITY_DIR) / f"{case['name']}.html"
        _strip_exceptions(normalize(go_page.read_text(encoding='utf-8')), 'go', case, used)
        _strip_exceptions(normalize(render_jinja(app, case)), 'jinja', case, used)
    stale = [EXCEPTIONS[i]['reason'] for i in range(len(EXCEPTIONS)) if i not in used]
    assert not stale, f'unused parity exceptions: {stale}'
    for exception in EXCEPTIONS:
        assert exception['reason'].strip(), exception


def test_every_template_page_has_a_case():
    assert {c['page'] for c in CASES} == set(TEMPLATES)
