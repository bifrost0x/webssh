"""Record how the Python release previews, imports and exports host documents.

Writes a corpus with the expected results so the Go tests replay it without
Python. Run from the repository root with the venv in $WEBSSH_PYTHON_ROOT:

    WS=$WEBSSH_PYTHON_ROOT $WEBSSH_PYTHON_ROOT/.venv/bin/python -I internal/hosts/testdata/exchange_oracle.py \
        internal/hosts/testdata/exchange_oracle.json

The three routes of app/profile_exchange_routes.py run unchanged in a
Flask test client. Only what lies outside the exchange is replaced: the
signed-in user, the stored profiles, keys and jump hosts, the rate limit
and upsert_profile, whose answers each import case scripts and whose
payloads the corpus records.
"""
import base64
import io
import json
import os
import shlex
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

WS = Path(os.environ['WS'])
# The golden data sets live in this repository, not in the Python release.
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(WS))
os.environ.setdefault('SECRET_KEY', '0' * 64)
os.environ['DATA_DIR'] = tempfile.mkdtemp(prefix='exchange-oracle-')

from flask import Flask  # noqa: E402

import app.profile_exchange_routes as routes  # noqa: E402


class User:
    id = 3
    is_authenticated = True


STATE = {'profiles': [], 'jump_hosts': [], 'keys': [], 'answers': [], 'payloads': []}
routes.current_user = User()
routes.check_reauth_rate_limit = lambda *args: False
routes.load_profiles = lambda user_id: STATE['profiles']
routes.load_jump_hosts = lambda user_id: STATE['jump_hosts']
routes.load_key_summaries = lambda user_id: STATE['keys']


def upsert(user_id, payload, skip_duplicate=False):
    assert skip_duplicate is True
    STATE['payloads'].append(payload)
    answer = STATE['answers'].pop(0) if STATE['answers'] else 'ok'
    if answer == 'ok':
        return {'id': 'new-%d' % len(STATE['payloads'])}, None
    if answer == 'quota':
        raise routes.ConnectionStorageLimitError('Connection storage quota exceeded: x')
    return None, answer


routes.upsert_profile = upsert

app = Flask(__name__)
app.config['LOGIN_DISABLED'] = True
app.register_blueprint(routes.profile_exchange_blueprint)
client = app.test_client()

KEYS = [
    {'id': 'key-1', 'name': 'Laptop', 'usable': True},
    {'id': 'key-2', 'name': 'Locked', 'usable': False},
    {'id': 'key-3', 'name': 'Ü-Key', 'usable': True},
]
JUMPS = [{'id': 'jump-1', 'name': 'bastion', 'host': 'bastion.test'}]
KNOWN = 'AAAAC3NzaC1lZDI1NTE5AAAAIOL2WzJx0sV/B6VxWU9MnxKJFrrYYNJle330w6TBemSK'

OPENSSH = {
    'simple': 'Host web\n  HostName web.example.test\n  User deploy\n  Port 2222\n',
    'equals': 'Host=web\nHostName=web.test\nUser = deploy\nPort =22\n',
    'aliases': 'Host a b c\n HostName shared.test\n User ops\n',
    'pattern': 'Host *.lan\n User x\nHost real\n HostName real.test\n',
    'negated-pattern': 'Host !bad good\n HostName good.test\n',
    'global-first': 'User root\nHost a\n HostName a.test\n',
    'match': 'Host a\n HostName a.test\nMatch host a\n User x\n',
    'identity': 'Host k\n HostName k.test\n IdentityFile ~/.ssh/id_ed25519\n User u\n',
    'jump-alias': 'Host j\n HostName j.test\n ProxyJump bastion\n User u\n',
    'jump-none': 'Host j\n HostName j.test\n ProxyJump none\n',
    'jump-user-host': 'Host j\n HostName j.test\n ProxyJump admin@bastion.test:2222\n',
    'jump-chain': 'Host j\n HostName j.test\n ProxyJump a,b\n',
    'proxycommand': 'Host p\n HostName p.test\n ProxyCommand nc %h %p\n',
    'forward': 'Host f\n HostName f.test\n LocalForward 8080 localhost:80\n',
    'first-wins': 'Host w\n HostName first.test\n HostName second.test\n User a\n User b\n',
    'two-values': 'Host w\n HostName a.test b.test\n',
    'port-text': 'Host w\n HostName w.test\n Port ssh\n',
    'port-underscore': 'Host w\n HostName w.test\n Port 2_2\n',
    'port-fullwidth': 'Host w\n HostName w.test\n Port ２２\n',
    'port-sign': 'Host w\n HostName w.test\n Port +22\n',
    'port-zero': 'Host w\n HostName w.test\n Port 0\n',
    'port-huge': 'Host w\n HostName w.test\n Port 99999999999999999999\n',
    'quoted': 'Host "web"\n HostName "web.test"\n User \'deploy\'\n',
    'quoted-space': 'Host w\n HostName "a b.test"\n',
    'escape': 'Host w\\x\n HostName w.test\n',
    'escape-in-quotes': 'Host w\n User "de\\"ploy"\n HostName w.test\n',
    'escape-other-in-quotes': 'Host w\n User "de\\ploy"\n HostName w.test\n',
    'comment-inline': 'Host w # comment\n HostName w.test#tail\n',
    'comment-in-quotes': 'Host w\n HostName "w#x.test"\n',
    'empty-quotes': 'Host w\n User ""\n HostName w.test\n',
    'unterminated': 'Host "w\n HostName w.test\n',
    'trailing-escape': 'Host w\\\n',
    'case-keywords': 'HOST w\n HOSTNAME w.test\n uSeR u\n',
    'overlap': 'Host w\n HostName a.test\nHost W\n HostName b.test\n',
    'overlap-fold': 'Host straße\n HostName a.test\n',
    'unicode-alias': 'Host café\n HostName a.test\n',
    'host-no-alias': 'Host\n HostName a.test\n',
    'invalid-host': 'Host w\n HostName bad_host!\n',
    'ip-host': 'Host w\n HostName 2001:db8::1\n',
    'ipv4-zero': 'Host w\n HostName 010.0.0.1\n',
    'gateway-user': 'Host w\n HostName w.test\n User alice:prod-db\n',
    'gateway-ticket': 'Host w\n HostName w.test\n User ticket-abc:x\n',
    'bad-username': 'Host w\n HostName w.test\n User "a b"\n',
    'long-alias': 'Host ' + 'a' * 129 + '\n',
    'no-hostname': 'Host only-alias\n User u\n',
    'crlf': 'Host w\r\n HostName w.test\r\n',
    'vertical-tab': 'Host w\x0b HostName w.test\n',
    'line-separator': 'Host w  HostName w.test\n',
    'nbsp': 'Host w\n HostName w.test\n',
    'tab': 'Host\tw\n\tHostName\tw.test\n',
    'known-hosts': 'web.test ssh-ed25519 ' + KNOWN + '\n',
    'known-hosts-revoked': '# x\n@revoked web.test ssh-ed25519 ' + KNOWN + '\n',
    'known-hosts-commented': '# web.test ssh-ed25519 ' + KNOWN + '\nHost w\n HostName w.test\n',
    'known-hosts-hashed': '|1|abc= ecdsa-sha2-nistp256 AAAA\n',
    'many-warnings': ''.join('Host h%d\n HostName h%d.test\n Bogus%d yes\n' % (i, i, i) for i in range(12)),
    '100-hosts': ''.join('Host h%d\n HostName h%d.test\n' % (i, i) for i in range(100)),
    '101-hosts': ''.join('Host h%d\n HostName h%d.test\n' % (i, i) for i in range(101)),
    '101-aliases': 'Host ' + ' '.join('a%d' % i for i in range(101)) + '\n',
    'empty': '',
    'only-comments': '# nothing\n\n   \n',
}


def host(**values):
    return values


JSON_DOCS = {
    'full': {'format': 'webssh-hosts', 'version': 1, 'hosts': [
        host(name='Web', host='web.test', port=22, username='deploy', group='Prod', favorite=True,
             use_tmux=False, auth_type='password', platform_icon='debian', role_override='web'),
        host(name='Keyed', host='k.test', port=2222, username='u', auth_type='key', requires_key=True),
        host(name='Jumped', host='j.test', username='u', jump_alias='bastion'),
        host(name='Herdr', host='h.test', username='u', herdr=True, use_herdr=True),
        host(name='Socks', host='s.test', username='u', socks_route_omitted=True,
             warnings=['SOCKS5 route not exported']),
        host(name='Tail', host='t.test', username='root', auth_type='tailscale'),
    ]},
    'defaults': {'format': 'webssh-hosts', 'version': 1, 'hosts': [{'name': 'only-name.test'}]},
    'empty-hosts': {'format': 'webssh-hosts', 'version': 1, 'hosts': []},
    'tailscale-key': {'format': 'webssh-hosts', 'version': 1, 'hosts': [
        host(name='T', host='t.test', username='u', auth_type='tailscale', requires_key=True)]},
    'tailscale-jump': {'format': 'webssh-hosts', 'version': 1, 'hosts': [
        host(name='T', host='t.test', username='u', auth_type='tailscale', jump_alias='b')]},
    'bad-values': {'format': 'webssh-hosts', 'version': 1, 'hosts': [
        host(name='', host='a.test'), host(name='  ', host='a.test'), host(name='x', host='bad host'),
        host(name='x', host='a.test', port=True), host(name='x', host='a.test', port=22.0),
        host(name='x', host='a.test', port=0), host(name='x', host='a.test', port=65536),
        host(name='x', host='a.test', port='22'), host(name='x', host='a.test', requires_key='yes'),
        host(name='x', host='a.test', auth_type='kerberos'), host(name='x', host='a.test', auth_type=None),
        host(name='x', host='a.test', platform_icon='amiga'), host(name='x', host='a.test', platform_icon='auto'),
        host(name='x', host='a.test', platform_icon=7), host(name='x', host='a.test', role_override='auto'),
        host(name='x', host='a.test', role_override='wizard'), host(name='x', host='a.test', group='g' * 65),
        host(name='x', host='a.test', group=None), host(name='x', host='a.test', favorite=1),
        host(name='x', host='a.test', use_tmux='true'), host(name='x', host='a.test', herdr=None),
        host(name='x', host='a.test', use_herdr=0), host(name='x\u0007', host='a.test'),
        host(name='n' * 129, host='a.test'), host(name='x', host='a' * 254),
        host(name='x', host='a.test', jump_alias=5), host(name='x', host='a.test', jump_alias=''),
        host(name='x', host='a.test', jump_alias=0), host(name='x', host='a.test', jump_alias='j' * 129),
        host(name='x', host='a.test', jump_alias='with space'), host(name='x', host='a.test', username=5),
        host(name='x', host='a.test', username='a' * 33), host(name='x', host='a.test', username='al:ice:x'),
        host(name='x', host='a.test', username=' a:b'), host(name='x', host='a.test', username='ü'),
        host(name=5, host='a.test'), host(host='a.test'), host(name='x', host=None),
        host(name='x', host=' a.test '), host(name='x', host='a.test', auth_type='key', requires_key=False),
    ]},
    'unknown-field': {'format': 'webssh-hosts', 'version': 1, 'hosts': [host(name='x', key_id='k')]},
    'socks-false': {'format': 'webssh-hosts', 'version': 1, 'hosts': [host(name='x', socks_route_omitted=False)]},
    'socks-one': {'format': 'webssh-hosts', 'version': 1, 'hosts': [host(name='x', socks_route_omitted=1)]},
    'warnings-alone': {'format': 'webssh-hosts', 'version': 1, 'hosts': [host(name='x', warnings=['SOCKS5 route not exported'])]},
    'warnings-other': {'format': 'webssh-hosts', 'version': 1, 'hosts': [host(name='x', socks_route_omitted=True, warnings=['x'])]},
    'record-not-object': {'format': 'webssh-hosts', 'version': 1, 'hosts': ['x']},
    'extra-top': {'format': 'webssh-hosts', 'version': 1, 'hosts': [], 'extra': 1},
    'format-other': {'format': 'other', 'version': 1, 'hosts': []},
    'version-2': {'format': 'webssh-hosts', 'version': 2, 'hosts': []},
    'version-float': {'format': 'webssh-hosts', 'version': 1.0, 'hosts': []},
    'version-true': {'format': 'webssh-hosts', 'version': True, 'hosts': []},
    'hosts-object': {'format': 'webssh-hosts', 'version': 1, 'hosts': {}},
    '101-records': {'format': 'webssh-hosts', 'version': 1, 'hosts': [host(name='h%d' % i) for i in range(101)]},
    'top-array': [],
}

RAW_JSON = {
    'invalid-json': '{"format": ',
    'duplicate-names': '{"format": "other", "format": "webssh-hosts", "version": 1, "hosts": []}',
    'nan-port': '{"format": "webssh-hosts", "version": 1, "hosts": [{"name": "x", "port": NaN}]}',
    'deep': '[' * 20000 + ']' * 20000,
    'big-int-port': '{"format": "webssh-hosts", "version": 1, "hosts": [{"name": "x", "port": 123456789012345678901234567890}]}',
    'exponent-port': '{"format": "webssh-hosts", "version": 1, "hosts": [{"name": "x", "port": 2.2e1}]}',
}


def post(path, body):
    response = client.post(path, data=json.dumps(body, ensure_ascii=False), content_type='application/json')
    return {'status': response.status_code, 'body': response.get_json()}


def previews():
    STATE['keys'], STATE['jump_hosts'] = KEYS, JUMPS
    out = []
    for name, source in OPENSSH.items():
        out.append({'name': 'openssh-' + name, 'request': {'format': 'openssh', 'source': source},
                    **post('/api/profiles/exchange/preview', {'format': 'openssh', 'source': source})})
    for name, document in JSON_DOCS.items():
        source = json.dumps(document, ensure_ascii=False)
        out.append({'name': 'json-' + name, 'request': {'format': 'json', 'source': source},
                    **post('/api/profiles/exchange/preview', {'format': 'json', 'source': source})})
    for name, source in RAW_JSON.items():
        out.append({'name': 'json-' + name, 'request': {'format': 'json', 'source': source},
                    **post('/api/profiles/exchange/preview', {'format': 'json', 'source': source})})
    for name, request in {
        'format-missing': {'source': 'Host a\n'},
        'format-xml': {'format': 'xml', 'source': 'Host a\n'},
        'source-number': {'format': 'json', 'source': 5},
        'source-missing': {'format': 'openssh'},
        'too-large': {'format': 'xml', 'source': 'x' * (64 * 1024 + 1)},
        'at-limit': {'format': 'openssh', 'source': '#' * (64 * 1024)},
        'multibyte-over': {'format': 'openssh', 'source': 'ü' * (32 * 1024 + 1)},
    }.items():
        out.append({'name': name, 'request': request, **post('/api/profiles/exchange/preview', request)})
    for name, raw in {'array-body': '[]', 'text-body': 'x', 'lone-surrogate': '{"format": "openssh", "source": "Host a\\ud800\\n"}'}.items():
        response = client.post('/api/profiles/exchange/preview', data=raw, content_type='application/json')
        out.append({'name': name, 'raw': raw, 'status': response.status_code, 'body': response.get_json()})
    return out


SOURCE = 'Host web\n HostName web.test\n User deploy\nHost keyed\n HostName k.test\n IdentityFile x\n User u\n' \
         'Host jumped\n HostName j.test\n ProxyJump bastion\n User u\n'
TAIL_DOC = json.dumps(JSON_DOCS['full'], ensure_ascii=False)


def imports():
    STATE['keys'], STATE['jump_hosts'] = KEYS, JUMPS
    cases = [
        ('all-mapped', SOURCE, 'openssh', [
            {'index': 0, 'username': 'deploy', 'key_id': '', 'jump_host_id': ''},
            {'index': 1, 'username': 'u', 'key_id': 'key-1', 'jump_host_id': ''},
            {'index': 2, 'username': 'u', 'key_id': '', 'jump_host_id': 'jump-1'}], ['ok', 'ok', 'ok']),
        ('missing-mapping', SOURCE, 'openssh', [{'index': 1, 'username': 'u'}, {'index': 2}], []),
        ('override-username', SOURCE, 'openssh', [{'index': 0, 'username': 'other'}], ['ok']),
        ('no-username-member', SOURCE, 'openssh', [{'index': 0}], ['ok']),
        ('duplicate-skipped', SOURCE, 'openssh', [{'index': 0}], ['Duplicate profile']),
        ('save-error', SOURCE, 'openssh', [{'index': 0}], ['Invalid username format']),
        ('quota', SOURCE, 'openssh', [{'index': 0}], ['quota']),
        ('json-full', TAIL_DOC, 'json', [{'index': 0}, {'index': 3}, {'index': 5, 'key_id': 'key-1'}], ['ok', 'ok', 'ok']),
        ('blocked', TAIL_DOC, 'json', [{'index': 4}], []),
        ('blocked-openssh', 'Host a\n HostName a.test\n ProxyCommand x\n', 'openssh', [{'index': 0}], []),
        ('index-out-of-range', SOURCE, 'openssh', [{'index': 3}], []),
        ('index-negative', SOURCE, 'openssh', [{'index': -1}], []),
        ('index-bool', SOURCE, 'openssh', [{'index': True}], []),
        ('index-float', SOURCE, 'openssh', [{'index': 0.0}], []),
        ('index-repeated', SOURCE, 'openssh', [{'index': 0}, {'index': 0}], []),
        ('selection-extra', SOURCE, 'openssh', [{'index': 0, 'name': 'x'}], []),
        ('selection-not-object', SOURCE, 'openssh', ['x'], []),
        ('mapping-not-string', SOURCE, 'openssh', [{'index': 0, 'key_id': 5}], []),
        ('mapping-null', SOURCE, 'openssh', [{'index': 0, 'username': None}], []),
        ('mapping-too-long', SOURCE, 'openssh', [{'index': 0, 'username': 'u' * 129}], []),
        ('selections-missing', SOURCE, 'openssh', None, []),
        ('selections-object', SOURCE, 'openssh', {}, []),
        ('selections-101', SOURCE, 'openssh', [{'index': 0}] * 101, []),
        ('selections-empty', SOURCE, 'openssh', [], []),
        ('invalid-source', '{"format": ', 'json', [{'index': 0}], []),
        ('known-hosts', 'a.test ssh-ed25519 ' + KNOWN, 'openssh', [{'index': 0}], []),
    ]
    out = []
    for name, source, fmt, selections, answers in cases:
        STATE['payloads'], STATE['answers'] = [], list(answers)
        body = {'format': fmt, 'source': source}
        if selections is not None:
            body['selections'] = selections
        result = post('/api/profiles/exchange', body)
        out.append({'name': name, 'request': body, 'answers': answers, **result, 'payloads': STATE['payloads']})
    return out


def golden_stores():
    tmp = Path(tempfile.mkdtemp(prefix='exchange-oracle-golden-'))
    with tarfile.open(REPO / 'tests/golden/fixture/datadir.tar') as archive:
        archive.extractall(tmp, filter='data')
    base = tmp / 'data/users/user_3'
    return {name: json.loads((base / (name + '.json')).read_text())[name] for name in ('profiles', 'jump_hosts')}


def export_case(name, profiles, jump_hosts):
    STATE['profiles'], STATE['jump_hosts'] = profiles, jump_hosts
    response = client.get('/api/profiles/exchange')
    out = {'name': name, 'profiles': profiles, 'jump_hosts': jump_hosts, 'status': response.status_code,
           'content_type': response.headers.get('Content-Type'),
           'disposition': response.headers.get('Content-Disposition'),
           'omitted': response.headers.get('X-WebSSH-SOCKS-Routes-Omitted')}
    if response.mimetype == 'application/zip':
        with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
            out['entries'] = [{'name': info.filename, 'compress_type': info.compress_type,
                               'data': base64.b64encode(archive.read(info)).decode()} for info in archive.infolist()]
    else:
        out['body'] = response.data.decode()
    return out


def many(count, name_size=8, **extra):
    return [{'id': 'p%d' % i, 'name': ('n%d-' % i).ljust(name_size, 'x'), 'host': 'h%d.test' % i, 'port': 22,
             'username': 'u', 'auth_type': 'password', **extra} for i in range(count)]


def exports():
    golden = golden_stores()
    synthetic = [
        {'id': 's1', 'name': 'Socks ü', 'host': 's.test', 'port': 22, 'username': 'u', 'auth_type': 'password',
         'socks_proxy_id': 'proxy-1', 'herdr': True, 'use_herdr': False, 'role_override': 'auto',
         'detected_platform': 'debian', 'sort_order': 3, 'startup_mode': 'none'},
        {'id': 's2', 'name': 'Jump \U0001F680', 'host': 'j.test', 'port': 2200, 'username': 'u', 'auth_type': 'key',
         'key_id': 'key-1', 'jump_host_id': 'jump-1', 'role_override': 'storage', 'use_herdr': True, 'herdr': True},
        {'id': 's3', 'name': 'Lost jump', 'host': 'l.test', 'username': 'u', 'jump_host_id': 'gone', 'group': 'G'},
        {'id': 's4', 'name': 'Minimal', 'host': 'm.test'},
        {'id': 's5', 'name': 'Tail', 'host': 't.test', 'username': 'root', 'auth_type': 'tailscale', 'favorite': True,
         'use_tmux': True, 'platform_icon': 'raspberrypi', 'herdr': False},
    ]
    return [
        export_case('golden', golden['profiles'], golden['jump_hosts']),
        export_case('synthetic', synthetic, JUMPS),
        export_case('empty', [], []),
        export_case('exactly-100', many(100), []),
        export_case('101-records', many(101), []),
        export_case('250-records', many(250, socks_proxy_id='px'), []),
        export_case('byte-batches', many(60, name_size=1200), []),
        export_case('one-oversized', many(1, name_size=70000) + many(2), []),
    ]


SHLEX_LINES = [
    'a b c', '  a\tb  ', 'a#b c', '#x', 'a "b c" d', "a 'b \\ c'", 'a\\ b', 'a\\b', '"a\\"b"', '"a\\xb"',
    '"a\\\\b"', '""', "''", 'a""b', '"a"\'b\'c', 'a \\', '"unterminated', "'unterminated", '\\', 'x \\#y',
    '"#not comment"', 'a#', '# full', 'a\rb', '\u00fc \u00e4', 'k=v', 'k = v', '\u00a0a', 'a\u3000b', '"a\\\'"',
]
LINES = ['a\nb', 'a\r\nb', 'a\rb', 'a\x0bb\x0cc', 'a\x1cb\x1dc\x1ed\x1fe', 'a\x85b\u2028c\u2029d', 'a\n', '\n\n', '', 'a\r\n\r\n']


def shlex_cases():
    out = []
    for line in SHLEX_LINES:
        line = line.encode().decode('unicode_escape') if '\\u' in line else line
        try:
            out.append({'line': line, 'tokens': shlex.split(line, comments=True, posix=True)})
        except ValueError:
            out.append({'line': line, 'error': True})
    return out


if __name__ == '__main__':
    exported = exports()
    # E40: files the Python release exported, read back by the preview of
    # the Go build (the single document as downloaded, and each archive
    # member).
    STATE['keys'], STATE['jump_hosts'] = KEYS, JUMPS
    files = [('e40-' + e['name'], e['body'].strip()) for e in exported if 'body' in e]
    files += [('e40-%s-%s' % (e['name'], m['name']), base64.b64decode(m['data']).decode())
              for e in exported for m in e.get('entries', [])[:2]]
    e40 = [{'name': name, 'request': {'format': 'json', 'source': text},
            **post('/api/profiles/exchange/preview', {'format': 'json', 'source': text})} for name, text in files]
    corpus = {'previews': previews() + e40, 'imports': imports(), 'exports': exported, 'shlex': shlex_cases(),
              'splitlines': [{'text': t, 'lines': t.splitlines()} for t in LINES]}
    for item in corpus['previews']:
        if item['name'] == 'json-nan-port':
            item['body'] = None  # holds NaN, which is not JSON; Go refuses the document (deviation)
    Path(sys.argv[1]).write_text(json.dumps(corpus, indent=1, ensure_ascii=False) + '\n')
