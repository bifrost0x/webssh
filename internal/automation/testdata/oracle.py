"""Record how the Python release normalizes runbooks, cleans and bounds
step output and exports runs.

Writes a corpus with the expected results so the Go tests replay it
without Python. Run from the repository root with the project virtual
environment:

    WS=$PWD .venv/bin/python -I internal/automation/testdata/oracle.py \
        internal/automation/testdata/oracle.json

The functions run unchanged: normalize_runbook and digest of
automation_store.py, _plain_output, _redact_output and execute_step of
automation_transport.py (over a fake channel), and the export route of
automation_routes.py with the history of the service replaced.
"""
import base64
import copy
import json
import os
import sys
import tempfile
from pathlib import Path

WS = Path(os.environ['WS'])
sys.path.insert(0, str(WS))
os.environ.setdefault('SECRET_KEY', '0' * 64)
os.environ['DATA_DIR'] = tempfile.mkdtemp(prefix='automation-oracle-')

import app.automation_routes as routes  # noqa: E402
import app.automation_store as store  # noqa: E402
import app.automation_transport as transport  # noqa: E402


def b64(raw):
    return base64.b64encode(raw).decode('ascii')


def normalize(value):
    raw = json.dumps(value)
    try:
        book = store.normalize_runbook(json.loads(raw))
        if 'id' not in value:
            book['id'] = None
        return {'input': raw, 'ok': book, 'digest': store.digest(book) if book['id'] else None}
    except (store.AutomationError, TypeError) as error:
        return {'input': raw, 'error': getattr(error, 'code', 'type_error')}


STEP = dict(name='Step', command='id', timeout=30, sudo=False)
RUNBOOKS = [
    dict(id='a', name='Book', steps=[STEP]),
    dict(name='No id', steps=[STEP]),
    dict(id='a', name='Book', steps=[dict(name='x', command='y')], stop_on_error=False),
    dict(id='a', name='Book', steps=[]),
    dict(id='a', name='Book', steps=[STEP] * 21),
    dict(id='a', name='Book', steps=[STEP] * 20),
    dict(id='a', name='Book', steps='x'),
    dict(id='a', name='Book', steps=[dict(STEP, timeout=0)]),
    dict(id='a', name='Book', steps=[dict(STEP, timeout=301)]),
    dict(id='a', name='Book', steps=[dict(STEP, timeout=300)]),
    dict(id='a', name='Book', steps=[dict(STEP, timeout=30.0)]),
    dict(id='a', name='Book', steps=[dict(STEP, timeout=True)]),
    dict(id='a', name='Book', steps=[dict(STEP, sudo=1)]),
    dict(id='a', name='Book', steps=[dict(STEP, sudo=True)]),
    dict(id='a', name='Book', steps=[dict(STEP, name='')]),
    dict(id='a', name='Book', steps=[dict(STEP, name=' \t　\x1c')]),
    dict(id='a', name='Book', steps=[dict(STEP, name='a\x00b')]),
    dict(id='a', name='Book', steps=[dict(STEP, name='é' * 64)]),
    dict(id='a', name='Book', steps=[dict(STEP, name='é' * 65)]),
    dict(id='a', name='Book', steps=[dict(STEP, command='x' * 8192)]),
    dict(id='a', name='Book', steps=[dict(STEP, command='x' * 8193)]),
    dict(id='a', name='Book', steps=[dict(STEP, command=None)]),
    dict(id='a', name='Book', steps=[dict(STEP, name=5, timeout=0)]),
    dict(id='a', name='Book', steps=[STEP], stop_on_error='yes'),
    dict(id='a', name='Book', steps=[dict(STEP, name='')], stop_on_error='yes'),
    dict(id='', name='Book', steps=[STEP]),
    dict(id=None, name='Book', steps=[STEP]),
    dict(id='i' * 64, name='Book', steps=[STEP]),
    dict(id='i' * 65, name='Book', steps=[STEP]),
    dict(id='a', name='', steps=[STEP]),
    dict(id='', name='', steps=[STEP]),
    dict(id='a', steps=[STEP]),
    dict(id='a', name='Ünïcødé ✓ \U0001f680 עב', steps=[dict(STEP, name='Schritt ✓', command='echo "✓"\nexit 3', sudo=True)]),
    dict(id='a', name='Book', steps=[5]),
]


def plain_cases():
    texts = [
        'plain', 'a\x1b[31mred\x1b[0m', 'a\x1b[', 'a\x1b[\n', 'a\x1b[12', 'a\x1b[12\n', '\x9b31mx',
        'x\x1b]0;title\x07y', 'x\x1b]0;title\x1b\\y', 'x\x1b]0;title', 'x\x1b]0;title\n', 'x\x1b]0;a\nb\n',
        'x\x9dtitle\x07y', 'x\x1bPdata\x1b\\y', 'x\x1bPdata', 'x\x1bPdata\n', 'x\x1b_apc', 'x\x1bXsos\x1b\\z',
        'x\x1b^pm\n', 'x\x1b(Bq', 'x\x1b', 'x\x1b\n', 'x\x1b!', 'x\x1b !~', 'x\x1b\x07y', 'a\r\nb\rc',
        'tab\there\x00nul\x7f​zw‮rlo﻿', '� ok', '\x1b[1;2;3 q', 'a\x1b[?25lb', 'end\x1b]',
        '\x1b]\x1b]\x07', 'x\x1b]a\x1b\\\x1b[1m', 'multi\nline\n', 'a\x85b c',
    ]
    return [{'input': t, 'ok': transport._plain_output(t)} for t in texts]


def redact_cases():
    cases = [
        ('the secret is hunter2', ['hunter2'], False),
        ('hunter2hunter2', ['hunter2', 'hunter'], False),
        ('ends with hunt', ['hunter2'], True),
        ('ends with hunt', ['hunter2'], False),
        ('ends with h', ['hunter2'], True),
        ('xéé', ['ééz'], True),
        ('pw', ['', 'pw'], True),
        ('abc', ['abcdef', 'bcd'], True),
        ('', ['x'], True),
    ]
    return [{'input': v, 'secrets': s, 'interrupted': i, 'ok': transport._redact_output(v, s, i)} for v, s, i in cases]


class Channel:
    """A finished command as paramiko delivers it."""

    def __init__(self, stdout, stderr, status):
        self.parts = [bytearray(stdout), bytearray(stderr)]
        self.status = status
        self.closed = False
        self.eof_received = True

    def shutdown_write(self):
        pass

    def recv_ready(self):
        return bool(self.parts[0])

    def recv_stderr_ready(self):
        return bool(self.parts[1])

    def _take(self, index, size):
        chunk = bytes(self.parts[index][:size])
        del self.parts[index][:size]
        return chunk

    def recv(self, size):
        return self._take(0, size)

    def recv_stderr(self, size):
        return self._take(1, size)

    def exit_status_ready(self):
        return True

    def recv_exit_status(self):
        return self.status

    def close(self):
        self.closed = True


def step_cases():
    cases = [
        (b'hello\n', b'', 0, (), 8192),
        (b'', b'boom\n', 1, (), 8192),
        ((b'x', 9000), b'', 0, (), 8192),
        ((b'x', 9000), (b'e', 100), 0, (), 8192),
        ((b'o', 100), (b'e', 9000), 2, (), 8192),
        ((b'x', 300000), b'', 0, (), 8192),
        (b'\x1b[31mred\x1b[0m pw=hunter2\r\n', b'hunter2', 0, ('hunter2',), 8192),
        ('é'.encode() * 5000, b'', 0, (), 8192),
        (b'abc\xe2\x82', b'', 0, (), 8192),
        (b'abc\xe2\x82xyz\xff\xfe\xf0\x9f\x98', b'', 0, (), 8192),
        (b'\xed\xa0\x80 \xc0\xaf \xf4\x90\x80\x80 \xe0\x80\x80', b'', 0, (), 8192),
        (b'out', b'err', 0, (), 5),
        (b'out', b'err', 0, (), 0),
        (b'o' * 10, b'e' * 10, 0, (), 7),
        ('€'.encode() * 10, b'', 0, (), 8),
        (b'secret: hunt', b'', 0, ('hunter2',), 8192),
        (b'', b'', 255, (), 8192),
    ]
    out = []
    for stdout_spec, stderr_spec, status, secrets, budget in cases:
        stdout_chunk, stdout_repeat = stdout_spec if isinstance(stdout_spec, tuple) else (stdout_spec, 1)
        stderr_chunk, stderr_repeat = stderr_spec if isinstance(stderr_spec, tuple) else (stderr_spec, 1)
        stdout, stderr = stdout_chunk * stdout_repeat, stderr_chunk * stderr_repeat
        original = transport.paramiko_channels.open_exec_channel
        transport.paramiko_channels.open_exec_channel = (
            lambda _t, _c, timeout, before_exec, s=stdout, e=stderr, st=status: (before_exec(), Channel(s, e, st))[1])
        try:
            result = transport.execute_step(object(), dict(name='s', command='c', timeout=30, sudo=False),
                                            lambda: False, secrets, budget)
        finally:
            transport.paramiko_channels.open_exec_channel = original
        result.pop('duration')
        out.append({'stdout': b64(stdout_chunk), 'stdout_repeat': stdout_repeat,
                    'stderr': b64(stderr_chunk), 'stderr_repeat': stderr_repeat, 'status': status, 'secrets': list(secrets),
                    'budget': budget, 'ok': result})
    return out


def runs():
    step = dict(name='Schritt 0 ✓', status='failed', exit_code=1, duration=0.25, reason='nonzero_exit',
                stdout='ünïcødé\n', stderr='boom\n', output_truncated=False)
    target = dict(id='c11a', name='Password server', host='pw.golden.test', port=22, username='operator',
                  group=None, status='failed', reason=None, steps=[step])
    base = dict(id='golden-run-0001', name='Ünïcødé \U0001f680', runbook_id='rb',
                created_at='2026-11-02T09:03:54.250000+00:00', finished_at='2026-11-02T09:03:54.250000+00:00',
                status='failed', targets=[target])
    hostile = copy.deepcopy(base)
    hostile['name'] = '=cmd|calc'
    hostile['targets'][0]['steps'][0].update(stdout='+1,"two"\r\nthree', stderr='-x\n@y', name='\tTab')
    hostile['targets'][0]['group'] = ' @group'
    hostile['targets'][0]['name'] = '﻿=bom'
    old = dict(id='old-run', name='Old', created_at='2025-01-01T00:00:00+00:00', status='succeeded',
               targets=[dict(target, status='succeeded', group='Lab',
                             steps=[dict(name='Only', status='succeeded', exit_code=0, duration=3),
                                    dict(name='Second', status='skipped', exit_code=None, duration=0.1)])])
    running = dict(id='open', runbook_id='rb', name='Open', created_at='2026-01-01T00:00:00+00:00',
                   status='running', schedule_id='sched', claim_id='claim',
                   targets=[dict(target, status='running', group='G', reason=None,
                                 steps=[dict(step, status='running', reason=None, exit_code=None, duration=0),
                                        dict(step, status='queued', reason=None, exit_code=None, duration=0)])])
    null_finished = dict(base, finished_at=None)
    out = []
    for run in (base, hostile, old, running, null_finished):
        stored = json.dumps(run, ensure_ascii=True)
        entry = {'stored': stored}
        for fmt in ('json', 'csv'):
            entry[fmt] = export(json.loads(stored), fmt)
        out.append(entry)
    return out


def export(run, fmt):
    from flask import Flask

    class Service:
        def history(self, _user_id):
            return [run]

    class User:
        id = 1

    app = Flask('oracle')
    saved = (routes._auth, routes._enabled, routes.service, routes.current_user)
    routes._auth = lambda: None
    routes._enabled = lambda: None
    routes.service = lambda: Service()
    routes.current_user = User()
    try:
        with app.test_request_context(f'/?format={fmt}'):
            response = routes.export_run.__wrapped__(run['id'])
            return {'body': b64(response.get_data()), 'content_type': response.headers['Content-Type']}
    finally:
        routes._auth, routes._enabled, routes.service, routes.current_user = saved


def golden():
    """The exports of every run in the golden data sets, keyed by archive."""
    import tarfile
    out = {}
    for archive in [WS / 'tests/golden/fixture/datadir.tar', *sorted((WS / 'tests/golden/fixture/legacy').glob('*.tar'))]:
        with tarfile.open(archive) as tar:
            for member in tar.getmembers():
                if member.name.endswith('/automation.json'):
                    user = int(member.name.split('/user_')[1].split('/')[0])
                    for book in json.loads(tar.extractfile(member).read())['runbooks']:
                        out.setdefault(archive.name + ':runbooks', []).append({
                            'user_id': user, 'run_id': book['id'], 'json': store.digest(book), 'csv': ''})
                    continue
                if not member.name.endswith('/automation-runs.json'):
                    continue
                document = json.loads(tar.extractfile(member).read())
                user = int(member.name.split('/user_')[1].split('/')[0])
                for run in document['runs']:
                    out.setdefault(archive.name, []).append({
                        'user_id': user, 'run_id': run['id'],
                        'json': export(run, 'json')['body'], 'csv': export(run, 'csv')['body']})
    return out


def main(path):
    corpus = {
        'runbooks': [normalize(v) for v in RUNBOOKS],
        'plain': plain_cases(),
        'redact': redact_cases(),
        'steps': step_cases(),
        'runs': runs(),
        'golden': golden(),
    }
    Path(path).write_text(json.dumps(corpus, indent=1, ensure_ascii=True) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main(sys.argv[1])
