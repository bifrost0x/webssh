"""Record how the Python release validates and measures host contexts.

Writes a corpus with the expected results so the Go tests replay it without
Python. Run from the repository root with the project virtual environment:

    WS=$PWD .venv/bin/python -I internal/hostops/testdata/context_oracle.py \
        internal/hostops/testdata/context_oracle.json

Each case is a request body of PUT /api/profiles/<id>/context. The decision
applies the checks of app/host_context_routes.py and write_context of
app/host_context.py up to the ownership check: the body shape, the content
rules (_valid_content), the encoded size and the revision type.
"""
import json
import os
import sys
import tempfile
from pathlib import Path

WS = Path(os.environ['WS'])
sys.path.insert(0, str(WS))
os.environ.setdefault('SECRET_KEY', '0' * 64)
os.environ['DATA_DIR'] = tempfile.mkdtemp(prefix='context-oracle-')

from app.host_context import _valid_content  # noqa: E402


def decide(text):
    try:
        data = json.loads(text)
    except ValueError:
        return 'invalid'
    if not isinstance(data, dict) or set(data) != {'revision', 'notes', 'directories', 'command_sets'}:
        return 'invalid'
    content = {key: value for key, value in data.items() if key != 'revision'}
    try:
        valid = _valid_content(content)
        content_bytes = json.dumps(content, ensure_ascii=False).encode('utf-8')
    except (TypeError, ValueError, UnicodeError):
        valid = False
        content_bytes = b''
    if not valid or len(content_bytes) > 512 * 1024 or type(data['revision']) is not int:
        return 'invalid'
    return 'ok'


def body(notes='', directories=(), command_sets=(), revision=0, **extra):
    value = {'revision': revision, 'notes': notes, 'directories': list(directories),
             'command_sets': list(command_sets)}
    value.update(extra)
    return json.dumps(value, ensure_ascii=False)


CASES = [
    ('empty', body()),
    ('notes', body('Private deployment notes\n\twith "quotes" and \\ and \x01 and ü 🚀')),
    ('notes-limit', body('n' * 100000)),
    ('notes-over-limit', body('n' * 100001)),
    ('notes-astral-limit', body('🚀' * 100000)),
    ('dirs', body(directories=['/var/log', '/etc', '/home/ü/Dokumente'])),
    ('dirs-20', body(directories=['/d%d' % i for i in range(20)])),
    ('dirs-21', body(directories=['/d%d' % i for i in range(21)])),
    ('dirs-duplicate', body(directories=['/a', '/a'])),
    ('dirs-relative', body(directories=['var/log'])),
    ('dirs-empty', body(directories=[''])),
    ('dirs-root', body(directories=['/'])),
    ('dirs-space', body(directories=['/my files'])),
    ('dirs-nbsp', body(directories=['/a b'])),
    ('dirs-tab', body(directories=['/a\tb'])),
    ('dirs-newline', body(directories=['/a\nb'])),
    ('dirs-del', body(directories=['/a\x7fb'])),
    ('dirs-zero-width', body(directories=['/a​b'])),
    ('dirs-bidi', body(directories=['/a‮b'])),
    ('dirs-line-separator', body(directories=['/a b'])),
    ('dirs-private-use', body(directories=['/ab'])),
    ('dirs-4096-bytes', body(directories=['/' + 'a' * 4095])),
    ('dirs-4097-bytes', body(directories=['/' + 'a' * 4096])),
    ('dirs-multibyte-over', body(directories=['/' + 'ü' * 2048])),
    ('dirs-not-string', '{"revision": 0, "notes": "", "directories": [1], "command_sets": []}'),
    ('dirs-null', '{"revision": 0, "notes": "", "directories": null, "command_sets": []}'),
    ('dirs-object', '{"revision": 0, "notes": "", "directories": {}, "command_sets": []}'),
    ('sets', body(command_sets=['set-1', 'ü' * 128])),
    ('sets-129', body(command_sets=['s' * 129])),
    ('sets-empty-ref', body(command_sets=[''])),
    ('sets-duplicate', body(command_sets=['a', 'a'])),
    ('sets-21', body(command_sets=['s%d' % i for i in range(21)])),
    ('notes-not-string', '{"revision": 0, "notes": 5, "directories": [], "command_sets": []}'),
    ('notes-null', '{"revision": 0, "notes": null, "directories": [], "command_sets": []}'),
    ('revision-float', '{"revision": 1.0, "notes": "", "directories": [], "command_sets": []}'),
    ('revision-bool', '{"revision": true, "notes": "", "directories": [], "command_sets": []}'),
    ('revision-string', '{"revision": "1", "notes": "", "directories": [], "command_sets": []}'),
    ('revision-null', '{"revision": null, "notes": "", "directories": [], "command_sets": []}'),
    ('revision-negative', body(revision=-3)),
    ('revision-exponent', '{"revision": 1e2, "notes": "", "directories": [], "command_sets": []}'),
    ('revision-huge', '{"revision": 123456789012345678901234567890, "notes": "", "directories": [], "command_sets": []}'),
    ('missing-member', '{"revision": 0, "notes": "", "directories": []}'),
    ('extra-member', body(extra=1)),
    ('array', '[]'),
    ('string', '"x"'),
    ('broken', '{"revision": 0,'),
    ('content-at-limit', body('\x01' * 80000, directories=['/%d' % i + '\\' * 1000 for i in range(20)])),
    ('content-over-512k', body('\x01' * 90000)),
]


def sizes():
    contents = [
        {'notes': '', 'directories': [], 'command_sets': []},
        {'notes': 'a "b" \\ \n\t\x01 ü 🚀 \x7f', 'directories': ['/x', '/ü y'], 'command_sets': ['s1', 'ß']},
        {'notes': 'x' * 50, 'directories': ['/' + 'd' * 40], 'command_sets': []},
    ]
    out = []
    for content in contents:
        document = {'version': 1, 'hosts': {}}
        for index in range(3):
            document['hosts']['profile-%d-ü' % index] = {**content, 'revision': 10 ** index}
        out.append({
            'content': content,
            'content_size': len(json.dumps(content, ensure_ascii=False).encode('utf-8')),
            'document_size': len(json.dumps(document, ensure_ascii=False).encode('utf-8')),
            'empty_document_size': len(json.dumps({'version': 1, 'hosts': {}}, ensure_ascii=False).encode()),
        })
    return out


if __name__ == '__main__':
    corpus = {
        'cases': [{'name': n, 'body': b, 'decision': decide(b)} for n, b in CASES],
        'sizes': sizes(),
    }
    Path(sys.argv[1]).write_text(json.dumps(corpus, indent=1, ensure_ascii=False) + '\n')
