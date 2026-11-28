"""Record how app/editor_text.py encodes editor text (FS1 oracle).

Run from the repository root with the venv in $WEBSSH_PYTHON_ROOT:
    $WEBSSH_PYTHON_ROOT/.venv/bin/python internal/files/testdata/oracle_editor.py > internal/files/testdata/encode-vectors.json
"""

import base64
import importlib.util
import json
import os
import pathlib
import random
import sys

# The Python release, a worktree of it (scripts/record-python-oracles.sh).
root = pathlib.Path(os.environ['WEBSSH_PYTHON_ROOT'])
spec = importlib.util.spec_from_file_location('editor_text', root / 'app' / 'editor_text.py')
editor_text = importlib.util.module_from_spec(spec)
spec.loader.exec_module(editor_text)


def b64(data):
    return base64.b64encode(data).decode('ascii')


def case(content, encoding, newline, original):
    out = {
        'content': content,
        'encoding': encoding,
        'newline': newline,
        'original': None if original is None else b64(original),
    }
    try:
        out['bytes'] = b64(editor_text.encode_editor_text(
            content, encoding=encoding, newline=newline, original=original))
    except editor_text.EditorEncodingError as error:
        out['error'] = {'character': error.character, 'line': error.line}
    except ValueError:
        out['error'] = {'value': True}
    return out


def mixed_file(rng, lines, vocabulary):
    parts = []
    for _ in range(lines):
        parts.append(rng.choice(vocabulary) + rng.choice(['\n', '\r\n']))
    if rng.random() < 0.5:
        parts.append(rng.choice(vocabulary))
    return ''.join(parts)


def edit(rng, text, vocabulary):
    lines = text.replace('\r\n', '\n').split('\n')
    for _ in range(rng.randint(0, 6)):
        op = rng.random()
        index = rng.randint(0, len(lines))
        if op < 0.35:
            lines.insert(index, rng.choice(vocabulary))
        elif op < 0.65 and lines:
            del lines[min(index, len(lines) - 1)]
        elif lines:
            lines[min(index, len(lines) - 1)] = rng.choice(vocabulary)
    return '\n'.join(lines)


cases = [
    case('a\nb\n', 'utf-8', 'lf', None),
    case('a\r\nb\n', 'utf-8', 'lf', None),
    case('a\nb\n', 'utf-8', 'crlf', None),
    case('a\rb\n', 'utf-8', 'crlf', None),
    case('café\n', 'latin-1', 'lf', None),
    case('snow ☃\nline', 'latin-1', 'lf', None),
    case('x\n€', 'latin-1', 'crlf', None),
    case('x', 'utf-16', 'lf', None),
    case('x', 'utf-8', 'weird', None),
    case('a\nb\n', 'utf-8', 'mixed', None),
    case('a\nb\nc\n', 'utf-8', 'mixed', b'a\r\nb\nc\r\n'),
    case('a\nX\nb\nc\n', 'utf-8', 'mixed', b'a\r\nb\nc\r\n'),
    case('a\nc\n', 'utf-8', 'mixed', b'a\r\nb\nc\r\n'),
    case('', 'utf-8', 'mixed', b'a\r\nb\n'),
    case('new\n', 'utf-8', 'mixed', b''),
    case('a\nb', 'utf-8', 'mixed', b'a\r\nb\n'),
    case('a\nb\nc\nd', 'latin-1', 'mixed', b'a\r\n\xe9\nc\r\n'),
    case('é\né\r\n', 'latin-1', 'mixed', b'\xe9\r\n\xe9\n'),
]

rng = random.Random(20261127)
small = ['alpha', 'beta', 'gamma', '', 'delta', '  indented', 'x = 1', '}']
for _ in range(120):
    original = mixed_file(rng, rng.randint(0, 30), small)
    content = edit(rng, original, small + ['changed', 'new line'])
    cases.append(case(content, 'utf-8', 'mixed', original.encode('utf-8')))

# Many repeated lines: autojunk marks popular lines with 200 or more lines.
repeated = ['', '}', 'end', 'same', 'value %d']
for size in (199, 200, 250, 400, 900):
    vocabulary = [line % rng.randint(0, 40) if '%' in line else line for line in repeated * 3]
    original = mixed_file(rng, size, vocabulary)
    for _ in range(3):
        content = edit(rng, original, vocabulary + ['changed'])
        cases.append(case(content, 'utf-8', 'mixed', original.encode('utf-8')))
        shorter = '\n'.join(content.split('\n')[: size // 2])
        cases.append(case(shorter, 'utf-8', 'mixed', original.encode('utf-8')))

# Above the comparison bound the middle is mapped by position.
big = ''.join(f'line {i}' + ('\r\n' if i % 3 else '\n') for i in range(1600))
changed = '\n'.join(f'other {i}' for i in range(1500))
cases.append(case(changed, 'utf-8', 'mixed', big.encode('utf-8')))

json.dump(cases, sys.stdout, ensure_ascii=False, indent=0)
sys.stdout.write('\n')
