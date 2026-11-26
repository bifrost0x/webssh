"""Compare two generator outputs, allowing only documented differences.

Usage::

    python -m tests.golden.compare OUT_A OUT_B

Exit status 0 means: every data archive member and every backup member is
identical (app.db compared as a sorted-schema dump), and manifest.json differs only where it records
non-deterministic values (see manifest ``nondeterministic``).
"""

import hashlib
import json
import sqlite3
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

_DATABASE = 'app.db'


def database_dump(path):
    """Schema statements sorted, rows in order.

    SQLAlchemy emits CREATE INDEX in set order of Index objects, which hash by
    identity, so the schema order in the file is not reproducible.
    """
    connection = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
    try:
        lines = list(connection.iterdump())
    finally:
        connection.close()
    schema = sorted(line for line in lines if line.startswith('CREATE'))
    rows = [line for line in lines if not line.startswith('CREATE')]
    return schema, rows


def _content_digest(name, data):
    if name == 'manifest.json':
        document = json.loads(data)
        for entry in document['files']:
            if entry['path'] == _DATABASE:
                entry.pop('sha256')
                entry.pop('size')
        return document
    if Path(name).name != _DATABASE:
        return hashlib.sha256(data).hexdigest()
    with tempfile.TemporaryDirectory() as work:
        path = Path(work) / _DATABASE
        path.write_bytes(data)
        return database_dump(path)


def _tar_members(path):
    with tarfile.open(path) as archive:
        result = {}
        for info in archive.getmembers():
            content = None
            if info.isfile():
                content = _content_digest(info.name, archive.extractfile(info).read())
            result[info.name] = (info.type, info.mode, info.mtime, content)
        return result


def _files(root):
    return {p.relative_to(root).as_posix(): p for p in root.rglob('*') if p.is_file()}


def _zip_members(path):
    with zipfile.ZipFile(path) as archive:
        return {info.filename: _content_digest(info.filename, archive.read(info))
                for info in archive.infolist()}


def _normalized_manifest(path):
    document = json.loads(path.read_text(encoding='utf-8'))
    if document.get('format') == 'webssh-golden-legacy-data-set':
        for entry in document['files']:
            entry.pop('sha256')
            entry.pop('size')
        for backup in document['backups'].values():
            for entry in backup.get('values', backup)['files']:
                if Path(entry['path']).name == _DATABASE:
                    entry.pop('sha256')
                    entry.pop('size')
        return document
    for entry in document['values']['ssh_keys']['rejected']:
        if not entry['deterministic']:
            entry.pop('plaintext_b64')
    for entry in document['files']:
        if not entry['deterministic']:
            entry.pop('sha256')
            entry.pop('size')
    for backup in document['values']['backups'].values():
        for entry in backup['files']:
            if Path(entry['path']).name == _DATABASE:
                entry.pop('sha256')
                entry.pop('size')
    return document


def compare(first, second):
    problems = []
    a, b = _files(first), _files(second)
    if set(a) != set(b):
        problems.append(f'file sets differ: {sorted(set(a) ^ set(b))}')
    for name in sorted(set(a) & set(b)):
        if Path(name).name == 'manifest.json':
            if _normalized_manifest(a[name]) != _normalized_manifest(b[name]):
                problems.append(f'{name} differs beyond documented fields')
            continue
        if name.endswith('.tar'):
            if _tar_members(a[name]) != _tar_members(b[name]):
                problems.append(f'data archive members differ: {name}')
        elif name.endswith('.zip'):
            if _zip_members(a[name]) != _zip_members(b[name]):
                problems.append(f'backup members differ: {name}')
        elif Path(name).name == _DATABASE:
            if database_dump(a[name]) != database_dump(b[name]):
                problems.append(f'database content differs: {name}')
        elif a[name].read_bytes() != b[name].read_bytes():
            problems.append(f'file differs: {name}')
    return problems


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        print(__doc__)
        return 2
    problems = compare(Path(args[0]), Path(args[1]))
    for problem in problems:
        print(problem)
    print('identical within documented non-determinism' if not problems
          else f'{len(problems)} difference(s)')
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
