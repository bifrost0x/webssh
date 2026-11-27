"""Record the copy and conflict rules of the Python release as test vectors.

Usage (from the repository root, with the project virtual environment):

    SECRET_KEY=$(openssl rand -hex 32) DATA_DIR=$(mktemp -d) \
        .venv/bin/python -I internal/transfer/testdata/python_conflicts.py . \
        internal/transfer/testdata/python_conflicts.json

app/remote_transfer.py and app/transfer_errors.py are loaded unchanged
from the given checkout. The file sources are in memory and follow the
rules of the SFTP backend that matter here: a writer without replace
refuses an existing name (CONFLICT), a writer with replace refuses a
directory or a link (ATOMIC_REPLACE_UNAVAILABLE), a missing parent is
NOT_FOUND, links are reported and never followed. Every combination of
source entry, destination state, conflict policy and limit is copied;
the vector holds the public failure code and the destination tree after.
"""

import errno
import io
import json
import pathlib
import posixpath
import sys
from contextlib import contextmanager

root = pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root))

from app import remote_transfer, sftp_handler  # noqa: E402
from app.file_backend import FileReaderLease  # noqa: E402
from app.transfer_errors import classify_transfer_failure  # noqa: E402


class Tree:
    """path -> ('dir', None) | ('file', bytes) | ('link', target)"""

    def __init__(self, spec):
        self.nodes = {'/': ('dir', None)}
        for path, node in spec.items():
            parts = path.strip('/').split('/')
            for i in range(1, len(parts)):
                self.nodes.setdefault('/' + '/'.join(parts[:i]), ('dir', None))
            self.nodes[path] = node

    def children(self, directory):
        return sorted(p for p in self.nodes if p != '/' and posixpath.dirname(p) == directory)


class Backend:
    def __init__(self, tree):
        self.tree = tree

    def normalize_path(self, path):
        if not isinstance(path, str) or not path.startswith('/'):
            return None
        return posixpath.normpath(path)

    def _stat(self, path):
        node = self.tree.nodes.get(path)
        if node is None:
            raise FileNotFoundError(errno.ENOENT, 'missing')
        kind, value = node
        return {
            'name': posixpath.basename(path), 'path': path,
            'size': len(value) if kind == 'file' else 0,
            'is_dir': kind == 'dir', 'is_symlink': kind == 'link',
        }

    def stat_or_raise(self, source, path, *, follow_links=False):
        return self._stat(path)

    def check_exists_or_raise(self, source, path):
        try:
            st = self._stat(path)
        except FileNotFoundError:
            return {'exists': False, 'is_dir': False, 'size': 0}
        return {'exists': True, 'is_dir': st['is_dir'], 'size': st['size']}

    def mkdir_or_raise(self, source, path):
        if path in self.tree.nodes:
            raise FileExistsError(errno.EEXIST, 'exists')
        parent = self.tree.nodes.get(posixpath.dirname(path))
        if parent is None or parent[0] != 'dir':
            raise FileNotFoundError(errno.ENOENT, 'missing parent')
        self.tree.nodes[path] = ('dir', None)

    @contextmanager
    def open_reader(self, source, path, *, io_lane='control', _expected_identities=None):
        kind, value = self.tree.nodes[path]
        if kind != 'file':
            raise IsADirectoryError(errno.EISDIR, 'not a file')
        yield FileReaderLease(reader=io.BytesIO(value), size=len(value))

    @contextmanager
    def open_atomic_writer(self, source, path, *, replace, cancel_event, io_lane='control'):
        parent = self.tree.nodes.get(posixpath.dirname(path))
        if parent is None or parent[0] != 'dir':
            raise FileNotFoundError(errno.ENOENT, 'missing parent')
        existing = self.tree.nodes.get(path)
        if existing is not None and not replace:
            raise FileExistsError(errno.EEXIST, 'exists')
        if existing is not None and existing[0] != 'file':
            raise sftp_handler.AtomicOverwriteUnavailable('atomic replacement is unavailable')
        buffer = io.BytesIO()
        yield buffer
        self.tree.nodes[path] = ('file', buffer.getvalue())

    def iter_tree(self, source, path, *, budget, cancel_event, follow_links=False, io_lane='control',
                  _expected_identities=None):
        def walk(directory):
            for child in self.tree.children(directory):
                budget.consume()
                st = self._stat(child)
                yield st
                if st['is_dir'] and not st['is_symlink']:
                    yield from walk(child)
        return walk(path)


class Source:
    def __init__(self, source_id, tree):
        self.source_id = source_id
        self.backend = Backend(tree)


SOURCE = {
    '/src/file.txt': ('file', b'hello'),
    '/src/dir/a.txt': ('file', b'a'),
    '/src/dir/sub/b.txt': ('file', b'bb'),
    '/src/dir/empty': ('dir', None),
    '/src/link': ('link', '/src/file.txt'),
    '/src/linkdir/ok.txt': ('file', b'ok'),
    '/src/linkdir/zz': ('link', '/src/file.txt'),
}

DESTINATIONS = {
    'absent': {'/dst/keep': ('file', b'k')},
    'file': {'/dst/x': ('file', b'old')},
    'empty_dir': {'/dst/x': ('dir', None)},
    'dir_with_file': {'/dst/x/a.txt': ('file', b'old')},
    'dir_with_sub_file': {'/dst/x/sub': ('file', b'old')},
    'dir_with_a_dir': {'/dst/x/a.txt': ('dir', None)},
    'link': {'/dst/x': ('link', '/dst/keep'), '/dst/keep': ('file', b'k')},
    'no_parent': {'/dst/keep': ('file', b'k')},
}

ENTRIES = ['/src/file.txt', '/src/dir', '/src/link', '/src/linkdir', '/src/missing']
LIMITS = {'normal': (1000, 100), 'bytes': (3, 100), 'members': (1000, 2)}


def dump(tree):
    out = []
    for path in sorted(tree.nodes):
        kind, value = tree.nodes[path]
        if kind == 'file':
            out.append(f'{path} file {value.decode()}')
        elif kind == 'link':
            out.append(f'{path} link {value}')
        else:
            out.append(f'{path} dir')
    return out


def run(source, source_path, destination, destination_path, policy, limit):
    budget = remote_transfer.TransferBudget(max_bytes=limit[0], max_members=limit[1])
    try:
        remote_transfer.copy_remote_entry(source, source_path, destination, destination_path, policy, budget,
                                          None, None, chunk_size=4)
        return 'OK'
    except Exception as error:  # every failure is classified like the handler did
        return classify_transfer_failure(error, operation='remote_transfer').code


vectors = []
for entry in ENTRIES:
    for dest_name, dest_spec in DESTINATIONS.items():
        for policy in ('error', 'replace'):
            for limit_name, limit in LIMITS.items():
                source = Source('sftp-session:a', Tree(SOURCE))
                destination = Source('smb-quick:b', Tree(dest_spec))
                target = '/nope/x' if dest_name == 'no_parent' else '/dst/x'
                code = run(source, entry, destination, target, policy, limit)
                vectors.append({
                    'source': entry, 'destination': dest_name, 'target': target, 'policy': policy,
                    'limit': limit_name, 'code': code, 'tree': dump(destination.backend.tree),
                })

# One source to itself: the same path is refused, another path is a copy.
for target in ('/src/file.txt', '/src/copy.txt', '/src/dir', '/src/dir/sub'):
    for policy in ('error', 'replace'):
        tree = Tree(SOURCE)
        source = Source('sftp-session:a', tree)
        entry = '/src/dir' if target.startswith('/src/dir') else '/src/file.txt'
        code = run(source, entry, source, target, policy, LIMITS['normal'])
        vectors.append({'source': entry, 'destination': 'same', 'target': target, 'policy': policy,
                        'limit': 'normal', 'code': code, 'tree': dump(tree)})

# Content-Disposition of downloads (_content_disposition). Accented letters
# are left out: Python kept their base letter (NFKD), Go drops them.
from app.transfer_routes import _content_disposition  # noqa: E402

NAMES = ['plain.txt', 'two words.tar.gz', 'a"b;c\\d.txt', '日本語.txt', '日本', 'x~y-z_1.0', '%41.txt',
         "quote'n<tag>.html", 'emoji \U0001f600.png', '', 'dir/inner.txt', '.hidden', 'Ä']
dispositions = {name: _content_disposition(name) for name in NAMES if name != 'Ä'}

doc = {
    'dispositions': dispositions,
    'source': {k: [v[0], v[1].decode() if isinstance(v[1], bytes) else v[1]] for k, v in SOURCE.items()},
    'destinations': {k: {p: [v[0], v[1].decode() if isinstance(v[1], bytes) else v[1]] for p, v in s.items()}
                     for k, s in DESTINATIONS.items()},
    'limits': LIMITS,
    'vectors': vectors,
}
pathlib.Path(sys.argv[2]).write_text(json.dumps(doc, indent=1, sort_keys=True) + '\n')
