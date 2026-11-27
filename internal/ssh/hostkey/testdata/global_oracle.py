"""Record how the Python store adds and removes global known_hosts entries.

Writes a corpus with the expected results so the Go tests replay it without
Python. Run from the repository root with the project virtual environment:

    WS=$PWD .venv/bin/python -I internal/ssh/hostkey/testdata/global_oracle.py \
        internal/ssh/hostkey/testdata/global_oracle.json

HostKeyStore.add_file_entry and delete_file_entry run unchanged on a
temporary global file; the route's status rule (409 for "already" and
"different key", else 400) is applied as in app/host_key_routes.py.
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import tempfile
from pathlib import Path

WS = Path(os.environ['WS'])
sys.path.insert(0, str(WS))
os.environ.setdefault('SECRET_KEY', '0' * 64)
os.environ['DATA_DIR'] = tempfile.mkdtemp(prefix='hostkey-global-oracle-')

import paramiko  # noqa: E402
from cryptography.hazmat.primitives import serialization as ser  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa  # noqa: E402

from app.host_key_store import HostKeyStore  # noqa: E402


def pkey(private):
    pem = private.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.OpenSSH,
                                ser.NoEncryption()).decode()
    import io
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(pem))
        except paramiko.SSHException:
            continue
    raise RuntimeError('no key class')


KEYS = {
    'edA': pkey(ed25519.Ed25519PrivateKey.generate()),
    'edB': pkey(ed25519.Ed25519PrivateKey.generate()),
    'ecC': pkey(ec.generate_private_key(ec.SECP256R1())),
    'rsaD': pkey(rsa.generate_private_key(65537, 2048)),
}


def key(name):
    return KEYS[name].get_name() + ' ' + KEYS[name].get_base64()


def hashed(host, salt):
    digest = hmac.new(salt, host.encode(), hashlib.sha1).digest()
    return '|1|' + base64.b64encode(salt).decode() + '|' + base64.b64encode(digest).decode()


SALT = bytes(range(20))
HASHED = hashed('hashed.test', SALT)
BASE = '\n'.join([
    '# managed by the administrator',
    'web.test ' + key('edA') + ' comment',
    '[db.test]:2222 ' + key('ecC'),
    '@revoked old.test ' + key('edB'),
    '@cert-authority *.corp.test ' + key('rsaD'),
    HASHED + ' ' + key('edB'),
    '',
])

ADDS = [
    ('plain', None, 'new.test ' + key('edB')),
    ('with-comment', None, '  new.test ' + key('edB') + ' operator laptop  '),
    ('tabs', None, 'new.test\t' + key('edB')),
    ('port', None, '[new.test]:2200 ' + key('edA')),
    ('several-hosts', None, 'a.test,b.test,[c.test]:23 ' + key('rsaD')),
    ('negated', None, 'a.test,!b.test ' + key('edB')),
    ('wildcard', None, '*.lan ' + key('edB')),
    ('hashed', None, hashed('other.test', bytes(20)) + ' ' + key('edA')),
    ('revoked', None, '@revoked web.test ' + key('edA')),
    ('revoked-new', None, '@revoked new.test ' + key('edB')),
    ('cert-authority', None, '@cert-authority *.corp.test ' + key('edA')),
    ('unknown-marker', None, '@trusted new.test ' + key('edA')),
    ('duplicate', None, 'web.test ' + key('edA')),
    ('duplicate-case', None, 'WEB.test ' + key('edA')),
    ('duplicate-in-list', None, 'x.test,web.test ' + key('edA')),
    ('different-key', None, 'web.test ' + KEYS['edB'].get_name() + ' ' + KEYS['edB'].get_base64()),
    ('other-algorithm', None, 'web.test ' + key('ecC')),
    ('hashed-duplicate', None, HASHED + ' ' + key('edB')),
    ('hashed-different', None, HASHED + ' ' + key('edA')),
    ('port-differs', None, '[web.test]:2200 ' + key('edB')),
    ('empty', None, ''),
    ('spaces', None, '   '),
    ('newline', None, 'a.test ' + key('edA') + '\nb.test ' + key('edB')),
    ('carriage-return', None, 'a.test ' + key('edA') + '\r'),
    ('too-few-fields', None, 'a.test ' + KEYS['edA'].get_name()),
    ('bad-base64', None, 'a.test ssh-ed25519 AAAA$$$'),
    ('wrong-type-name', None, 'a.test ssh-rsa ' + KEYS['edA'].get_base64()),
    ('unknown-type', None, 'a.test ssh-dss ' + KEYS['edA'].get_base64()),
    ('bad-hash', None, '|1|abc|def ' + key('edA')),
    ('empty-pattern', None, 'a.test,,b.test ' + key('edA')),
    ('too-long', None, 'a.test ' + key('edA') + ' ' + 'x' * 16384),
    ('number', None, 42),
    ('null', None, None),
    ('list', None, ['a.test ' + key('edA')]),
    ('no-file', 'none', 'new.test ' + key('edA')),
    ('no-trailing-newline', 'web.test ' + key('edA'), 'new.test ' + key('edB')),
    ('empty-file', '', 'new.test ' + key('edB')),
    ('crlf-file', 'web.test ' + key('edA') + '\r\n', 'new.test ' + key('edB')),
]


def add_case(name, base, value):
    path = Path(tempfile.mkdtemp(prefix='global-')) / 'known_hosts'
    text = BASE if base is None else base
    if base != 'none':
        path.write_bytes(text.encode())
    entry, error = HostKeyStore.add_file_entry(
        path, value, scope='global', owner_id=None, lock_key='host_keys:global')
    after = path.read_bytes().decode() if path.exists() else None
    out = {'name': name, 'base': None if base == 'none' else text, 'value': value, 'after': after}
    if error:
        out['error'] = error
        out['status'] = 409 if 'already' in error or 'different key' in error else 400
    else:
        out['entry'] = {k: entry[k] for k in ('id', 'host', 'port', 'hosts', 'marker', 'algorithm',
                                              'fingerprint', 'scope', 'owner_id')}
    return out


def ids(text):
    path = Path(tempfile.mkdtemp(prefix='global-')) / 'known_hosts'
    path.write_bytes(text.encode())
    return [e['id'] for e in HostKeyStore.list_file(path, scope='global', owner_id=None)]


def delete_case(name, base, entry_id):
    path = Path(tempfile.mkdtemp(prefix='global-')) / 'known_hosts'
    if base is not None:
        path.write_bytes(base.encode())
    removed = HostKeyStore.delete_file_entry(
        path, entry_id, scope='global', owner_id=None, lock_key='host_keys:global')
    after = path.read_bytes().decode() if path.exists() else None
    return {'name': name, 'base': base, 'id': entry_id, 'removed': removed, 'after': after}


def build():
    listed = ids(BASE)
    crlf = 'a.test ' + key('edA') + '\r\nb.test ' + key('edB') + '\r\n'
    duplicate = 'a.test ' + key('edA') + '\nx.test ' + key('edB') + '\na.test ' + key('edA') + '\n'
    deletes = [delete_case('entry-%d' % i, BASE, entry_id) for i, entry_id in enumerate(listed)]
    deletes += [
        delete_case('crlf', crlf, ids(crlf)[0]),
        delete_case('same-line-twice', duplicate, ids(duplicate)[0]),
        delete_case('unknown', BASE, '0' * 64),
        delete_case('not-hex', BASE, listed[0].upper()),
        delete_case('short', BASE, listed[0][:63]),
        delete_case('no-file', None, listed[0]),
    ]
    return {
        'paramiko': paramiko.__version__,
        'list': HostKeyStore.list_file(_write(BASE), scope='global', owner_id=None),
        'adds': [add_case(*c) for c in ADDS],
        'deletes': deletes,
    }


def _write(text):
    path = Path(tempfile.mkdtemp(prefix='global-')) / 'known_hosts'
    path.write_bytes(text.encode())
    return path


if __name__ == '__main__':
    corpus = build()
    for item in corpus['list']:
        item.pop('first_seen')
        item.pop('last_seen')
    Path(sys.argv[1]).write_text(json.dumps(corpus, indent=1, ensure_ascii=False) + '\n')
