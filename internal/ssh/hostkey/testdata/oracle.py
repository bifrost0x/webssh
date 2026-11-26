"""Record how the Python host key store parses, matches and manages known_hosts.

Writes a corpus with the expected results so the Go tests replay it without
Python. Run from the repository root with the project virtual environment:

    WS=$PWD .venv/bin/python -I internal/ssh/hostkey/testdata/oracle.py \
        internal/ssh/hostkey/testdata/oracle.json
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
os.environ['DATA_DIR'] = tempfile.mkdtemp(prefix='hostkey-oracle-')

import paramiko  # noqa: E402
from cryptography.hazmat.primitives import serialization as ser  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa  # noqa: E402

from app.host_key_store import (  # noqa: E402
    HostKeyStore, RevokedHostKeyError, _LayeredHostKeys, _ParsedHostKeyFile,
)


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
    'ec384': pkey(ec.generate_private_key(ec.SECP384R1())),
    'rsaD': pkey(rsa.generate_private_key(65537, 2048)),
}


def line(hosts, name, marker=None):
    k = KEYS[name]
    parts = ([marker] if marker else []) + [hosts, k.get_name(), k.get_base64()]
    return ' '.join(parts)


def hashed(host, salt=None):
    salt = salt or os.urandom(20)
    digest = hmac.new(salt, host.encode(), hashlib.sha1).digest()
    return '|1|%s|%s' % (base64.b64encode(salt).decode(), base64.b64encode(digest).decode())


def parse(text):
    if text is None:
        return _ParsedHostKeyFile(), None
    try:
        return HostKeyStore._parse_raw(text.encode('utf-8')), None
    except paramiko.SSHException as exc:
        return None, str(exc)


def outcome(layered, hostname, key):
    keys = layered.lookup(hostname)
    if keys is None:
        return 'revoked' if layered.is_revoked(hostname, key) else 'unknown'
    ours = keys.get(key.get_name())
    if ours is None:
        if layered.is_revoked(hostname, key):
            return 'revoked'
        return 'changed_after_prompt'
    return 'trusted' if ours == key else 'changed'


def listing(text, scope, owner):
    if text is None:
        return []
    out = []
    for raw_line in text.encode('utf-8').splitlines():
        try:
            e = HostKeyStore._management_entry(raw_line, scope=scope, owner_id=owner, timestamp=None)
        except paramiko.SSHException as exc:
            return {'error': str(exc)}
        if e is not None:
            out.append({k: e[k] for k in ('id', 'host', 'port', 'hosts', 'marker', 'algorithm', 'fingerprint')})
    return out


def case(name, user=None, glob=None, hostnames=(), presented=()):
    user_file, user_err = parse(user)
    glob_file, glob_err = parse(glob)
    result = {'name': name, 'user': user, 'global': glob,
              'user_error': user_err, 'global_error': glob_err,
              'user_list': listing(user, 'user', 3) if user_err is None else None,
              'global_list': listing(glob, 'global', None) if glob_err is None else None,
              'lookups': []}
    if user_err or glob_err:
        return result
    layered = _LayeredHostKeys(glob_file, user_file)
    for hostname in hostnames:
        keys = layered.lookup(hostname)
        entry = {
            'hostname': hostname,
            'effective': None if keys is None else [
                [t, keys[t].get_base64()] for t in keys.keys()],
            'outcomes': {},
        }
        for kname in presented:
            entry['outcomes'][kname] = outcome(layered, hostname, KEYS[kname])
        result['lookups'].append(entry)
    return result


def build():
    ed, ed2, ecc, rs = 'edA', 'edB', 'ecC', 'rsaD'
    every = ('edA', 'edB', 'ecC', 'ec384', 'rsaD')
    cases = []
    add = cases.append
    add(case('plain', user=line('host.test', ed) + '\n', hostnames=['host.test', 'HOST.test', 'other.test'], presented=every))
    add(case('port', user=line('[host.test]:2222', ecc) + '\n',
             hostnames=['[host.test]:2222', 'host.test', '[host.test]:22', '[HOST.TEST]:2222'], presented=every))
    add(case('multi-host', user=line('a.test,b.test,10.0.0.1', rs) + '\n',
             hostnames=['a.test', 'b.test', '10.0.0.1', 'c.test'], presented=every))
    add(case('wildcard', glob=line('*.lab.test', ed) + '\n' + line('db?.lab.test', ecc) + '\n',
             hostnames=['x.lab.test', 'db1.lab.test', 'db12.lab.test', 'lab.test', 'X.LAB.TEST', 'a.b.lab.test'], presented=every))
    add(case('negation', glob=line('*.lab.test,!secret.lab.test', ed) + '\n',
             hostnames=['x.lab.test', 'secret.lab.test', 'SECRET.lab.test'], presented=every))
    h = hashed('hashed.test')
    hp = hashed('[hashed.test]:2200')
    add(case('hashed', user=line(h, ed) + '\n' + line(hp, ecc) + '\n',
             hostnames=['hashed.test', 'HASHED.test', '[hashed.test]:2200', 'other.test'], presented=every))
    hu = hashed('Upper.Test')
    add(case('hashed-upper', user=line(hu, ed) + '\n', hostnames=['Upper.Test', 'upper.test', 'UPPER.TEST'], presented=every))
    add(case('negated-hashed', glob=line('*.test,!' + hashed('no.test'), ed) + '\n',
             hostnames=['no.test', 'yes.test'], presented=every))
    add(case('user-first', user=line('h.test', ed) + '\n', glob=line('h.test', ed2) + '\n' + line('h.test', ecc) + '\n',
             hostnames=['h.test'], presented=every))
    add(case('first-entry-wins', user=line('h.test', ed) + '\n' + line('h.test', ed2) + '\n',
             hostnames=['h.test'], presented=every))
    add(case('revoked-global', user=line('h.test', ed) + '\n', glob=line('h.test', ed, '@revoked') + '\n',
             hostnames=['h.test'], presented=every))
    add(case('revoked-falls-through', user=line('h.test', ed) + '\n',
             glob=line('h.test', ed, '@revoked') + '\n' + line('h.test', ed2) + '\n',
             hostnames=['h.test'], presented=every))
    add(case('revoked-other-host', glob=line('x.test', ed, '@revoked') + '\n', user=line('h.test', ed) + '\n',
             hostnames=['h.test', 'x.test'], presented=every))
    add(case('revoked-wildcard', glob=line('*.test', rs, '@revoked') + '\n', user=line('h.test', ed) + '\n',
             hostnames=['h.test', 'z.test'], presented=every))
    add(case('cert-authority-ignored', glob='@cert-authority *.test ' + KEYS[ed].get_name() + ' ' + KEYS[ed].get_base64() + '\n',
             hostnames=['h.test'], presented=every))
    add(case('comments-blank-crlf', user='# comment\r\n\r\n   \r\n' + line('h.test', ed) + ' trailing comment here\r\n\t' + line('i.test', ecc) + '\n',
             hostnames=['h.test', 'i.test'], presented=every))
    add(case('tabs', user=KEYS[ed].get_name().join(['h.test\t', '\t']) + KEYS[ed].get_base64() + '\n',
             hostnames=['h.test'], presented=every))
    add(case('no-trailing-newline', user=line('h.test', ed), hostnames=['h.test'], presented=every))
    add(case('formfeed-in-line', user=line('h.test', ed) + '\x0c\n', hostnames=['h.test'], presented=every))
    add(case('golden-like', user=line('pw.golden.test', ed) + '\n' + line('[uni.golden.test]:2222', ecc) + '\n',
             glob=line('bastion.golden.test', ed) + '\n' + line('compromised.golden.test', rs, '@revoked') + '\n',
             hostnames=['pw.golden.test', '[uni.golden.test]:2222', 'bastion.golden.test', 'compromised.golden.test', 'key.golden.test'],
             presented=every))
    # Malformed input: the whole file must be rejected the same way.
    add(case('bad-marker', user='@foo h.test ' + KEYS[ed].get_name() + ' ' + KEYS[ed].get_base64() + '\n'))
    add(case('too-few-fields', user='h.test ssh-ed25519\n'))
    add(case('bad-base64', user='h.test ssh-ed25519 !!!notbase64\n'))
    add(case('type-mismatch', user='h.test ssh-rsa ' + KEYS[ed].get_base64() + '\n'))
    add(case('unknown-type', user='h.test ssh-foo ' + KEYS[ed].get_base64() + '\n'))
    add(case('dss-line', user='h.test ssh-dss AAAAB3NzaC1kc3MAAACBAP' + 'A' * 40 + '\n'))
    add(case('empty-host', user='a.test,,b.test ' + KEYS[ed].get_name() + ' ' + KEYS[ed].get_base64() + '\n'))
    add(case('bad-hash', user='|1|abc|def ' + KEYS[ed].get_name() + ' ' + KEYS[ed].get_base64() + '\n'))
    add(case('invalid-utf8-free', user=line('hé.test', ed) + '\n', hostnames=['hé.test', 'HÉ.test'], presented=every))
    add(case('base64-noise', user='h.test ' + KEYS[ed].get_name() + ' ' + KEYS[ed].get_base64()[:20] + '*' + KEYS[ed].get_base64()[20:] + '\n',
             hostnames=['h.test'], presented=every))
    rsa_b64 = KEYS[rs].get_base64()
    add(case('rsa-sha2-type-string', user='h.test rsa-sha2-256 ' + rsa_b64 + '\n', hostnames=['h.test'], presented=every))
    add(case('ecdsa-curve-mismatch', user='h.test ecdsa-sha2-nistp384 ' + KEYS[ecc].get_base64() + '\n', hostnames=['h.test'], presented=every))
    add(case('rsa-cert-type-string', user='h.test ssh-rsa-cert-v01@openssh.com ' + rsa_b64 + '\n', hostnames=['h.test'], presented=every))
    add(case('ec384', user=line('h.test', 'ec384') + '\n', hostnames=['h.test'], presented=every))
    return cases


def base64_vectors():
    import binascii
    import random
    rng = random.Random(7)
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    noise = '=*!. -_\x00'
    inputs = ['', 'QQ', 'QQ=', 'QQ==', 'QQ===', 'QUI=', 'QUJD', 'QUJD=', 'QUJDRA', 'QUJDRA==', 'QQ==QUJD',
              'Q', 'QUJDR', 'QU=JD', '=QUJD', 'QU*JD', 'QUJD\nRA==', 'QUJD====', 'QUJDRA=x']
    for _ in range(400):
        n = rng.randint(0, 14)
        inputs.append(''.join(rng.choice(alphabet + noise if rng.random() < .3 else alphabet) for _ in range(n)))
    out = []
    for text in inputs:
        try:
            out.append({'in': text, 'out': base64.b64encode(base64.decodebytes(text.encode('latin-1'))).decode()})
        except (binascii.Error, ValueError) as exc:
            out.append({'in': text, 'error': str(exc)})
    return out


def recorded_lines():
    out = []
    for name, key in KEYS.items():
        for host in ('h.test', '[h.test]:2222'):
            out.append({'key': name, 'hostname': host,
                        'line': paramiko.hostkeys.HostKeyEntry([host], key).to_line(),
                        'fingerprint': key.fingerprint})
    return out


TARGETS = [
    {'id': 'p1', 'name': 'Plain', 'kind': 'ssh', 'host': 'h.test', 'port': 22},
    {'id': 'p2', 'name': 'Port', 'kind': 'ssh', 'host': 'h.test', 'port': 2222},
    {'id': 'p3', 'name': 'Wild', 'kind': 'ssh', 'host': 'x.lab.test', 'port': None},
    {'id': 'j1', 'name': 'Bastion', 'kind': 'jump', 'host': 'bastion.test', 'port': 22},
    {'id': 'p4', 'name': 'Other', 'kind': 'ssh', 'host': 'other.test', 'port': 22},
]


def store_case(name, user=None, glob=None, records=()):
    """Drive a real HostKeyStore on temporary files."""
    work = Path(tempfile.mkdtemp(prefix='hostkey-store-'))
    gpath, users = work / 'known_hosts', work / 'users'
    upath = users / 'user_3' / 'known_hosts'
    upath.parent.mkdir(parents=True)

    def reset():
        for path, text in ((gpath, glob), (upath, user)):
            if text is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(text.encode('utf-8'))

    reset()
    store = HostKeyStore(3, gpath, users)
    out = {'name': name, 'user': user, 'global': glob, 'targets': TARGETS,
           'effective': store.effective_targets(TARGETS), 'impacts': [], 'deletes': [], 'records': []}
    entries = store.list_entries()
    for entry in entries:
        impact = store.deletion_impact(entry['id'], TARGETS)
        out['impacts'].append({'id': entry['id'], 'targets': impact['targets'], 'unresolved': impact['unresolved']})
    for entry_id in [e['id'] for e in entries] + ['f' * 64, 'xyz']:
        reset()
        removed = store.delete_entry(entry_id)
        out['deletes'].append({'id': entry_id, 'ok': removed,
                               'raw': upath.read_bytes().decode('utf-8') if upath.exists() else None})
    for hostname, key in records:
        reset()
        try:
            store.record(hostname, KEYS[key])
            result = 'ok'
        except RevokedHostKeyError:
            result = 'revoked'
        except paramiko.BadHostKeyException:
            result = 'changed'
        out['records'].append({'hostname': hostname, 'key': key, 'result': result,
                               'raw': upath.read_bytes().decode('utf-8') if upath.exists() else None})
    return out


def store_cases():
    ed, ed2, ecc, rs = 'edA', 'edB', 'ecC', 'rsaD'
    recs = [('h.test', ed), ('h.test', ed2), ('h.test', ecc), ('[h.test]:2222', ed), ('new.test', rs),
            ('x.lab.test', ed2), ('bastion.test', ed)]
    return [
        store_case('empty', records=recs),
        store_case('user-and-global',
                   user=line('h.test', ed) + '\n' + line('[h.test]:2222', ecc) + '\n',
                   glob=line('*.lab.test', ed) + '\n' + line('bastion.test', rs) + '\n' + line('h.test', ed2) + '\n',
                   records=recs),
        store_case('revocations',
                   user=line('h.test', ed) + '\n' + line('h.test,x.lab.test', ed2, '@revoked') + '\n',
                   glob=line('h.test', ed, '@revoked') + '\n' + line('h.test', ecc) + '\n',
                   records=recs),
        store_case('wildcards-and-hashes',
                   user='# kept comment\r\n' + line('*.lab.test,!secret.lab.test', ecc) + '\r\n'
                        + line(hashed('bastion.test'), ed) + '\n\n' + line('h.test,other.test', rs),
                   records=recs),
        store_case('duplicate-lines',
                   user=line('h.test', ed) + '\n' + line('h.test', ed) + '\n' + line('other.test', ecc) + '\n',
                   records=recs),
    ]


if __name__ == '__main__':
    data = {
        'paramiko': paramiko.__version__,
        'keys': {n: {'type': k.get_name(), 'base64': k.get_base64(), 'fingerprint': k.fingerprint}
                 for n, k in KEYS.items()},
        'cases': build(),
        'recorded': recorded_lines(),
        'base64': base64_vectors(),
        'stores': store_cases(),
    }
    Path(sys.argv[1]).write_text(json.dumps(data, indent=1, ensure_ascii=False) + '\n')
