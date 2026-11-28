"""Record the saved-password rules of the Python release.

Writes a corpus with the expected results so the Go tests replay it without
Python. Run from the repository root with the venv in $WEBSSH_PYTHON_ROOT:

    WS=$WEBSSH_PYTHON_ROOT $WEBSSH_PYTHON_ROOT/.venv/bin/python -I internal/vault/testdata/credential_oracle.py \
        internal/vault/testdata/credential-oracle.json

The rules run unchanged: CredentialService._normalize_target, resources(),
credential_status(), the native branch of prepare_vault(), _binds_saved_secret
of credential_routes.py and the legacy vault decryption of automation_vault.py.
Only what lies outside them is replaced: the record loaders, the per-user
lock, the feature switch, the intent store and the account incarnation.
"""
import base64
import contextlib
import copy
import json
import os
import sys
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace

WS = Path(os.environ['WS'])
sys.path.insert(0, str(WS))
os.environ.setdefault('SECRET_KEY', '0' * 64)
os.environ['DATA_DIR'] = tempfile.mkdtemp(prefix='credential-oracle-')

from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt  # noqa: E402

import app.automation_vault as av  # noqa: E402
import app.credential_service as cs  # noqa: E402
from app.automation_store import AutomationError, profile_fingerprint  # noqa: E402
from app.credential_routes import _binds_saved_secret  # noqa: E402

USER = 7
INCARNATION = '2026-11-20T08:15:30.123456'


def code_of(function, *args):
    try:
        return {'ok': function(*args)}
    except AutomationError as error:
        return {'error': error.code}


# --- _normalize_target ------------------------------------------------------

TARGETS = [
    {'host': 'a.example', 'port': 22, 'username': 'root'},
    {'host': 'a.example', 'username': 'root', 'auth_type': 'password', 'key_id': None},
    {'host': 'a.example', 'port': 0, 'username': 'root'},
    {'host': 'a.example', 'port': 2222, 'username': 'root', 'jump_host_id': 'j1'},
    {'host': 'a.example', 'username': 'root', 'proxy_jump': {'jump_host_id': 'j1'}},
    {'host': 'a.example', 'username': 'root', 'jump_host_id': 'j2', 'proxy_jump': {'jump_host_id': 'j1'}},
    {'host': 'a.example', 'username': 'root', 'proxy_jump': {'jump_host_id': ''}},
    {'host': 'a.example', 'username': 'root', 'proxy_jump': 'j1'},
    {'host': 'a.example', 'username': 'root', 'socks_proxy_id': 's1'},
    {'host': 'a.example', 'username': 'root', 'socks_proxy': {'socks_proxy_id': 's1'}},
    {'host': 'a.example', 'username': 'root', 'socks_proxy_id': 's1', 'jump_host_id': 'j1'},
    {'host': 'a.example', 'username': 'root', 'socks_proxy_id': 's1', 'auth_type': 'tailscale'},
    {'host': 'a.example', 'username': 'root', 'jump_host_id': 5},
    {'host': 'a.example', 'username': 'root', 'jump_host_id': ''},
    {'host': 'p.example', 'username': 'u', 'kind': 'socks'},
    {'host': 'p.example', 'port': 1081, 'username': 'u', 'kind': 'socks', 'remote_dns': False},
    {'host': 'p.example', 'username': 'u', 'kind': 'socks', 'remote_dns': 'yes'},
    {'host': 'p.example', 'username': 'u', 'kind': 'socks', 'socks_proxy': {'socks_proxy_id': 's1'}},
    {'host': 'p.example', 'username': 'u', 'kind': 'socks', 'jump_host_id': 'j1'},
    {'host': 'p.example', 'username': 'u', 'auth_type': 'password', 'remote_dns': True},
    {'host': 'f.example', 'username': 'u', 'share': 'data'},
    {'host': 'f.example', 'username': 'u', 'share': 'data', 'domain': 'CORP', 'port': 4455},
    {'host': 'f.example', 'username': 'u', 'share': 'data', 'socks_proxy_id': 's1'},
    {'host': 'f.example', 'username': 'u', 'share': '', 'domain': 'CORP'},
    {'host': 'häst.example', 'username': 'Jürgen \U0001F600', 'port': 22.0},
    {},
]

normalize = [dict(target=t, **code_of(cs.CredentialService._normalize_target, copy.deepcopy(t))) for t in TARGETS]

# --- resources() and credential_status() ------------------------------------

PROFILES = [
    {'id': 'p1', 'name': 'Direct', 'host': 'a.example', 'port': 22, 'username': 'root', 'auth_type': 'password',
     'key_id': None, 'jump_host_id': None},
    {'id': 'p2', 'name': 'Jumped', 'host': 'b.example', 'port': 22, 'username': 'root', 'auth_type': 'password',
     'jump_host_id': 'j1'},
    {'id': 'p3', 'name': 'Proxied', 'host': 'c.example', 'port': 2222, 'username': 'admin', 'auth_type': 'password',
     'socks_proxy_id': 's1'},
    {'id': 'p4', 'name': 'Lost route', 'host': 'd.example', 'port': 22, 'username': 'root', 'auth_type': 'password',
     'jump_host_id': 'gone'},
    {'id': 'p5', 'name': 'Key', 'host': 'e.example', 'port': 22, 'username': 'root', 'auth_type': 'key',
     'key_id': 'k1'},
    {'id': 'dup', 'name': 'First', 'host': 'f.example', 'port': 22, 'username': 'x', 'auth_type': 'password'},
    {'id': 'dup', 'name': 'Second', 'host': 'g.example', 'port': 22, 'username': 'x', 'auth_type': 'password'},
    {'id': 'p6', 'host': 'u.example', 'port': 22, 'username': 'nö', 'auth_type': 'password'},
]
JUMPS = [
    {'id': 'j1', 'name': 'Bastion', 'host': 'bastion.example', 'port': 22, 'username': 'jump', 'auth_type': 'password',
     'key_id': None, 'created_at': '2026-11-01T00:00:00'},
]
PROXIES = [
    {'id': 's1', 'name': 'Proxy', 'host': 'proxy.example', 'port': 1080, 'username': 'sock', 'auth_type': 'password',
     'remote_dns': True},
    {'id': 's2', 'name': 'Local DNS', 'host': 'proxy2.example', 'port': 1081, 'username': None, 'auth_type': 'none',
     'remote_dns': False},
]
SHARES = [
    {'id': 'm1', 'name': 'Files', 'host': 'files.example', 'username': 'u', 'share': 'data', 'domain': 'CORP'},
    {'id': 'm2', 'name': 'Public', 'host': 'files.example', 'username': 'u', 'share': 'pub'},
]

cs.user_data_access = lambda user_id: contextlib.nullcontext()
cs.load_profiles = lambda user_id: copy.deepcopy(PROFILES)
cs.load_jump_hosts = lambda user_id: copy.deepcopy(JUMPS)
cs.load_socks_proxies = lambda user_id: copy.deepcopy(PROXIES)
cs.load_smb_shares = lambda user_id: copy.deepcopy(SHARES)

service = cs.CredentialService.__new__(cs.CredentialService)
service._lock = threading.RLock()
service._vault_mutations = threading.Lock()
resources = service.resources(USER)
fingerprints = [dict(id=r['id'], kind=r['kind'], fingerprint=profile_fingerprint(r),
                     route_fingerprint=r.get('route_fingerprint')) for r in resources]

ASSIGNED = {
    'p1': dict(credential_id='c1', fingerprint=profile_fingerprint(resources[0]), generation='g' * 64),
    'p2': dict(credential_id='c1', fingerprint='0' * 64, generation='g' * 64),
    'jump:j1': dict(credential_id='c2', fingerprint=next(profile_fingerprint(r) for r in resources if r['id'] == 'jump:j1'),
                    generation='g' * 64),
    'smb:m1': dict(credential_id='c2', fingerprint=next(profile_fingerprint(r) for r in resources if r['id'] == 'smb:m1'),
                   generation='g' * 64),
    'socks:s1': dict(credential_id='c2', fingerprint=next(profile_fingerprint(r) for r in resources if r['id'] == 'socks:s1'),
                     generation='g' * 64),
    'p3': dict(credential_id='gone', fingerprint='0' * 64, generation='g' * 64),
}
DOC = dict(version=1, credentials={
    'c1': dict(id='c1', name='One', username='', version='v' * 64, updated_at='x', ciphertext='AAAA'),
    'c2': dict(id='c2', name='Two', username='', version='w' * 64, updated_at='x', ciphertext='AAAA'),
}, assignments=ASSIGNED, imports=[])
service.named = SimpleNamespace(read=lambda uid: copy.deepcopy(DOC))


def named_assigned(uid, profile):
    doc = copy.deepcopy(DOC)
    assignment = doc['assignments'].get(profile['id'])
    if assignment is None:
        raise AutomationError('credential_missing')
    if assignment['fingerprint'] != profile_fingerprint(profile):
        raise AutomationError('credential_target_changed')
    if assignment['credential_id'] not in doc['credentials']:
        raise AutomationError('not_found')
    return assignment, doc['credentials'][assignment['credential_id']]


service.named.assigned = named_assigned
import app.app_settings as settings  # noqa: E402
settings.is_credentials_enabled = lambda: True
settings.credentials_policy_revision = lambda: 'rev'
statuses = {r['id']: service.credential_status(USER, r) for r in resources if r['id'] != 'dup'}

# --- prepare_vault(operation="native") --------------------------------------

service._named_enabled = lambda erase=False: None
service._remember = lambda uid, aid, payload: 't' * 43
p1 = copy.deepcopy(ASSIGNED['p1'])
MUTATIONS = [
    {'method': 'create', 'name': 'n', 'password': 'p'},
    {'method': 'assign', 'resource_id': 'p5', 'credential_id': 'c1'},
    {'method': 'assign', 'resource_id': 'p1', 'credential_id': 'c1'},
    {'method': 'assign', 'resource_id': 'p1', 'credential_id': 'c2'},
    {'method': 'assign', 'resource_id': 'p1', 'credential_id': 'c2', 'replace_credential_id': 'c1'},
    {'method': 'assign', 'resource_id': 'p1', 'credential_id': 'c2', 'replace_credential_id': 'c3'},
    {'method': 'assign', 'resource_id': 'p1', 'credential_id': None},
    {'method': 'create', 'resource_id': 'p1', 'name': 'n', 'password': 'p'},
    {'method': 'create', 'resource_id': 'p1', 'name': 'n', 'password': 'p', 'replace_credential_id': 'c1'},
    {'method': 'assign', 'resource_id': 'p1', 'credential_id': 'c1', 'expected_assignment': p1},
    {'method': 'assign', 'resource_id': 'p1', 'credential_id': 'c1', 'expected_assignment': None},
    {'method': 'assign', 'resource_id': 'p5', 'credential_id': 'c1', 'expected_assignment': None},
    {'method': 'assign', 'resource_id': 'dup', 'credential_id': 'c1'},
    {'method': 'assign', 'resource_id': 'missing', 'credential_id': 'c1'},
    {'method': 'assign', 'resource_id': 5, 'credential_id': 'c1'},
    {'method': 'assign', 'resource_id': 'jump:j1', 'credential_id': 'c1', 'replace_credential_id': 'c2'},
    {'method': 'delete', 'credential_id': 'c1'},
]


def prepare(mutation):
    result = service.prepare_vault(USER, 1, dict(operation='native', mutation=copy.deepcopy(mutation)))
    return True if result.get('intent') else result


prepares = [dict(mutation=m, **code_of(prepare, m)) for m in MUTATIONS]
prepares.append(dict(mutation=None, **code_of(lambda: service.prepare_vault(USER, 1, dict(operation='native', mutation=[])))))

binds = [dict(method=m, data=d, ok=_binds_saved_secret(m, d)) for m, d in [
    ('assign', {'credential_id': 'c1'}), ('assign', {'credential_id': None}), ('assign', {}),
    ('assign', {'credential_id': ''}), ('import', {}), ('authorize_target', {}), ('create', {'credential_id': 'c1'}),
    ('update', {}), ('delete', {}), ('create_for_resource', {}),
]]

# --- legacy vault ------------------------------------------------------------

av.incarnation = lambda user_id: INCARNATION
PASSPHRASE = 'oracle vault passphrase äöü'
LONG = ('ä' * 2048)


def vault_document(version, records):
    salt, nonce = bytes(range(16)), bytes(range(12))
    key = Scrypt(salt=salt, length=32, n=131072, r=8, p=1).derive(PASSPHRASE.encode())
    aad = f'webssh-automation-vault-v{version}:{USER}:{INCARNATION}'.encode()
    payload = json.dumps(records, separators=(',', ':')).encode()
    return dict(version=version, kdf='scrypt-131072-8-1', salt=base64.b64encode(salt).decode(),
                nonce=base64.b64encode(nonce).decode(),
                ciphertext=base64.b64encode(AESGCM(key).encrypt(nonce, payload, aad)).decode())


v1_records = {'p1': dict(fingerprint=profile_fingerprint(resources[0]), password='first secret'),
              'gone': dict(fingerprint='e' * 64, password=LONG)}
v2_records = {'p1': dict(fingerprint=profile_fingerprint(resources[0]), password='first secret', generation='a' * 64),
              'jump:j1': dict(fingerprint='1' * 64, password='second', generation='b' * 64)}
vaults = []
for version, records in ((1, v1_records), (2, v2_records)):
    document = vault_document(version, records)
    vault = av.Vault()
    key = av._derive(PASSPHRASE, av._decode(document['salt'], 32))
    decrypted = vault._decrypt(USER, key, document)
    wrong = code_of(lambda: vault._decrypt(USER, av._derive('another long passphrase', av._decode(document['salt'], 32)), document))
    from app.automation_store import digest
    vaults.append(dict(version=version, document=json.dumps(document), records=decrypted,
                       revision=digest(document), wrong=wrong))
short = code_of(av._derive, 'too short', bytes(16))

out = dict(user=USER, incarnation=INCARNATION, passphrase=PASSPHRASE, normalize=normalize,
           records=dict(profiles=PROFILES, jump_hosts=JUMPS, socks_proxies=PROXIES, smb_shares=SHARES),
           resources=fingerprints, assignments=ASSIGNED, statuses=statuses, prepares=prepares, binds=binds,
           vaults=vaults, short_passphrase=short)
Path(sys.argv[1]).write_text(json.dumps(out, indent=1, ensure_ascii=True) + '\n')
