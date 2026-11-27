"""Record the offline recovery of connection stores (connection-store).

Writes the stores, the summaries Python lists and the outcome of recovery
deletions, so the Go tests replay them without Python. Run from the
repository root with the project virtual environment:

    WS=$PWD .venv/bin/python -I internal/hosts/testdata/recovery_oracle.py \
        internal/hosts/testdata/recovery_oracle.json
"""
import json
import os
import sys
import tempfile
from pathlib import Path

WS = Path(os.environ['WS'])
sys.path.insert(0, str(WS))
os.environ.setdefault('SECRET_KEY', '0' * 64)
os.environ['DATA_DIR'] = tempfile.mkdtemp(prefix='recovery-oracle-')

import app.jump_host_manager as jm  # noqa: E402
import app.profile_manager as pm  # noqa: E402
import app.socks_proxy_manager as sm  # noqa: E402

USER = 3
STORE = Path(tempfile.mkdtemp(prefix='recovery-oracle-store-'))


def unwrap(module):
    for name in dir(module):
        value = getattr(module, name)
        if callable(value) and getattr(value, '__module__', None) == module.__name__ and hasattr(value, '__wrapped__'):
            setattr(module, name, value.__wrapped__)


for module in (pm, jm, sm):
    unwrap(module)

pm.get_user_profiles_file = lambda user_id: STORE / 'profiles.json'
jm._get_file = lambda user_id: STORE / 'jump_hosts.json'
sm._get_file = lambda user_id: STORE / 'socks_proxies.json'

JUMP = [
    {'id': 'j-used', 'name': 'Bastion', 'host': 'bastion.example', 'port': 22, 'username': 'ops', 'auth_type': 'key'},
    {'id': 'j-free', 'name': 'Jump é中\U0001f600', 'host': 'free.example', 'port': 2222, 'username': 'x', 'auth_type': 'password'},
]
SOCKS = [
    {'id': 's-used', 'name': 'Proxy', 'host': '10.0.0.1', 'port': 1080, 'username': '', 'auth_type': 'none',
     'remote_dns': True, 'created_at': '2026-01-01T00:00:00'},
    {'id': 's-free', 'name': 'Other\tproxy', 'host': 'p.example', 'port': 1081, 'username': 'u',
     'auth_type': 'password', 'remote_dns': False, 'created_at': '2026-01-02T00:00:00'},
]
PROFILES = [
    {'id': 'p1', 'name': 'Alpha', 'host': 'alpha.example', 'port': 22, 'username': 'root',
     'jump_host_id': 'j-used', 'group': 'Ops', 'favorite': True},
    {'id': 'p2', 'name': 'Name with "quotes" and \\ and \u2028', 'host': 'b\u00fccher.example', 'port': 2200,
     'username': 'u', 'sort_order': 12345678901234567890, 'created_at': '2026-01-01T00:00:00'},
    {'id': 'p3', 'name': 'x' * 200, 'host': 'c.example', 'port': 22, 'username': '\x7f\x01'},
    {'id': 'p4', 'name': 'Via proxy', 'host': 'd.example', 'port': 22, 'socks_proxy_id': 's-used', 'favorite': False},
]


def write_stores():
    (STORE / 'profiles.json').write_text(json.dumps({'schema_version': 3, 'profiles': PROFILES}, indent=2))
    (STORE / 'jump_hosts.json').write_text(json.dumps({'schema_version': 2, 'jump_hosts': JUMP}, indent=2))
    (STORE / 'socks_proxies.json').write_text(json.dumps({'schema_version': 2, 'socks_proxies': SOCKS}, indent=2))


def stores():
    return {
        'profiles': [json.dumps(p) for p in pm._load_profiles_for_recovery_delete(USER)[0]],
        'jump_hosts': [json.dumps(j) for j in jm._load_jump_hosts_for_recovery_delete(USER)],
        'socks_proxies': [json.dumps(s) for s in sm._load_socks_proxies_for_recovery_delete(USER)],
    }


def summaries():
    profiles, error = pm.load_profile_recovery_summaries(USER)
    assert error is None, error
    return {
        'profiles': profiles,
        'jump-hosts': jm.load_jump_host_recovery_summaries(USER),
        'socks-proxies': sm.load_socks_proxy_recovery_summaries(USER),
    }


def delete(kind, selector):
    if kind == 'profiles':
        ok, error = pm.delete_profile_recovery_record(USER, selector)
    elif kind == 'jump-hosts':
        ok, error, _ = jm.delete_jump_host_recovery_record(USER, selector)
    else:
        ok, error, _ = sm.delete_socks_proxy_recovery_record(USER, selector)
    return {'ok': bool(ok), 'error': error}


def main():
    write_stores()
    base = stores()
    listed = summaries()
    cases = []

    def run(name, kind, selector):
        cases.append({'name': name, 'kind': kind, 'selector': selector, 'result': delete(kind, selector),
                      'after': stores()})

    run('malformed selector', 'profiles', 'r1:01:' + '0' * 64)
    run('out of range', 'profiles', 'r1:9:' + listed['profiles'][0]['selector'].split(':')[2])
    run('wrong ordinal', 'profiles', 'r1:1:' + listed['profiles'][0]['selector'].split(':')[2])
    run('jump host in use', 'jump-hosts', listed['jump-hosts'][0]['selector'])
    run('proxy in use', 'socks-proxies', listed['socks-proxies'][0]['selector'])
    run('delete free jump host', 'jump-hosts', listed['jump-hosts'][1]['selector'])
    run('delete free proxy', 'socks-proxies', listed['socks-proxies'][1]['selector'])
    run('delete profile', 'profiles', listed['profiles'][0]['selector'])
    run('stale selector', 'profiles', listed['profiles'][2]['selector'])
    run('delete used jump host after profile', 'jump-hosts', listed['jump-hosts'][0]['selector'])
    after = summaries()
    out = {'base': base, 'summaries': listed, 'cases': cases, 'final_summaries': after}
    Path(sys.argv[1]).write_text(json.dumps(out, indent=1, sort_keys=True) + '\n')


main()
