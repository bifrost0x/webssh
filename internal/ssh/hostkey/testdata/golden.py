"""List the golden fixture's known_hosts files with the Python store.

Run from the repository root with the project virtual environment:

    WS=$PWD .venv/bin/python -I internal/ssh/hostkey/testdata/golden.py \
        internal/ssh/hostkey/testdata/golden.json
"""
import json
import os
import sys
import tarfile
import tempfile
from pathlib import Path

WS = Path(os.environ['WS'])
sys.path.insert(0, str(WS))
os.environ.setdefault('SECRET_KEY', '0' * 64)
work = Path(tempfile.mkdtemp(prefix='hostkey-golden-'))
os.environ['DATA_DIR'] = str(work / 'unused')

from app.host_key_store import HostKeyStore, _LayeredHostKeys  # noqa: E402

with tarfile.open(WS / 'tests/golden/fixture/datadir.tar') as archive:
    for name in ('data/known_hosts', 'data/users/user_3/known_hosts'):
        archive.extract(name, work, filter='data')

global_path = work / 'data/known_hosts'
user_path = work / 'data/users/user_3/known_hosts'
layered = _LayeredHostKeys(HostKeyStore._load_strict(global_path), HostKeyStore._load_strict(user_path))
hosts = ['pw.golden.test', '[uni.golden.test]:2222', 'key.golden.test', 'bastion.golden.test', 'compromised.golden.test']
out = {
    'global': [{k: e[k] for k in ('id', 'host', 'port', 'algorithm', 'fingerprint', 'marker')}
               for e in HostKeyStore.list_file(global_path, scope='global', owner_id=None)],
    'user': [{k: e[k] for k in ('id', 'host', 'port', 'algorithm', 'fingerprint', 'marker')}
             for e in HostKeyStore.list_file(user_path, scope='user', owner_id=3)],
    'lookups': {h: [[t, (layered.lookup(h) or {})[t].get_base64()] for t in (layered.lookup(h) or {}).keys()] for h in hosts},
}
Path(sys.argv[1]).write_text(json.dumps(out, indent=1) + '\n')
