"""Write manifest.json: parameters, expected plaintext and file inventory."""

import dataclasses
import datetime as dt
import hashlib
import json
import platform
from importlib import metadata

from . import descriptions, runtime

FORMAT = 'webssh-golden-data-set'
VERSION = 1
_PACKAGES = ('Flask', 'Werkzeug', 'itsdangerous', 'Flask-Login', 'Flask-WTF',
             'Flask-SQLAlchemy', 'SQLAlchemy', 'cryptography', 'bcrypt',
             'webauthn', 'cbor2', 'paramiko')
# Present in the environment but specific to one machine or run.
_VOLATILE_ENV = ('DATA_DIR', 'TRANSFER_TEMP_DIR', 'BACKUP_TEMP_DIR')

NONDETERMINISTIC = [
    {'path': 'artifacts/backups/*.zip',
     'reason': 'ZIP member timestamps come from staging-file mtimes '
               '(zipfile ZipInfo.from_file); member contents are identical per run'},
    {'path': 'datadir.tar, data/app.db and the app.db member of each backup',
     'reason': 'CREATE INDEX order follows identity-hashed SQLAlchemy Index objects; '
               'schema and rows are identical, compare with compare.database_dump'},
    {'path': 'values.ssh_keys.rejected[deterministic=false]',
     'reason': 'PEM/PKCS#8 passphrase encryption draws IV and salt inside OpenSSL'},
]


def _plain(value):
    if dataclasses.is_dataclass(value):
        return _plain(dataclasses.asdict(value))
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    if isinstance(value, dt.datetime):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {'hex': bytes(value).hex()}
    return value


def _inventory(out, data_dir):
    files = []
    sources = [(p, 'data/' + p.relative_to(data_dir).as_posix())
               for p in data_dir.rglob('*') if p.is_file()]
    sources += [(p, p.relative_to(out).as_posix()) for p in out.rglob('*')
                if p.is_file() and p.suffix == '.zip'
                and p.relative_to(out).parts[0] != 'legacy']
    for path, relative in sorted(sources, key=lambda item: item[1]):
        content = path.read_bytes()
        files.append({
            'path': relative,
            'size': len(content),
            'sha256': hashlib.sha256(content).hexdigest(),
            'mode': oct(path.stat().st_mode & 0o777),
            'deterministic': not relative.endswith(('.zip', '/app.db')),
        })
    return files


def build(out, facts, data_dir):
    environment = {k: v for k, v in runtime.environment('<DATA_DIR>', '/w').items()
                   if k not in _VOLATILE_ENV}
    secret = facts.pop('secret_key')
    return {
        'format': FORMAT,
        'version': VERSION,
        'generator': {
            'command': 'python -m tests.golden.generate',
            'seed': runtime.SEED,
            'clock_start': runtime.START.isoformat(),
            'python': platform.python_version(),
            'packages': {name: metadata.version(name) for name in _PACKAGES},
        },
        'environment': environment,
        'secret_key': {'value': secret, 'file': 'data/secret_key',
                       'note': 'synthetic, derived from the seed'},
        'reference': {
            'cookie_verify_at': _plain(facts.pop('cookie_verify_at')),
            'note': 'Cookie expectations hold at this instant; the authentication '
                    'sessions expire 30 minutes after their login.',
        },
        'data_kinds': descriptions.DATA_KINDS,
        'entity_inventory': [
            {'entity': name, 'source': source, 'in_fixture': present, 'cases': cases}
            for name, source, present, cases in descriptions.ENTITIES
        ],
        'values': _plain(facts),
        'nondeterministic': NONDETERMINISTIC,
        'data_archive': {
            'path': runtime.DATA_ARCHIVE,
            'layout': 'ustar; members under data/ (the DATA_DIR root), sorted, '
                      'mtime = clock_start, uid/gid 0, file modes kept, '
                      'empty user directories included',
            'note': 'every "data/..." path in this manifest is a member of this archive',
        },
        'files': _inventory(out, data_dir),
    }


def write_manifest(out, facts, data_dir):
    document = build(out, facts, data_dir)
    (out / 'manifest.json').write_text(
        json.dumps(document, indent=1, sort_keys=True, ensure_ascii=False) + '\n',
        encoding='utf-8',
    )
