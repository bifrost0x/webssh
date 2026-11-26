"""Write ``legacy/manifest.json``: releases, cases, expected values, files."""

import hashlib
import json

from .. import runtime

FORMAT = 'webssh-golden-legacy-data-set'
VERSION = 1

# Where each case of migration-spec 8.2 and of the legacy request lives.
CASES = [
    ('vault passphrase in the manifest', 'main manifest values.vault_passphrase; values.extended.vault_v1.passphrase'),
    ('backup format version 1', 'backups/backup-v1-8c41517.zip (written by 8c41517)'),
    ('vault version 1', 'datadir-extended.tar, user legacy_stores (constructed, no release wrote v1)'),
    ('store files at schema 0', 'datadir-2fcd38a.tar and datadir-v1.0.0.tar (written by the releases)'),
    ('store files at schema 1', 'datadir-extended.tar, user legacy_stores (constructed); variant app_settings_schema_1'),
    ('profiles at schema 2 with tailscale_authorized', 'datadir-extended.tar, user legacy_profiles_v2 (constructed); backup-v1 (8c41517)'),
    ('commands.json object form', 'datadir-extended.tar, user legacy_stores (constructed from 131964f)'),
    ('database with missing additive columns', 'datadir-2fcd38a.tar (no is_admin/is_locked), datadir-v1.0.0.tar'),
    ('DSA and passphrase-protected key files', 'datadir-2fcd38a.tar, pioneer_user (written by 2fcd38a)'),
    ('records above current limits', 'datadir-v1.0.0.tar bulk_user (501 commands, 65 set steps); 2fcd38a 200-character profile name'),
    ('non-empty global notepad', 'datadir-2fcd38a.tar pioneer_user; datadir-extended.tar local_user'),
    ('workspace presets and tour state', 'datadir-extended.tar local_user'),
    ('persistent ssh_sessions with display names', 'datadir-v1.0.0.tar; datadir-extended.tar local_user'),
    ('created_at NULL and created_at vectors', 'datadir-extended.tar users created_null, created_vector_*'),
    ('interrupted key deletion', 'datadir-extended.tar local_user (both crash points)'),
    ('schedule with a stale claim', 'datadir-extended.tar'),
    ('schedule with the incarnation of a deleted account', 'datadir-extended.tar'),
    ('host context for a deleted profile', 'datadir-extended.tar local_user'),
    ('recovery-check.json', 'datadir-extended.tar; variants recovery_check_malformed, recovery_check_oversized'),
    ('restore-status.json per state', 'values.extended.restore_status (path-bound, materialised by the test)'),
    ('Python backup with data/go/', 'backups/with-go-dir.zip'),
    ('Python backup with data/logs/', 'backups/with-logs-members.zip (edited archive)'),
    ('SECRET_KEY variants of I-08', 'variants secret_key_*'),
    ('backup with an outdated data/secret_key', 'backups/outdated-secret-key.zip'),
    ('LDAP revocation fence', 'datadir-extended.tar .ldap-revocation-fences/<ldap_user id>'),
    ('sqlite_stat1, extra index, unknown table', 'datadir-extended.tar app.db'),
    ('trigger and view in app.db', 'variant database_trigger_and_view (SQL to apply)'),
    ('@cert-authority line', 'datadir-extended.tar known_hosts'),
    ('ADMIN_USERS naming a missing account', 'variant admin_users_missing_account'),
    ('legacy single-user paths', 'datadir-extended.tar profiles.json, keys/, commands/ at the root (constructed)'),
]

NONDETERMINISTIC = [
    {'path': 'backups/*.zip',
     'reason': 'member timestamps come from staging-file mtimes; member contents are identical'},
    {'path': 'datadir-*.tar member data/app.db and app.db members of the backups',
     'reason': 'CREATE INDEX order; compare with tests.golden.compare.database_dump'},
]


def _inventory(out):
    files = []
    for path in sorted(p for p in out.rglob('*') if p.is_file() and p.name != 'manifest.json'):
        content = path.read_bytes()
        files.append({'path': path.relative_to(out).as_posix(), 'size': len(content),
                      'sha256': hashlib.sha256(content).hexdigest(),
                      'deterministic': False})
    return files


def build(out, old, releases, facts):
    environment = {k: v for k, v in runtime.environment('<DATA_DIR>', '/w').items()
                   if k not in ('DATA_DIR', 'TRANSFER_TEMP_DIR', 'BACKUP_TEMP_DIR')}
    return {
        'format': FORMAT,
        'version': VERSION,
        'generator': {'command': 'python -m tests.golden.legacy.build', 'seed': 'webssh-golden-legacy-v1 '
                      '(old releases), webssh-golden-extended-v1 (3.3.x)'},
        'secret_key': {'value': runtime.secret_key(), 'source': 'environment SECRET_KEY for the '
                       'release DATA_DIRs (no secret_key file: an explicit SECRET_KEY is never '
                       'persisted by the entrypoint); data/secret_key in datadir-extended.tar'},
        'environment': environment,
        'releases': releases,
        'cases': [{'case': case, 'where': where} for case, where in CASES],
        'datadirs': {
            'datadir-2fcd38a.tar': {'release': 'initial', 'values': old['initial'],
                                    'note': 'state after the initial release only'},
            'datadir-v1.0.0.tar': {'release': 'v1.0.0', 'values': old['v1.0.0'],
                                   'note': 'datadir-2fcd38a.tar upgraded by v1.0.0 plus its additions'},
            'datadir-extended.tar': {'release': '3.3.x (this tree)', 'base': '../datadir.tar',
                                     'environment': environment},
        },
        'backups': {
            'backups/backup-v1-8c41517.zip': {'release': 'backup_v1', 'values': old['backup_v1'],
                                              'source': 'datadir-v1.0.0.tar started by 8c41517'},
            **{f"backups/{name.replace('_', '-')}.zip": value
               for name, value in facts.pop('backups').items()},
        },
        'variants': facts.pop('variants'),
        'values': {'extended': facts, 'passwords': _passwords(old)},
        'nondeterministic': NONDETERMINISTIC,
        'files': _inventory(out),
    }


def _passwords(old):
    result = {}
    for stage in ('initial', 'v1.0.0'):
        for name, user in old[stage]['users'].items():
            result[name] = user['password']
    return result


def write_manifest(out, old, releases, facts):
    document = build(out, old, releases, facts)
    (out / 'manifest.json').write_text(
        json.dumps(document, indent=1, sort_keys=True, ensure_ascii=False, default=str) + '\n',
        encoding='utf-8')
