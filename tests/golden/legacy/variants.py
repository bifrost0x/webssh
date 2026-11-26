"""Backups written by 3.3.x and mutually exclusive DATA_DIR variants.

Backups (``legacy/backups/``):

* ``with-go-dir.zip``: create_backup of the extended DATA_DIR after a Go
  directory appeared (``go/`` is not excluded by 3.3.x, so it is exported).
* ``with-logs-members.zip``: no release writes ``data/logs/`` members
  (_BACKUP_EXCLUDED_TOP_LEVEL_DIRECTORIES); an edited archive does. Built from
  a create_backup stage plus one log file, written with the release's own
  _write_archive and manifest payload, so it verifies.
* ``outdated-secret-key.zip``: create_backup while ``data/secret_key`` holds an
  older value than the SECRET_KEY the process runs with.

Variants are overlays on the extended DATA_DIR and are stored in the legacy
manifest: files to write (base64) or remove, environment changes, and what
3.3.x does with them.
"""

import base64
import hashlib
import json
import shutil
import sqlite3
import tempfile
from pathlib import Path

from .extend import TRIGGER_AND_VIEW

OUTDATED_SECRET = 'f' * 64
LOG_LINE = '{"timestamp": "2026-11-02T10:00:00Z", "level": "INFO", "message": "edited archive"}\n'


def _b64(data):
    return base64.b64encode(data if isinstance(data, bytes) else data.encode('utf-8')).decode('ascii')


def _describe(manifest):
    return {'format_version': manifest.format_version,
            'data_schema_version': manifest.data_schema_version,
            'files': [dict(path=f.path, sha256=f.sha256, size=f.size) for f in manifest.files]}


def backups(data_dir, out_dir):
    from app.backup_manager import (
        BackupFile, BackupManifest, _stage_source, _write_archive, create_backup,
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    result = {}
    with tempfile.TemporaryDirectory(prefix='golden-variant-') as work:
        copy = Path(work) / 'data'
        shutil.copytree(data_dir, copy, symlinks=True)
        go = copy / 'go'
        go.mkdir(mode=0o700)
        connection = sqlite3.connect(go / 'webssh.db')
        connection.execute('CREATE TABLE schema_migrations (version INTEGER NOT NULL)')
        connection.execute('INSERT INTO schema_migrations VALUES (1)')
        connection.commit()
        connection.close()
        (go / 'webssh.db').chmod(0o600)
        result['with_go_dir'] = _describe(create_backup(copy, out_dir / 'with-go-dir.zip'))
        shutil.rmtree(go)

        (copy / 'secret_key').write_text(OUTDATED_SECRET + '\n', encoding='ascii')
        result['outdated_secret_key'] = dict(
            _describe(create_backup(copy, out_dir / 'outdated-secret-key.zip')),
            archived_secret_key=OUTDATED_SECRET)

        stage = Path(work) / 'stage'
        stage.mkdir(mode=0o700)
        manifest = _stage_source(copy, stage, include_remote_credentials=False)
        (stage / 'logs').mkdir(mode=0o700)
        (stage / 'logs' / 'app.log').write_text(LOG_LINE, encoding='utf-8')
        log = BackupFile('logs/app.log', hashlib.sha256(LOG_LINE.encode()).hexdigest(),
                         len(LOG_LINE.encode()))
        edited = BackupManifest(manifest.format_version,
                                tuple(sorted(manifest.files + (log,), key=lambda f: f.path)),
                                manifest.data_schema_version, manifest.created_at,
                                manifest.producer)
        _write_archive(stage, out_dir / 'with-logs-members.zip', edited)
        result['with_logs_members'] = dict(_describe(edited), log_member='data/logs/app.log')
    return result


def restore_status_templates():
    """Each restore state as maintenance_mode writes it, fingerprint as placeholder."""
    from app import maintenance_mode
    templates = {}
    fingerprint = maintenance_mode._data_fingerprint()
    writers = {
        'preparing': lambda: maintenance_mode.begin_preparing('golden-op'),
        'in_progress': lambda: maintenance_mode.mark_in_progress('golden-op', 'operation-golden-op/rollback.zip'),
        'succeeded': lambda: maintenance_mode.mark_succeeded('golden-op'),
        'failed': lambda: maintenance_mode.mark_failed('golden-op', 'Restore failed'),
        'rollback_failed': lambda: maintenance_mode.mark_failed('golden-op', 'Rollback failed',
                                                                rollback_failed=True),
    }
    path = maintenance_mode._status_path()
    for state, write in writers.items():
        if state == 'rollback_failed':
            maintenance_mode.mark_in_progress('golden-op', 'operation-golden-op/rollback.zip')
        write()
        document = json.loads(path.read_text(encoding='utf-8'))
        if document.get('data_fingerprint') == fingerprint:
            document['data_fingerprint'] = '{DATA_FINGERPRINT}'
        templates[state] = document
    path.unlink()
    maintenance_mode._state = maintenance_mode._state_path = None
    return {'location': '{BACKUP_TEMP_DIR}/instance-{sha256(realpath(DATA_DIR))[:32]}/restore-status.json',
            'data_fingerprint': 'sha256 hex of realpath(DATA_DIR)',
            'source': 'app/maintenance_mode.py',
            'documents': templates,
            'expected': {state: {'maintenance_active': state in {'preparing', 'in_progress', 'rollback_failed'}}
                         for state in templates}}


def variants(data_dir):
    data_dir = Path(data_dir)
    app_settings = json.loads((data_dir / 'app_settings.json').read_text(encoding='utf-8'))
    app_settings['schema_version'] = 1
    secret = (data_dir / 'secret_key').read_text(encoding='ascii').strip()
    return {
        'recovery_check_malformed': {
            'files': {'data/recovery-check.json': _b64('{"restored_at": ')},
            'expected': {'restore_marker': None},
            'note': 'customer_workflows._restore_marker treats it as absent'},
        'recovery_check_oversized': {
            'files': {'data/recovery-check.json': _b64(json.dumps(
                {'restored_at': '2026-11-02T10:00:00+00:00', 'padding': 'x' * 600}))},
            'expected': {'restore_marker': None}},
        'app_settings_schema_1': {
            'files': {'data/app_settings.json': _b64(json.dumps(app_settings, indent=2))},
            'expected': {'loads': True, 'migrated_to': 2},
            'note': 'no release wrote schema 1; migrate_app_settings_v1_to_v2 still applies'},
        'secret_key_crlf': {
            'files': {'data/secret_key': _b64(secret + '\r\n')},
            'environment': {'SECRET_KEY': None},
            'expected': {'entrypoint_secret_key_b64': _b64(secret + '\r'), 'data_decrypts': False},
            'note': 'entrypoint.sh: $(cat file) strips only the final LF'},
        'secret_key_placeholder_env': {
            'environment': {'SECRET_KEY': ' changeme '},
            'expected': {'entrypoint_secret_key_b64': _b64(secret), 'data_decrypts': True},
            'note': 'placeholders are compared lower-case with whitespace removed'},
        'secret_key_empty_file': {
            'files': {'data/secret_key': _b64('')},
            'environment': {'SECRET_KEY': None},
            'expected': {'entrypoint_secret_key_b64': '', 'python_starts': False},
            'note': 'config.py raises without DEBUG when SECRET_KEY is empty'},
        'secret_key_conflicting_legacy_path': {
            'legacy_secret_key_file': _b64(OUTDATED_SECRET + '\n'),
            'environment': {'SECRET_KEY': None},
            'expected': {'entrypoint_exit': 1,
                         'stderr': 'ERROR: conflicting secret_key files exist under /app/data and DATA_DIR.'},
            'note': 'LEGACY_SECRET_KEY_FILE is /app/data/secret_key; tests point it elsewhere'},
        'database_trigger_and_view': {
            'sql': TRIGGER_AND_VIEW,
            'expected': {'application_starts': True, 'create_backup_error': 'backup database is invalid'},
            'note': 'restore_database.harden_imported_database rejects triggers and views'},
        'admin_users_missing_account': {
            'environment': {'ADMIN_USERS': 'cfg_admin,ghost_admin'},
            'expected': {'ghost_admin_exists': False, 'cfg_admin_is_admin': True}},
    }
