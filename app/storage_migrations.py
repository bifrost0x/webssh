"""Explicit, versioned migrations for persistent JSON documents."""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
from typing import Callable
import uuid

from .storage_errors import StorageCorruptionError
from .storage_utils import atomic_write_json, fsync_parent_directory


CURRENT_STORAGE_VERSIONS = {
    'profiles': 2,
    'command_sets': 2,
    'jump_hosts': 2,
    'keys': 2,
    'settings': 2,
    'app_settings': 2,
    'smb_shares': 2,
}


def _version_document(document, version):
    if not isinstance(document, dict):
        raise ValueError('invalid storage document')
    result = deepcopy(document)
    result['schema_version'] = version
    return result


def migrate_profiles_v0_to_v1(document):
    return _version_document(document, 1)


def migrate_profiles_v1_to_v2(document):
    result = deepcopy(document)
    profiles = result.get('profiles')
    if isinstance(profiles, list):
        for profile in profiles:
            if not isinstance(profile, dict) or 'startup_mode' in profile:
                continue
            if profile.get('command_set_id'):
                profile['startup_mode'] = 'command_set'
            elif profile.get('command_id'):
                profile['startup_mode'] = 'command'
            elif profile.get('startup_commands'):
                profile['startup_mode'] = 'free_text'
            else:
                profile['startup_mode'] = 'none'
    result['schema_version'] = 2
    return result


def migrate_command_sets_v0_to_v1(document):
    return _version_document(document, 1)


def migrate_command_sets_v1_to_v2(document):
    return _version_document(document, 2)


def migrate_jump_hosts_v0_to_v1(document):
    return _version_document(document, 1)


def migrate_jump_hosts_v1_to_v2(document):
    return _version_document(document, 2)


def migrate_keys_v0_to_v1(document):
    return _version_document(document, 1)


def migrate_keys_v1_to_v2(document):
    return _version_document(document, 2)


def migrate_settings_v0_to_v1(document):
    return _version_document(document, 1)


def migrate_settings_v1_to_v2(document):
    return _version_document(document, 2)


def migrate_app_settings_v0_to_v1(document):
    return _version_document(document, 1)


def migrate_app_settings_v1_to_v2(document):
    return _version_document(document, 2)


def migrate_smb_shares_v0_to_v1(document):
    return _version_document(document, 1)


def migrate_smb_shares_v1_to_v2(document):
    return _version_document(document, 2)


_MIGRATIONS = {
    store_name: {
        0: globals()[f'migrate_{store_name}_v0_to_v1'],
        1: globals()[f'migrate_{store_name}_v1_to_v2'],
    }
    for store_name in CURRENT_STORAGE_VERSIONS
}


def migrate_document(store_name: str, document: object) -> tuple[object, bool]:
    """Return a current document without mutating the caller's object."""
    if store_name not in CURRENT_STORAGE_VERSIONS:
        raise ValueError(f'unknown storage store: {store_name}')

    if isinstance(document, dict):
        version = document.get('schema_version', 0)
    else:
        raise ValueError(f'invalid storage document for {store_name}')
    if type(version) is not int or version < 0:
        raise ValueError(f'invalid storage version for {store_name}')

    current = CURRENT_STORAGE_VERSIONS[store_name]
    if version > current:
        raise ValueError(f'future storage version for {store_name}: {version}')

    result = deepcopy(document)
    changed = False
    while version < current:
        migration = _MIGRATIONS[store_name].get(version)
        if migration is None:
            raise ValueError(
                f'missing storage migration for {store_name} version {version}'
            )
        result = migration(result)
        version += 1
        changed = True
    return result, changed


def backup_before_migration(path: Path) -> Path:
    """Create and verify an exact, private, uniquely named sibling backup."""
    path = Path(path)
    source = path.read_bytes()
    source_digest = hashlib.sha256(source).digest()
    backup = path.with_name(f'{path.name}.{uuid.uuid4().hex}.bak')
    descriptor = None
    try:
        descriptor = os.open(
            backup,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, 'wb') as handle:
            descriptor = None
            handle.write(source)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(backup, 0o600)
        if hashlib.sha256(backup.read_bytes()).digest() != source_digest:
            raise OSError('migration backup verification failed')
        fsync_parent_directory(backup)
        return backup
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        try:
            backup.unlink()
        except FileNotFoundError:
            pass
        raise


def migrate_file(
    path: Path,
    store_name: str,
    validator: Callable[[object], bool] | None = None,
    default_factory: Callable[[], object] | None = None,
) -> object:
    """Load and migrate one file, backing it up before the first write.

    A default is used only when the initial file open raises
    ``FileNotFoundError``. Any later disappearance or other filesystem error
    fails closed.
    """
    path = Path(path)
    source_missing = False
    try:
        handle = path.open('rb')
    except FileNotFoundError as exc:
        if default_factory is None:
            raise StorageCorruptionError(path, 'read failed') from exc
        document = default_factory()
        source_missing = True
    except OSError as exc:
        raise StorageCorruptionError(path, 'read failed') from exc
    else:
        try:
            with handle:
                raw = handle.read()
        except Exception as exc:
            raise StorageCorruptionError(path, 'read failed') from exc
        try:
            document = json.loads(raw.decode('utf-8'))
        except UnicodeError as exc:
            raise StorageCorruptionError(path, 'invalid Unicode') from exc
        except json.JSONDecodeError as exc:
            raise StorageCorruptionError(path, 'invalid JSON') from exc

    try:
        migrated, changed = migrate_document(store_name, document)
    except ValueError as exc:
        raise StorageCorruptionError(path, 'unsupported schema') from exc
    if validator is not None:
        try:
            valid = validator(migrated)
        except Exception as exc:
            raise StorageCorruptionError(path, 'validation failed') from exc
        if not valid:
            raise StorageCorruptionError(path, 'validation failed')
    if source_missing or not changed:
        return migrated

    backup_before_migration(path)
    atomic_write_json(path, migrated)
    return migrated
