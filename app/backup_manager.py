"""Verified backup and restore operations for the WebSSH data directory."""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import sqlite3
import stat
import tempfile
import zipfile

import config
from .storage_utils import atomic_copy_file, fsync_parent_directory


_FORMAT_VERSION = 2
_LEGACY_FORMAT_VERSION = 1
_CURRENT_DATA_SCHEMA_VERSION = 1
_DATA_SCHEMA_MIGRATIONS = {0: 1}
_PRODUCER = 'webssh'
_MANIFEST_NAME = 'manifest.json'
_DATA_PREFIX = 'data/'
_DATABASE_PATH = 'app.db'
_EXCLUDED_TOP_LEVEL_DIRECTORIES = {'logs', 'tmp'}


class BackupIntegrityError(ValueError):
    """Raised when a backup is unsafe, malformed, or fails verification."""


@dataclass(frozen=True)
class BackupFile:
    path: str
    sha256: str
    size: int


@dataclass(frozen=True)
class BackupManifest:
    format_version: int
    files: tuple[BackupFile, ...]
    data_schema_version: int = 0
    created_at: str | None = None
    producer: str | None = None


@dataclass(frozen=True)
class BackupCompatibility:
    compatible: bool
    legacy: bool
    data_schema_version: int
    current_data_schema_version: int
    reason: str


def _safe_relative_path(value):
    if not isinstance(value, str) or not value or '\\' in value:
        raise BackupIntegrityError('backup contains an unsafe path')
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or any(part in {'', '.', '..'} for part in path.parts)
        or any(':' in part for part in path.parts)
    ):
        raise BackupIntegrityError('backup contains an unsafe path')
    return path


def _manifest_payload(manifest):
    document = {
        'files': [
            {
                'path': item.path,
                'sha256': item.sha256,
                'size': item.size,
            }
            for item in manifest.files
        ],
        'format_version': manifest.format_version,
    }
    if manifest.format_version == _FORMAT_VERSION:
        document.update({
            'created_at': manifest.created_at,
            'data_schema_version': manifest.data_schema_version,
            'producer': manifest.producer,
        })
    return json.dumps(
        document,
        sort_keys=True,
        separators=(',', ':'),
    ).encode('utf-8')


def _valid_utc_timestamp(value):
    if not isinstance(value, str) or not value.endswith('Z'):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + '+00:00')
    except ValueError:
        return False
    return parsed.tzinfo == timezone.utc


def _parse_manifest(payload):
    try:
        document = json.loads(payload.decode('utf-8'))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BackupIntegrityError('backup manifest is invalid') from exc
    if not isinstance(document, dict):
        raise BackupIntegrityError('backup manifest is incompatible')
    format_version = document.get('format_version')
    if type(format_version) is not int:
        raise BackupIntegrityError('backup manifest is incompatible')
    if format_version == _LEGACY_FORMAT_VERSION:
        expected_keys = {'files', 'format_version'}
        data_schema_version = 0
        created_at = None
        producer = None
    elif format_version == _FORMAT_VERSION:
        expected_keys = {
            'created_at',
            'data_schema_version',
            'files',
            'format_version',
            'producer',
        }
        data_schema_version = document.get('data_schema_version')
        created_at = document.get('created_at')
        producer = document.get('producer')
        if (
            type(data_schema_version) is not int
            or data_schema_version < 0
            or producer != _PRODUCER
            or not _valid_utc_timestamp(created_at)
        ):
            raise BackupIntegrityError('backup manifest is incompatible')
    else:
        raise BackupIntegrityError('backup manifest is incompatible')
    if (
        set(document) != expected_keys
        or not isinstance(document.get('files'), list)
    ):
        raise BackupIntegrityError('backup manifest is incompatible')

    files = []
    for raw_item in document['files']:
        if (
            not isinstance(raw_item, dict)
            or set(raw_item) != {'path', 'sha256', 'size'}
            or not isinstance(raw_item['path'], str)
            or not isinstance(raw_item['sha256'], str)
            or len(raw_item['sha256']) != 64
            or any(
                character not in '0123456789abcdef'
                for character in raw_item['sha256']
            )
            or type(raw_item['size']) is not int
            or raw_item['size'] < 0
        ):
            raise BackupIntegrityError('backup manifest is invalid')
        _safe_relative_path(raw_item['path'])
        files.append(BackupFile(**raw_item))

    paths = [item.path for item in files]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise BackupIntegrityError(
            'backup manifest paths must be unique and sorted'
        )
    return BackupManifest(
        format_version,
        tuple(files),
        data_schema_version,
        created_at,
        producer,
    )


def evaluate_backup_compatibility(manifest):
    data_schema_version = manifest.data_schema_version
    legacy = manifest.format_version == _LEGACY_FORMAT_VERSION
    common = {
        'legacy': legacy,
        'data_schema_version': data_schema_version,
        'current_data_schema_version': _CURRENT_DATA_SCHEMA_VERSION,
    }
    if data_schema_version > _CURRENT_DATA_SCHEMA_VERSION:
        return BackupCompatibility(
            compatible=False,
            reason='backup data schema is newer than this WebSSH version',
            **common,
        )

    cursor = data_schema_version
    visited = set()
    while cursor < _CURRENT_DATA_SCHEMA_VERSION:
        if cursor in visited:
            break
        visited.add(cursor)
        next_version = _DATA_SCHEMA_MIGRATIONS.get(cursor)
        if (
            type(next_version) is not int
            or next_version <= cursor
            or next_version > _CURRENT_DATA_SCHEMA_VERSION
        ):
            break
        cursor = next_version
    if cursor != _CURRENT_DATA_SCHEMA_VERSION:
        return BackupCompatibility(
            compatible=False,
            reason='no complete migration path for backup data schema',
            **common,
        )
    if legacy:
        reason = 'legacy archive can be migrated'
    elif data_schema_version < _CURRENT_DATA_SCHEMA_VERSION:
        reason = 'backup data schema can be migrated'
    else:
        reason = 'backup data schema is current'
    return BackupCompatibility(compatible=True, reason=reason, **common)


def require_restore_compatible(manifest):
    compatibility = evaluate_backup_compatibility(manifest)
    if not compatibility.compatible:
        raise BackupIntegrityError(
            f'backup is not restore compatible: {compatibility.reason}'
        )
    return compatibility


def _regular_zip_info(name):
    info = zipfile.ZipInfo(name)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o600) << 16
    return info


def _copy_regular_file(source, destination):
    source_stat = source.lstat()
    if stat.S_ISLNK(source_stat.st_mode):
        raise BackupIntegrityError(
            f'backup source contains a symbolic link: {source.name}'
        )
    if not stat.S_ISREG(source_stat.st_mode):
        raise BackupIntegrityError(
            f'backup source contains a non-regular file: {source.name}'
        )

    digest = hashlib.sha256()
    size = 0
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0)
    flags |= getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(source, flags)
    try:
        opened_stat = os.fstat(descriptor)
        if (
            source_stat.st_dev,
            source_stat.st_ino,
        ) != (
            opened_stat.st_dev,
            opened_stat.st_ino,
        ) or not stat.S_ISREG(opened_stat.st_mode):
            raise BackupIntegrityError(
                f'backup source changed while being opened: {source.name}'
            )
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with os.fdopen(descriptor, 'rb') as source_handle:
            descriptor = None
            with destination.open('wb') as destination_handle:
                while chunk := source_handle.read(1024 * 1024):
                    destination_handle.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
                destination_handle.flush()
                os.fsync(destination_handle.fileno())
        os.chmod(destination, 0o600)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return digest.hexdigest(), size


def _stage_source(data_dir, stage, excluded_relative_paths=frozenset()):
    files = []
    for current_root, directory_names, file_names in os.walk(
        data_dir,
        topdown=True,
        followlinks=False,
    ):
        current = Path(current_root)
        for directory_name in directory_names:
            directory = current / directory_name
            if directory.is_symlink():
                raise BackupIntegrityError(
                    'backup source contains a symbolic link'
                )
        if current == data_dir:
            directory_names[:] = [
                name for name in directory_names
                if name not in _EXCLUDED_TOP_LEVEL_DIRECTORIES
            ]
        for file_name in file_names:
            source = current / file_name
            relative = source.relative_to(data_dir).as_posix()
            if relative in excluded_relative_paths:
                continue
            _safe_relative_path(relative)
            staged = stage / relative
            digest, size = _copy_regular_file(source, staged)
            files.append(BackupFile(relative, digest, size))
    created_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    return BackupManifest(
        _FORMAT_VERSION,
        tuple(sorted(files, key=lambda item: item.path)),
        _CURRENT_DATA_SCHEMA_VERSION,
        created_at,
        _PRODUCER,
    )


def _write_archive(stage, archive, manifest):
    with zipfile.ZipFile(
        archive,
        mode='w',
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=6,
    ) as backup:
        backup.writestr(
            _regular_zip_info(_MANIFEST_NAME),
            _manifest_payload(manifest),
        )
        for item in manifest.files:
            backup.write(
                stage / Path(*PurePosixPath(item.path).parts),
                arcname=_DATA_PREFIX + item.path,
            )


def _publish_archive(temporary_archive, destination):
    try:
        os.link(temporary_archive, destination, follow_symlinks=False)
    except FileExistsError as exc:
        raise FileExistsError(
            f'backup destination already exists: {destination}'
        ) from exc
    except OSError as exc:
        raise OSError(
            'backup destination filesystem does not support atomic '
            'no-clobber publication'
        ) from exc
    temporary_archive.unlink()
    fsync_parent_directory(destination)


def create_backup(data_dir, destination):
    data_dir = Path(data_dir)
    if data_dir.is_symlink():
        raise BackupIntegrityError(
            'backup source must be a real directory'
        )
    data_dir = data_dir.resolve(strict=True)
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(
            f'backup destination already exists: {destination}'
        )
    destination_resolved = destination.resolve(strict=False)
    if destination_resolved.is_relative_to(data_dir):
        raise ValueError('backup destination must be outside DATA_DIR')
    if not data_dir.is_dir() or data_dir.is_symlink():
        raise BackupIntegrityError(
            'backup source must be a real directory'
        )

    temporary_archive = None
    with tempfile.TemporaryDirectory(
        dir=destination.parent,
        prefix='.webssh-backup-stage-',
    ) as temporary_directory:
        stage = Path(temporary_directory) / 'data'
        stage.mkdir(mode=0o700)
        manifest = _stage_source(data_dir, stage)
        try:
            with tempfile.NamedTemporaryFile(
                dir=destination.parent,
                prefix=f'.{destination.name}.',
                suffix='.tmp',
                delete=False,
            ) as handle:
                temporary_archive = Path(handle.name)
            _write_archive(stage, temporary_archive, manifest)
            os.chmod(temporary_archive, 0o600)
            if verify_backup(temporary_archive) != manifest:
                raise BackupIntegrityError(
                    'published backup verification failed'
                )
            _publish_archive(temporary_archive, destination)
            temporary_archive = None
        finally:
            if temporary_archive is not None:
                temporary_archive.unlink(missing_ok=True)
    return manifest


def _validated_members(backup):
    infos = backup.infolist()
    if len(infos) > config.BACKUP_MAX_MEMBERS:
        raise BackupIntegrityError('backup contains too many members')
    names = [info.filename for info in infos]
    if len(names) != len(set(names)):
        raise BackupIntegrityError('backup contains duplicate members')
    for info in infos:
        normalized = info.filename[:-1] if info.is_dir() else info.filename
        if normalized:
            _safe_relative_path(normalized)
        mode = (info.external_attr >> 16) & 0xFFFF
        if mode and stat.S_ISLNK(mode):
            raise BackupIntegrityError(
                'backup contains a symbolic link'
            )
        if info.flag_bits & 0x1:
            raise BackupIntegrityError('encrypted backup members are unsupported')
    if names.count(_MANIFEST_NAME) != 1:
        raise BackupIntegrityError(
            'backup must contain exactly one manifest'
        )
    members = {info.filename: info for info in infos if not info.is_dir()}
    manifest_info = members[_MANIFEST_NAME]
    if manifest_info.file_size > config.BACKUP_MAX_MANIFEST_SIZE:
        raise BackupIntegrityError('backup manifest is too large')

    total_size = 0
    for name, info in members.items():
        if name == _MANIFEST_NAME:
            continue
        if info.file_size > config.BACKUP_MAX_FILE_SIZE:
            raise BackupIntegrityError('backup member exceeds file size limit')
        total_size += info.file_size
        if total_size > config.BACKUP_MAX_TOTAL_SIZE:
            raise BackupIntegrityError('backup exceeds total size limit')
        if (
            info.file_size
            and info.file_size / max(info.compress_size, 1)
            > config.BACKUP_MAX_COMPRESSION_RATIO
        ):
            raise BackupIntegrityError(
                'backup member exceeds compression ratio limit'
            )
    return members


def _read_manifest(backup, members):
    info = members[_MANIFEST_NAME]
    with backup.open(info, 'r') as handle:
        payload = handle.read(config.BACKUP_MAX_MANIFEST_SIZE + 1)
    if len(payload) > config.BACKUP_MAX_MANIFEST_SIZE:
        raise BackupIntegrityError('backup manifest is too large')
    return _parse_manifest(payload)


def _validate_webssh_database(path: Path) -> None:
    connection = None
    try:
        uri = path.resolve(strict=True).as_uri() + '?mode=ro&immutable=1'
        connection = sqlite3.connect(uri, uri=True)
        connection.execute('PRAGMA query_only = ON')
        connection.execute('PRAGMA trusted_schema = OFF')
        if connection.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
            raise BackupIntegrityError('backup database is invalid')
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table'"
            )
        }
        if 'users' not in tables:
            raise BackupIntegrityError('backup database is not a WebSSH database')
        user_columns = {
            row[1] for row in connection.execute('PRAGMA table_info(users)')
        }
        if not {'id', 'username', 'password_hash'} <= user_columns:
            raise BackupIntegrityError('backup database is not a WebSSH database')
    except BackupIntegrityError:
        raise
    except (OSError, sqlite3.DatabaseError) as exc:
        raise BackupIntegrityError('backup database is invalid') from exc
    finally:
        if connection is not None:
            connection.close()


def _verify_database_member(backup, info, expected_size) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix='.webssh-backup-database-',
        suffix='.db',
    )
    temporary = Path(temporary_name)
    try:
        size = 0
        with os.fdopen(descriptor, 'wb') as destination:
            descriptor = None
            with backup.open(info, 'r') as source:
                while chunk := source.read(1024 * 1024):
                    size += len(chunk)
                    if size > expected_size:
                        raise BackupIntegrityError(
                            'backup database exceeds its declared size'
                        )
                    destination.write(chunk)
            destination.flush()
            os.fsync(destination.fileno())
        os.chmod(temporary, 0o600)
        if size != expected_size:
            raise BackupIntegrityError('backup database size is invalid')
        _validate_webssh_database(temporary)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def verify_backup(archive):
    try:
        with zipfile.ZipFile(Path(archive), 'r') as backup:
            members = _validated_members(backup)
            manifest = _read_manifest(backup, members)
            expected_names = {
                _MANIFEST_NAME,
                *(_DATA_PREFIX + item.path for item in manifest.files),
            }
            if set(members) != expected_names:
                raise BackupIntegrityError(
                    'backup members do not match the manifest'
                )
            database = next(
                (item for item in manifest.files if item.path == _DATABASE_PATH),
                None,
            )
            if database is None:
                raise BackupIntegrityError('backup database is missing')
            total_size = 0
            for item in manifest.files:
                info = members[_DATA_PREFIX + item.path]
                if info.file_size != item.size:
                    raise BackupIntegrityError(
                        f'backup checksum or size mismatch for {item.path}'
                    )
                digest = hashlib.sha256()
                size = 0
                with backup.open(info, 'r') as handle:
                    while chunk := handle.read(1024 * 1024):
                        digest.update(chunk)
                        size += len(chunk)
                        total_size += len(chunk)
                        if (
                            size > item.size
                            or size > config.BACKUP_MAX_FILE_SIZE
                            or total_size > config.BACKUP_MAX_TOTAL_SIZE
                        ):
                            raise BackupIntegrityError(
                                'backup streamed size exceeds configured limits'
                            )
                if size != item.size or digest.hexdigest() != item.sha256:
                    raise BackupIntegrityError(
                        f'backup checksum mismatch for {item.path}'
                    )
            _verify_database_member(
                backup,
                members[_DATA_PREFIX + _DATABASE_PATH],
                database.size,
            )
            return manifest
    except BackupIntegrityError:
        raise
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        raise BackupIntegrityError(
            'backup archive is unreadable or invalid'
        ) from exc


def _validate_restore_targets(data_dir, manifest):
    if data_dir.exists() and (
        data_dir.is_symlink() or not data_dir.is_dir()
    ):
        raise BackupIntegrityError(
            'restore destination must be a real directory'
        )
    for item in manifest.files:
        target = data_dir / Path(*PurePosixPath(item.path).parts)
        current = data_dir
        for part in PurePosixPath(item.path).parts[:-1]:
            current /= part
            if current.exists() and (
                current.is_symlink() or not current.is_dir()
            ):
                raise BackupIntegrityError(
                    'restore destination contains an unsafe path'
                )
        if target.exists() and (
            target.is_symlink() or not target.is_file()
        ):
            raise BackupIntegrityError(
                'restore destination contains an unsafe path'
            )


def _existing_persistent_files(data_dir):
    if not data_dir.exists():
        return set()
    paths = set()
    for current_root, directory_names, file_names in os.walk(
        data_dir,
        topdown=True,
        followlinks=False,
    ):
        current = Path(current_root)
        if current == data_dir:
            directory_names[:] = [
                name for name in directory_names
                if name not in _EXCLUDED_TOP_LEVEL_DIRECTORIES
            ]
        for directory_name in directory_names:
            if (current / directory_name).is_symlink():
                raise BackupIntegrityError(
                    'restore destination contains an unsafe path'
                )
        for file_name in file_names:
            path = current / file_name
            relative = path.relative_to(data_dir)
            if (
                len(relative.parts) > 1
                and relative.parts[0]
                in _EXCLUDED_TOP_LEVEL_DIRECTORIES
            ):
                continue
            path_stat = path.lstat()
            if (
                stat.S_ISLNK(path_stat.st_mode)
                or not stat.S_ISREG(path_stat.st_mode)
            ):
                raise BackupIntegrityError(
                    'restore destination contains an unsafe path'
                )
            paths.add(relative)
    return paths


def _copy_for_rollback(source, rollback, relative):
    rollback_path = rollback / relative
    rollback_path.parent.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o700,
    )
    atomic_copy_file(source, rollback_path)


def _restore_staged_files(
    stage,
    data_dir,
    manifest,
    rollback,
    extra_paths,
):
    rollback_paths = set()
    new_paths = set()
    created_directories = []
    try:
        if not data_dir.exists():
            data_dir.mkdir(parents=True, mode=0o700)
            created_directories.append(data_dir)
        for relative in extra_paths:
            _copy_for_rollback(
                data_dir / relative,
                rollback,
                relative,
            )
            rollback_paths.add(relative)
        for item in manifest.files:
            relative = Path(*PurePosixPath(item.path).parts)
            target = data_dir / relative
            missing_parents = []
            parent = target.parent
            while parent != data_dir and not parent.exists():
                missing_parents.append(parent)
                parent = parent.parent
            for directory in reversed(missing_parents):
                directory.mkdir(mode=0o700)
                created_directories.append(directory)

            if target.exists():
                _copy_for_rollback(target, rollback, relative)
                rollback_paths.add(relative)
            else:
                new_paths.add(relative)
            atomic_copy_file(stage / relative, target)
        for relative in extra_paths:
            (data_dir / relative).unlink()
    except Exception:
        rollback_error = None
        for relative in reversed(tuple(rollback_paths)):
            try:
                atomic_copy_file(rollback / relative, data_dir / relative)
            except Exception as exc:
                rollback_error = rollback_error or exc
        for relative in new_paths:
            try:
                (data_dir / relative).unlink(missing_ok=True)
            except Exception as exc:
                rollback_error = rollback_error or exc
        for directory in reversed(created_directories):
            try:
                directory.rmdir()
            except OSError:
                pass
        if rollback_error is not None:
            raise RuntimeError('backup restore rollback failed') from rollback_error
        raise


def _verify_staged_files(stage, manifest):
    for item in manifest.files:
        relative = Path(*PurePosixPath(item.path).parts)
        path = stage / relative
        digest = hashlib.sha256()
        size = 0
        with path.open('rb') as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
        if size != item.size or digest.hexdigest() != item.sha256:
            raise BackupIntegrityError(
                f'backup checksum mismatch for {item.path}'
            )


def restore_backup(archive, data_dir):
    archive = Path(archive)
    data_dir = Path(data_dir)
    if data_dir.is_symlink():
        raise BackupIntegrityError(
            'restore destination must be a real directory'
        )
    data_dir = data_dir.resolve(strict=False)
    manifest = verify_backup(archive)
    require_restore_compatible(manifest)
    _validate_restore_targets(data_dir, manifest)
    existing_paths = _existing_persistent_files(data_dir)
    manifest_paths = {
        Path(*PurePosixPath(item.path).parts)
        for item in manifest.files
    }
    extra_paths = existing_paths - manifest_paths
    data_dir.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(
        dir=data_dir.parent,
        prefix='.webssh-restore-',
    ) as temporary_directory:
        temporary = Path(temporary_directory)
        stage = temporary / 'stage'
        rollback = temporary / 'rollback'
        stage.mkdir(mode=0o700)
        rollback.mkdir(mode=0o700)
        with zipfile.ZipFile(archive, 'r') as backup:
            members = _validated_members(backup)
            if _read_manifest(backup, members) != manifest:
                raise BackupIntegrityError(
                    'backup changed after initial verification'
                )
            extracted_total = 0
            for item in manifest.files:
                relative = Path(*PurePosixPath(item.path).parts)
                target = stage / relative
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                info = members[_DATA_PREFIX + item.path]
                if info.file_size != item.size:
                    raise BackupIntegrityError(
                        f'backup checksum or size mismatch for {item.path}'
                    )
                extracted_size = 0
                with backup.open(info, 'r') as source:
                    with target.open('wb') as destination:
                        while chunk := source.read(1024 * 1024):
                            extracted_size += len(chunk)
                            extracted_total += len(chunk)
                            if (
                                extracted_size > item.size
                                or extracted_size > config.BACKUP_MAX_FILE_SIZE
                                or extracted_total
                                > config.BACKUP_MAX_TOTAL_SIZE
                            ):
                                raise BackupIntegrityError(
                                    'backup streamed size exceeds configured '
                                    'limits'
                                )
                            destination.write(chunk)
                        destination.flush()
                        os.fsync(destination.fileno())
                if extracted_size != item.size:
                    raise BackupIntegrityError(
                        f'backup checksum or size mismatch for {item.path}'
                    )
                os.chmod(target, 0o600)
        _verify_staged_files(stage, manifest)
        _restore_staged_files(
            stage,
            data_dir,
            manifest,
            rollback,
            extra_paths,
        )
