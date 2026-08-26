"""Share-confined FileBackend implementation for ephemeral SMB sources."""

from __future__ import annotations

from contextlib import contextmanager
import errno
import hashlib
import secrets
import stat as stat_module

import config

from .file_backend import FileReaderLease, FileWriteOutcome
from .smb_paths import SMBPath, SMBPathRejected
from .smb_protocol import SMBProtocolError


_REPARSE_POINT = 0x00000400


class SMBBackendError(Exception):
    pass


class FileConflict(SMBBackendError):
    pass


class NonAtomicOverwriteRequired(SMBBackendError):
    """Atomic SMB replacement is unavailable for this target."""


class _MemberBudget:
    def __init__(self, limit):
        self.limit = limit
        self.used = 0

    def consume(self):
        self.used += 1
        if self.used > self.limit:
            raise SMBBackendError('Directory exceeds configured member limit')


class SMBBackend:
    def __init__(self, pool=None):
        self._bound_pool = pool

    def _pool(self):
        if self._bound_pool is not None:
            return self._bound_pool
        from . import smb_pool

        return smb_pool.smb_connection_pool

    def _owned_source(self, source):
        actual = self._pool().get_source(source.source_id, source.user_id)
        if actual is None:
            raise SMBBackendError('Source unavailable')
        return actual

    @staticmethod
    def _path(value):
        try:
            return SMBPath.parse(value)
        except SMBPathRejected as exc:
            raise SMBBackendError('Invalid path') from exc

    def _unc(self, actual, value):
        return self._path(value).to_unc(actual.target_ip, actual.share)

    @staticmethod
    def _mutable_path(path):
        if not path.segments:
            raise SMBBackendError('Share root cannot be modified')
        return path

    @staticmethod
    def _is_not_found(exc):
        return (
            isinstance(exc, FileNotFoundError)
            or isinstance(exc, SMBProtocolError)
            and exc.public_code == 'NOT_FOUND'
            or isinstance(exc, OSError)
            and exc.errno == errno.ENOENT
        )

    def _validate_path_components(
        self,
        actual,
        path,
        *,
        include_leaf=True,
        allow_missing_leaf=False,
        session=None,
    ):
        """Reject reparse points before a full-path SMB operation.

        The subsequent protocol operation also uses FILE_OPEN_REPARSE_POINT
        where the pinned client exposes an open primitive.  Walking components
        first gives stable application errors and covers mutation helpers that
        otherwise expose only a full-path API.
        """
        session = session or actual.session
        segments = path.segments if include_leaf else path.segments[:-1]
        for index in range(1, len(segments) + 1):
            component = SMBPath(segments[:index])
            try:
                file_stat = session.invoke(
                    'stat',
                    component.to_unc(actual.target_ip, actual.share),
                    follow_symlinks=False,
                )
            except Exception as exc:
                is_leaf = index == len(path.segments)
                if allow_missing_leaf and is_leaf and self._is_not_found(exc):
                    return
                raise
            if self._is_reparse(file_stat):
                raise SMBBackendError('Reparse points are not supported')

    @staticmethod
    def _is_reparse(file_stat):
        return bool(getattr(file_stat, 'st_file_attributes', 0) & _REPARSE_POINT)

    @staticmethod
    def _is_directory(file_stat):
        attributes = getattr(file_stat, 'st_file_attributes', 0)
        return bool(attributes & 0x10) or stat_module.S_ISDIR(
            getattr(file_stat, 'st_mode', 0)
        )

    @staticmethod
    def _reader_lease(remote_file):
        """Build metadata from the connected SMB handle's CREATE response."""
        handle = getattr(remote_file, 'fd', None)
        size = getattr(handle, 'end_of_file', None)
        attributes = getattr(handle, 'file_attributes', None)
        if isinstance(attributes, bool):
            raise SMBBackendError('File metadata is unavailable')
        try:
            attributes = int(attributes)
        except (TypeError, ValueError) as exc:
            raise SMBBackendError('File metadata is unavailable') from exc
        if attributes < 0:
            raise SMBBackendError('File metadata is unavailable')
        is_reparse = bool(attributes & _REPARSE_POINT)
        is_directory = bool(attributes & 0x10)
        if is_reparse or is_directory:
            raise SMBBackendError('File is not readable')
        try:
            return FileReaderLease(
                reader=remote_file,
                size=size,
                is_dir=is_directory,
                is_symlink=is_reparse,
            )
        except ValueError as exc:
            raise SMBBackendError('File metadata is unavailable') from exc

    @contextmanager
    def _open_reader_locked(self, actual, smb_path, session):
        """Open and validate one object while the caller owns its I/O lane."""
        unc = smb_path.to_unc(actual.target_ip, actual.share)
        self._validate_path_components(
            actual,
            smb_path,
            session=session,
        )
        remote_file = session.invoke(
            'open_file_no_follow',
            unc,
            mode='rb',
            buffering=0,
        )
        with remote_file:
            yield self._reader_lease(remote_file)

    @staticmethod
    def _io_lane(actual, io_lane):
        if io_lane == 'control':
            return (
                getattr(actual, 'control_session', actual.session),
                getattr(actual, 'control_lock', actual.lock),
            )
        if io_lane == 'transfer':
            return (
                getattr(actual, 'transfer_session', actual.session),
                getattr(actual, 'transfer_lock', actual.lock),
            )
        raise SMBBackendError('Invalid SMB I/O lane')

    @staticmethod
    def _write_all(remote_file, data):
        view = memoryview(data)
        written = 0
        while written < len(view):
            count = remote_file.write(view[written:])
            if not isinstance(count, int) or count <= 0:
                raise SMBBackendError('Incomplete file write')
            written += count

    @staticmethod
    def _public_error(exc):
        if isinstance(exc, SMBBackendError):
            return str(exc)
        if isinstance(exc, FileNotFoundError):
            return 'File or directory not found'
        if isinstance(exc, PermissionError):
            return 'Permission denied'
        if isinstance(exc, (TimeoutError, ConnectionError)):
            return 'SMB operation timed out'
        if isinstance(exc, SMBProtocolError):
            protocol_errors = {
                'SOURCE_UNAVAILABLE': 'Source unavailable',
                'PERMISSION_DENIED': 'Permission denied',
                'NOT_FOUND': 'File or directory not found',
                'SHARE_UNAVAILABLE': 'Share unavailable',
                'CONFLICT': 'File conflict',
                'TIMEOUT': 'SMB operation timed out',
            }
            if exc.public_code in protocol_errors:
                return protocol_errors[exc.public_code]
            return 'SMB operation failed'
        if isinstance(exc, OSError) and exc.errno == errno.ENOENT:
            return 'File or directory not found'
        return 'SMB operation failed'

    def normalize_path(self, path):
        try:
            return str(SMBPath.parse(path))
        except SMBPathRejected:
            return None

    def inspect_directory_access(self, source, path):
        """Return non-mutating access evidence for one owned directory."""
        actual = self._owned_source(source)
        directory = self._path(path)
        unc = directory.to_unc(actual.target_ip, actual.share)
        with actual.lock:
            self._validate_path_components(actual, directory)
            return actual.session.inspect_directory_access(unc)

    def list_directory(self, source, path):
        iterator = None
        try:
            actual = self._owned_source(source)
            directory = self._path(path)
            unc = directory.to_unc(actual.target_ip, actual.share)
            items = []
            with actual.lock:
                self._validate_path_components(actual, directory)
                iterator = actual.session.invoke('scandir_no_follow', unc)
                for entry in iterator:
                    try:
                        child = directory.child(entry.name)
                    except SMBPathRejected as exc:
                        raise SMBBackendError('Unsafe directory response') from exc
                    if len(items) >= config.MAX_TRANSFER_MEMBERS:
                        raise SMBBackendError('Directory exceeds configured member limit')
                    file_stat = entry.stat(follow_symlinks=False)
                    is_reparse = self._is_reparse(file_stat) or entry.is_symlink()
                    items.append({
                        'name': entry.name,
                        'path': str(child),
                        'size': getattr(file_stat, 'st_size', 0) or 0,
                        'mode': getattr(file_stat, 'st_mode', 0),
                        'is_dir': bool(
                            entry.is_dir(follow_symlinks=False)
                            and not is_reparse
                        ),
                        'is_symlink': is_reparse,
                        'modified': getattr(file_stat, 'st_mtime', 0),
                    })
            return items, None
        except Exception as exc:
            return None, self._public_error(exc)
        finally:
            if iterator is not None:
                try:
                    iterator.close()
                except Exception:
                    pass

    def stat_or_raise(self, source, path, *, follow_links=False):
        if follow_links:
            raise SMBBackendError('Reparse points are not supported')
        actual = self._owned_source(source)
        smb_path = self._path(path)
        with actual.lock:
            self._validate_path_components(actual, smb_path)
            file_stat = actual.session.invoke(
                'stat',
                smb_path.to_unc(actual.target_ip, actual.share),
                follow_symlinks=False,
            )
        if self._is_reparse(file_stat):
            raise SMBBackendError('Reparse points are not supported')
        return {
            'name': smb_path.name,
            'path': str(smb_path),
            'size': getattr(file_stat, 'st_size', 0) or 0,
            'mode': getattr(file_stat, 'st_mode', 0),
            'is_dir': self._is_directory(file_stat),
            'is_symlink': False,
            'modified': getattr(file_stat, 'st_mtime', 0),
            'permissions': oct(getattr(file_stat, 'st_mode', 0))[-3:],
        }

    def stat(self, source, path, *, follow_links=False):
        try:
            return self.stat_or_raise(
                source, path, follow_links=follow_links
            ), None
        except Exception as exc:
            return None, self._public_error(exc)

    def mkdir_or_raise(self, source, path):
        actual = self._owned_source(source)
        smb_path = self._mutable_path(self._path(path))
        with actual.lock:
            self._validate_path_components(
                actual, smb_path, include_leaf=False
            )
            actual.session.invoke(
                'mkdir_no_follow',
                smb_path.to_unc(actual.target_ip, actual.share),
            )

    def mkdir(self, source, path):
        try:
            self.mkdir_or_raise(source, path)
            return True, None
        except Exception as exc:
            return False, self._public_error(exc)

    def rename(self, source, old_path, new_path, *, replace=False):
        try:
            actual = self._owned_source(source)
            old_smb_path = self._mutable_path(self._path(old_path))
            new_smb_path = self._mutable_path(self._path(new_path))
            old_unc = old_smb_path.to_unc(actual.target_ip, actual.share)
            new_unc = new_smb_path.to_unc(actual.target_ip, actual.share)
            with actual.lock:
                self._validate_path_components(actual, old_smb_path)
                self._validate_path_components(
                    actual,
                    new_smb_path,
                    allow_missing_leaf=True,
                )
                actual.session.invoke(
                    'replace' if replace else 'rename',
                    old_unc,
                    new_unc,
                )
            return True, None
        except Exception as exc:
            return False, self._public_error(exc)

    def delete(
        self,
        source,
        path,
        *,
        recursive,
        budget,
        cancel_event,
    ):
        if cancel_event is not None and cancel_event.is_set():
            return False, 'Operation cancelled'
        try:
            actual = self._owned_source(source)
            smb_path = self._mutable_path(self._path(path))
            unc = smb_path.to_unc(actual.target_ip, actual.share)
            with actual.lock:
                self._validate_path_components(actual, smb_path)
                file_stat = actual.session.invoke(
                    'stat', unc, follow_symlinks=False
                )
                if self._is_reparse(file_stat):
                    raise SMBBackendError('Reparse points are not supported')
                if self._is_directory(file_stat):
                    if not recursive:
                        actual.session.invoke('rmdir', unc)
                else:
                    actual.session.invoke('remove', unc)
                    return True, None

            if recursive:
                entries = list(self.iter_tree(
                    source,
                    path,
                    budget=budget,
                    cancel_event=cancel_event,
                    follow_links=False,
                ))
                if any(entry['is_symlink'] for entry in entries):
                    raise SMBBackendError('Reparse points are not supported')
                files = [entry for entry in entries if not entry['is_dir']]
                directories = sorted(
                    (entry for entry in entries if entry['is_dir']),
                    key=lambda entry: entry['path'].count('/'),
                    reverse=True,
                )
                with actual.lock:
                    for entry in (*files, *directories):
                        if cancel_event is not None and cancel_event.is_set():
                            raise SMBBackendError('Operation cancelled')
                        entry_unc = self._unc(actual, entry['path'])
                        self._validate_path_components(
                            actual, self._path(entry['path'])
                        )
                        actual.session.invoke(
                            'rmdir' if entry['is_dir'] else 'remove',
                            entry_unc,
                        )
                    self._validate_path_components(actual, smb_path)
                    actual.session.invoke('rmdir', unc)
            return True, None
        except Exception as exc:
            return False, self._public_error(exc)

    @contextmanager
    def open_reader(self, source, path, *, io_lane='control'):
        actual = self._owned_source(source)
        session, lane_lock = self._io_lane(actual, io_lane)
        smb_path = self._path(path)
        with lane_lock:
            with self._open_reader_locked(actual, smb_path, session) as lease:
                yield lease

    @contextmanager
    def open_atomic_writer(
        self,
        source,
        path,
        *,
        replace,
        cancel_event,
        io_lane='control',
    ):
        actual = self._owned_source(source)
        session, lane_lock = self._io_lane(actual, io_lane)
        destination = self._path(path)
        if not destination.name:
            raise SMBBackendError('Invalid path')
        temporary = destination.parent().child(
            f'.{destination.name}.webssh-write-{secrets.token_hex(12)}.tmp'
        )
        destination_unc = destination.to_unc(actual.target_ip, actual.share)
        temporary_unc = temporary.to_unc(actual.target_ip, actual.share)
        with lane_lock:
            remote_file = None
            try:
                self._validate_path_components(
                    actual,
                    destination,
                    allow_missing_leaf=True,
                    session=session,
                )
                remote_file = session.invoke(
                    'open_file_no_follow',
                    temporary_unc,
                    mode='xb',
                    buffering=0,
                )
                with remote_file:
                    yield remote_file
                if cancel_event is not None and cancel_event.is_set():
                    raise SMBBackendError('Operation cancelled')
                try:
                    self._validate_path_components(
                        actual,
                        destination,
                        allow_missing_leaf=True,
                        session=session,
                    )
                    session.invoke(
                        'replace' if replace else 'rename',
                        temporary_unc,
                        destination_unc,
                    )
                except Exception as exc:
                    if replace:
                        if isinstance(exc, SMBProtocolError):
                            if exc.public_code == 'PERMISSION_DENIED':
                                raise NonAtomicOverwriteRequired(
                                    'Atomic replacement requires delete permission'
                                ) from exc
                            if exc.public_code != 'CONFLICT':
                                raise
                        elif not (
                            isinstance(exc, OSError)
                            and exc.errno in {errno.EEXIST, errno.ENOTEMPTY}
                        ):
                            raise
                        raise FileConflict(
                            'Atomic replacement is unavailable'
                        ) from exc
                    raise
            except Exception:
                try:
                    session.invoke('remove', temporary_unc)
                except Exception:
                    pass
                raise

    def iter_tree(
        self,
        source,
        path,
        *,
        budget,
        cancel_event,
        follow_links=False,
        io_lane='control',
    ):
        if follow_links:
            raise SMBBackendError('Following reparse points is unavailable')
        actual = self._owned_source(source)
        session, lane_lock = self._io_lane(actual, io_lane)
        root = self._path(path)
        member_budget = budget or _MemberBudget(config.MAX_TRANSFER_MEMBERS)

        def cancelled():
            return cancel_event is not None and cancel_event.is_set()

        def iterate():
            with lane_lock:
                self._validate_path_components(
                    actual, root, session=session
                )

                def walk(directory, depth=0):
                    if depth > 50:
                        raise SMBBackendError(
                            'Maximum directory depth exceeded'
                        )
                    if cancelled():
                        raise SMBBackendError('Operation cancelled')
                    iterator = session.invoke(
                        'scandir_no_follow',
                        directory.to_unc(actual.target_ip, actual.share),
                    )
                    try:
                        for entry in iterator:
                            member_budget.consume()
                            if cancelled():
                                raise SMBBackendError('Operation cancelled')
                            try:
                                child = directory.child(entry.name)
                            except SMBPathRejected as exc:
                                raise SMBBackendError(
                                    'Unsafe directory response'
                                ) from exc
                            file_stat = entry.stat(follow_symlinks=False)
                            is_reparse = (
                                self._is_reparse(file_stat)
                                or entry.is_symlink()
                            )
                            is_directory = bool(
                                entry.is_dir(follow_symlinks=False)
                                and not is_reparse
                            )
                            yield {
                                'name': entry.name,
                                'path': str(child),
                                'size': getattr(file_stat, 'st_size', 0) or 0,
                                'mode': getattr(file_stat, 'st_mode', 0),
                                'is_dir': is_directory,
                                'is_symlink': is_reparse,
                            }
                            if is_directory:
                                yield from walk(child, depth + 1)
                    finally:
                        try:
                            iterator.close()
                        except Exception:
                            pass

                yield from walk(root)

        return iterate()

    def get_home_directory(self, source):
        try:
            self._owned_source(source)
            return '/', None
        except Exception as exc:
            return None, self._public_error(exc)

    def check_exists_or_raise(self, source, path):
        try:
            result = self.stat_or_raise(source, path, follow_links=False)
        except Exception as exc:
            if self._is_not_found(exc):
                return {'exists': False, 'is_dir': False, 'size': 0}
            raise
        return {
            'exists': True,
            'is_dir': result['is_dir'],
            'size': result['size'],
        }

    def check_exists(self, source, path):
        try:
            return self.check_exists_or_raise(source, path), None
        except Exception as exc:
            error = self._public_error(exc)
        if error == 'File or directory not found':
            return {'exists': False, 'is_dir': False, 'size': 0}, None
        return None, error

    def get_file_stat(self, source, path):
        return self.stat(source, path, follow_links=False)

    def _read_bounded(self, source, path, maximum, *, offset=0):
        if maximum < 0 or offset < 0:
            raise SMBBackendError('Invalid read range')
        actual = self._owned_source(source)
        smb_path = self._path(path)
        with actual.lock:
            with self._open_reader_locked(
                actual,
                smb_path,
                actual.session,
            ) as lease:
                if offset:
                    lease.reader.seek(offset)
                data = lease.reader.read(maximum + 1)
                return lease.size, data

    def _editor_revision_locked(self, actual, destination):
        """Hash one validated editor target while the caller owns its lane."""
        with self._open_reader_locked(
            actual,
            destination,
            actual.session,
        ) as lease:
            if lease.size > config.MAX_EDITOR_FILE_SIZE:
                raise SMBBackendError('File too large to edit')
            data = lease.reader.read(config.MAX_EDITOR_FILE_SIZE + 1)
        if len(data) > config.MAX_EDITOR_FILE_SIZE:
            raise SMBBackendError('File too large to edit')
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _edit_conflict():
        return FileWriteOutcome(
            success=False,
            error='The file changed on the server. Reopen it before saving.',
            code='EDIT_CONFLICT',
        )

    @staticmethod
    def _generated_leaf(destination, purpose, token):
        return f'.{destination.name}.webssh-{purpose}-{token}'

    def _remove_generated(self, actual, path):
        try:
            actual.session.invoke(
                'remove', path.to_unc(actual.target_ip, actual.share)
            )
            return True
        except Exception:
            return False

    def _recoverable_replace(
        self,
        actual,
        destination,
        data,
        *,
        expected_revision,
    ):
        """Install an editor save with a sibling backup and bounded rollback."""
        token = secrets.token_hex(12)
        temporary = destination.parent().child(
            self._generated_leaf(destination, 'write', token) + '.tmp'
        )
        recovery = destination.parent().child(
            self._generated_leaf(destination, 'recovery', token) + '.bak'
        )
        destination_unc = destination.to_unc(actual.target_ip, actual.share)
        temporary_unc = temporary.to_unc(actual.target_ip, actual.share)
        recovery_unc = recovery.to_unc(actual.target_ip, actual.share)

        with actual.lock:
            try:
                current_revision = self._editor_revision_locked(
                    actual, destination
                )
            except Exception as exc:
                return FileWriteOutcome(
                    success=False,
                    error=self._public_error(exc),
                )
            if not expected_revision or expected_revision != current_revision:
                return self._edit_conflict()

            try:
                self._validate_path_components(
                    actual, temporary, allow_missing_leaf=True
                )
                self._validate_path_components(
                    actual, recovery, allow_missing_leaf=True
                )
                remote_file = actual.session.invoke(
                    'open_file_no_follow',
                    temporary_unc,
                    mode='xb',
                    buffering=0,
                )
                with remote_file:
                    self._write_all(remote_file, data)
            except Exception as exc:
                self._remove_generated(actual, temporary)
                return FileWriteOutcome(
                    success=False,
                    error=self._public_error(exc),
                )

            try:
                self._validate_path_components(actual, destination)
                actual.session.invoke('rename', destination_unc, recovery_unc)
            except Exception as exc:
                removed = self._remove_generated(actual, temporary)
                if not removed:
                    return FileWriteOutcome(
                        success=False,
                        error='The save failed and a temporary recovery file remains.',
                        code='SMB_RECOVERY_REQUIRED',
                        recovery_leaves=(temporary.name,),
                    )
                return FileWriteOutcome(
                    success=False,
                    error=self._public_error(exc),
                )

            try:
                actual.session.invoke('rename', temporary_unc, destination_unc)
            except Exception:
                try:
                    actual.session.invoke('rename', recovery_unc, destination_unc)
                except Exception:
                    return FileWriteOutcome(
                        success=False,
                        error=(
                            'The replacement and automatic rollback failed. '
                            'Manual recovery is required.'
                        ),
                        code='SMB_RECOVERY_REQUIRED',
                        recovery_leaves=(temporary.name, recovery.name),
                    )
                self._remove_generated(actual, temporary)
                return FileWriteOutcome(
                    success=False,
                    error='The replacement failed. The original file was restored.',
                    code='SMB_RECOVERABLE_REPLACE_FAILED',
                )

            revision = hashlib.sha256(data).hexdigest()
            if not self._remove_generated(actual, recovery):
                return FileWriteOutcome(
                    success=True,
                    warning_code='SMB_RECOVERY_BACKUP_RETAINED',
                    recovery_leaves=(recovery.name,),
                    revision=revision,
                )
            return FileWriteOutcome(success=True, revision=revision)

    @staticmethod
    def _decode(data):
        if b'\x00' in data[:1024]:
            return None, True, None
        try:
            return data.decode('utf-8'), False, 'utf-8'
        except UnicodeDecodeError:
            try:
                return data.decode('latin-1'), False, 'latin-1'
            except UnicodeDecodeError:
                return None, True, None

    def read_file_preview(
        self,
        source,
        path,
        *,
        max_bytes,
        offset,
        tail_lines,
    ):
        try:
            max_bytes = min(int(max_bytes), config.MAX_PREVIEW_SIZE)
            offset = int(offset)
            if max_bytes <= 0 or offset < 0:
                raise SMBBackendError('Invalid preview options')

            actual = self._owned_source(source)
            smb_path = self._path(path)
            with actual.lock:
                with self._open_reader_locked(
                    actual,
                    smb_path,
                    actual.session,
                ) as lease:
                    file_size = lease.size
                    if file_size > config.MAX_SUPPORTED_FILE_SIZE:
                        raise SMBBackendError('File exceeds supported size')
                    read_offset = (
                        max(0, file_size - max_bytes) if tail_lines else offset
                    )
                    if read_offset:
                        lease.reader.seek(read_offset)
                    data = lease.reader.read(max_bytes + 1)
            available_at_stat = max(0, file_size - read_offset)
            if len(data) > max_bytes and available_at_stat <= max_bytes:
                raise SMBBackendError('File exceeds preview limit')
            data = data[:max_bytes]
            if tail_lines:
                try:
                    requested_lines = max(1, min(
                        int(tail_lines), config.MAX_PREVIEW_TAIL_LINES
                    ))
                except (TypeError, ValueError) as exc:
                    raise SMBBackendError('Invalid preview options') from exc
                lines = data.split(b'\n')
                if len(lines) > requested_lines:
                    data = b'\n'.join(lines[-requested_lines:])
            content, binary, _encoding = self._decode(data)
            return {
                'content': content,
                'size': file_size,
                'read_size': len(data),
                'truncated': read_offset > 0 or read_offset + len(data) < file_size,
                'is_binary': binary,
                'offset': read_offset,
            }, None
        except Exception as exc:
            return None, self._public_error(exc)

    def read_file_for_edit(self, source, path):
        try:
            file_size, data = self._read_bounded(
                source,
                path,
                config.MAX_EDITOR_FILE_SIZE,
            )
            if file_size > config.MAX_EDITOR_FILE_SIZE or len(data) > config.MAX_EDITOR_FILE_SIZE:
                raise SMBBackendError('File too large to edit')
            content, binary, encoding = self._decode(data)
            if binary or content is None:
                raise SMBBackendError('Binary file cannot be edited')
            newline = 'crlf' if b'\r\n' in data else 'lf'
            return {
                'content': content.replace('\r\n', '\n'),
                'size': file_size,
                'encoding': encoding,
                'newline': newline,
                'revision': hashlib.sha256(data).hexdigest(),
            }, None
        except Exception as exc:
            return None, self._public_error(exc)

    def read_binary_preview(self, source, path, *, max_size):
        try:
            file_size, data = self._read_bounded(source, path, max_size)
            if file_size > max_size or len(data) > max_size:
                raise SMBBackendError('File too large for download')
            return data, None
        except Exception as exc:
            return None, self._public_error(exc)

    def write_file_text(
        self,
        source,
        path,
        content,
        *,
        encoding,
        newline,
        allow_non_atomic=False,
        expected_revision=None,
        replace_strategy='atomic',
    ):
        try:
            if not isinstance(content, str):
                raise SMBBackendError('Invalid file content')
            if encoding not in {'utf-8', 'latin-1'}:
                encoding = 'utf-8'
            text = content.replace('\r\n', '\n')
            if newline == 'crlf':
                text = text.replace('\n', '\r\n')
            try:
                data = text.encode(encoding)
            except UnicodeEncodeError:
                data = text.encode('utf-8')
            if len(data) > config.MAX_EDITOR_FILE_SIZE:
                raise SMBBackendError('File too large to edit')
            # Retained for wire compatibility only. A boolean must never enable
            # a truncating overwrite of the destination.
            del allow_non_atomic
            if replace_strategy not in {'atomic', 'recoverable_swap'}:
                raise SMBBackendError('Invalid replacement strategy')

            actual = self._owned_source(source)
            destination = self._mutable_path(self._path(path))
            if replace_strategy == 'recoverable_swap':
                return self._recoverable_replace(
                    actual,
                    destination,
                    data,
                    expected_revision=expected_revision,
                )

            with actual.lock:
                current_revision = self._editor_revision_locked(
                    actual, destination
                )
                if (
                    not expected_revision
                    or expected_revision != current_revision
                ):
                    return self._edit_conflict()
                try:
                    with self.open_atomic_writer(
                        source,
                        path,
                        replace=True,
                        cancel_event=None,
                    ) as remote_file:
                        self._write_all(remote_file, data)
                except NonAtomicOverwriteRequired:
                    return FileWriteOutcome(
                        success=False,
                        error=(
                            'This SMB account cannot replace the file '
                            'atomically.'
                        ),
                        code='SMB_RECOVERABLE_REPLACE_REQUIRED',
                        revision=current_revision,
                    )
            return FileWriteOutcome(
                success=True,
                revision=hashlib.sha256(data).hexdigest(),
            )
        except Exception as exc:
            return FileWriteOutcome(
                success=False,
                error=self._public_error(exc),
            )


smb_backend = SMBBackend()
