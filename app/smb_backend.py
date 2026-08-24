"""Share-confined FileBackend implementation for ephemeral SMB sources."""

from __future__ import annotations

from contextlib import contextmanager
import errno
import secrets
import stat as stat_module

import config

from .smb_paths import SMBPath, SMBPathRejected
from .smb_protocol import SMBProtocolError


_REPARSE_POINT = 0x00000400


class SMBBackendError(Exception):
    pass


class FileConflict(SMBBackendError):
    pass


class NonAtomicOverwriteRequired(SMBBackendError):
    """Atomic SMB replacement was denied but a direct overwrite may work."""


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
    ):
        """Reject reparse points before a full-path SMB operation.

        The subsequent protocol operation also uses FILE_OPEN_REPARSE_POINT
        where the pinned client exposes an open primitive.  Walking components
        first gives stable application errors and covers mutation helpers that
        otherwise expose only a full-path API.
        """
        segments = path.segments if include_leaf else path.segments[:-1]
        for index in range(1, len(segments) + 1):
            component = SMBPath(segments[:index])
            try:
                file_stat = actual.session.invoke(
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

    def stat(self, source, path, *, follow_links=False):
        if follow_links:
            return None, 'Reparse points are not supported'
        try:
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
            }, None
        except Exception as exc:
            return None, self._public_error(exc)

    def mkdir(self, source, path):
        try:
            actual = self._owned_source(source)
            smb_path = self._path(path)
            with actual.lock:
                self._validate_path_components(
                    actual, smb_path, include_leaf=False
                )
                actual.session.invoke(
                    'mkdir_no_follow',
                    smb_path.to_unc(actual.target_ip, actual.share),
                )
            return True, None
        except Exception as exc:
            return False, self._public_error(exc)

    def rename(self, source, old_path, new_path, *, replace=False):
        try:
            actual = self._owned_source(source)
            old_unc = self._unc(actual, old_path)
            new_unc = self._unc(actual, new_path)
            old_smb_path = self._path(old_path)
            new_smb_path = self._path(new_path)
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
            unc = self._unc(actual, path)
            smb_path = self._path(path)
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
    def open_reader(self, source, path):
        actual = self._owned_source(source)
        smb_path = self._path(path)
        unc = smb_path.to_unc(actual.target_ip, actual.share)
        with actual.lock:
            self._validate_path_components(actual, smb_path)
            file_stat = actual.session.invoke(
                'stat', unc, follow_symlinks=False
            )
            if self._is_reparse(file_stat) or self._is_directory(file_stat):
                raise SMBBackendError('File is not readable')
            remote_file = actual.session.invoke(
                'open_file_no_follow', unc, mode='rb', buffering=0
            )
            with remote_file:
                yield remote_file

    @contextmanager
    def open_atomic_writer(
        self,
        source,
        path,
        *,
        replace,
        cancel_event,
    ):
        actual = self._owned_source(source)
        destination = self._path(path)
        if not destination.name:
            raise SMBBackendError('Invalid path')
        temporary = destination.parent().child(
            f'.{destination.name}.webssh-write-{secrets.token_hex(12)}.tmp'
        )
        destination_unc = destination.to_unc(actual.target_ip, actual.share)
        temporary_unc = temporary.to_unc(actual.target_ip, actual.share)
        with actual.lock:
            remote_file = None
            try:
                self._validate_path_components(
                    actual,
                    destination,
                    allow_missing_leaf=True,
                )
                remote_file = actual.session.invoke(
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
                    )
                    actual.session.invoke(
                        'replace' if replace else 'rename',
                        temporary_unc,
                        destination_unc,
                    )
                except Exception as exc:
                    if replace:
                        if (
                            isinstance(exc, SMBProtocolError)
                            and exc.public_code == 'PERMISSION_DENIED'
                        ):
                            raise NonAtomicOverwriteRequired(
                                'Atomic replacement requires delete permission'
                            ) from exc
                        raise FileConflict(
                            'Atomic replacement is unavailable'
                        ) from exc
                    raise
            except Exception:
                try:
                    actual.session.invoke('remove', temporary_unc)
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
    ):
        if follow_links:
            raise SMBBackendError('Following reparse points is unavailable')
        actual = self._owned_source(source)
        root = self._path(path)
        member_budget = budget or _MemberBudget(config.MAX_TRANSFER_MEMBERS)

        def cancelled():
            return cancel_event is not None and cancel_event.is_set()

        def iterate():
            with actual.lock:
                self._validate_path_components(actual, root)

                def walk(directory, depth=0):
                    if depth > 50:
                        raise SMBBackendError(
                            'Maximum directory depth exceeded'
                        )
                    if cancelled():
                        raise SMBBackendError('Operation cancelled')
                    iterator = actual.session.invoke(
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

    def check_exists(self, source, path):
        result, error = self.stat(source, path, follow_links=False)
        if error == 'File or directory not found':
            return {'exists': False, 'is_dir': False, 'size': 0}, None
        if error:
            return None, error
        return {
            'exists': True,
            'is_dir': result['is_dir'],
            'size': result['size'],
        }, None

    def get_file_stat(self, source, path):
        return self.stat(source, path, follow_links=False)

    def _read_bounded(self, source, path, maximum, *, offset=0):
        if maximum < 0 or offset < 0:
            raise SMBBackendError('Invalid read range')
        actual = self._owned_source(source)
        smb_path = self._path(path)
        unc = smb_path.to_unc(actual.target_ip, actual.share)
        with actual.lock:
            self._validate_path_components(actual, smb_path)
            file_stat = actual.session.invoke(
                'stat', unc, follow_symlinks=False
            )
            if self._is_reparse(file_stat) or self._is_directory(file_stat):
                raise SMBBackendError('File is not readable')
            file_size = getattr(file_stat, 'st_size', 0) or 0
            remote_file = actual.session.invoke(
                'open_file_no_follow', unc, mode='rb', buffering=0
            )
            with remote_file:
                if offset:
                    remote_file.seek(offset)
                data = remote_file.read(maximum + 1)
        return file_size, data

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
            unc = smb_path.to_unc(actual.target_ip, actual.share)
            with actual.lock:
                self._validate_path_components(actual, smb_path)
                file_stat = actual.session.invoke(
                    'stat', unc, follow_symlinks=False
                )
                if self._is_reparse(file_stat) or self._is_directory(file_stat):
                    raise SMBBackendError('File is not readable')
                file_size = getattr(file_stat, 'st_size', 0) or 0
                if file_size > config.MAX_SUPPORTED_FILE_SIZE:
                    raise SMBBackendError('File exceeds supported size')
                read_offset = (
                    max(0, file_size - max_bytes) if tail_lines else offset
                )
                remote_file = actual.session.invoke(
                    'open_file_no_follow', unc, mode='rb', buffering=0
                )
                with remote_file:
                    if read_offset:
                        remote_file.seek(read_offset)
                    data = remote_file.read(max_bytes + 1)
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
            try:
                with self.open_atomic_writer(
                    source,
                    path,
                    replace=True,
                    cancel_event=None,
                ) as remote_file:
                    self._write_all(remote_file, data)
            except NonAtomicOverwriteRequired:
                if allow_non_atomic is not True:
                    raise
                actual = self._owned_source(source)
                destination_unc = self._unc(actual, path)
                destination = self._path(path)
                with actual.lock:
                    self._validate_path_components(actual, destination)
                    file_stat = actual.session.invoke(
                        'stat',
                        destination_unc,
                        follow_symlinks=False,
                    )
                    if self._is_reparse(file_stat):
                        raise SMBBackendError(
                            'Reparse points are not supported'
                        )
                    if self._is_directory(file_stat):
                        raise SMBBackendError('File is not writable')
                    remote_file = actual.session.invoke(
                        'open_file_no_follow',
                        destination_unc,
                        mode='wb',
                        buffering=0,
                    )
                    with remote_file:
                        self._write_all(remote_file, data)
            return True, None
        except NonAtomicOverwriteRequired:
            raise
        except Exception as exc:
            return False, self._public_error(exc)


smb_backend = SMBBackend()
