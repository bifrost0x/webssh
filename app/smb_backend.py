"""Share-confined FileBackend implementation for ephemeral SMB sources."""

from __future__ import annotations

from contextlib import contextmanager
import errno
import hashlib
import secrets
import stat as stat_module

import config

from .file_backend import (
    FileOperationCancelled,
    FileReaderLease,
    FileSourceChanged,
    FileWriteOutcome,
)
from .smb_paths import SMBPath, SMBPathRejected
from .smb_protocol import SMBProtocolError


_REPARSE_POINT = 0x00000400
_DIRECTORY = 0x00000010
_READ_ONLY = 0x00000001
_SOURCE_CHANGED_PROTOCOL_CODES = frozenset({
    'CONFLICT',
    'IDENTITY_UNAVAILABLE',
    'NOT_FOUND',
    'REPARSE_POINT_REJECTED',
})


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


class _SMBDirectoryListing:
    """One SMB scandir iterator resumed under the owned source lock."""

    def __init__(self, backend, source, path):
        self._backend = backend
        self._actual = backend._owned_source(source)
        self._directory = backend._path(path)
        self._iterator = None
        self._lookahead = None
        self._budget = _MemberBudget(config.MAX_TRANSFER_MEMBERS)
        self._closed = False
        with self._actual.lock:
            self._iterator = self._actual.session.invoke(
                'scandir_verified',
                self._directory.to_unc(
                    self._actual.target_ip,
                    self._actual.share,
                ),
            )

    def _next_payload(self):
        if self._iterator is None:
            raise StopIteration
        entry = next(self._iterator)
        self._budget.consume()
        return self._backend._directory_payload(self._directory, entry)

    def read_page(self, page_size):
        if self._closed:
            return None, 'Directory listing expired', False
        try:
            with self._actual.lock:
                page = []
                if self._lookahead is not None:
                    page.append(self._lookahead)
                    self._lookahead = None
                while len(page) < page_size:
                    page.append(self._next_payload())
                try:
                    self._lookahead = self._next_payload()
                except StopIteration:
                    self._close_locked()
                    return page, None, False
                return page, None, True
        except StopIteration:
            with self._actual.lock:
                self._close_locked()
            return page, None, False
        except Exception as error:
            with self._actual.lock:
                self._close_locked()
            return None, self._backend._public_error(error), False

    def _close_locked(self):
        if self._closed:
            return
        self._closed = True
        if self._iterator is not None:
            try:
                self._iterator.close()
            except Exception:
                pass
            self._iterator = None

    def close(self):
        with self._actual.lock:
            self._close_locked()


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
    def _stable_identity(value):
        if isinstance(value, bool):
            raise SMBBackendError('SMB object identity is unavailable')
        try:
            identity = int(value)
        except (TypeError, ValueError) as exc:
            raise SMBBackendError(
                'SMB object identity is unavailable'
            ) from exc
        if identity <= 0:
            raise SMBBackendError('SMB object identity is unavailable')
        return identity

    @contextmanager
    def _mutation_guard(
        self,
        actual,
        *paths,
        session=None,
    ):
        """Pin every existing ancestor until a path mutation completes."""
        session = session or actual.session
        ancestors = []
        seen = set()
        for path in paths:
            for index in range(1, len(path.segments)):
                ancestor = SMBPath(path.segments[:index]).to_unc(
                    actual.target_ip,
                    actual.share,
                )
                if ancestor not in seen:
                    seen.add(ancestor)
                    ancestors.append(ancestor)
        with session.pin_mutation_ancestors(ancestors):
            yield

    @staticmethod
    def _is_reparse(file_stat):
        return bool(getattr(file_stat, 'st_file_attributes', 0) & _REPARSE_POINT)

    @staticmethod
    def _is_directory(file_stat):
        attributes = getattr(file_stat, 'st_file_attributes', 0)
        return bool(attributes & 0x10) or stat_module.S_ISDIR(
            getattr(file_stat, 'st_mode', 0)
        )

    def _directory_payload(
        self,
        directory,
        entry,
        *,
        identity_chain=None,
    ):
        try:
            child = directory.child(entry.name)
        except SMBPathRejected as exc:
            raise SMBBackendError('Unsafe directory response') from exc
        info = getattr(entry, 'smb_info', None)
        if info is None:
            raise SMBBackendError('File metadata is unavailable')
        identity = self._stable_identity(getattr(info, 'file_id', None))
        try:
            attributes = int(getattr(info, 'file_attributes'))
            size = int(getattr(info, 'end_of_file'))
        except (TypeError, ValueError, AttributeError) as exc:
            raise SMBBackendError('File metadata is unavailable') from exc
        if attributes < 0 or size < 0:
            raise SMBBackendError('File metadata is unavailable')
        is_reparse = bool(attributes & _REPARSE_POINT)
        is_directory = bool(attributes & _DIRECTORY) and not is_reparse
        mode = (
            stat_module.S_IFDIR | 0o111
            if attributes & _DIRECTORY
            else stat_module.S_IFREG
        )
        mode |= 0o444 if attributes & _READ_ONLY else 0o666
        modified = getattr(info, 'last_write_time', 0)
        if hasattr(modified, 'timestamp'):
            modified = modified.timestamp()
        if not isinstance(modified, (int, float)):
            modified = 0
        payload = {
            'name': entry.name,
            'path': str(child),
            'size': size,
            'mode': mode,
            'is_dir': is_directory,
            'is_symlink': is_reparse,
            'modified': modified,
        }
        if identity_chain is not None:
            payload['_smb_identity'] = identity
            payload['_smb_identity_chain'] = tuple(identity_chain) + (
                identity,
            )
        return payload

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
    def _open_reader_locked(
        self,
        actual,
        smb_path,
        session,
        *,
        expected_identities=None,
    ):
        """Open and validate one object while the caller owns its I/O lane."""
        unc = smb_path.to_unc(actual.target_ip, actual.share)
        remote_file = session.invoke(
            'open_file_verified',
            unc,
            expected_identities=expected_identities,
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
        if isinstance(exc, FileOperationCancelled):
            return 'Operation cancelled'
        if isinstance(exc, SMBBackendError):
            return str(exc)
        if isinstance(exc, FileSourceChanged):
            return 'File conflict'
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
                'REPARSE_POINT_REJECTED': 'Reparse points are not supported',
                'IDENTITY_UNAVAILABLE': (
                    'SMB object identity is unavailable'
                ),
                'MUTATION_GUARD_REQUIRED': 'SMB mutation safety check failed',
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
            return actual.session.inspect_directory_access(unc)

    def list_directory(self, source, path):
        try:
            actual = self._owned_source(source)
            directory = self._path(path)
            items = []
            iterator = None
            with actual.lock:
                try:
                    iterator = actual.session.invoke(
                        'scandir_verified',
                        directory.to_unc(actual.target_ip, actual.share),
                    )
                    for entry in iterator:
                        if len(items) >= config.MAX_TRANSFER_MEMBERS:
                            raise SMBBackendError(
                                'Directory exceeds configured member limit'
                            )
                        items.append(
                            self._directory_payload(directory, entry)
                        )
                finally:
                    if iterator is not None:
                        iterator.close()
            return items, None
        except Exception as exc:
            return None, self._public_error(exc)

    def open_directory_listing(self, source, path):
        try:
            return _SMBDirectoryListing(self, source, path), None
        except Exception as error:
            return None, self._public_error(error)

    def stat_or_raise(self, source, path, *, follow_links=False):
        if follow_links:
            raise SMBBackendError('Reparse points are not supported')
        actual = self._owned_source(source)
        smb_path = self._path(path)
        with actual.lock:
            info = actual.session.invoke(
                'stat_verified',
                smb_path.to_unc(actual.target_ip, actual.share),
            )
        try:
            attributes = int(info.file_attributes)
            size = int(info.end_of_file)
            modified = float(info.last_write_time)
        except (TypeError, ValueError, AttributeError) as exc:
            raise SMBBackendError('File metadata is unavailable') from exc
        if attributes < 0 or size < 0:
            raise SMBBackendError('File metadata is unavailable')
        if attributes & _REPARSE_POINT:
            raise SMBBackendError('Reparse points are not supported')
        try:
            identity_chain = tuple(
                self._stable_identity(value)
                for value in info.identity_chain
            )
        except (TypeError, AttributeError) as exc:
            raise SMBBackendError(
                'SMB object identity is unavailable'
            ) from exc
        if len(identity_chain) != len(smb_path.segments):
            raise SMBBackendError('SMB object identity is unavailable')
        mode = (
            stat_module.S_IFDIR | 0o111
            if attributes & _DIRECTORY
            else stat_module.S_IFREG
        )
        mode |= 0o444 if attributes & _READ_ONLY else 0o666
        return {
            'name': smb_path.name,
            'path': str(smb_path),
            'size': size,
            'mode': mode,
            'is_dir': bool(attributes & _DIRECTORY),
            'is_symlink': False,
            'modified': modified,
            'permissions': oct(mode)[-3:],
            '_smb_identity_chain': identity_chain,
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
            with self._mutation_guard(actual, smb_path):
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
                with self._mutation_guard(
                    actual, old_smb_path, new_smb_path
                ):
                    self._validate_path_components(actual, old_smb_path)
                    self._validate_path_components(
                        actual,
                        new_smb_path,
                        allow_missing_leaf=True,
                    )
                    actual.session.invoke(
                        'rename_verified',
                        old_unc,
                        new_unc,
                        replace=replace,
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
                root_info = actual.session.invoke('stat_verified', unc)
                root_chain = tuple(
                    self._stable_identity(value)
                    for value in root_info.identity_chain
                )
                if len(root_chain) != len(smb_path.segments):
                    raise SMBBackendError(
                        'SMB object identity is unavailable'
                    )
                try:
                    root_attributes = int(root_info.file_attributes)
                except (TypeError, ValueError, AttributeError) as exc:
                    raise SMBBackendError(
                        'File metadata is unavailable'
                    ) from exc
                if root_attributes & _REPARSE_POINT:
                    raise SMBBackendError('Reparse points are not supported')
                is_directory = bool(root_attributes & _DIRECTORY)
                if not is_directory or not recursive:
                    with self._mutation_guard(actual, smb_path):
                        actual.session.invoke(
                            'delete_verified',
                            unc,
                            expected_identities=root_chain,
                        )
                    return True, None

            entries = list(self.iter_tree(
                source,
                path,
                budget=budget,
                cancel_event=cancel_event,
                follow_links=False,
                _expected_identities=root_chain,
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
                        raise FileOperationCancelled('Operation cancelled')
                    entry_path = self._path(entry['path'])
                    identity_chain = tuple(
                        self._stable_identity(value)
                        for value in entry.get(
                            '_smb_identity_chain',
                            (),
                        )
                    )
                    if len(identity_chain) != len(entry_path.segments):
                        raise SMBBackendError(
                            'SMB object identity is unavailable'
                        )
                    with self._mutation_guard(actual, entry_path):
                        actual.session.invoke(
                            'delete_verified',
                            self._unc(actual, entry['path']),
                            expected_identities=identity_chain,
                        )
                if cancel_event is not None and cancel_event.is_set():
                    raise FileOperationCancelled('Operation cancelled')
                with self._mutation_guard(actual, smb_path):
                    actual.session.invoke(
                        'delete_verified',
                        unc,
                        expected_identities=root_chain,
                    )
            return True, None
        except Exception as exc:
            return False, self._public_error(exc)

    @contextmanager
    def open_reader(
        self,
        source,
        path,
        *,
        io_lane='control',
        _expected_identities=None,
    ):
        actual = self._owned_source(source)
        session, lane_lock = self._io_lane(actual, io_lane)
        smb_path = self._path(path)
        with lane_lock:
            opened = False
            try:
                with self._open_reader_locked(
                    actual,
                    smb_path,
                    session,
                    expected_identities=_expected_identities,
                ) as lease:
                    opened = True
                    yield lease
            except SMBProtocolError as exc:
                if (
                    not opened
                    and _expected_identities is not None
                    and exc.public_code in _SOURCE_CHANGED_PROTOCOL_CODES
                ):
                    raise FileSourceChanged(
                        'The enumerated remote file changed before opening'
                    ) from exc
                raise

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
            installed = False
            cleanup_allowed = True
            try:
                with self._mutation_guard(
                    actual, destination, temporary, session=session
                ):
                    self._validate_path_components(
                        actual,
                        destination,
                        allow_missing_leaf=True,
                        session=session,
                    )
                    remote_file = session.invoke(
                        'create_file_move_verified',
                        temporary_unc,
                    )
                    yield remote_file
                    if cancel_event is not None and cancel_event.is_set():
                        raise FileOperationCancelled('Operation cancelled')
                    try:
                        self._validate_path_components(
                            actual,
                            destination,
                            allow_missing_leaf=True,
                            session=session,
                        )
                        cleanup_allowed = False
                        committed, rename_error = (
                            self._rename_open_handle_reconciled(
                                session,
                                remote_file,
                                temporary_unc,
                                destination_unc,
                                replace=replace,
                            )
                        )
                        if committed is True:
                            installed = True
                        else:
                            cleanup_allowed = committed is False
                            raise rename_error
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
            except BaseException:
                if (
                    remote_file is not None
                    and not installed
                    and cleanup_allowed
                ):
                    try:
                        session.invoke(
                            'delete_open_handle_verified', remote_file
                        )
                    except Exception:
                        pass
                raise
            finally:
                if remote_file is not None:
                    try:
                        self._close_handle_or_taint_session(
                            session,
                            remote_file,
                        )
                    except Exception:
                        if installed:
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
        _expected_identities=None,
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
                def walk(
                    directory,
                    depth=0,
                    expected_identities=None,
                    parent_iterator=None,
                    parent_entry=None,
                ):
                    if depth > 50:
                        raise SMBBackendError(
                            'Maximum directory depth exceeded'
                        )
                    if cancelled():
                        raise FileOperationCancelled('Operation cancelled')
                    if parent_iterator is None:
                        iterator = session.invoke(
                            'scandir_verified',
                            directory.to_unc(
                                actual.target_ip,
                                actual.share,
                            ),
                            expected_identities=expected_identities,
                        )
                    else:
                        try:
                            iterator = parent_iterator.open_child_directory(
                                parent_entry
                            )
                        except SMBProtocolError as exc:
                            if (
                                exc.public_code
                                in _SOURCE_CHANGED_PROTOCOL_CODES
                            ):
                                raise FileSourceChanged(
                                    'The enumerated remote tree changed '
                                    'during traversal'
                                ) from exc
                            raise
                    try:
                        identity_chain = tuple(
                            self._stable_identity(value)
                            for value in iterator.identity_chain
                        )
                        if len(identity_chain) != len(directory.segments):
                            raise SMBBackendError(
                                'SMB object identity is unavailable'
                            )
                        for entry in iterator:
                            member_budget.consume()
                            if cancelled():
                                raise FileOperationCancelled(
                                    'Operation cancelled'
                                )
                            payload = self._directory_payload(
                                directory,
                                entry,
                                identity_chain=identity_chain,
                            )
                            yield payload
                            if payload['is_dir']:
                                yield from walk(
                                    self._path(payload['path']),
                                    depth + 1,
                                    parent_iterator=iterator,
                                    parent_entry=entry,
                                )
                    finally:
                        iterator.close()

                try:
                    yield from walk(
                        root,
                        expected_identities=_expected_identities,
                    )
                except SMBProtocolError as exc:
                    if (
                        exc.public_code == 'CONFLICT'
                        or (
                            _expected_identities is not None
                            and exc.public_code
                            in _SOURCE_CHANGED_PROTOCOL_CODES
                        )
                    ):
                        raise FileSourceChanged(
                            'The enumerated remote tree changed during traversal'
                        ) from exc
                    raise

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
    def _editor_revision_from_handle(remote_file, info):
        """Hash bytes from the exact handle that will later be renamed."""
        try:
            size = int(info.end_of_file)
        except (TypeError, ValueError, AttributeError) as exc:
            raise SMBBackendError('File metadata is unavailable') from exc
        if size < 0 or size > config.MAX_EDITOR_FILE_SIZE:
            raise SMBBackendError('File too large to edit')
        remote_file.seek(0)
        data = remote_file.read(config.MAX_EDITOR_FILE_SIZE + 1)
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

    @staticmethod
    def _open_handle_location(session, remote_file, candidates):
        """Locate an open FILEID without reopening candidate pathnames."""
        for label, candidate in candidates:
            try:
                matches = session.invoke(
                    'open_handle_matches_path_verified',
                    remote_file,
                    candidate,
                )
            except Exception:
                return None
            if matches is True:
                return label
            if matches is not False:
                return None
        return None

    def _rename_open_handle_reconciled(
        self,
        session,
        remote_file,
        source_unc,
        destination_unc,
        *,
        replace,
    ):
        """Resolve a lost rename response through the same open FILEID."""
        try:
            session.invoke(
                'rename_open_handle_verified',
                remote_file,
                destination_unc,
                replace=replace,
            )
            return True, None
        except Exception as error:
            location = self._open_handle_location(
                session,
                remote_file,
                (
                    ('destination', destination_unc),
                    ('source', source_unc),
                ),
            )
            if location == 'destination':
                return True, None
            if location == 'source':
                return False, error
            return None, error

    def _delete_generated_handle(self, actual, remote_file):
        try:
            actual.session.invoke(
                'delete_open_handle_verified', remote_file
            )
            return True
        except Exception:
            return False

    @staticmethod
    def _close_handle_or_taint_session(session, remote_file):
        """Close one handle, or make a pre-send close failure non-reusable.

        smbprotocol marks the handle closed even when the server's CLOSE reply
        is lost. If it is still open, close the owning protocol session so an
        exclusive FILEID cannot make a successfully installed destination
        inaccessible to subsequent connections.
        """
        try:
            remote_file.close()
            return False
        except BaseException as close_error:
            control_flow_error = not isinstance(close_error, Exception)
            try:
                if remote_file.closed:
                    if control_flow_error:
                        raise close_error
                    return False
            except (AttributeError, RuntimeError):
                pass
            close_session = getattr(session, 'close', None)
            if not callable(close_session):
                raise close_error
            try:
                close_session()
            except BaseException:
                raise close_error
            if getattr(session, '_closed', False) is not True:
                try:
                    if remote_file.closed:
                        if control_flow_error:
                            raise close_error
                        return False
                except (AttributeError, RuntimeError):
                    pass
                raise close_error
            if control_flow_error:
                raise close_error
            return True

    def _rollback_interrupted_recoverable_replace(
        self,
        actual,
        destination_handle,
        temporary_handle,
        *,
        destination_unc,
        temporary_unc,
        recovery_unc,
    ):
        """Best-effort rollback after a non-Exception control-flow abort.

        Every decision is based on the two already-open FILEIDs. Unknown
        locations retain both artifacts rather than risking deletion through a
        stale pathname.
        """
        try:
            original_location = (
                self._open_handle_location(
                    actual.session,
                    destination_handle,
                    (
                        ('destination', destination_unc),
                        ('recovery', recovery_unc),
                    ),
                )
                if destination_handle is not None
                else None
            )
            temporary_location = (
                self._open_handle_location(
                    actual.session,
                    temporary_handle,
                    (
                        ('destination', destination_unc),
                        ('temporary', temporary_unc),
                    ),
                )
                if temporary_handle is not None
                else None
            )

            if original_location == 'destination':
                if temporary_location == 'temporary':
                    self._delete_generated_handle(actual, temporary_handle)
                return
            if original_location != 'recovery':
                return

            if temporary_location == 'destination':
                moved_back, _move_error = (
                    self._rename_open_handle_reconciled(
                        actual.session,
                        temporary_handle,
                        destination_unc,
                        temporary_unc,
                        replace=False,
                    )
                )
                if moved_back is not True:
                    return
                temporary_location = 'temporary'
            if temporary_location != 'temporary':
                return

            restored, _restore_error = self._rename_open_handle_reconciled(
                actual.session,
                destination_handle,
                recovery_unc,
                destination_unc,
                replace=False,
            )
            if restored is True:
                self._delete_generated_handle(actual, temporary_handle)
        except BaseException:
            # Preserve the original control-flow exception. Any ambiguous
            # identity is intentionally left intact for manual recovery.
            return

    def _recoverable_replace(
        self,
        actual,
        destination,
        data,
        *,
        expected_revision,
    ):
        with actual.lock:
            with self._mutation_guard(actual, destination):
                return self._recoverable_replace_guarded(
                    actual,
                    destination,
                    data,
                    expected_revision=expected_revision,
                )

    def _recoverable_replace_guarded(
        self,
        actual,
        destination,
        data,
        *,
        expected_revision,
    ):
        """Install an editor save using only identity-bound open handles."""
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

        destination_handle = None
        temporary_handle = None
        replacement_installed = False
        try:
            with actual.lock:
                try:
                    destination_handle, destination_info = (
                        actual.session.invoke(
                            'open_file_move_verified', destination_unc
                        )
                    )
                    current_revision = self._editor_revision_from_handle(
                        destination_handle,
                        destination_info,
                    )
                except Exception as exc:
                    return FileWriteOutcome(
                        success=False,
                        error=self._public_error(exc),
                    )
                if (
                    not expected_revision
                    or expected_revision != current_revision
                ):
                    return self._edit_conflict()

                try:
                    self._validate_path_components(
                        actual, temporary, allow_missing_leaf=True
                    )
                    self._validate_path_components(
                        actual, recovery, allow_missing_leaf=True
                    )
                    temporary_handle = actual.session.invoke(
                        'create_file_move_verified',
                        temporary_unc,
                    )
                    self._write_all(temporary_handle, data)
                except Exception as exc:
                    if (
                        temporary_handle is not None
                        and not self._delete_generated_handle(
                            actual, temporary_handle
                        )
                    ):
                        return FileWriteOutcome(
                            success=False,
                            error=(
                                'The save failed and a temporary recovery '
                                'file remains.'
                            ),
                            code='SMB_RECOVERY_REQUIRED',
                            recovery_leaves=(temporary.name,),
                        )
                    return FileWriteOutcome(
                        success=False,
                        error=self._public_error(exc),
                    )

                committed, rename_error = self._rename_open_handle_reconciled(
                    actual.session,
                    destination_handle,
                    destination_unc,
                    recovery_unc,
                    replace=False,
                )
                if committed is not True:
                    if committed is None:
                        return FileWriteOutcome(
                            success=False,
                            error=(
                                'The save outcome is uncertain. Manual '
                                'recovery may be required.'
                            ),
                            code='SMB_RECOVERY_REQUIRED',
                            recovery_leaves=(
                                temporary.name,
                                recovery.name,
                            ),
                        )
                    removed = self._delete_generated_handle(
                        actual, temporary_handle
                    )
                    if not removed:
                        return FileWriteOutcome(
                            success=False,
                            error=(
                                'The save failed and a temporary recovery '
                                'file remains.'
                            ),
                            code='SMB_RECOVERY_REQUIRED',
                            recovery_leaves=(temporary.name,),
                        )
                    return FileWriteOutcome(
                        success=False,
                        error=self._public_error(rename_error),
                    )

                installed, _install_error = self._rename_open_handle_reconciled(
                    actual.session,
                    temporary_handle,
                    temporary_unc,
                    destination_unc,
                    replace=False,
                )
                if installed is not True:
                    if installed is None:
                        return FileWriteOutcome(
                            success=False,
                            error=(
                                'The replacement outcome is uncertain. '
                                'Manual recovery is required.'
                            ),
                            code='SMB_RECOVERY_REQUIRED',
                            recovery_leaves=(
                                temporary.name,
                                recovery.name,
                            ),
                        )
                    rolled_back, _rollback_error = (
                        self._rename_open_handle_reconciled(
                            actual.session,
                            destination_handle,
                            recovery_unc,
                            destination_unc,
                            replace=False,
                        )
                    )
                    if rolled_back is not True:
                        return FileWriteOutcome(
                            success=False,
                            error=(
                                'The replacement and automatic rollback '
                                'failed. Manual recovery is required.'
                            ),
                            code='SMB_RECOVERY_REQUIRED',
                            recovery_leaves=(temporary.name, recovery.name),
                        )
                    if not self._delete_generated_handle(
                        actual, temporary_handle
                    ):
                        return FileWriteOutcome(
                            success=False,
                            error=(
                                'The original file was restored, but a '
                                'temporary recovery file remains.'
                            ),
                            code='SMB_RECOVERY_REQUIRED',
                            recovery_leaves=(temporary.name,),
                        )
                    return FileWriteOutcome(
                        success=False,
                        error=(
                            'The replacement failed. The original file was '
                            'restored.'
                        ),
                        code='SMB_RECOVERABLE_REPLACE_FAILED',
                    )

                # From this point the new bytes own the destination and the
                # recovery handle may already be delete-pending. A control-flow
                # abort during backup cleanup must preserve the installed file,
                # never attempt to move it away for a rollback whose source may
                # no longer exist.
                replacement_installed = True
                revision = hashlib.sha256(data).hexdigest()
                if not self._delete_generated_handle(
                    actual, destination_handle
                ):
                    return FileWriteOutcome(
                        success=True,
                        warning_code='SMB_RECOVERY_BACKUP_RETAINED',
                        recovery_leaves=(recovery.name,),
                        revision=revision,
                    )
                return FileWriteOutcome(success=True, revision=revision)
        except BaseException:
            if not replacement_installed:
                self._rollback_interrupted_recoverable_replace(
                    actual,
                    destination_handle,
                    temporary_handle,
                    destination_unc=destination_unc,
                    temporary_unc=temporary_unc,
                    recovery_unc=recovery_unc,
                )
            raise
        finally:
            session_tainted = False
            pending_close_error = None
            for remote_file in (temporary_handle, destination_handle):
                if remote_file is not None:
                    if session_tainted:
                        continue
                    try:
                        session_tainted = self._close_handle_or_taint_session(
                            actual.session,
                            remote_file,
                        )
                    except BaseException as close_error:
                        session_tainted = (
                            getattr(actual.session, '_closed', False) is True
                        )
                        if (
                            pending_close_error is None
                            and (
                                not isinstance(close_error, Exception)
                                or replacement_installed
                            )
                        ):
                            pending_close_error = close_error
            if pending_close_error is not None:
                raise pending_close_error

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
            return FileWriteOutcome(
                success=False,
                error=(
                    'A recoverable SMB replacement must be confirmed before '
                    'saving this file.'
                ),
                code='SMB_RECOVERABLE_REPLACE_REQUIRED',
                revision=current_revision,
            )
        except Exception as exc:
            return FileWriteOutcome(
                success=False,
                error=self._public_error(exc),
            )


smb_backend = SMBBackend()
