"""Strict SMB 3.1.1 protocol boundary.

Only this module may import the SMB client packages.  It converts their broad,
reconnecting API into one encrypted, non-reconnecting connection per file
source and exposes stable public error codes to the rest of the application.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, replace
from threading import RLock
import uuid

import smbclient
from smbclient._io import (
    SMBDirectoryIO,
    SMBFileIO,
    SMBFileTransaction,
    SMBRawIO,
    query_info,
    set_info,
)
from smbclient._pool import ClientConfig
from smbprotocol.connection import Connection, Dialects
from smbprotocol.exceptions import (
    AccessDenied,
    BadNetworkName,
    DirectoryNotEmpty,
    IOTimeout,
    LogonFailure,
    ObjectNameCollision,
    ObjectNameNotFound,
    ObjectPathNotFound,
    SMBOSError,
    SharingViolation,
)
from smbprotocol.header import NtStatus
from smbprotocol.file_info import (
    FileAllInformation,
    FileBasicInformation,
    FileDispositionInformation,
    FileInternalInformation,
    FileRenameInformation,
    FileStandardInformation,
)
from smbprotocol.open import (
    CreateOptions,
    DirectoryAccessMask,
    FileAttributes,
    FileInformationClass,
    FilePipePrinterAccessMask,
)
from smbprotocol.session import Session, SessionFlags

from .smb_diagnostics import build_smb_diagnostic


class SMBProtocolError(Exception):
    """Protocol failure with a non-sensitive code suitable for clients."""

    def __init__(
        self,
        public_code: str,
        message: str = 'SMB operation failed',
        *,
        diagnostic_phase='file_operation',
        diagnostic_exception_type=None,
        diagnostic_nt_status=None,
    ):
        super().__init__(message)
        self.public_code = public_code
        diagnostic = build_smb_diagnostic(
            phase=diagnostic_phase,
            exception_type=diagnostic_exception_type,
            nt_status=diagnostic_nt_status,
        )
        self.diagnostic_phase = diagnostic['diagnostic_phase']
        self.diagnostic_exception_type = diagnostic[
            'diagnostic_exception_type'
        ]
        self.diagnostic_nt_status = diagnostic['diagnostic_nt_status']


def _mapped_protocol_error(exc, *, phase='file_operation'):
    diagnostic = build_smb_diagnostic(phase=phase, exception=exc)

    def mapped(code):
        return SMBProtocolError(code, **diagnostic)

    if isinstance(exc, LogonFailure):
        return mapped('AUTHENTICATION_REQUIRED')
    if isinstance(exc, SMBOSError):
        if exc.ntstatus in {
            NtStatus.STATUS_LOGON_FAILURE,
            NtStatus.STATUS_WRONG_PASSWORD,
            NtStatus.STATUS_PASSWORD_EXPIRED,
        }:
            return mapped('AUTHENTICATION_REQUIRED')
        if exc.ntstatus in {
            NtStatus.STATUS_ACCESS_DENIED,
            NtStatus.STATUS_PRIVILEGE_NOT_HELD,
        }:
            return mapped('PERMISSION_DENIED')
        if exc.ntstatus in {
            NtStatus.STATUS_OBJECT_NAME_NOT_FOUND,
            NtStatus.STATUS_OBJECT_PATH_NOT_FOUND,
            NtStatus.STATUS_NOT_FOUND,
        }:
            return mapped('NOT_FOUND')
        if exc.ntstatus == NtStatus.STATUS_BAD_NETWORK_NAME:
            return mapped('SHARE_UNAVAILABLE')
        if exc.ntstatus in {
            NtStatus.STATUS_OBJECT_NAME_COLLISION,
            NtStatus.STATUS_SHARING_VIOLATION,
            NtStatus.STATUS_DIRECTORY_NOT_EMPTY,
            NtStatus.STATUS_FILE_IS_A_DIRECTORY,
            NtStatus.STATUS_NOT_A_DIRECTORY,
        }:
            return mapped('CONFLICT')
        return mapped('OPERATION_FAILED')
    if isinstance(exc, AccessDenied):
        return mapped('PERMISSION_DENIED')
    if isinstance(exc, (ObjectNameNotFound, ObjectPathNotFound)):
        return mapped('NOT_FOUND')
    if isinstance(exc, BadNetworkName):
        return mapped('SHARE_UNAVAILABLE')
    if isinstance(exc, (ObjectNameCollision, SharingViolation, DirectoryNotEmpty)):
        return mapped('CONFLICT')
    if isinstance(exc, IOTimeout):
        return mapped('TIMEOUT')
    return None


def _stable_identity(value):
    """Return one usable server object identity or fail closed."""
    if isinstance(value, bool):
        raise SMBProtocolError('IDENTITY_UNAVAILABLE')
    try:
        identity = int(value)
    except (TypeError, ValueError) as exc:
        raise SMBProtocolError('IDENTITY_UNAVAILABLE') from exc
    if identity <= 0:
        raise SMBProtocolError('IDENTITY_UNAVAILABLE')
    return identity


def _disabled_dfs_lookup(_value):
    """Never resolve a configured UNC path through process-global DFS state."""
    return None


def _reject_dfs_referral(_referral):
    """Fail closed if the pinned smbclient version attempts to cache DFS."""
    raise SMBProtocolError('SHARE_UNAVAILABLE')


@dataclass(frozen=True)
class SMBObjectInfo:
    """Metadata obtained from an already-bound SMB handle or its parent."""

    name: str
    file_id: int
    file_attributes: int
    end_of_file: int
    last_write_time: float
    number_of_links: int
    identity_chain: tuple[int, ...] = ()

    @property
    def smb_info(self):
        """Keep the backend entry contract independent of smbclient types."""
        return self


def _safe_int(value, *, identity=False):
    if identity:
        return _stable_identity(value)
    if isinstance(value, bool):
        raise SMBProtocolError('OPERATION_FAILED')
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise SMBProtocolError('OPERATION_FAILED') from exc
    if result < 0:
        raise SMBProtocolError('OPERATION_FAILED')
    return result


def _filetime_seconds(value):
    """Convert an SMB FILETIME or datetime-like value to Unix seconds."""
    if hasattr(value, 'timestamp'):
        return float(value.timestamp())
    ticks = _safe_int(value)
    if ticks == 0:
        return 0.0
    # 100-nanosecond ticks between 1601-01-01 and 1970-01-01.
    return (ticks - 116444736000000000) / 10_000_000


def _query_open_info(raw, *, name=''):
    """Read identity and user-visible metadata from one open handle."""
    with SMBFileTransaction(raw) as transaction:
        query_info(transaction, FileBasicInformation)
        query_info(transaction, FileInternalInformation)
        query_info(transaction, FileStandardInformation)
    basic, internal, standard = transaction.results
    return SMBObjectInfo(
        name=name,
        file_id=_stable_identity(
            internal['index_number'].get_value()
        ),
        file_attributes=_safe_int(
            basic['file_attributes'].get_value()
        ),
        end_of_file=_safe_int(
            standard['end_of_file'].get_value()
        ),
        last_write_time=_filetime_seconds(
            basic['last_write_time'].get_value()
        ),
        number_of_links=_safe_int(
            standard['number_of_links'].get_value()
        ),
    )


def _entry_from_directory_info(raw_info):
    name = raw_info['file_name'].get_value().decode('utf-16-le')
    return SMBObjectInfo(
        name=name,
        file_id=_stable_identity(raw_info['file_id'].get_value()),
        file_attributes=_safe_int(
            raw_info['file_attributes'].get_value()
        ),
        end_of_file=_safe_int(raw_info['end_of_file'].get_value()),
        last_write_time=_filetime_seconds(
            raw_info['last_write_time'].get_value()
        ),
        # FILE_ID_FULL_DIRECTORY_INFORMATION does not expose link count.
        number_of_links=0,
    )


def _query_exact_child(directory, name):
    """Resolve one exact child through an already-open parent handle."""
    matches = []
    for raw_info in directory.query_directory(
        name,
        FileInformationClass.FILE_ID_FULL_DIRECTORY_INFORMATION,
    ):
        entry = _entry_from_directory_info(raw_info)
        if entry.name in {'.', '..'}:
            continue
        if entry.name.casefold() != name.casefold():
            raise SMBProtocolError('CONFLICT')
        matches.append(entry)
        if len(matches) > 1:
            raise SMBProtocolError('CONFLICT')
    if not matches:
        raise SMBProtocolError('NOT_FOUND')
    return matches[0]


def _split_unc(path):
    if not isinstance(path, str) or not path.startswith('\\\\'):
        raise SMBProtocolError('OPERATION_FAILED')
    parts = path[2:].split('\\')
    if len(parts) < 2 or any(not part for part in parts):
        raise SMBProtocolError('OPERATION_FAILED')
    return '\\\\' + '\\'.join(parts[:2]), tuple(parts[2:])


def _validate_open_type(raw, *, is_directory):
    attributes = _safe_int(getattr(raw.fd, 'file_attributes', None))
    if attributes & int(FileAttributes.FILE_ATTRIBUTE_REPARSE_POINT):
        raise SMBProtocolError('REPARSE_POINT_REJECTED')
    actual_directory = bool(
        attributes & int(FileAttributes.FILE_ATTRIBUTE_DIRECTORY)
    )
    if actual_directory != is_directory:
        raise SMBProtocolError('CONFLICT')


def _validate_share_binding(raw, path):
    """Reject DFS or any tree connection outside the requested share."""
    requested_share, _components = _split_unc(path)
    descriptor = getattr(raw, 'fd', None)
    tree = getattr(descriptor, 'tree_connect', None)
    actual_share = getattr(tree, 'share_name', None)
    if (
        not isinstance(actual_share, str)
        or actual_share.rstrip('\\').casefold()
        != requested_share.rstrip('\\').casefold()
        or getattr(tree, 'is_dfs_share', None) is not False
    ):
        raise SMBProtocolError('SHARE_UNAVAILABLE')


def _permission_denied(exc):
    if isinstance(exc, SMBProtocolError):
        return exc.public_code == 'PERMISSION_DENIED'
    mapped = _mapped_protocol_error(exc)
    return mapped is not None and mapped.public_code == 'PERMISSION_DENIED'


def _verified_directory_flag(info):
    attributes = _safe_int(info.file_attributes)
    if attributes & int(FileAttributes.FILE_ATTRIBUTE_REPARSE_POINT):
        raise SMBProtocolError('REPARSE_POINT_REJECTED')
    return bool(attributes & int(FileAttributes.FILE_ATTRIBUTE_DIRECTORY))


def _open_raw(
    path,
    *,
    is_directory,
    desired_access,
    connection_kwargs,
    share_access='rwd',
):
    raw_type = SMBDirectoryIO if is_directory else SMBFileIO
    raw = None
    try:
        raw = raw_type(
            path,
            mode='rb',
            share_access=share_access,
            desired_access=int(desired_access),
            create_options=int(CreateOptions.FILE_OPEN_REPARSE_POINT),
            **connection_kwargs,
        )
        _validate_share_binding(raw, path)
        raw.open()
        _validate_share_binding(raw, path)
        _validate_open_type(raw, is_directory=is_directory)
        return raw
    except BaseException:
        if raw is not None:
            try:
                raw.close()
            except Exception:
                pass
        raise


def _open_untyped_raw(
    path,
    *,
    desired_access,
    connection_kwargs,
    share_access='rwd',
):
    raw = None
    try:
        raw = SMBRawIO(
            path,
            mode='rb',
            share_access=share_access,
            desired_access=int(desired_access),
            create_options=int(CreateOptions.FILE_OPEN_REPARSE_POINT),
            **connection_kwargs,
        )
        _validate_share_binding(raw, path)
        raw.open()
        _validate_share_binding(raw, path)
        attributes = _safe_int(getattr(raw.fd, 'file_attributes', None))
        if attributes & int(FileAttributes.FILE_ATTRIBUTE_REPARSE_POINT):
            raise SMBProtocolError('REPARSE_POINT_REJECTED')
        return raw
    except BaseException:
        if raw is not None:
            try:
                raw.close()
            except Exception:
                pass
        raise


def _open_verified_path(
    path,
    *,
    purpose,
    expected_identities=None,
    **connection_kwargs,
):
    """Bind path components by ID, with a narrow list-denied fallback.

    Normal paths use exact directory queries from the already-open parent.
    Some SMB servers deny those queries while still permitting access to a
    known child.  In that compatibility case we hold metadata handles for
    every opaque component and perform a second full identity pass.  This
    rejects ordinary one-way replacement but cannot exclude a synchronized
    rename-away/rename-back (ABA) by another principal.
    """
    root, components = _split_unc(path)
    if expected_identities is None:
        expected = None
    else:
        try:
            expected = tuple(expected_identities)
        except TypeError as exc:
            raise SMBProtocolError('OPERATION_FAILED') from exc
        if len(expected) != len(components):
            raise SMBProtocolError('OPERATION_FAILED')
        expected = tuple(_stable_identity(value) for value in expected)

    list_access = int(
        DirectoryAccessMask.FILE_LIST_DIRECTORY
        | DirectoryAccessMask.FILE_READ_ATTRIBUTES
    )
    read_attributes = int(FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES)

    def leaf_access():
        if purpose == 'directory':
            return list_access
        if purpose == 'directory_pin':
            # A pin only reads metadata and retains the verified handle. Keep
            # the baseline ACL contract: traversing through the pinned leaf is
            # neither required nor requested.
            return read_attributes
        if purpose == 'file_read':
            return int(
                FilePipePrinterAccessMask.FILE_READ_DATA
                | FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES
            )
        if purpose == 'file_move':
            return int(
                FilePipePrinterAccessMask.DELETE
                | FilePipePrinterAccessMask.FILE_READ_DATA
                | FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES
            )
        if purpose == 'rename':
            return int(
                FilePipePrinterAccessMask.DELETE
                | FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES
            )
        if purpose == 'delete':
            return int(
                FilePipePrinterAccessMask.DELETE
                | FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES
            )
        if purpose == 'delete_read_only':
            return int(
                FilePipePrinterAccessMask.DELETE
                | FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES
                | FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES
            )
        return read_attributes

    root_access = (
        list_access
        if components or purpose == 'directory'
        else read_attributes
    )
    root_share_access = (
        'r' if purpose == 'directory_pin' and not components else 'rwd'
    )
    opaque = False
    try:
        current = _open_raw(
            root,
            is_directory=True,
            desired_access=root_access,
            connection_kwargs=connection_kwargs,
            share_access=root_share_access,
        )
    except Exception as exc:
        if (
            not components
            or root_access != list_access
            or not _permission_denied(exc)
        ):
            raise
        current = _open_raw(
            root,
            is_directory=True,
            desired_access=read_attributes,
            connection_kwargs=connection_kwargs,
            share_access=root_share_access,
        )
        opaque = True
    current_path = root
    identity_chain = []
    opaque_records = []
    try:
        current_info = _query_open_info(current)
        if opaque:
            opaque_records.append((root, current, current_info))
        if not components:
            if purpose in {'file_read', 'file_move', 'rename'}:
                raise SMBProtocolError('CONFLICT')
            return current, current_info

        for index, component in enumerate(components):
            is_leaf = index == len(components) - 1
            child_path = current_path + '\\' + component

            entry = None
            if not opaque:
                try:
                    entry = _query_exact_child(current, component)
                except Exception as exc:
                    if not _permission_denied(exc):
                        raise
                    opaque = True
                    opaque_records.append((
                        current_path,
                        current,
                        current_info,
                    ))

            if opaque:
                desired_access = leaf_access() if is_leaf else read_attributes
                if not is_leaf:
                    child = _open_raw(
                        child_path,
                        is_directory=True,
                        desired_access=desired_access,
                        connection_kwargs=connection_kwargs,
                    )
                elif purpose in {'file_read', 'file_move'}:
                    child = _open_raw(
                        child_path,
                        is_directory=False,
                        desired_access=desired_access,
                        connection_kwargs=connection_kwargs,
                        share_access=(
                            'r' if purpose == 'file_move' else 'rwd'
                        ),
                    )
                elif purpose in {'directory', 'directory_pin'}:
                    child = _open_raw(
                        child_path,
                        is_directory=True,
                        desired_access=desired_access,
                        connection_kwargs=connection_kwargs,
                        share_access=(
                            'r'
                            if purpose == 'directory_pin' and is_leaf
                            else 'rwd'
                        ),
                    )
                else:
                    child = _open_untyped_raw(
                        child_path,
                        desired_access=desired_access,
                        connection_kwargs=connection_kwargs,
                    )
                try:
                    info = _query_open_info(child, name=component)
                    is_directory = _verified_directory_flag(info)
                    if not is_leaf and not is_directory:
                        raise SMBProtocolError('NOT_FOUND')
                    if (
                        is_leaf
                        and purpose in {'file_read', 'file_move'}
                        and is_directory
                    ):
                        raise SMBProtocolError('CONFLICT')
                    if (
                        is_leaf
                        and purpose in {'directory', 'directory_pin'}
                        and not is_directory
                    ):
                        raise SMBProtocolError('CONFLICT')
                    if expected is not None and (
                        info.file_id != expected[index]
                    ):
                        raise SMBProtocolError('CONFLICT')
                except BaseException:
                    try:
                        child.close()
                    except Exception:
                        pass
                    raise
                identity_chain.append(info.file_id)
                opaque_records.append((child_path, child, info))
                current = child
                current_info = info
                current_path = child_path
                continue

            identity_chain.append(entry.file_id)
            is_directory = bool(
                entry.file_attributes
                & int(FileAttributes.FILE_ATTRIBUTE_DIRECTORY)
            )
            if entry.file_attributes & int(
                FileAttributes.FILE_ATTRIBUTE_REPARSE_POINT
            ):
                raise SMBProtocolError('REPARSE_POINT_REJECTED')
            if not is_leaf and not is_directory:
                raise SMBProtocolError('NOT_FOUND')
            if expected is not None and entry.file_id != expected[index]:
                raise SMBProtocolError('CONFLICT')
            if (
                is_leaf
                and purpose in {'file_read', 'file_move'}
                and is_directory
            ):
                raise SMBProtocolError('CONFLICT')
            if (
                is_leaf
                and purpose in {'directory', 'directory_pin'}
                and not is_directory
            ):
                raise SMBProtocolError('CONFLICT')

            desired_access = leaf_access() if is_leaf else list_access
            try:
                child = _open_raw(
                    child_path,
                    is_directory=is_directory,
                    desired_access=desired_access,
                    connection_kwargs=connection_kwargs,
                    share_access=(
                        'r' if is_leaf and purpose in {
                            'directory_pin',
                            'file_move',
                        } else 'rwd'
                    ),
                )
            except Exception as exc:
                allow_opaque_fallback = (
                    is_directory
                    and _permission_denied(exc)
                    and (not is_leaf or purpose == 'directory_pin')
                )
                if not allow_opaque_fallback:
                    raise
                child = _open_raw(
                    child_path,
                    is_directory=True,
                    desired_access=read_attributes,
                    connection_kwargs=connection_kwargs,
                    share_access=(
                        'r'
                        if purpose == 'directory_pin' and is_leaf
                        else 'rwd'
                    ),
                )
                opaque = True
            try:
                info = _query_open_info(child, name=entry.name)
                if info.file_id != entry.file_id:
                    raise SMBProtocolError('CONFLICT')
                if _verified_directory_flag(info) != is_directory:
                    raise SMBProtocolError('CONFLICT')
            except BaseException:
                try:
                    child.close()
                except Exception:
                    pass
                raise

            if opaque:
                # The parent was the authority that bound this child's ID.
                # Retain and reverify it as part of the opaque path rather
                # than leaking it or accepting a parent replacement.
                opaque_records.append((
                    current_path,
                    current,
                    current_info,
                ))
                opaque_records.append((child_path, child, info))
            else:
                try:
                    current.close()
                except BaseException:
                    try:
                        child.close()
                    except Exception:
                        pass
                    raise
            current = child
            current_info = info
            current_path = child_path

        if opaque_records:
            for verify_path, _held, held_info in opaque_records:
                verify_directory = _verified_directory_flag(held_info)
                verifier = _open_raw(
                    verify_path,
                    is_directory=verify_directory,
                    # These independent reopens only compare metadata; they
                    # never descend through the verifier handle. Requesting
                    # FILE_TRAVERSE here would reject valid list-only ACLs
                    # without strengthening the identity check.
                    desired_access=read_attributes,
                    connection_kwargs=connection_kwargs,
                )
                try:
                    verify_info = _query_open_info(verifier)
                    if verify_info.file_id != held_info.file_id:
                        raise SMBProtocolError('CONFLICT')
                    if (
                        _verified_directory_flag(verify_info)
                        != verify_directory
                    ):
                        raise SMBProtocolError('CONFLICT')
                finally:
                    verifier.close()
            for _held_path, held, _held_info in opaque_records[:-1]:
                held.close()

        info = replace(
            current_info,
            identity_chain=tuple(identity_chain),
        )
        return current, info
    except BaseException:
        closed = set()
        for _held_path, held, _held_info in reversed(opaque_records):
            if id(held) in closed:
                continue
            closed.add(id(held))
            try:
                held.close()
            except Exception:
                pass
        if id(current) not in closed:
            try:
                current.close()
            except Exception:
                pass
        raise


class _VerifiedDirectoryIterator:
    """Enumerate one verified directory handle and own its lifetime."""

    def __init__(
        self,
        raw,
        info,
        *,
        path=None,
        connection_kwargs=None,
    ):
        self._raw = raw
        self._path = path
        self._connection_kwargs = (
            None if connection_kwargs is None else dict(connection_kwargs)
        )
        try:
            self._iterator = raw.query_directory(
                '*',
                FileInformationClass.FILE_ID_FULL_DIRECTORY_INFORMATION,
            )
        except BaseException:
            try:
                raw.close()
            except Exception:
                pass
            raise
        self.identity = info.file_id
        self.identity_chain = info.identity_chain
        self.closed = False

    def __iter__(self):
        return self

    def __next__(self):
        if self.closed:
            raise StopIteration
        try:
            while True:
                entry = _entry_from_directory_info(next(self._iterator))
                if entry.name not in {'.', '..'}:
                    return entry
        except StopIteration:
            self.close()
            raise
        except Exception as exc:
            self.close()
            mapped = _mapped_protocol_error(exc)
            if mapped is not None:
                raise mapped from exc
            raise

    def open_child_directory(self, entry):
        """Open one enumerated child without rewalking the share root."""
        if (
            self.closed
            or self._path is None
            or self._connection_kwargs is None
        ):
            raise SMBProtocolError('OPERATION_FAILED')

        child = None
        try:
            expected_identity = _stable_identity(entry.file_id)
            if not _verified_directory_flag(entry):
                raise SMBProtocolError('CONFLICT')
            child_path = self._path + '\\' + entry.name
            child = _open_raw(
                child_path,
                is_directory=True,
                desired_access=int(
                    DirectoryAccessMask.FILE_LIST_DIRECTORY
                    | DirectoryAccessMask.FILE_READ_ATTRIBUTES
                ),
                connection_kwargs=self._connection_kwargs,
            )
            info = _query_open_info(child, name=entry.name)
            if info.file_id != expected_identity:
                raise SMBProtocolError('CONFLICT')
            if not _verified_directory_flag(info):
                raise SMBProtocolError('CONFLICT')
            info = replace(
                info,
                identity_chain=(*self.identity_chain, info.file_id),
            )
            owned_child = child
            child = None
            return _VerifiedDirectoryIterator(
                owned_child,
                info,
                path=child_path,
                connection_kwargs=self._connection_kwargs,
            )
        except BaseException as exc:
            if child is not None:
                try:
                    child.close()
                except Exception:
                    pass
            if isinstance(exc, Exception):
                mapped = _mapped_protocol_error(exc)
                if mapped is not None:
                    raise mapped from exc
            raise

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self._iterator.close()
        except Exception:
            pass
        try:
            self._raw.close()
        except Exception:
            pass


def _verified_scandir(path, *, expected_identities=None, **kwargs):
    raw, info = _open_verified_path(
        path,
        purpose='directory',
        expected_identities=expected_identities,
        **kwargs,
    )
    return _VerifiedDirectoryIterator(
        raw,
        info,
        path=path,
        connection_kwargs=kwargs,
    )


def _verified_stat(path, *, expected_identities=None, **kwargs):
    raw, info = _open_verified_path(
        path,
        purpose='stat',
        expected_identities=expected_identities,
        **kwargs,
    )
    try:
        return info
    finally:
        raw.close()


def _verified_file_reader(path, *, expected_identities=None, **kwargs):
    raw, _info = _open_verified_path(
        path,
        purpose='file_read',
        expected_identities=expected_identities,
        **kwargs,
    )
    return raw


def _verified_file_move_handle(
    path,
    *,
    expected_identities=None,
    **kwargs,
):
    """Open one exact file for revision reads and same-handle renames."""
    return _open_verified_path(
        path,
        purpose='file_move',
        expected_identities=expected_identities,
        **kwargs,
    )


def _create_file_move_handle(path, **connection_kwargs):
    """Exclusively create a writable file that can be renamed by its handle."""
    raw = None
    try:
        raw = SMBFileIO(
            path,
            mode='xb',
            share_access=None,
            desired_access=int(
                FilePipePrinterAccessMask.DELETE
                | FilePipePrinterAccessMask.FILE_WRITE_DATA
                | FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES
            ),
            create_options=int(CreateOptions.FILE_OPEN_REPARSE_POINT),
            **connection_kwargs,
        )
        _validate_share_binding(raw, path)
        raw.open()
        _validate_share_binding(raw, path)
        _validate_open_type(raw, is_directory=False)
        return raw
    except BaseException:
        if raw is not None:
            try:
                raw.close()
            except Exception:
                pass
        raise


def _require_open_handle(raw):
    """Reject handles that a transaction helper would reopen by pathname."""
    try:
        closed = raw.closed
    except (AttributeError, RuntimeError) as exc:
        raise SMBProtocolError('OPERATION_FAILED') from exc
    if closed is not False:
        raise SMBProtocolError('OPERATION_FAILED')


def _open_handle_matches_path(raw, path, **_connection_kwargs):
    """Compare a candidate path with the name bound to one open FILEID."""
    _require_open_handle(raw)
    _validate_share_binding(raw, path)
    _root, expected_components = _split_unc(path)
    if not expected_components:
        raise SMBProtocolError('OPERATION_FAILED')

    # smbprotocol 1.17's FileNameInformation parser intentionally has no
    # INFO_TYPE/INFO_CLASS metadata, so it cannot be passed directly to
    # smbclient.query_info().  FileAllInformation is the supported query class
    # that contains the same name structure.  Its default output allocation is
    # only the fixed 100-byte prefix, therefore reserve enough room for the
    # bounded share-relative path as well.
    with SMBFileTransaction(raw) as transaction:
        query_info(
            transaction,
            FileAllInformation,
            output_buffer_length=65536,
        )
    try:
        current_name = (
            transaction.results[0]['name_information']
            .get_value()['file_name']
            .get_value()
        )
    except (AttributeError, IndexError, KeyError, TypeError) as exc:
        raise SMBProtocolError('OPERATION_FAILED') from exc
    if isinstance(current_name, bytes):
        try:
            current_name = current_name.decode('utf-16-le')
        except UnicodeDecodeError as exc:
            raise SMBProtocolError('OPERATION_FAILED') from exc
    if not isinstance(current_name, str):
        raise SMBProtocolError('OPERATION_FAILED')
    current_name = current_name.removeprefix('\\')
    current_components = tuple(current_name.split('\\'))
    if (
        len(current_components) != len(expected_components)
        or any(
            not component
            or component in {'.', '..'}
            or '\x00' in component
            for component in current_components
        )
    ):
        return False
    return tuple(
        component.casefold() for component in current_components
    ) == tuple(component.casefold() for component in expected_components)


def _rename_open_handle(
    raw,
    destination,
    *,
    replace=False,
    **_connection_kwargs,
):
    """Rename the object bound to ``raw`` without resolving its source again."""
    _require_open_handle(raw)
    if not isinstance(replace, bool):
        raise SMBProtocolError('OPERATION_FAILED')
    _validate_share_binding(raw, destination)
    _root, components = _split_unc(destination)
    if not components:
        raise SMBProtocolError('OPERATION_FAILED')
    rename_info = FileRenameInformation()
    rename_info['replace_if_exists'] = bool(replace)
    rename_info['root_directory'] = 0
    rename_info['file_name'] = '\\'.join(components)
    with SMBFileTransaction(raw) as transaction:
        set_info(transaction, rename_info)


def _verified_rename(
    path,
    destination,
    *,
    replace=False,
    expected_identities=None,
    **kwargs,
):
    raw, _info = _open_verified_path(
        path,
        purpose='rename',
        expected_identities=expected_identities,
        **kwargs,
    )
    try:
        _rename_open_handle(raw, destination, replace=replace)
    finally:
        raw.close()


def _verified_directory_handle(path, *, expected_identities=None, **kwargs):
    return _open_verified_path(
        path,
        purpose='directory_pin',
        expected_identities=expected_identities,
        **kwargs,
    )


def _set_delete_disposition(raw, **_connection_kwargs):
    _require_open_handle(raw)
    disposition = FileDispositionInformation()
    disposition['delete_pending'] = True
    with SMBFileTransaction(raw) as transaction:
        set_info(transaction, disposition)


def _set_file_attributes(raw, attributes):
    basic_info = FileBasicInformation()
    basic_info['creation_time'] = 0
    basic_info['last_access_time'] = 0
    basic_info['last_write_time'] = 0
    basic_info['change_time'] = 0
    basic_info['file_attributes'] = int(attributes)
    with SMBFileTransaction(raw) as transaction:
        set_info(transaction, basic_info)


def _is_read_only_delete_failure(exc, attributes):
    try:
        status = int(getattr(exc, 'ntstatus'))
        attributes = int(attributes)
    except (AttributeError, TypeError, ValueError):
        return False
    return (
        status == int(NtStatus.STATUS_CANNOT_DELETE)
        and bool(
            attributes
            & int(FileAttributes.FILE_ATTRIBUTE_READONLY)
        )
    )


def _verified_delete(path, *, expected_identities=None, **kwargs):
    """Set delete disposition with the minimum rights on a verified handle."""
    raw, info = _open_verified_path(
        path,
        purpose='delete',
        expected_identities=expected_identities,
        **kwargs,
    )
    direct_failure = None
    try:
        try:
            _set_delete_disposition(raw)
            return
        except Exception as exc:
            if not _is_read_only_delete_failure(
                exc,
                info.file_attributes,
            ):
                raise
            direct_failure = exc

        fallback = None
        try:
            fallback, fallback_info = _open_verified_path(
                path,
                purpose='delete_read_only',
                expected_identities=info.identity_chain,
                **kwargs,
            )
            if fallback_info.file_id != info.file_id:
                raise SMBProtocolError('CONFLICT')
            original_attributes = int(fallback_info.file_attributes)
            read_only = int(FileAttributes.FILE_ATTRIBUTE_READONLY)
            if not original_attributes & read_only:
                raise SMBProtocolError('CONFLICT') from direct_failure
            writable_attributes = original_attributes & ~read_only
            if writable_attributes == 0:
                writable_attributes = int(
                    FileAttributes.FILE_ATTRIBUTE_NORMAL
                )
            try:
                _set_file_attributes(fallback, writable_attributes)
                _set_delete_disposition(fallback)
            except BaseException as fallback_error:
                try:
                    _set_file_attributes(fallback, original_attributes)
                except BaseException as restore_error:
                    raise restore_error from fallback_error
                raise
        finally:
            if fallback is not None:
                fallback.close()
    finally:
        raw.close()


class _MappedIterator:
    """Keep deferred SMB directory failures inside the protocol boundary."""

    def __init__(self, iterator):
        self._iterator = iterator

    def __iter__(self):
        return self

    def __next__(self):
        try:
            return next(self._iterator)
        except StopIteration:
            raise
        except Exception as exc:
            mapped = _mapped_protocol_error(exc)
            if mapped is not None:
                raise mapped from exc
            raise

    def close(self):
        return self._iterator.close()


class _SealedConnectionCache(dict):
    """Per-source cache that cannot create or replace a connection."""

    def __init__(self, key, connection):
        super().__init__({key: connection})
        self._key = key
        self._sealed = True

    def get(self, key, default=None):
        if self._sealed:
            if key != self._key:
                raise SMBProtocolError('SOURCE_UNAVAILABLE')
            connection = super().get(key)
            transport = getattr(connection, 'transport', None)
            if (
                connection is None
                or transport is None
                or not getattr(transport, 'connected', False)
            ):
                raise SMBProtocolError('SOURCE_UNAVAILABLE')
            return connection
        return super().get(key, default)

    def __setitem__(self, key, value):
        if getattr(self, '_sealed', False):
            raise SMBProtocolError('SOURCE_UNAVAILABLE')
        return super().__setitem__(key, value)


class _RealSMBProtocol:
    smb_3_1_1 = Dialects.SMB_3_1_1

    def configure_global(self, **kwargs):
        config = ClientConfig(**kwargs)
        # smbprotocol 1.17 stores DFS caches on a process-global singleton,
        # and its high-level mutation helpers can consult them even when
        # skip_dfs is set.  This module is pinned to that dependency version;
        # clear and override the private referral hooks so an approved
        # \\server\share path can never be silently rebound to another share.
        config._referral_cache = []
        config._domain_cache = []
        config.lookup_referral = _disabled_dfs_lookup
        config.lookup_domain = _disabled_dfs_lookup
        config.cache_referral = _reject_dfs_referral

    def new_connection(
        self,
        *,
        server,
        port,
        require_signing,
        dialect,
        timeout,
        io_idle_timeout,
    ):
        connection = Connection(
            uuid.uuid4(),
            server,
            port,
            require_signing=require_signing,
        )
        # smbprotocol intentionally exposes this as its experimental bounded
        # receive timeout.  Keeping the dependency access here contains API
        # drift to this single, pinned-version module.
        connection._receive_timeout = io_idle_timeout
        connection.connect(dialect=dialect, timeout=timeout)
        return connection

    @staticmethod
    def connection_supports_encryption(connection):
        # SMB 3.1.1 advertises the selected cipher in a negotiate context;
        # smbprotocol folds both the legacy capability bit and that context
        # into this version-pinned boolean.
        return connection.supports_encryption is True

    @staticmethod
    def new_session(
        connection,
        *,
        username,
        password,
        require_encryption,
        auth_protocol,
    ):
        return Session(
            connection,
            username=username,
            password=password,
            require_encryption=require_encryption,
            auth_protocol=auth_protocol,
        )

    @staticmethod
    def session_is_guest_or_null(session):
        flags = getattr(session, 'session_flags', 0)
        return bool(
            flags
            & (
                SessionFlags.SMB2_SESSION_FLAG_IS_GUEST
                | SessionFlags.SMB2_SESSION_FLAG_IS_NULL
            )
        )

    @staticmethod
    def close_connection(connection, *, timeout):
        try:
            connection.disconnect(close=True, timeout=timeout)
        except BaseException:
            try:
                # smbprotocol closes its transport only after every session,
                # tree, and open has logged off.  If that cleanup fails, force
                # the transport-only path so its receiver thread cannot outlive
                # the source that owned it.
                connection.disconnect(close=False, timeout=timeout)
            except BaseException:
                transport = getattr(connection, 'transport', None)
                close_transport = getattr(transport, 'close', None)
                if callable(close_transport):
                    try:
                        close_transport()
                    except BaseException:
                        pass
            raise

    @staticmethod
    def invoke(name, *args, **kwargs):
        no_follow_operations = {
            'open_file_no_follow': 'open_file',
            'scandir_no_follow': 'scandir',
            'mkdir_no_follow': 'mkdir',
        }
        if name in no_follow_operations:
            name = no_follow_operations[name]
            kwargs['create_options'] = (
                int(kwargs.get('create_options', 0))
                | int(CreateOptions.FILE_OPEN_REPARSE_POINT)
            )
        try:
            if name == 'scandir_verified':
                return _verified_scandir(*args, **kwargs)
            if name == 'stat_verified':
                return _verified_stat(*args, **kwargs)
            if name == 'open_file_verified':
                return _verified_file_reader(*args, **kwargs)
            if name == 'open_file_move_verified':
                return _verified_file_move_handle(*args, **kwargs)
            if name == 'create_file_move_verified':
                return _create_file_move_handle(*args, **kwargs)
            if name == 'open_directory_verified':
                return _verified_directory_handle(*args, **kwargs)
            if name == 'delete_verified':
                return _verified_delete(*args, **kwargs)
            if name == 'delete_open_handle_verified':
                return _set_delete_disposition(*args, **kwargs)
            if name == 'open_handle_matches_path_verified':
                return _open_handle_matches_path(*args, **kwargs)
            if name == 'rename_open_handle_verified':
                return _rename_open_handle(*args, **kwargs)
            if name == 'rename_verified':
                return _verified_rename(*args, **kwargs)
            operation = getattr(smbclient, name, None)
            if operation is None or name.startswith('_'):
                raise SMBProtocolError('OPERATION_UNAVAILABLE')
            result = operation(*args, **kwargs)
            return _MappedIterator(result) if name == 'scandir' else result
        except Exception as exc:
            mapped = _mapped_protocol_error(exc)
            if mapped is not None:
                raise mapped from exc
            raise


class SMBProtocolSession:
    """One authenticated, encrypted SMB transport owned by one source."""

    def __init__(
        self,
        *,
        protocol,
        target_ip,
        canonical_host,
        raw_connection,
        raw_session,
        io_idle_timeout,
    ):
        self._protocol = protocol
        self.target_ip = target_ip
        self.canonical_host = canonical_host
        self.raw_connection = raw_connection
        self.raw_session = raw_session
        self.io_idle_timeout = io_idle_timeout
        self.dialect = raw_connection.dialect
        self.encrypted = True
        self.signed = True
        self.secure_negotiate = True
        self._lock = RLock()
        self._closed = False
        self._mutation_guard_depth = 0
        self.connection_cache = _SealedConnectionCache(
            f'{target_ip.lower()}:445',
            raw_connection,
        )

    def _ensure_alive(self):
        transport = getattr(self.raw_connection, 'transport', None)
        if self._closed or transport is None or not transport.connected:
            raise SMBProtocolError('SOURCE_UNAVAILABLE')

    def invoke(self, name, *args, **kwargs):
        """Run one high-level operation without allowing implicit reconnect."""

        with self._lock:
            self._ensure_alive()
            open_mode = kwargs.get('mode', 'rb')
            mutating_open = (
                name in {'open_file', 'open_file_no_follow'}
                and (
                    not isinstance(open_mode, str)
                    or '+' in open_mode
                    or any(
                        marker in open_mode.lower()
                        for marker in ('a', 'w', 'x')
                    )
                )
            )
            if (
                name in {
                    'create_file_move_verified',
                    'delete_open_handle_verified',
                    'delete_verified',
                    'mkdir_no_follow',
                    'open_file_move_verified',
                    'remove',
                    'rename',
                    'rename_open_handle_verified',
                    'rename_verified',
                    'replace',
                    'rmdir',
                }
                or mutating_open
            ) and self._mutation_guard_depth < 1:
                raise SMBProtocolError('MUTATION_GUARD_REQUIRED')
            call_kwargs = {
                'username': self.raw_session.username,
                'password': None,
                'port': 445,
                'encrypt': True,
                'connection_timeout': self.io_idle_timeout,
                'connection_cache': self.connection_cache,
                'auth_protocol': 'ntlm',
                'require_signing': True,
            }
            call_kwargs.update(kwargs)
            try:
                return self._protocol.invoke(name, *args, **call_kwargs)
            except SMBProtocolError:
                raise
            except Exception as exc:
                raise SMBProtocolError('OPERATION_FAILED') from exc

    @contextmanager
    def pin_directories(self, paths, *, expected_identities=None):
        """Hold verified handles with best-effort final share denial."""
        handles = []
        identities = {}
        expected_identities = expected_identities or {}
        with self._lock:
            self._ensure_alive()
        try:
            for path in dict.fromkeys(paths):
                handle, info = self.invoke(
                    'open_directory_verified',
                    path,
                )
                handles.append(handle)
                expected = expected_identities.get(path)
                identity = _stable_identity(info.file_id)
                if (
                    expected is not None
                    and identity != _stable_identity(expected)
                ):
                    raise SMBProtocolError('CONFLICT')
                identities[path] = identity
            yield identities
        finally:
            with self._lock:
                for handle in reversed(handles):
                    try:
                        handle.close()
                    except Exception:
                        pass

    @contextmanager
    def pin_mutation_ancestors(self, paths, *, expected_identities=None):
        """Hold verified directory identities while permitting mutations."""
        entered = False
        with self._lock:
            with self.pin_directories(
                paths,
                expected_identities=expected_identities,
            ) as identities:
                try:
                    self._mutation_guard_depth += 1
                    entered = True
                    yield identities
                finally:
                    if entered:
                        self._mutation_guard_depth -= 1

    def inspect_directory_access(self, path):
        """Validate listing and query root directory rights without mutation."""
        iterator = self.invoke('scandir_verified', path)
        try:
            next(iter(iterator), None)
        finally:
            try:
                iterator.close()
            except Exception:
                pass

        access = {'list': 'granted'}
        probes = (
            ('create_file', DirectoryAccessMask.FILE_ADD_FILE),
            ('create_directory', DirectoryAccessMask.FILE_ADD_SUBDIRECTORY),
            ('delete_children', DirectoryAccessMask.FILE_DELETE_CHILD),
        )
        for name, desired_access in probes:
            handle = None
            try:
                handle = self.invoke(
                    'open_file_no_follow',
                    path,
                    mode='rb',
                    buffering=0,
                    file_type='dir',
                    desired_access=int(desired_access),
                )
                access[name] = 'granted'
            except SMBProtocolError as exc:
                access[name] = (
                    'denied'
                    if exc.public_code == 'PERMISSION_DENIED'
                    else 'unknown'
                )
            except Exception:
                access[name] = 'unknown'
            finally:
                if handle is not None:
                    try:
                        handle.close()
                    except Exception:
                        pass
        return access

    def close(self):
        with self._lock:
            if self._closed:
                return False
            self._closed = True
            self.connection_cache.clear()
            try:
                self._protocol.close_connection(
                    self.raw_connection,
                    timeout=self.io_idle_timeout,
                )
            except Exception:
                pass
            return True


class SMBProtocolClient:
    """Create strictly negotiated SMB sessions from already-approved IPs."""

    def __init__(self, protocol=None):
        self._protocol = protocol or _RealSMBProtocol()
        self._protocol.configure_global(
            username=None,
            password=None,
            domain_controller=None,
            skip_dfs=True,
            auth_protocol='ntlm',
            require_secure_negotiate=True,
        )

    @staticmethod
    def _cancelled(cancel_event):
        return cancel_event is not None and cancel_event.is_set()

    def connect(
        self,
        *,
        target_ip,
        canonical_host,
        username,
        password,
        timeout,
        io_idle_timeout,
        cancel_event=None,
    ):
        if self._cancelled(cancel_event):
            raise SMBProtocolError('CONNECT_CANCELLED')

        connection = None
        raw_session = None
        diagnostic_phase = 'transport_negotiate'
        try:
            connection = self._protocol.new_connection(
                server=target_ip,
                port=445,
                require_signing=True,
                dialect=self._protocol.smb_3_1_1,
                timeout=timeout,
                io_idle_timeout=io_idle_timeout,
            )
            diagnostic_phase = 'security_requirements'
            if connection.dialect != self._protocol.smb_3_1_1:
                raise SMBProtocolError(
                    'DIALECT_REQUIRED',
                    diagnostic_phase=diagnostic_phase,
                )
            if not self._protocol.connection_supports_encryption(connection):
                raise SMBProtocolError(
                    'ENCRYPTION_REQUIRED',
                    diagnostic_phase=diagnostic_phase,
                )
            if self._cancelled(cancel_event):
                raise SMBProtocolError('CONNECT_CANCELLED')

            diagnostic_phase = 'session_authentication'
            raw_session = self._protocol.new_session(
                connection,
                username=username,
                password=password,
                require_encryption=True,
                auth_protocol='ntlm',
            )
            raw_session.connect()
            if self._protocol.session_is_guest_or_null(raw_session):
                raise SMBProtocolError(
                    'AUTHENTICATION_REQUIRED',
                    diagnostic_phase=diagnostic_phase,
                )
            if not getattr(raw_session, 'encrypt_data', False):
                raise SMBProtocolError(
                    'ENCRYPTION_REQUIRED',
                    diagnostic_phase='security_requirements',
                )
            if self._cancelled(cancel_event):
                raise SMBProtocolError('CONNECT_CANCELLED')

            raw_session.password = None
            return SMBProtocolSession(
                protocol=self._protocol,
                target_ip=target_ip,
                canonical_host=canonical_host,
                raw_connection=connection,
                raw_session=raw_session,
                io_idle_timeout=io_idle_timeout,
            )
        except SMBProtocolError:
            if raw_session is not None:
                raw_session.password = None
            if connection is not None:
                try:
                    self._protocol.close_connection(
                        connection,
                        timeout=io_idle_timeout,
                    )
                except Exception:
                    pass
            raise
        except Exception as exc:
            if raw_session is not None:
                raw_session.password = None
            if connection is not None:
                try:
                    self._protocol.close_connection(
                        connection,
                        timeout=io_idle_timeout,
                    )
                except Exception:
                    pass
            mapped = _mapped_protocol_error(exc, phase=diagnostic_phase)
            if mapped is not None:
                raise mapped from exc
            diagnostic = build_smb_diagnostic(
                phase=diagnostic_phase,
                exception=exc,
            )
            raise SMBProtocolError('CONNECTION_FAILED', **diagnostic) from exc
