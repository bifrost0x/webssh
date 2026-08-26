"""Stable, credential-free public failures for file transfers."""

from __future__ import annotations

from dataclasses import dataclass
import errno

from .remote_transfer import (
    RemoteTransferCancelled,
    RemoteTransferConflict,
    RemoteTransferLimitExceeded,
)
from . import sftp_handler
from .smb_backend import FileConflict, NonAtomicOverwriteRequired


_FAILURE_DEFINITIONS = {
    'PERMISSION_DENIED': {
        'messages': frozenset({
            'No write permission for the destination.',
            'No read permission for the source.',
            'Permission denied for this file operation.',
        }),
        'retryable': False,
        'http_status': 403,
    },
    'CONFLICT': {
        'messages': frozenset({
            'A file or folder already exists at the destination.',
        }),
        'retryable': False,
        'http_status': 409,
    },
    'NOT_FOUND': {
        'messages': frozenset({
            'The requested file or folder was not found.',
        }),
        'retryable': False,
        'http_status': 404,
    },
    'SHARE_UNAVAILABLE': {
        'messages': frozenset({'The SMB share is unavailable.'}),
        'retryable': True,
        'http_status': 404,
    },
    'TIMEOUT': {
        'messages': frozenset({'The file operation timed out.'}),
        'retryable': True,
        'http_status': 504,
    },
    'SOURCE_UNAVAILABLE': {
        'messages': frozenset({
            'The file source is no longer available. Reconnect and try again.',
        }),
        'retryable': True,
        'http_status': 404,
    },
    'LIMIT_EXCEEDED': {
        'messages': frozenset({'The transfer exceeds the configured limit.'}),
        'retryable': False,
        'http_status': 413,
    },
    'CANCELLED': {
        'messages': frozenset({'The transfer was cancelled.'}),
        'retryable': False,
        'http_status': 409,
    },
    'ATOMIC_REPLACE_UNAVAILABLE': {
        'messages': frozenset({
            'Safe overwrite is unavailable for this destination.',
        }),
        'retryable': False,
        'http_status': 409,
    },
    'TRANSFER_UNAVAILABLE': {
        'messages': frozenset({'The transfer could not be completed.'}),
        'retryable': False,
        'http_status': 500,
    },
}

_LIMIT_KINDS = frozenset({
    'upload',
    'download',
    'archive',
    'remote_transfer',
})
_MAX_PUBLIC_BYTE_COUNT = (1 << 63) - 1


@dataclass(frozen=True, slots=True)
class TransferFailure:
    """One allowlisted public failure shared by HTTP and Socket.IO."""

    code: str
    message: str
    retryable: bool
    http_status: int
    limit_kind: str | None = None
    limit_bytes: int | None = None
    actual_bytes: int | None = None

    def __post_init__(self):
        definition = _FAILURE_DEFINITIONS.get(self.code)
        if (
            definition is None
            or self.message not in definition['messages']
            or self.retryable is not definition['retryable']
            or self.http_status != definition['http_status']
        ):
            raise ValueError('unsupported public transfer failure')
        context = (self.limit_kind, self.limit_bytes, self.actual_bytes)
        if self.code != 'LIMIT_EXCEEDED':
            if any(value is not None for value in context):
                raise ValueError('limit context is only valid for limit failures')
            return
        if all(value is None for value in context):
            return
        if self.limit_kind not in _LIMIT_KINDS:
            raise ValueError('unsupported public transfer limit kind')
        if not _valid_public_byte_count(self.limit_bytes):
            raise ValueError('invalid public transfer limit')
        if (
            self.actual_bytes is not None
            and not _valid_public_byte_count(self.actual_bytes)
        ):
            raise ValueError('invalid public transfer size')

    def to_public_dict(self) -> dict[str, object]:
        payload = {
            'error_code': self.code,
            'error': self.message,
            'retryable': self.retryable,
        }
        if self.limit_kind is not None:
            payload['limit_kind'] = self.limit_kind
            payload['limit_bytes'] = self.limit_bytes
            if self.actual_bytes is not None:
                payload['actual_bytes'] = self.actual_bytes
        return payload


def _valid_public_byte_count(value) -> bool:
    return (
        type(value) is int
        and 0 <= value <= _MAX_PUBLIC_BYTE_COUNT
    )


def _permission_message(operation: str) -> str:
    if operation == 'upload':
        return 'No write permission for the destination.'
    if operation in {'download', 'folder_download'}:
        return 'No read permission for the source.'
    return 'Permission denied for this file operation.'


def _failure(
    code: str,
    operation: str,
    *,
    limit_kind: str | None = None,
    limit_bytes: int | None = None,
    actual_bytes: int | None = None,
) -> TransferFailure:
    definition = _FAILURE_DEFINITIONS[code]
    message = (
        _permission_message(operation)
        if code == 'PERMISSION_DENIED'
        else next(iter(definition['messages']))
    )
    return TransferFailure(
        code,
        message,
        definition['retryable'],
        definition['http_status'],
        limit_kind,
        limit_bytes,
        actual_bytes,
    )


def _public_code(error: BaseException) -> str | None:
    code = getattr(error, 'public_code', None)
    if code in _FAILURE_DEFINITIONS:
        return code
    return None


def classify_transfer_failure(
    error: BaseException,
    *,
    operation: str,
    limit_kind: str | None = None,
    limit_bytes: int | None = None,
    actual_bytes: int | None = None,
) -> TransferFailure:
    """Classify an internal error without reflecting its text to the client."""
    if not isinstance(error, BaseException):
        raise TypeError('error must be an exception')
    if not isinstance(operation, str) or not operation:
        raise ValueError('operation is required')

    code = _public_code(error)
    if code is None:
        if isinstance(error, (FileConflict, RemoteTransferConflict)):
            code = 'CONFLICT'
        elif isinstance(error, NonAtomicOverwriteRequired):
            code = 'ATOMIC_REPLACE_UNAVAILABLE'
        elif isinstance(error, RemoteTransferLimitExceeded):
            code = 'LIMIT_EXCEEDED'
        elif isinstance(error, RemoteTransferCancelled):
            code = 'CANCELLED'
        elif isinstance(
            error,
            (
                sftp_handler.UploadSizeExceeded,
                sftp_handler.TransferSizeExceeded,
                sftp_handler.TransferMemberLimitExceeded,
            ),
        ):
            code = 'LIMIT_EXCEEDED'
        elif isinstance(error, sftp_handler.TransferCancelled):
            code = 'CANCELLED'
        elif isinstance(error, PermissionError):
            code = 'PERMISSION_DENIED'
        elif isinstance(error, FileNotFoundError):
            code = 'NOT_FOUND'
        elif isinstance(error, TimeoutError):
            code = 'TIMEOUT'
        elif isinstance(error, ConnectionError):
            code = 'SOURCE_UNAVAILABLE'
        elif isinstance(error, OSError):
            code = {
                errno.EACCES: 'PERMISSION_DENIED',
                errno.EPERM: 'PERMISSION_DENIED',
                errno.ENOENT: 'NOT_FOUND',
                errno.EEXIST: 'CONFLICT',
                errno.ENOTEMPTY: 'CONFLICT',
                errno.ETIMEDOUT: 'TIMEOUT',
            }.get(error.errno)

    return _failure(
        code or 'TRANSFER_UNAVAILABLE',
        operation,
        limit_kind=limit_kind,
        limit_bytes=limit_bytes,
        actual_bytes=actual_bytes,
    )
