import errno

import pytest

from app.remote_transfer import (
    RemoteTransferCancelled,
    RemoteTransferConflict,
    RemoteTransferLimitExceeded,
)
from app.smb_backend import FileConflict, NonAtomicOverwriteRequired
from app.smb_protocol import SMBProtocolError
from app.transfer_errors import TransferFailure, classify_transfer_failure


@pytest.mark.parametrize(
    ('error', 'operation', 'code', 'message', 'http_status', 'retryable'),
    (
        (
            SMBProtocolError('PERMISSION_DENIED', r'secret \\server\share'),
            'upload',
            'PERMISSION_DENIED',
            'No write permission for the destination.',
            403,
            False,
        ),
        (
            PermissionError(r'secret \\server\share'),
            'download',
            'PERMISSION_DENIED',
            'No read permission for the source.',
            403,
            False,
        ),
        (
            FileConflict('sensitive destination'),
            'upload',
            'CONFLICT',
            'A file or folder already exists at the destination.',
            409,
            False,
        ),
        (
            RemoteTransferConflict('sensitive destination'),
            'remote_transfer',
            'CONFLICT',
            'A file or folder already exists at the destination.',
            409,
            False,
        ),
        (
            FileNotFoundError(errno.ENOENT, r'secret \\server\share'),
            'download',
            'NOT_FOUND',
            'The requested file or folder was not found.',
            404,
            False,
        ),
        (
            SMBProtocolError('SHARE_UNAVAILABLE', r'secret \\server\share'),
            'connect',
            'SHARE_UNAVAILABLE',
            'The SMB share is unavailable.',
            404,
            True,
        ),
        (
            TimeoutError(r'secret \\server\share'),
            'upload',
            'TIMEOUT',
            'The file operation timed out.',
            504,
            True,
        ),
        (
            SMBProtocolError('SOURCE_UNAVAILABLE', r'secret \\server\share'),
            'upload',
            'SOURCE_UNAVAILABLE',
            'The file source is no longer available. Reconnect and try again.',
            404,
            True,
        ),
        (
            RemoteTransferLimitExceeded('sensitive limit details'),
            'remote_transfer',
            'LIMIT_EXCEEDED',
            'The transfer exceeds the configured limit.',
            413,
            False,
        ),
        (
            RemoteTransferCancelled('sensitive cancellation details'),
            'remote_transfer',
            'CANCELLED',
            'The transfer was cancelled.',
            409,
            False,
        ),
        (
            NonAtomicOverwriteRequired('sensitive target'),
            'upload',
            'ATOMIC_REPLACE_UNAVAILABLE',
            'Safe overwrite is unavailable for this destination.',
            409,
            False,
        ),
        (
            RuntimeError(r'secret \\server\share'),
            'upload',
            'TRANSFER_UNAVAILABLE',
            'The transfer could not be completed.',
            500,
            False,
        ),
    ),
)
def test_classification_is_stable_safe_and_actionable(
    error,
    operation,
    code,
    message,
    http_status,
    retryable,
):
    failure = classify_transfer_failure(error, operation=operation)

    assert failure == TransferFailure(code, message, retryable, http_status)
    assert failure.to_public_dict() == {
        'error_code': code,
        'error': message,
        'retryable': retryable,
    }
    assert 'secret' not in repr(failure.to_public_dict())
    assert 'server' not in repr(failure.to_public_dict())


def test_unknown_protocol_code_uses_safe_fallback():
    failure = classify_transfer_failure(
        SMBProtocolError('UNEXPECTED_CODE', r'secret \\server\share'),
        operation='upload',
    )

    assert failure.code == 'TRANSFER_UNAVAILABLE'
    assert failure.http_status == 500
    assert failure.to_public_dict()['error'] == 'The transfer could not be completed.'


def test_transfer_failure_rejects_non_allowlisted_values():
    with pytest.raises(ValueError):
        TransferFailure('CUSTOM', 'Raw backend response', False, 418)


def test_transfer_failure_is_frozen():
    failure = classify_transfer_failure(PermissionError(), operation='upload')

    with pytest.raises(AttributeError):
        failure.code = 'TRANSFER_UNAVAILABLE'


def test_limit_failure_serializes_only_validated_numeric_context():
    failure = classify_transfer_failure(
        RemoteTransferLimitExceeded('internal budget'),
        operation='remote_transfer',
        limit_kind='remote_transfer',
        limit_bytes=100 * 1024 * 1024,
        actual_bytes=142 * 1024 * 1024,
    )

    assert failure.to_public_dict() == {
        'error_code': 'LIMIT_EXCEEDED',
        'error': 'The transfer exceeds the configured limit.',
        'retryable': False,
        'limit_kind': 'remote_transfer',
        'limit_bytes': 100 * 1024 * 1024,
        'actual_bytes': 142 * 1024 * 1024,
    }


@pytest.mark.parametrize(
    'context',
    (
        {'limit_kind': 'raw_backend', 'limit_bytes': 1},
        {'limit_kind': 'upload'},
        {'limit_kind': 'upload', 'limit_bytes': True},
        {'limit_kind': 'upload', 'limit_bytes': -1},
        {'limit_kind': 'upload', 'limit_bytes': 2 ** 63},
        {'limit_kind': 'upload', 'limit_bytes': 1, 'actual_bytes': False},
        {'limit_kind': 'upload', 'limit_bytes': 1, 'actual_bytes': -1},
    ),
)
def test_limit_failure_rejects_unsafe_context(context):
    with pytest.raises(ValueError):
        TransferFailure(
            'LIMIT_EXCEEDED',
            'The transfer exceeds the configured limit.',
            False,
            413,
            **context,
        )


def test_non_limit_failure_rejects_limit_context():
    with pytest.raises(ValueError):
        TransferFailure(
            'TRANSFER_UNAVAILABLE',
            'The transfer could not be completed.',
            False,
            500,
            limit_kind='upload',
            limit_bytes=1,
        )
