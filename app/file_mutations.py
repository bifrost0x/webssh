"""Small validated contracts for explicit remote file mutations."""

import errno
import hashlib
import hmac
import json
import math
import posixpath
import re
import stat
import time

from flask import current_app

import config


MUTATION_TIMEOUT = 10.0
METADATA_TTL = 60
_MESSAGES = {
    'INVALID_REQUEST': 'Invalid file operation request.',
    'CONFLICT': 'A file or folder with this name already exists.',
    'PERMISSION_DENIED': 'Permission denied for this file operation.',
    'NOT_FOUND': 'The file or folder no longer exists.',
    'UNSUPPORTED_OPERATION': 'This file operation is not supported.',
    'METADATA_CHANGED': 'The file metadata changed. Reopen the permissions dialog.',
    'TIMEOUT': 'The file operation timed out before it could start.',
    'OPERATION_FAILED': 'The remote file operation failed.',
    'OUTCOME_UNKNOWN': 'The result could not be confirmed. Refresh before taking further action.',
    'MODE_MISMATCH': 'The server reported different permissions. Refresh and review the current state.',
}


class FileMutationError(Exception):
    """An application-authored code and message, never remote exception text."""

    def __init__(self, code, *, actual_mode=None):
        self.code = code if code in _MESSAGES else 'OPERATION_FAILED'
        self.actual_mode = actual_mode
        super().__init__(_MESSAGES[self.code])


def mutation_failure(error, *, uncertain=False):
    if isinstance(error, FileMutationError):
        return error
    code = getattr(error, 'public_code', None)
    if code == 'OPERATION_UNAVAILABLE' or getattr(error, 'sftp_status', None) == 8:
        code = 'UNSUPPORTED_OPERATION'
    if code not in {'PERMISSION_DENIED', 'NOT_FOUND', 'CONFLICT', 'UNSUPPORTED_OPERATION'}:
        code = None
    number = getattr(error, 'errno', None)
    if isinstance(error, PermissionError) or number in {errno.EACCES, errno.EPERM, errno.EROFS}:
        code = 'PERMISSION_DENIED'
    elif isinstance(error, FileExistsError) or number in {errno.EEXIST, errno.ENOTEMPTY}:
        code = 'CONFLICT'
    elif isinstance(error, FileNotFoundError) or number == errno.ENOENT:
        code = 'NOT_FOUND'
    elif number in {errno.EOPNOTSUPP, errno.ENOSYS} or code == 'OPERATION_UNAVAILABLE':
        code = 'UNSUPPORTED_OPERATION'
    if code is None:
        code = 'OUTCOME_UNKNOWN' if uncertain and getattr(error, 'sftp_status', None) is None else ('TIMEOUT' if isinstance(error, TimeoutError) else 'OPERATION_FAILED')
    return FileMutationError(code)


def _valid_text(value, maximum):
    if not isinstance(value, str) or not value or len(value) > maximum:
        return False
    if any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value):
        return False
    try:
        return len(value.encode('utf-8')) <= maximum
    except UnicodeEncodeError:
        return False


def validate_leaf(name):
    if not _valid_text(name, 255) or name in {'.', '..'} or '/' in name or '\\' in name:
        raise FileMutationError('INVALID_REQUEST')
    return name


def validate_path(path, *, mutation=False):
    maximum = min(4096, config.FILE_CONTROL_MAX_PATH_BYTES)
    if not _valid_text(path, maximum) or path.startswith('//') or '\\' in path or '..' in path.split('/'):
        raise FileMutationError('INVALID_REQUEST')
    normalized = posixpath.normpath(path)
    if mutation and normalized in {'/', '.', '..'}:
        raise FileMutationError('INVALID_REQUEST')
    return normalized


def creation_path(parent_path, name):
    parent = validate_path(parent_path)
    leaf = validate_leaf(name)
    return validate_path(posixpath.join(parent, leaf), mutation=True)


def parse_mode(mode):
    if not isinstance(mode, str) or re.fullmatch(r'[0-7]{3}', mode, re.ASCII) is None:
        raise FileMutationError('INVALID_REQUEST')
    return int(mode, 8)


def permission_snapshot(info):
    mode = getattr(info, 'st_mode', None)
    if type(mode) is not int or mode < 0 or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
        raise FileMutationError('UNSUPPORTED_OPERATION')
    size = getattr(info, 'st_size', None)
    modified = getattr(info, 'st_mtime', None)
    if type(size) is not int or size < 0 or size > 2**63 - 1:
        raise FileMutationError('UNSUPPORTED_OPERATION')
    if type(modified) not in {int, float} or not math.isfinite(modified) or abs(modified) > 2**63 - 1:
        raise FileMutationError('UNSUPPORTED_OPERATION')
    snapshot = {
        'mode': f'{stat.S_IMODE(mode) & 0o777:03o}',
        'special_bits': mode & 0o7000,
        'object_type': 'directory' if stat.S_ISDIR(mode) else 'file',
        'size': size,
        'modified': modified,
    }
    for field, attribute in [('uid', 'st_uid'), ('gid', 'st_gid')]:
        value = getattr(info, attribute, None)
        if value is not None:
            if type(value) is not int or not 0 <= value <= 2**32 - 1:
                raise FileMutationError('UNSUPPORTED_OPERATION')
            snapshot[field] = value
    return snapshot


def _metadata_digest(user_id, source_id, path, snapshot):
    value = json.dumps([str(user_id), source_id, path, snapshot], sort_keys=True, separators=(',', ':'), allow_nan=False)
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def _sign(value):
    key = current_app.secret_key
    if not key:
        raise FileMutationError('OPERATION_FAILED')
    if isinstance(key, str):
        key = key.encode('utf-8')
    return hmac.new(key, b'file-permissions-v1\x00' + value.encode('ascii'), hashlib.sha256).hexdigest()


def issue_metadata_token(user_id, source_id, path, snapshot, *, now=None):
    stamp = int(time.time() if now is None else now)
    body = f'{stamp}.{_metadata_digest(user_id, source_id, path, snapshot)}'
    return f'{body}.{_sign(body)}'


def verify_metadata_token(token, user_id, source_id, path, snapshot, *, now=None):
    if not isinstance(token, str) or len(token) > 512 or re.fullmatch(r'[0-9]{1,12}\.[a-f0-9]{64}\.[a-f0-9]{64}', token) is None:
        raise FileMutationError('METADATA_CHANGED')
    stamp, digest, signature = token.split('.')
    clock = time.time() if now is None else now
    if not 0 <= clock - int(stamp) <= METADATA_TTL:
        raise FileMutationError('METADATA_CHANGED')
    if not hmac.compare_digest(signature, _sign(f'{stamp}.{digest}')) or not hmac.compare_digest(digest, _metadata_digest(user_id, source_id, path, snapshot)):
        raise FileMutationError('METADATA_CHANGED')
