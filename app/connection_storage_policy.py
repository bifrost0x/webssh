"""Prospective quotas for saved connection and jump-host metadata."""

from hashlib import sha256
import hmac
import json
from pathlib import Path
import re

import config


class ConnectionStorageLimitError(ValueError):
    """A saved-connection mutation would grow beyond its resource budget."""


PROFILE_NAME_MAX_BYTES = 512
PROFILE_HOST_MAX_BYTES = 1024
PROFILE_USERNAME_MAX_BYTES = 128
PROFILE_GROUP_MAX_BYTES = 256
PROFILE_REFERENCE_MAX_BYTES = 128
PROFILE_STARTUP_MAX_BYTES = 64 * 1024
JUMP_HOST_NAME_MAX_BYTES = 512
_RECOVERY_SELECTOR_PATTERN = re.compile(
    r'r1:(0|[1-9][0-9]{0,9}):([0-9a-f]{64})'
)
_RECOVERY_SELECTOR_DOMAIN = b'webssh-connection-recovery-selector-v1\0'


def _error(message):
    raise ConnectionStorageLimitError(
        f'Connection storage quota exceeded: {message}'
    )


def utf8_size(value):
    try:
        return len(value.encode('utf-8'))
    except UnicodeEncodeError:
        _error('text is not valid UTF-8')


def bounded_text(value, maximum, label, legacy=None):
    if not isinstance(value, str):
        _error(f'{label} must be text')
    size = utf8_size(value)
    if size <= maximum:
        return
    if isinstance(legacy, str) and size <= utf8_size(legacy):
        return
    _error(f'{label} is too large')


def validate_profile(profile, legacy=None):
    """Enforce UTF-8 field budgets on one changed profile."""
    legacy = legacy if isinstance(legacy, dict) else {}
    for field, maximum, label in (
        ('id', PROFILE_REFERENCE_MAX_BYTES, 'profile id'),
        ('name', PROFILE_NAME_MAX_BYTES, 'profile name'),
        ('host', PROFILE_HOST_MAX_BYTES, 'profile host'),
        ('username', PROFILE_USERNAME_MAX_BYTES, 'profile username'),
        ('group', PROFILE_GROUP_MAX_BYTES, 'profile group'),
        ('key_id', PROFILE_REFERENCE_MAX_BYTES, 'key reference'),
        ('jump_host_id', PROFILE_REFERENCE_MAX_BYTES, 'jump-host reference'),
        ('command_id', PROFILE_REFERENCE_MAX_BYTES, 'command reference'),
        ('command_set_id', PROFILE_REFERENCE_MAX_BYTES, 'command-set reference'),
        ('startup_commands', PROFILE_STARTUP_MAX_BYTES, 'startup commands'),
        (
            'parameters_override',
            PROFILE_STARTUP_MAX_BYTES,
            'command parameters',
        ),
    ):
        value = profile.get(field)
        if value is None:
            continue
        bounded_text(value, maximum, label, legacy.get(field))


def validate_jump_host(jump_host, legacy=None):
    """Enforce UTF-8 field budgets on one changed jump host."""
    legacy = legacy if isinstance(legacy, dict) else {}
    for field, maximum, label in (
        ('id', PROFILE_REFERENCE_MAX_BYTES, 'jump-host id'),
        ('name', JUMP_HOST_NAME_MAX_BYTES, 'jump-host name'),
        ('host', PROFILE_HOST_MAX_BYTES, 'jump-host host'),
        ('username', PROFILE_USERNAME_MAX_BYTES, 'jump-host username'),
        ('key_id', PROFILE_REFERENCE_MAX_BYTES, 'key reference'),
    ):
        value = jump_host.get(field)
        if value is None:
            continue
        bounded_text(value, maximum, label, legacy.get(field))


def _file_size(path):
    try:
        return Path(path).stat().st_size
    except FileNotFoundError:
        return 0


def _serialize_document(document, *, compact=False):
    try:
        kwargs = {'separators': (',', ':')} if compact else {'indent': 2}
        return json.dumps(document, **kwargs).encode('utf-8')
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ConnectionStorageLimitError(
            'Connection storage quota exceeded: data is not serializable'
        ) from exc


def enforce_store_read_limit(path, *, record_count=None, maximum_count=None):
    """Reject oversized legacy stores before normal listing or launch paths."""
    if _file_size(path) > config.CONNECTION_STORE_MAX_BYTES:
        _error('stored data exceeds its byte limit')
    if (
        record_count is not None
        and maximum_count is not None
        and record_count > maximum_count
    ):
        _error(f'more than {maximum_count} stored records are not allowed')


def enforce_store_recovery_limit(path, *, record_count=None):
    """Bound legacy recovery before and after JSON deserialization.

    Recovery deliberately permits a store larger than the normal read limit,
    but it must never become an unbounded parsing path.  Call once before the
    load for the byte ceiling and again with the decoded record count.
    """
    if _file_size(path) > config.CONNECTION_STORE_RECOVERY_MAX_BYTES:
        _error('stored data exceeds its recovery byte limit')
    if (
        record_count is not None
        and record_count > config.CONNECTION_STORE_RECOVERY_MAX_RECORDS
    ):
        _error(
            'more than '
            f'{config.CONNECTION_STORE_RECOVERY_MAX_RECORDS} recovery records '
            'are not allowed'
        )


def recovery_record_selector(scope, index, record):
    """Return a stable, opaque selector for one record at one exact ordinal."""
    if not isinstance(scope, str) or not scope:
        raise ValueError('recovery selector scope is required')
    if type(index) is not int or index < 0:
        raise ValueError('recovery selector index is invalid')
    canonical = json.dumps(
        record,
        ensure_ascii=True,
        separators=(',', ':'),
        sort_keys=True,
    ).encode('utf-8')
    digest = sha256(
        _RECOVERY_SELECTOR_DOMAIN
        + scope.encode('utf-8')
        + b'\0'
        + str(index).encode('ascii')
        + b'\0'
        + canonical
    ).hexdigest()
    return f'r1:{index}:{digest}'


def resolve_recovery_record_selector(scope, records, selector):
    """Resolve a selector only when its current ordinal and content still match."""
    if not isinstance(selector, str):
        return None
    match = _RECOVERY_SELECTOR_PATTERN.fullmatch(selector)
    if match is None:
        return None
    index = int(match.group(1))
    if index >= len(records):
        return None
    expected = recovery_record_selector(scope, index, records[index])
    return index if hmac.compare_digest(expected, selector) else None


def enforce_store_transition(
    *,
    path,
    other_path,
    prospective_document,
    prospective_count,
    previous_count,
    maximum_count,
    previous_document=None,
    compact=False,
):
    """Return the exact approved payload for a prospective store transition."""
    path = Path(path)
    current_size = _file_size(path)
    other_size = _file_size(other_path)
    prospective_payload = _serialize_document(
        prospective_document,
        compact=compact,
    )
    prospective_size = len(prospective_payload)
    previous_size = current_size
    if previous_document is not None:
        if not compact:
            previous_size = max(
                previous_size,
                len(_serialize_document(previous_document, compact=False)),
            )
        if prospective_size > config.CONNECTION_STORE_RECOVERY_MAX_BYTES:
            _error('one connection store would exceed its recovery byte limit')
        if compact and prospective_size > current_size:
            _error('recovery deletion would grow its connection store')
    if prospective_count > maximum_count and prospective_count > previous_count:
        _error(f'more than {maximum_count} records are not allowed')
    if (
        prospective_size > config.CONNECTION_STORE_MAX_BYTES
        and prospective_size > previous_size
    ):
        _error('one connection store would exceed its byte limit')
    if (
        prospective_size + other_size > config.CONNECTION_CONFIG_MAX_BYTES
        and prospective_size + other_size > previous_size + other_size
    ):
        _error('combined connection data would exceed its byte limit')
    return prospective_payload
