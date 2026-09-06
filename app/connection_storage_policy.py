"""Prospective quotas for saved connection and jump-host metadata."""

import json
from pathlib import Path

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


def _serialized_size(document):
    try:
        return len(json.dumps(document, indent=2).encode('utf-8'))
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


def enforce_store_transition(
    *,
    path,
    other_path,
    prospective_document,
    prospective_count,
    previous_count,
    maximum_count,
):
    """Reject growth while allowing deletion from legacy oversized stores."""
    path = Path(path)
    current_size = _file_size(path)
    other_size = _file_size(other_path)
    prospective_size = _serialized_size(prospective_document)
    if prospective_count > maximum_count and prospective_count > previous_count:
        _error(f'more than {maximum_count} records are not allowed')
    if (
        prospective_size > config.CONNECTION_STORE_MAX_BYTES
        and prospective_size > current_size
    ):
        _error('one connection store would exceed its byte limit')
    if (
        prospective_size + other_size > config.CONNECTION_CONFIG_MAX_BYTES
        and prospective_size + other_size > current_size + other_size
    ):
        _error('combined connection data would exceed its byte limit')
    return prospective_size
