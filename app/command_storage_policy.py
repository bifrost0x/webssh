"""Prospective resource policy for per-user command configuration."""

import json
from pathlib import Path

import config


COMMAND_NAME_MAX_BYTES = 512
COMMAND_TEXT_MAX_BYTES = 16 * 1024
COMMAND_PARAMETERS_MAX_BYTES = 16 * 1024
COMMAND_DESCRIPTION_MAX_BYTES = 16 * 1024
COMMAND_CATEGORY_MAX_BYTES = 256
COMMAND_OS_VALUE_MAX_BYTES = 128
COMMAND_ID_MAX_BYTES = 128


class CommandStorageLimitError(ValueError):
    """A command mutation would exceed a persistent resource boundary."""


def _error(message):
    raise CommandStorageLimitError(
        f'Command storage quota exceeded: {message}'
    )


def utf8_size(value):
    try:
        return len(value.encode('utf-8'))
    except UnicodeEncodeError:
        _error('text is not valid UTF-8')


def serialized_size(value):
    try:
        return len(json.dumps(value, indent=2).encode('utf-8'))
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise CommandStorageLimitError(
            'Command storage quota exceeded: data is not serializable'
        ) from exc


def _bounded_text(value, limit, label, legacy=None):
    if not isinstance(value, str):
        _error(f'{label} must be text')
    size = utf8_size(value)
    if size <= limit:
        return
    if isinstance(legacy, str) and size <= utf8_size(legacy):
        return
    _error(f'{label} is too large')


def validate_user_command(command, legacy=None):
    legacy = legacy if isinstance(legacy, dict) else {}
    _bounded_text(
        command.get('id', ''),
        COMMAND_ID_MAX_BYTES,
        'command id',
        legacy.get('id'),
    )
    for field, limit, label in (
        ('name', COMMAND_NAME_MAX_BYTES, 'command name'),
        ('command', COMMAND_TEXT_MAX_BYTES, 'command text'),
        ('parameters', COMMAND_PARAMETERS_MAX_BYTES, 'command parameters'),
        ('description', COMMAND_DESCRIPTION_MAX_BYTES, 'command description'),
        ('category', COMMAND_CATEGORY_MAX_BYTES, 'command category'),
    ):
        _bounded_text(
            command.get(field, ''),
            limit,
            label,
            legacy.get(field),
        )
    os_values = command.get('os', [])
    legacy_os = legacy.get('os', [])
    if not isinstance(os_values, list):
        _error('command operating systems must be a list')
    if (
        len(os_values) > config.COMMAND_OS_MAX_ENTRIES
        and len(os_values) > len(legacy_os if isinstance(legacy_os, list) else [])
    ):
        _error('too many command operating systems')
    for index, value in enumerate(os_values):
        previous = (
            legacy_os[index]
            if isinstance(legacy_os, list) and index < len(legacy_os)
            else None
        )
        _bounded_text(
            value,
            COMMAND_OS_VALUE_MAX_BYTES,
            'command operating system',
            previous,
        )


def validate_command_set(command_set, legacy=None):
    legacy = legacy if isinstance(legacy, dict) else {}
    for field, limit, label in (
        ('id', COMMAND_ID_MAX_BYTES, 'command set id'),
        ('name', COMMAND_NAME_MAX_BYTES, 'command set name'),
        (
            'description',
            COMMAND_DESCRIPTION_MAX_BYTES,
            'command set description',
        ),
    ):
        _bounded_text(
            command_set.get(field, ''),
            limit,
            label,
            legacy.get(field),
        )
    steps = command_set.get('steps', [])
    legacy_steps = legacy.get('steps', [])
    if not isinstance(steps, list):
        _error('command set steps must be a list')
    if (
        len(steps) > config.COMMAND_SET_MAX_STEPS
        and len(steps) > len(
            legacy_steps if isinstance(legacy_steps, list) else []
        )
    ):
        _error('too many command set steps')
    for index, step in enumerate(steps):
        previous = (
            legacy_steps[index]
            if isinstance(legacy_steps, list)
            and index < len(legacy_steps)
            and isinstance(legacy_steps[index], dict)
            else {}
        )
        if not isinstance(step, dict):
            _error('command set step is invalid')
        if step.get('type') == 'inline':
            _bounded_text(
                step.get('command', ''),
                COMMAND_TEXT_MAX_BYTES,
                'inline command',
                previous.get('command'),
            )
        elif step.get('type') == 'library':
            _bounded_text(
                step.get('command_id', ''),
                COMMAND_ID_MAX_BYTES,
                'command reference',
                previous.get('command_id'),
            )
            override = step.get('parameters_override')
            if override is not None:
                _bounded_text(
                    override,
                    COMMAND_PARAMETERS_MAX_BYTES,
                    'command parameter override',
                    previous.get('parameters_override'),
                )


def _file_size(path):
    try:
        return Path(path).stat().st_size
    except FileNotFoundError:
        return 0


def enforce_store_transition(
    *,
    path,
    prospective_document,
    prospective_count,
    maximum_count,
    other_path,
    previous_size=None,
    previous_count=None,
):
    """Reject only new growth beyond count, document, or aggregate quotas."""
    path = Path(path)
    current_size = (
        _file_size(path) if previous_size is None else int(previous_size)
    )
    current_count = (
        0
        if previous_count is None
        else int(previous_count)
    )
    prospective_size = serialized_size(prospective_document)
    if (
        prospective_count > maximum_count
        and prospective_count > current_count
    ):
        _error(f'more than {maximum_count} records are not allowed')
    if (
        prospective_size > config.COMMAND_STORE_MAX_BYTES
        and prospective_size > current_size
    ):
        _error('one command store would exceed its byte limit')
    other_size = _file_size(other_path)
    if (
        prospective_size + other_size > config.COMMAND_CONFIG_MAX_BYTES
        and prospective_size + other_size > current_size + other_size
    ):
        _error('combined command data would exceed its byte limit')
    return prospective_size


def command_storage_usage(user_data_dir):
    root = Path(user_data_dir)
    commands = _file_size(root / 'commands.json')
    command_sets = _file_size(root / 'command_sets.json')
    return {
        'commands_bytes': commands,
        'command_sets_bytes': command_sets,
        'total_bytes': commands + command_sets,
        'quota_bytes': config.COMMAND_CONFIG_MAX_BYTES,
        'over_quota': commands + command_sets > config.COMMAND_CONFIG_MAX_BYTES,
    }
