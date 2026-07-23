"""Canonical validation and resolution for post-connect command modes."""

from . import command_manager, command_set_manager
from .startup_commands import normalize_startup_commands


VALID_MODES = {'none', 'free_text', 'command', 'command_set'}


def infer_mode(payload):
    """Return the explicit mode or infer one for legacy profile data."""
    payload = payload if isinstance(payload, dict) else {}
    explicit = payload.get('startup_mode')
    if explicit is not None:
        return explicit
    if payload.get('command_set_id'):
        return 'command_set'
    if payload.get('command_id'):
        return 'command'
    if payload.get('startup_commands'):
        return 'free_text'
    return 'none'


def _command_index(user_id):
    """Return commands visible to one user, keyed by their stable IDs."""
    try:
        commands = command_manager.get_all_commands(user_id)
    except (OSError, ValueError, TypeError):
        return None, 'Command library is unreadable'

    index = {}
    for command in commands:
        if not isinstance(command, dict):
            continue
        command_id = command.get('id')
        command_text = command.get('command')
        if isinstance(command_id, str) and isinstance(command_text, str):
            index[command_id] = command
    return index, None


def _get_owned_command(user_id, command_id):
    if not isinstance(command_id, str) or not command_id:
        return None, 'Command not found'
    commands, error = _command_index(user_id)
    if error:
        return None, error
    command = commands.get(command_id)
    return (command, None) if command else (None, 'Command not found')


def _resolve_command(command, parameters_override=None, override_present=False):
    parameters = parameters_override if override_present else command.get('parameters', '')
    if parameters is None:
        parameters = command.get('parameters', '')
    if not isinstance(parameters, str):
        return None, 'Command parameters must be a string'
    if '\x00' in parameters:
        return None, 'Commands cannot contain NUL bytes'

    command_text = command['command']
    resolved = command_text + (f' {parameters}' if parameters else '')
    return normalize_startup_commands(resolved)


def _has_conflicting_references(mode, payload):
    command_id = payload.get('command_id')
    command_set_id = payload.get('command_set_id')
    if mode == 'command':
        return bool(command_set_id)
    if mode == 'command_set':
        return bool(command_id)
    if mode == 'free_text':
        return bool(command_id or command_set_id)
    return False


def validate_configuration(user_id, payload):
    """Validate one mode and return only the fields safe to persist."""
    if not isinstance(payload, dict):
        return None, 'Invalid post-connect command configuration'

    mode = infer_mode(payload)
    if mode not in VALID_MODES:
        return None, 'Invalid post-connect command mode'
    if _has_conflicting_references(mode, payload):
        return None, 'Conflicting post-connect command configuration'

    if mode == 'none':
        return {'startup_mode': 'none'}, None

    if mode == 'free_text':
        normalized, error = normalize_startup_commands(
            payload.get('startup_commands', '')
        )
        if error:
            return None, error
        return {
            'startup_mode': mode,
            'startup_commands': normalized,
        }, None

    if mode == 'command':
        command, error = _get_owned_command(user_id, payload.get('command_id'))
        if error:
            return None, error
        override_present = 'parameters_override' in payload
        override = payload.get('parameters_override')
        if override is not None and not isinstance(override, str):
            return None, 'Command parameters must be a string'
        _resolved, error = _resolve_command(
            command, override, override_present=override_present
        )
        if error:
            return None, error
        result = {
            'startup_mode': mode,
            'command_id': command['id'],
        }
        if override_present and override is not None:
            result['parameters_override'] = override
        return result, None

    command_set, error = command_set_manager.get_command_set(
        user_id, payload.get('command_set_id')
    )
    if error:
        return None, error
    return {
        'startup_mode': mode,
        'command_set_id': command_set['id'],
    }, None


def resolve_configuration(user_id, payload):
    """Resolve validated configuration to the exact terminal command string."""
    if not isinstance(payload, dict):
        return None, 'Invalid post-connect command configuration'
    mode = infer_mode(payload)
    if mode not in VALID_MODES:
        return None, 'Invalid post-connect command mode'
    if _has_conflicting_references(mode, payload):
        return None, 'Conflicting post-connect command configuration'

    if mode == 'none':
        return '', None
    if mode == 'free_text':
        return normalize_startup_commands(payload.get('startup_commands', ''))
    if mode == 'command_set':
        return command_set_manager.resolve_command_set(
            user_id, payload.get('command_set_id')
        )

    command, error = _get_owned_command(user_id, payload.get('command_id'))
    if error:
        return None, error
    override_present = 'parameters_override' in payload
    override = payload.get('parameters_override')
    if override is not None and not isinstance(override, str):
        return None, 'Command parameters must be a string'
    return _resolve_command(
        command,
        override,
        override_present=override_present,
    )
