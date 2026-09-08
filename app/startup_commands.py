"""Validation helpers for optional commands sent after an SSH connection."""


MAX_STARTUP_COMMANDS_LENGTH = 4096
MAX_STARTUP_COMMANDS_UTF8_BYTES = MAX_STARTUP_COMMANDS_LENGTH * 4


def validate_command_parameters(value):
    """Bound a parameter fragment before it can be concatenated."""
    if not isinstance(value, str):
        return 'Command parameters must be a string'
    if len(value) > MAX_STARTUP_COMMANDS_LENGTH:
        return 'Command parameters must not exceed 4096 characters'
    try:
        encoded_size = len(value.encode('utf-8'))
    except UnicodeEncodeError:
        return 'Command parameters must be valid UTF-8'
    if encoded_size > MAX_STARTUP_COMMANDS_UTF8_BYTES:
        return 'Command parameters exceed the UTF-8 byte limit'
    if '\x00' in value:
        return 'Commands cannot contain NUL bytes'
    return None


def normalize_startup_commands(value):
    """Return LF-normalized startup commands and an optional validation error."""
    if not isinstance(value, str):
        return '', 'Startup commands must be text'

    if len(value) > MAX_STARTUP_COMMANDS_LENGTH:
        return '', 'Startup commands must not exceed 4096 characters'

    if '\x00' in value:
        return '', 'Startup commands must not contain NUL bytes'

    value = value.replace('\r\n', '\n').replace('\r', '\n')
    if len(value) > MAX_STARTUP_COMMANDS_LENGTH:
        return '', 'Startup commands must not exceed 4096 characters'

    return value, None


def to_terminal_input(value):
    """Convert normalized linefeeds to the terminal's Enter input character."""
    return value.replace('\n', '\r')
