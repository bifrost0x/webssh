"""Validation helpers for optional commands sent after an SSH connection."""


MAX_STARTUP_COMMANDS_LENGTH = 4096


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
