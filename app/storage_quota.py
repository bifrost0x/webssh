"""Size primitives shared by the command and connection storage policies.

Each policy passes ``error``, a callable that turns a message into its own
quota exception, so user-facing texts stay specific to the policy.
"""

from pathlib import Path


def utf8_size(value, *, error):
    try:
        return len(value.encode('utf-8'))
    except UnicodeEncodeError:
        raise error('text is not valid UTF-8')


def bounded_text(value, maximum, label, legacy=None, *, error):
    """Reject text over ``maximum`` bytes unless it does not grow ``legacy``."""
    if not isinstance(value, str):
        raise error(f'{label} must be text')
    size = utf8_size(value, error=error)
    if size <= maximum:
        return
    if isinstance(legacy, str) and size <= utf8_size(legacy, error=error):
        return
    raise error(f'{label} is too large')


def file_size(path):
    try:
        return Path(path).stat().st_size
    except FileNotFoundError:
        return 0
