"""Stable, non-sensitive SSH connection errors for browser presentation."""


class SSHConnectionError(str):
    """A safe client message with an optional stable machine-readable code."""

    def __new__(cls, message, *, code=None, context=None):
        instance = super().__new__(cls, message)
        instance.code = code
        instance.context = context
        return instance


def connection_error_payload(error, **extra):
    """Return a Socket.IO-safe payload without leaking Paramiko details."""
    payload = {'error': str(error), **extra}
    code = getattr(error, 'code', None)
    context = getattr(error, 'context', None)
    if code:
        payload['code'] = code
    if context:
        payload['context'] = context
    return payload
