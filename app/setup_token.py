"""One-time setup token that guards account creation while no account exists.

The first account becomes administrator. Without a secret, whoever reaches a
fresh instance first, including a web page that uses DNS rebinding against a
LAN address, would get that account. The token is printed only to the process
output (``docker logs``), which requires access to the host. It is kept in
memory, so a restart prints a new one, and it is no longer asked for once an
account exists.
"""

import hmac
import secrets
import sys
from threading import Lock

from .models import User

_lock = Lock()
_token = None


def setup_token_required():
    return User.query.with_entities(User.id).first() is None


def current_setup_token():
    global _token
    with _lock:
        if _token is None:
            _token = secrets.token_urlsafe(18)
            print(
                '\n'.join((
                    '',
                    f'WebSSH setup token: {_token}',
                    'Enter it on the registration page to create the first '
                    'administrator. It is only needed while no account exists '
                    'and changes when WebSSH restarts.',
                    '',
                )),
                file=sys.stderr,
                flush=True,
            )
        return _token


def setup_token_matches(value):
    if not isinstance(value, str):
        return False
    return hmac.compare_digest(
        value.strip().encode('utf-8', 'surrogatepass'),
        current_setup_token().encode('ascii'),
    )


def announce_setup_token_if_unclaimed():
    if setup_token_required():
        current_setup_token()
