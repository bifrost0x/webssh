"""Single-worker admission boundary for browser logins and revocation."""
from functools import wraps
from contextlib import contextmanager
import threading

_session_access_lock = threading.RLock()


@contextmanager
def login_access():
    with _session_access_lock:
        yield


def serialize_login_access(function):
    @wraps(function)
    def guarded(*args, **kwargs):
        with login_access():
            return function(*args, **kwargs)
    return guarded
