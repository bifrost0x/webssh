"""Drain complete account data operations before quarantining their storage."""

from contextlib import contextmanager, nullcontext
from functools import wraps
import threading
import time

from werkzeug.exceptions import ServiceUnavailable


class DataAccessUnavailable(ServiceUnavailable):
    description = 'Account data is temporarily unavailable; retry the operation.'


class DataAccessGate:
    def __init__(self):
        self._condition = threading.Condition()
        self._active = {}
        self._blocked = set()
        self._local = threading.local()
        self._closed = False
        self._operations = 0

    @property
    def closed(self):
        with self._condition:
            return self._closed

    @contextmanager
    def operation(self):
        """Keep an admitted request alive until its complete call stack exits."""
        depth = getattr(self._local, 'operation_depth', 0)
        with self._condition:
            if self._closed and not depth:
                raise DataAccessUnavailable()
            self._operations += 1
        self._local.operation_depth = depth + 1
        try:
            yield
        finally:
            self._local.operation_depth = depth
            with self._condition:
                self._operations -= 1
                self._condition.notify_all()

    def close_and_drain(self, *, timeout=30):
        """Stop admission until process restart, including on drain failure."""
        deadline = time.monotonic() + timeout
        with self._condition:
            self._closed = True
            if (getattr(self._local, 'owned', ())
                    or getattr(self._local, 'operation_depth', 0)):
                raise DataAccessUnavailable()
            while self._active or self._operations:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise DataAccessUnavailable()
                self._condition.wait(remaining)

    @contextmanager
    def access(self, user_id):
        user_id = int(user_id)
        owned = getattr(self._local, 'owned', None)
        if owned is None:
            owned = self._local.owned = set()
        if user_id in owned:
            yield False
            return
        with self._condition:
            if (user_id in self._blocked
                    or (self._closed and not getattr(self._local, 'operation_depth', 0))):
                raise DataAccessUnavailable()
            self._active[user_id] = self._active.get(user_id, 0) + 1
        owned.add(user_id)
        try:
            yield True
        finally:
            owned.remove(user_id)
            with self._condition:
                count = self._active[user_id] - 1
                if count:
                    self._active[user_id] = count
                else:
                    del self._active[user_id]
                self._condition.notify_all()

    @contextmanager
    def retire(self, user_id, *, on_blocked, timeout=30):
        user_id = int(user_id)
        deadline = time.monotonic() + timeout
        with self._condition:
            if user_id in self._blocked or user_id in getattr(self._local, 'owned', ()):
                raise DataAccessUnavailable()
            self._blocked.add(user_id)
        try:
            # Cancel remote resources before waiting, so their owners can exit.
            on_blocked()
            with self._condition:
                while self._active.get(user_id, 0):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise DataAccessUnavailable()
                    self._condition.wait(remaining)
            yield
        finally:
            with self._condition:
                self._blocked.remove(user_id)
                self._condition.notify_all()


def current_data_access():
    from flask import current_app
    return current_app.extensions['data_access']


def bind_user_data_access(user_id):
    """Bind delayed storage work to its original app and account incarnation."""
    from flask import current_app, has_app_context
    from .models import User, db

    if not has_app_context():
        # Standalone host-trust utilities have no application account database.
        return nullcontext
    app = current_app._get_current_object()
    with user_data_access(user_id):
        expected = db.session.query(User.created_at).filter_by(id=int(user_id)).first()

    @contextmanager
    def access():
        with app.app_context(), user_data_access(user_id):
            actual = db.session.query(User.created_at).filter_by(id=int(user_id)).first()
            if expected is None or actual is None or actual != expected:
                raise DataAccessUnavailable()
            yield

    return access


def init_data_access(app):
    """Track HTTP consumers before any authentication or persistent mutation."""
    from flask import g, request

    app.extensions['data_access'] = DataAccessGate()

    @app.before_request
    def admit_data_operation():
        gate = app.extensions['data_access']
        if request.endpoint == 'static':
            return None
        if gate.closed and request.path in {
            '/health', '/ready',
        }:
            return None
        context = gate.operation()
        context.__enter__()
        g._data_operation = context

    @app.teardown_request
    def release_data_operation(_error):
        context = g.pop('_data_operation', None)
        if context is not None:
            context.__exit__(None, None, None)


@contextmanager
def user_data_access(user_id):
    from flask import has_request_context, session
    from flask_login import current_user
    from .models import User, db

    gate = current_data_access()
    # The lease starts before selecting any cached identity or storage path.
    with gate.access(user_id) as outermost:
        if not outermost:
            yield
            return
        if (has_request_context() and session.get('_auth_session')
                and current_user.is_authenticated and current_user.id == int(user_id)):
            from .auth_assurance import current_authentication_session
            # An ORM refresh can replace even the cached incarnation. The
            # original browser token must still own a live server-side row.
            if current_authentication_session() is None:
                raise DataAccessUnavailable()
        cached = db.session.get(User, int(user_id))
        if cached is not None:
            expected = cached.created_at
            actual = db.session.query(User.created_at).filter_by(id=int(user_id)).first()
            if actual is None or actual[0] != expected:
                raise DataAccessUnavailable()
        yield


def user_operation(function):
    @wraps(function)
    def guarded(user_id, *args, **kwargs):
        with user_data_access(user_id):
            return function(user_id, *args, **kwargs)
    return guarded
