"""Socket-owned interactive SSH setup with an atomic cancellation boundary."""
import secrets
import threading
import time

from .quota_manager import QuotaKind, quota_manager


class SSHConnectionAttempt:
    """Cancellation and resource ownership for interactive SSH setup.

    A user cancellation loses after commit; disconnect and shutdown still stop
    runtime work. Legacy SSH clients retain their existing cancellation implementation.
    """

    timeout = None
    cancellation_error = ValueError

    def __init__(self, user_id, sid, request_id, *,
                 reservation=None, kind='terminal'):
        self.user_id = str(user_id)
        self.sid = sid
        self.request_id = request_id
        self.kind = kind
        self.reservation = reservation
        self.condition = threading.Condition(threading.RLock())
        self.cancel_event = threading.Event()
        self.runtime_cancel = None
        self.handle = None
        self.state = 'pending'
        self.cancel_reason = None
        self.resources = []
        self.deadline = (
            time.monotonic() + self.timeout if self.timeout else float('inf')
        )
        self.guard = None
        if self.timeout:
            self.guard = threading.Timer(
                self.timeout, self.cancel, kwargs={'reason': 'timeout'},
            )
            self.guard.daemon = True
            self.guard.start()

    @property
    def committed(self):
        return self.state == 'committed'

    @property
    def finished(self):
        return self.state == 'finished'

    @property
    def cancelled(self):
        return self.cancel_event.is_set()

    def bind_runtime(self, cancel_event):
        with self.condition:
            self.runtime_cancel = cancel_event

    def attach_handle(self, handle):
        with self.condition:
            self.handle = handle
            cancelled = self.cancelled
        if cancelled:
            handle.cancel()

    def check(self):
        with self.condition:
            if (self.cancelled or self.finished
                    or (self.runtime_cancel is not None and self.runtime_cancel.is_set())
                    or (not self.committed and time.monotonic() >= self.deadline)):
                raise self.cancellation_error()

    def is_set(self):
        try:
            self.check()
            return False
        except ValueError:
            return True

    def wait(self, timeout=None):
        deadline = None if timeout is None else time.monotonic() + timeout
        while not self.is_set():
            remaining = .1 if deadline is None else deadline - time.monotonic()
            if remaining <= 0:
                return False
            self.cancel_event.wait(min(remaining, .1))
        return True

    def commit_if_active(self):
        with self.condition:
            if self.is_set():
                return False
            self.state = 'committed'
            if self.guard is not None:
                self.guard.cancel()
            return True

    def own(self, resource):
        with self.condition:
            if not self.is_set():
                if resource not in self.resources:
                    self.resources.append(resource)
                return resource
        resource.close()
        raise self.cancellation_error()

    def handoff(self, *resources):
        with self.condition:
            self.check()
            for resource in resources:
                if resource in self.resources:
                    self.resources.remove(resource)

    def _clear_pending(self):
        """Protocol interactions may clear secrets while the condition is held."""

    def cancel(self, *, reason='user'):
        with self.condition:
            if self.committed and reason not in ('finished', 'disconnected', 'shutdown'):
                return False
            if self.finished:
                return False
            if self.cancel_reason is None:
                self.cancel_reason = reason
            self.cancel_event.set()
            if not self.committed:
                self.state = 'cancelled'
            self._clear_pending()
            resources, self.resources = self.resources, []
            handle = self.handle
            self.condition.notify_all()
        # Closing transports can take locks; never hold the registry/attempt lock.
        if handle is not None:
            handle.cancel()
        for resource in reversed(resources):
            try:
                resource.close()
            except Exception:
                pass
        return True

    def finish(self):
        if self.guard is not None:
            self.guard.cancel()
        self.cancel(reason='finished')
        with self.condition:
            if self.finished:
                return
            self.state = 'finished'
        if self.reservation is not None:
            self.reservation.release()


class SSHAttemptRegistry:
    """App-local admission and ownership for interactive SSH attempts."""

    def __init__(self):
        self.lock = threading.Lock()
        self.attempts = {}
        self.stopping = False

    def create(self, user_id, sid, request_id, *, factory=SSHConnectionAttempt,
               reserve=False, **kwargs):
        if request_id is not None and (
                not isinstance(request_id, str) or not 1 <= len(request_id) <= 128):
            raise ValueError('Invalid connection request ID')
        # Legacy clients without request IDs must still be cancelled on disconnect.
        key = (str(user_id), sid, request_id or secrets.token_urlsafe(24))
        with self.lock:
            if self.stopping or key in self.attempts:
                raise ValueError('Connection request already in progress or unavailable')
            reservation = (
                quota_manager.reserve(QuotaKind.BACKGROUND_JOB, user_id)
                if reserve else None
            )
            try:
                attempt = factory(
                    user_id, sid, request_id, reservation=reservation, **kwargs,
                )
                attempt.registry_key = key
                self.attempts[key] = attempt
                return attempt
            except Exception:
                if reservation is not None:
                    reservation.release()
                raise

    def get(self, user_id, sid, request_id):
        if not isinstance(request_id, str):
            return None
        with self.lock:
            return self.attempts.get((str(user_id), sid, request_id))

    def finish(self, attempt):
        attempt.finish()
        with self.lock:
            if self.attempts.get(attempt.registry_key) is attempt:
                del self.attempts[attempt.registry_key]

    def cancel_socket(self, sid):
        with self.lock:
            attempts = [a for a in self.attempts.values() if a.sid == sid]
        for attempt in attempts:
            attempt.cancel(reason='disconnected')

    def shutdown(self):
        with self.lock:
            self.stopping = True
            attempts = list(self.attempts.values())
        for attempt in attempts:
            attempt.cancel(reason='shutdown')
