from collections import defaultdict
from contextlib import contextmanager
from threading import RLock


class SocketCapacityRegistry:
    """Track process-local connection capacity for the single-worker runtime."""

    def __init__(self):
        self._lock = RLock()
        self._owners = {}
        self._by_user = defaultdict(set)
        self._terminal = set()
        self._admission_locks = {}

    @contextmanager
    def _reservation_lock(self, socket_sid):
        """Hold the lock belonging to one exact live reservation."""
        while True:
            with self._lock:
                admission_lock = self._admission_locks.get(socket_sid)
            if admission_lock is None:
                yield False
                return
            admission_lock.acquire()
            with self._lock:
                if self._admission_locks.get(socket_sid) is admission_lock:
                    break
            admission_lock.release()
        try:
            yield True
        finally:
            admission_lock.release()

    def reserve(self, user_id, socket_sid, max_total, max_per_user):
        """Atomically reserve one socket slot if both limits allow it."""
        user_id = int(user_id)
        with self._lock:
            if socket_sid in self._owners:
                return (
                    self._owners[socket_sid] == user_id
                    and socket_sid not in self._terminal
                )
            if len(self._owners) >= max_total:
                return False
            if len(self._by_user[user_id]) >= max_per_user:
                return False
            self._owners[socket_sid] = user_id
            self._by_user[user_id].add(socket_sid)
            self._admission_locks[socket_sid] = RLock()
            return True

    def release(self, socket_sid):
        """Release a socket slot and return its recorded owner, if any."""
        with self._reservation_lock(socket_sid) as reserved:
            if not reserved:
                return None
            with self._lock:
                user_id = self._owners.pop(socket_sid, None)
                self._terminal.discard(socket_sid)
                self._admission_locks.pop(socket_sid, None)
                if user_id is None:
                    return None
                user_sockets = self._by_user.get(user_id)
                if user_sockets is not None:
                    user_sockets.discard(socket_sid)
                    if not user_sockets:
                        self._by_user.pop(user_id, None)
                return user_id

    def mark_terminal(self, socket_sid):
        """Atomically terminalize one reservation and return its owner once."""
        with self._reservation_lock(socket_sid) as reserved:
            if not reserved:
                return None
            with self._lock:
                user_id = self._owners.get(socket_sid)
                if user_id is None or socket_sid in self._terminal:
                    return None
                self._terminal.add(socket_sid)
                return user_id

    def is_terminal(self, socket_sid):
        """Return whether a reserved transport must reject further binding."""
        with self._lock:
            return socket_sid in self._terminal

    def count_for_user(self, user_id):
        """Return the number of process-local sockets owned by one user."""
        user_id = int(user_id)
        with self._lock:
            return len(self._by_user.get(user_id, ()))

    def sids_for_user(self, user_id):
        """Snapshot exact transport IDs owned by one user."""
        user_id = int(user_id)
        with self._lock:
            return tuple(self._by_user.get(user_id, ()))

    def sids(self):
        """Snapshot every exact transport ID currently reserved."""
        with self._lock:
            return tuple(self._owners)

    def owner(self, socket_sid):
        """Return the recorded owner without changing the reservation."""
        with self._lock:
            return self._owners.get(socket_sid)

    def count(self):
        """Return the total number of process-local reservations."""
        with self._lock:
            return len(self._owners)

    @contextmanager
    def admission_guard(self, socket_sid, user_id):
        """Linearize namespace setup against terminalization and release."""
        user_id = int(user_id)
        with self._reservation_lock(socket_sid) as reserved:
            if not reserved:
                yield False
                return
            with self._lock:
                admitted = (
                    self._owners.get(socket_sid) == user_id
                    and socket_sid not in self._terminal
                )
            yield admitted


socket_capacity = SocketCapacityRegistry()
