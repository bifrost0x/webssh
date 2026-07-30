from collections import defaultdict
from threading import RLock


class SocketCapacityRegistry:
    """Track process-local Socket.IO capacity for the single-worker runtime."""

    def __init__(self):
        self._lock = RLock()
        self._owners = {}
        self._by_user = defaultdict(set)

    def reserve(self, user_id, socket_sid, max_total, max_per_user):
        """Atomically reserve one socket slot if both limits allow it."""
        user_id = int(user_id)
        with self._lock:
            if socket_sid in self._owners:
                return self._owners[socket_sid] == user_id
            if len(self._owners) >= max_total:
                return False
            if len(self._by_user[user_id]) >= max_per_user:
                return False
            self._owners[socket_sid] = user_id
            self._by_user[user_id].add(socket_sid)
            return True

    def release(self, socket_sid):
        """Release a socket slot and return its recorded owner, if any."""
        with self._lock:
            user_id = self._owners.pop(socket_sid, None)
            if user_id is None:
                return None
            user_sockets = self._by_user.get(user_id)
            if user_sockets is not None:
                user_sockets.discard(socket_sid)
                if not user_sockets:
                    self._by_user.pop(user_id, None)
            return user_id


socket_capacity = SocketCapacityRegistry()
