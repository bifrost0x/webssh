"""Bound per-session and per-user interactive SSH input throughput."""

from dataclasses import dataclass
import math
from threading import RLock
import time


@dataclass
class _Bucket:
    tokens: float
    updated_at: float


class SSHInputBudget:
    """Two-level token bucket for the documented single-worker runtime."""

    def __init__(
        self,
        *,
        session_capacity,
        session_rate,
        user_capacity,
        user_rate,
    ):
        self.session_capacity = int(session_capacity)
        self.session_rate = int(session_rate)
        self.user_capacity = int(user_capacity)
        self.user_rate = int(user_rate)
        if min(
            self.session_capacity,
            self.session_rate,
            self.user_capacity,
            self.user_rate,
        ) <= 0:
            raise ValueError('SSH input budgets must be positive')
        self._buckets = {}
        self._lock = RLock()

    def _state(self, key, capacity, rate, now):
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = _Bucket(float(capacity), now)
            self._buckets[key] = bucket
            return bucket
        elapsed = max(0.0, now - bucket.updated_at)
        bucket.tokens = min(float(capacity), bucket.tokens + elapsed * rate)
        bucket.updated_at = now
        return bucket

    def allow(self, user_id, session_id, byte_count, *, now=None):
        """Return ``(allowed, retry_after_ms)`` without charging denials."""
        byte_count = int(byte_count)
        if byte_count <= 0:
            return True, 0
        current = time.monotonic() if now is None else float(now)
        user_key = ('user', int(user_id))
        session_key = ('session', int(user_id), str(session_id))
        with self._lock:
            user_bucket = self._state(
                user_key,
                self.user_capacity,
                self.user_rate,
                current,
            )
            session_bucket = self._state(
                session_key,
                self.session_capacity,
                self.session_rate,
                current,
            )
            deficits = (
                max(0.0, byte_count - user_bucket.tokens)
                / self.user_rate,
                max(0.0, byte_count - session_bucket.tokens)
                / self.session_rate,
            )
            wait_seconds = max(deficits)
            if wait_seconds > 0:
                return False, max(1, math.ceil(wait_seconds * 1000))
            user_bucket.tokens -= byte_count
            session_bucket.tokens -= byte_count
            if len(self._buckets) > 1024:
                self._remove_stale_full_buckets(current)
            return True, 0

    def _remove_stale_full_buckets(self, now):
        for key, bucket in tuple(self._buckets.items()):
            if key[0] == 'user':
                capacity = self.user_capacity
                rate = self.user_rate
            else:
                capacity = self.session_capacity
                rate = self.session_rate
            refill_seconds = capacity / rate
            if now - bucket.updated_at >= max(60.0, refill_seconds * 2):
                self._buckets.pop(key, None)


def budget_from_config(config):
    return SSHInputBudget(
        session_capacity=config.SSH_INPUT_SESSION_BURST_BYTES,
        session_rate=config.SSH_INPUT_SESSION_BYTES_PER_SECOND,
        user_capacity=config.SSH_INPUT_USER_BURST_BYTES,
        user_rate=config.SSH_INPUT_USER_BYTES_PER_SECOND,
    )
