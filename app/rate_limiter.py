"""
Rate limiter implementations for WebSSH.

Provides two backends:
- InMemoryRateLimiter: Fast, no dependencies. Single-process only.
- RedisRateLimiter: Central counters that survive application restarts while
  Redis remains available.

The factory function create_rate_limiter() selects the backend based on
RATELIMIT_STORAGE_URL and gracefully falls back to in-memory if Redis
is unavailable.

Deployment note
---------------
This application requires a single worker because live SSH and Socket.IO
session state is stored in-process. Redis-backed rate limiting does not
change that deployment constraint. Its benefit here is preserving counters
across application process restarts while the Redis service keeps running.

Both backends record allowed requests only. Denied requests do not grow the
sliding-window bucket and therefore cannot keep allocating backend storage.
"""

import logging
import time
import uuid
from abc import ABC, abstractmethod
from collections import deque
from datetime import datetime, timezone

log = logging.getLogger(__name__)

_REDIS_ALLOW_SCRIPT = """
local key = KEYS[1]
local window_start = tonumber(ARGV[1])
local now = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])
local member = ARGV[5]

redis.call('ZREMRANGEBYSCORE', key, 0, window_start)
local count = redis.call('ZCARD', key)
if count >= limit then
    return 0
end

redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, ttl)
return 1
"""


class BaseRateLimiter(ABC):
    """Interface for rate limiter implementations."""

    @abstractmethod
    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        """Check if a request is allowed under the rate limit.

        Args:
            key: Identifier for the rate limit bucket (e.g., "login:192.168.1.1")
            limit: Maximum number of requests allowed in the window
            window_seconds: Time window in seconds

        Returns:
            True if the request is allowed, False if rate limited.
        """


class InMemoryRateLimiter(BaseRateLimiter):
    """In-memory sliding window rate limiter.

    ⚠️  LIMITATIONS:
    - Per-process only: not shared across Gunicorn workers
    - State lost on process restart
    - Not suitable for multi-instance deployments

    Denied requests are NOT recorded — the window drains naturally.
    """

    def __init__(self):
        self.events: dict[str, deque] = {}

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        now = datetime.now(timezone.utc).timestamp()
        window_start = now - window_seconds
        queue = self.events.get(key)
        if queue is None:
            queue = deque()
            self.events[key] = queue

        # Remove expired entries
        while queue and queue[0] < window_start:
            queue.popleft()

        # Check limit — do NOT record denied requests
        if len(queue) >= limit:
            return False

        # Record this request
        queue.append(now)

        # Periodic cleanup of stale keys (prevent memory leak)
        if len(self.events) > 50:
            stale = [k for k, q in self.events.items() if not q]
            for k in stale:
                del self.events[k]

        return True


class RedisRateLimiter(BaseRateLimiter):
    """Redis-backed sliding window rate limiter using sorted sets.

    A Lua script removes expired entries, checks the current count and adds
    an allowed request as one atomic Redis operation. Denied requests are not
    stored. Runtime failures activate a per-process in-memory fallback and a
    retry window so every request does not wait on an unavailable backend.
    """

    def __init__(self, redis_client, retry_interval_seconds: int = 30):
        self.redis = redis_client
        self.retry_interval_seconds = retry_interval_seconds
        self._fallback: InMemoryRateLimiter | None = None
        self._fallback_until = 0.0

    def _activate_fallback(self, error: Exception) -> None:
        if self._fallback is None:
            self._fallback = InMemoryRateLimiter()
            log.warning(
                "Rate limiter: Redis error (%s), falling back to in-memory "
                "for this process",
                error,
            )
        else:
            log.warning("Rate limiter: Redis recovery attempt failed (%s)", error)
        self._fallback_until = time.monotonic() + self.retry_interval_seconds

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        if self._fallback is not None and time.monotonic() < self._fallback_until:
            return self._fallback.allow(key, limit, window_seconds)

        now = time.time()
        window_start = now - window_seconds
        redis_key = f"ratelimit:{key}"

        try:
            allowed = self.redis.eval(
                _REDIS_ALLOW_SCRIPT,
                1,
                redis_key,
                window_start,
                now,
                limit,
                window_seconds + 1,
                uuid.uuid4().hex,
            )
            if self._fallback is not None:
                log.info("Rate limiter: Redis recovered, clearing in-memory fallback")
                self._fallback = None
                self._fallback_until = 0.0

            return bool(allowed)
        except Exception as e:
            self._activate_fallback(e)
            return self._fallback.allow(key, limit, window_seconds)


def create_rate_limiter(storage_url: str = "memory://") -> BaseRateLimiter:
    """Factory function to create the appropriate rate limiter.

    Args:
        storage_url: Backend URL. Supported formats:
            - "memory://" — in-memory (default, single-process only)
            - "redis://host:port/db" — Redis backend
            - "redis://:password@host:port/db" — Redis with auth

    Returns:
        BaseRateLimiter instance. A configured Redis backend remains
        recoverable if its startup connection check fails.
    """
    if storage_url.startswith("redis://") or storage_url.startswith("rediss://"):
        try:
            import redis

            client = redis.from_url(
                storage_url,
                decode_responses=False,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True,
            )
            limiter = RedisRateLimiter(client)
            try:
                client.ping()
            except Exception as e:
                limiter._activate_fallback(e)
            else:
                log.info(
                    "Rate limiter: Redis connected (%s)",
                    storage_url.split('@')[-1],
                )
            return limiter
        except ImportError:
            log.warning(
                "Rate limiter: redis package not installed. "
                "Install with: pip install redis. Falling back to in-memory."
            )
        except Exception as e:
            log.warning(
                "Rate limiter: Redis client configuration failed (%s). "
                "Falling back to in-memory.",
                e,
            )

    log.info("Rate limiter: using in-memory backend (single-process only)")
    return InMemoryRateLimiter()
