"""
Rate limiter implementations for WebSSH.

Provides two backends:
- InMemoryRateLimiter: Fast, no dependencies. Single-process only.
- RedisRateLimiter: Shared across workers, survives restarts. Requires Redis.

The factory function create_rate_limiter() selects the backend based on
RATELIMIT_STORAGE_URL and gracefully falls back to in-memory if Redis
is unavailable.

Deployment note
---------------
This application is designed for single-worker deployment in its default
mode because WebSocket (Socket.IO) session state lives in-process. Running
multiple workers without sticky sessions causes sessions to be lost across
requests. The Redis rate limiter is still valuable in single-worker mode
because it survives process restarts and can be shared if you later scale
to multiple workers with a message queue (e.g., Redis for Socket.IO).

Semantic difference between backends
-------------------------------------
The two backends differ in how they handle denied (over-limit) requests:

- InMemoryRateLimiter: Denied requests are NOT recorded. The sliding window
  naturally drains over time, so a client that keeps retrying will
  eventually get slots back as earlier entries expire.

- RedisRateLimiter: Denied requests ARE recorded (ZADD happens before the
  limit check). This means a client that keeps hammering never drains its
  window — it must go fully quiet for the entire window_duration. This is
  stricter against brute force but can penalize legitimate users behind
  shared IPs / NAT more heavily.

Both behaviours are intentional — Redis is more aggressive by design — but
operators should be aware of the difference when diagnosing user reports of
locked-out behaviour on shared networks.
"""

import logging
import time
import uuid
from abc import ABC, abstractmethod
from collections import deque
from datetime import datetime, timezone

log = logging.getLogger(__name__)


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

    Use RedisRateLimiter for production deployments with multiple workers.
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

    Uses atomic Redis operations (pipeline) for thread-safe counting:
    - ZREMRANGEBYSCORE: remove expired entries
    - ZADD: add current timestamp (UUID member to avoid collision)
    - ZCARD: count entries in window
    - EXPIRE: auto-cleanup after window

    Survives process restarts and works across multiple workers.

    Note: Denied requests ARE recorded (ZADD runs before the limit check),
    so a client that keeps hammering never drains its window — it must go
    fully quiet for window_seconds. See module docstring for details.
    """

    def __init__(self, redis_client):
        self.redis = redis_client
        # Lazily created in-memory fallback for runtime Redis failures.
        self._fallback: InMemoryRateLimiter | None = None

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time.time()
        window_start = now - window_seconds
        redis_key = f"ratelimit:{key}"

        try:
            pipe = self.redis.pipeline()
            # Remove entries outside the window
            pipe.zremrangebyscore(redis_key, 0, window_start)
            # Add current request timestamp. UUID member prevents collision
            # when two requests arrive at the same float timestamp.
            pipe.zadd(redis_key, {uuid.uuid4().hex: now})
            # Count requests in window
            pipe.zcard(redis_key)
            # Set TTL so keys auto-expire (prevents memory leak)
            pipe.expire(redis_key, window_seconds + 1)

            results = pipe.execute()
            request_count = results[2]  # ZCARD result

            # On successful Redis call, clear any stale fallback state
            # so we switch back to Redis on the next request.
            if self._fallback is not None:
                log.info("Rate limiter: Redis recovered, clearing in-memory fallback")
                self._fallback = None

            return request_count <= limit
        except Exception as e:
            # Runtime Redis failure: degrade to in-memory limiter rather than
            # allowing all requests through. This preserves brute-force
            # protection (per-process) while logging the outage.
            if self._fallback is None:
                log.warning(
                    f"Rate limiter: Redis error ({e}), "
                    f"falling back to in-memory limiter for this process"
                )
                self._fallback = InMemoryRateLimiter()
            return self._fallback.allow(key, limit, window_seconds)


def create_rate_limiter(storage_url: str = "memory://") -> BaseRateLimiter:
    """Factory function to create the appropriate rate limiter.

    Args:
        storage_url: Backend URL. Supported formats:
            - "memory://" — in-memory (default, single-process only)
            - "redis://host:port/db" — Redis backend
            - "redis://:password@host:port/db" — Redis with auth

    Returns:
        BaseRateLimiter instance. Falls back to InMemoryRateLimiter if
        Redis connection fails at startup.
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
            # Test connection
            client.ping()
            log.info(f"Rate limiter: Redis connected ({storage_url.split('@')[-1]})")
            return RedisRateLimiter(client)
        except ImportError:
            log.warning(
                "Rate limiter: redis package not installed. "
                "Install with: pip install redis. Falling back to in-memory."
            )
        except Exception as e:
            log.warning(
                f"Rate limiter: Redis connection failed ({e}). "
                f"Falling back to in-memory. Fix Redis or set RATELIMIT_STORAGE_URL=memory://"
            )

    log.info("Rate limiter: using in-memory backend (single-process only)")
    return InMemoryRateLimiter()
