"""Tests for Redis-backed rate limiting and outage recovery."""

import os
import sys
import threading
import types
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest

from app.rate_limiter import (
    InMemoryRateLimiter,
    RedisRateLimiter,
    create_rate_limiter,
)


class _StatefulPipeline:
    def __init__(self, redis_client):
        self.redis = redis_client
        self.operations = []

    def zremrangebyscore(self, key, minimum, maximum):
        self.operations.append(('remove', key, float(maximum)))
        return self

    def zadd(self, key, members):
        self.operations.append(('add', key, members))
        return self

    def zcard(self, key):
        self.operations.append(('count', key))
        return self

    def expire(self, key, seconds):
        self.operations.append(('expire', key, seconds))
        return self

    def execute(self):
        results = []
        for operation in self.operations:
            name, key, *args = operation
            bucket = self.redis.members.setdefault(key, {})
            if name == 'remove':
                maximum = args[0]
                for member in [m for m, score in bucket.items() if score <= maximum]:
                    del bucket[member]
                results.append(0)
            elif name == 'add':
                bucket.update(args[0])
                results.append(1)
            elif name == 'count':
                results.append(len(bucket))
            else:
                results.append(True)
        return results


class StatefulRedis:
    def __init__(self):
        self.members = {}

    def pipeline(self):
        return _StatefulPipeline(self)

    def eval(self, _script, _numkeys, key, window_start, now, limit, ttl, member):
        del ttl
        bucket = self.members.setdefault(key, {})
        for old_member in [m for m, score in bucket.items() if score <= float(window_start)]:
            del bucket[old_member]
        if len(bucket) >= int(limit):
            return 0
        bucket[member] = float(now)
        return 1

    def zcard(self, key):
        return len(self.members.get(key, {}))

    def delete(self, key):
        return int(self.members.pop(key, None) is not None)


class FlakyRedis:
    def __init__(self, failing=True):
        self.failing = failing
        self.calls = 0

    def eval(self, *_args):
        self.calls += 1
        if self.failing:
            raise ConnectionError('redis unavailable')
        return 1

    def ping(self):
        if self.failing:
            raise ConnectionError('redis unavailable')
        return True


def test_in_memory_limiter_enforces_limit_under_concurrent_access():
    """A non-atomic lookup/check/append sequence can admit both callers."""

    lookup_barrier = threading.Barrier(2)

    class CoordinatedLookupDict(dict):
        def get(self, key, default=None):
            value = super().get(key, default)
            try:
                lookup_barrier.wait(timeout=0.05)
            except threading.BrokenBarrierError:
                pass
            return value

    limiter = InMemoryRateLimiter()
    limiter.events = CoordinatedLookupDict()
    start = threading.Barrier(2)

    def attempt():
        start.wait(timeout=1)
        return limiter.allow('login:parallel', 1, 60)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _index: attempt(), range(2)))

    assert results.count(True) == 1
    assert results.count(False) == 1
    assert len(limiter.events['login:parallel']) == 1


def test_in_memory_limiter_reclaims_expired_unused_buckets(monkeypatch):
    """Buckets must expire without requiring the same key to be reused."""
    clock = {'now': 1_000.0}

    class FrozenDateTime:
        @classmethod
        def now(cls, _timezone):
            return datetime.fromtimestamp(clock['now'], timezone.utc)

    monkeypatch.setattr('app.rate_limiter.datetime', FrozenDateTime)
    limiter = InMemoryRateLimiter()

    for index in range(100):
        assert limiter.allow(f'login:client-{index}', 1, 10) is True
    assert len(limiter.events) == 100

    clock['now'] += 11
    assert limiter.allow('login:fresh-client', 1, 10) is True

    assert set(limiter.events) == {'login:fresh-client'}


def test_denied_in_memory_requests_do_not_allocate_buckets():
    limiter = InMemoryRateLimiter()

    for index in range(100):
        assert limiter.allow(f'login:denied-{index}', 0, 60) is False

    assert limiter.events == {}


def test_in_memory_cleanup_index_stays_bounded_and_releases_expired_keys(
    monkeypatch,
):
    clock = {'now': 2_000.0}

    class FrozenDateTime:
        @classmethod
        def now(cls, _timezone):
            return datetime.fromtimestamp(clock['now'], timezone.utc)

    monkeypatch.setattr('app.rate_limiter.datetime', FrozenDateTime)
    limiter = InMemoryRateLimiter()

    for index in range(256):
        assert limiter.allow(f'login:rotating-{index}', 1, 10) is True

    assert len(limiter._cleanup_keys) <= limiter._CLEANUP_WORK_PER_REQUEST

    clock['now'] += 11
    assert limiter.allow('login:after-expiry', 1, 10) is True

    assert set(limiter.events) == {'login:after-expiry'}
    assert set(limiter._expiry_deadlines) == {'login:after-expiry'}
    assert len(limiter._expiry_heap) == 1
    assert list(limiter._cleanup_keys) == ['login:after-expiry']


def test_denied_requests_do_not_grow_redis_bucket():
    client = StatefulRedis()
    limiter = RedisRateLimiter(client)

    allowed = sum(limiter.allow('login:attacker', 5, 60) for _ in range(1000))

    assert allowed == 5
    assert client.zcard('ratelimit:login:attacker') == 5


def _exercise_real_redis_probe(client, key):
    redis_key = f'ratelimit:{key}'
    client.delete(redis_key)
    try:
        limiter = RedisRateLimiter(client)
        allowed = sum(limiter.allow(key, 5, 60) for _ in range(1000))
        return allowed, client.zcard(redis_key)
    finally:
        client.delete(redis_key)


def test_real_redis_probe_cleans_only_its_namespaced_bucket():
    client = StatefulRedis()
    client.members['unrelated'] = {'keep': 1.0}

    allowed, stored = _exercise_real_redis_probe(
        client,
        'login:integration:isolated',
    )

    assert (allowed, stored) == (5, 5)
    assert client.members == {'unrelated': {'keep': 1.0}}


def test_runtime_fallback_skips_redis_until_retry_window(monkeypatch):
    clock = {'now': 100.0}
    monkeypatch.setattr('app.rate_limiter.time.monotonic', lambda: clock['now'])
    client = FlakyRedis()
    limiter = RedisRateLimiter(client, retry_interval_seconds=30)

    assert limiter.allow('login:client', 5, 60) is True
    assert limiter.allow('login:client', 5, 60) is True

    assert client.calls == 1


def test_runtime_fallback_recovers_after_retry_window(monkeypatch):
    clock = {'now': 100.0}
    monkeypatch.setattr('app.rate_limiter.time.monotonic', lambda: clock['now'])
    client = FlakyRedis()
    limiter = RedisRateLimiter(client, retry_interval_seconds=30)

    assert limiter.allow('login:client', 5, 60) is True
    client.failing = False
    clock['now'] = 131.0

    assert limiter.allow('login:client', 5, 60) is True
    assert client.calls == 2
    assert limiter._fallback is None


def test_startup_redis_failure_keeps_recoverable_backend(monkeypatch):
    client = FlakyRedis()
    redis_module = types.SimpleNamespace(from_url=lambda *_args, **_kwargs: client)
    monkeypatch.setitem(sys.modules, 'redis', redis_module)

    limiter = create_rate_limiter('redis://redis:6379/0')

    assert isinstance(limiter, RedisRateLimiter)
    assert limiter._fallback is not None
    assert limiter.allow('login:startup', 5, 60) is True
    assert client.calls == 0


def test_invalid_redis_configuration_falls_back_to_memory(monkeypatch):
    def reject_url(*_args, **_kwargs):
        raise ValueError('invalid redis URL')

    redis_module = types.SimpleNamespace(from_url=reject_url)
    monkeypatch.setitem(sys.modules, 'redis', redis_module)

    limiter = create_rate_limiter('redis://invalid')

    assert isinstance(limiter, InMemoryRateLimiter)


@pytest.mark.parametrize(
    ('storage_url', 'connection_class'),
    [
        ('redis://localhost:6379/0', 'Connection'),
        ('rediss://localhost:6380/0', 'SSLConnection'),
    ],
)
def test_redis_url_scheme_preserves_transport_configuration(
    monkeypatch, storage_url, connection_class
):
    """A scheme regression must not silently turn TLS Redis into memory-only."""
    import redis

    monkeypatch.setattr(redis.Redis, 'ping', lambda _client: True)

    limiter = create_rate_limiter(storage_url)

    assert isinstance(limiter, RedisRateLimiter)
    assert limiter.redis.connection_pool.connection_class.__name__ == connection_class


@pytest.mark.skipif(not os.environ.get('TEST_REDIS_URL'), reason='TEST_REDIS_URL is not configured')
def test_real_redis_does_not_store_denied_requests():
    import redis

    client = redis.from_url(os.environ['TEST_REDIS_URL'])
    key = f'login:integration:{uuid.uuid4().hex}'
    allowed, stored = _exercise_real_redis_probe(client, key)

    assert allowed == 5
    assert stored == 5
