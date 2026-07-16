"""Tests for Redis-backed rate limiting and outage recovery."""

import os
import sys
import types

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


def test_denied_requests_do_not_grow_redis_bucket():
    client = StatefulRedis()
    limiter = RedisRateLimiter(client)

    allowed = sum(limiter.allow('login:attacker', 5, 60) for _ in range(1000))

    assert allowed == 5
    assert client.zcard('ratelimit:login:attacker') == 5


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


@pytest.mark.skipif(not os.environ.get('TEST_REDIS_URL'), reason='TEST_REDIS_URL is not configured')
def test_real_redis_does_not_store_denied_requests():
    import redis

    client = redis.from_url(os.environ['TEST_REDIS_URL'])
    client.flushdb()
    limiter = RedisRateLimiter(client)

    allowed = sum(limiter.allow('login:integration', 5, 60) for _ in range(1000))

    assert allowed == 5
    assert client.zcard('ratelimit:login:integration') == 5
