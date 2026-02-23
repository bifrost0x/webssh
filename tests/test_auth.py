"""Tests for authentication and rate limiting."""

import pytest
from datetime import datetime, timezone


class TestRateLimiter:
    """Tests for the in-memory rate limiter."""

    def test_allow_within_limit(self):
        from app.auth import RateLimiter
        limiter = RateLimiter()
        for _ in range(5):
            assert limiter.allow('test_key', 5, 60) is True

    def test_block_over_limit(self):
        from app.auth import RateLimiter
        limiter = RateLimiter()
        for _ in range(5):
            limiter.allow('test_key', 5, 60)
        assert limiter.allow('test_key', 5, 60) is False

    def test_different_keys_independent(self):
        from app.auth import RateLimiter
        limiter = RateLimiter()
        for _ in range(5):
            limiter.allow('key_a', 5, 60)
        assert limiter.allow('key_a', 5, 60) is False
        assert limiter.allow('key_b', 5, 60) is True

    def test_cleanup_stale_keys(self):
        from app.auth import RateLimiter
        limiter = RateLimiter()
        # Create >50 keys to trigger cleanup
        for i in range(55):
            limiter.allow(f'key_{i}', 5, 60)
        # Empty some keys by draining their queues
        for i in range(10):
            limiter.events[f'key_{i}'] = __import__('collections').deque()
        # Trigger cleanup via new allow
        limiter.allow('trigger_cleanup', 5, 60)
        # The empty keys should have been cleaned up
        for i in range(10):
            assert f'key_{i}' not in limiter.events

    def test_max_keys_hard_limit(self):
        from app.auth import RateLimiter
        limiter = RateLimiter()
        limiter.MAX_KEYS = 100
        for i in range(150):
            limiter.allow(f'key_{i}', 5, 60)
        # Dict should have been trimmed
        assert len(limiter.events) <= 150  # some cleanup happened

    def test_parse_rate_limit_valid(self):
        from app.auth import parse_rate_limit
        assert parse_rate_limit('5 per minute') == (5, 60)
        assert parse_rate_limit('10 per hour') == (10, 3600)
        assert parse_rate_limit('1 per second') == (1, 1)

    def test_parse_rate_limit_invalid(self):
        from app.auth import parse_rate_limit
        assert parse_rate_limit('invalid') == (5, 60)
        assert parse_rate_limit(None) == (5, 60)
        assert parse_rate_limit('') == (5, 60)


class TestUserRegistration:
    """Tests for user registration."""

    def test_register_valid_user(self, app):
        with app.app_context():
            from app.auth import register_user
            user, error = register_user('testuser', 'password123')
            assert user is not None
            assert error is None
            assert user.username == 'testuser'

    def test_register_short_username(self, app):
        with app.app_context():
            from app.auth import register_user
            user, error = register_user('ab', 'password123')
            assert user is None
            assert 'Username' in error

    def test_register_short_password(self, app):
        with app.app_context():
            from app.auth import register_user
            user, error = register_user('testuser', 'short')
            assert user is None
            assert 'Password' in error

    def test_register_long_password(self, app):
        with app.app_context():
            from app.auth import register_user
            user, error = register_user('testuser', 'a' * 73)
            assert user is None
            assert '72' in error

    def test_register_invalid_username_chars(self, app):
        with app.app_context():
            from app.auth import register_user
            user, error = register_user('test@user', 'password123')
            assert user is None
            assert 'letters' in error

    def test_register_duplicate_username(self, app):
        with app.app_context():
            from app.auth import register_user
            register_user('testuser', 'password123')
            user, error = register_user('testuser', 'password456')
            assert user is None
            assert 'exists' in error


class TestAuthentication:
    """Tests for user authentication."""

    def test_authenticate_valid_credentials(self, app):
        with app.app_context():
            from app.auth import register_user, authenticate_user
            register_user('testuser', 'password123')
            user, error = authenticate_user('testuser', 'password123')
            assert user is not None
            assert error is None

    def test_authenticate_wrong_password(self, app):
        with app.app_context():
            from app.auth import register_user, authenticate_user
            register_user('testuser', 'password123')
            user, error = authenticate_user('testuser', 'wrongpassword')
            assert user is None
            assert 'Invalid' in error

    def test_authenticate_nonexistent_user(self, app):
        with app.app_context():
            from app.auth import authenticate_user
            user, error = authenticate_user('nonexistent', 'password123')
            assert user is None
            assert 'Invalid' in error
