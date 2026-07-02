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
        from collections import deque
        from app.auth import RateLimiter
        limiter = RateLimiter()
        # Create >50 keys so the cleanup branch (len > 50) is reached.
        for i in range(55):
            limiter.allow(f'key_{i}', 5, 60)
        # Drain some queues so they become empty (= stale).
        for i in range(10):
            limiter.events[f'key_{i}'] = deque()
        # Trigger cleanup via a new allow().
        limiter.allow('trigger_cleanup', 5, 60)
        # The empty keys should have been removed.
        for i in range(10):
            assert f'key_{i}' not in limiter.events

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

    def test_socket_rate_limit_blocks_after_limit(self):
        from app.auth import check_socket_rate_limit
        # Unique user id so the shared module-level limiter has no prior state.
        user_id = 918273
        # Within the limit -> not blocked (returns False).
        assert check_socket_rate_limit(user_id, 'ssh_connect', '2 per minute') is False
        assert check_socket_rate_limit(user_id, 'ssh_connect', '2 per minute') is False
        # Over the limit -> blocked (returns True).
        assert check_socket_rate_limit(user_id, 'ssh_connect', '2 per minute') is True

    def test_socket_rate_limit_per_user_isolation(self):
        from app.auth import check_socket_rate_limit
        user_a, user_b = 918274, 918275
        assert check_socket_rate_limit(user_a, 'ssh_connect', '1 per minute') is False
        assert check_socket_rate_limit(user_a, 'ssh_connect', '1 per minute') is True
        # A different user has an independent bucket.
        assert check_socket_rate_limit(user_b, 'ssh_connect', '1 per minute') is False


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

    def test_register_username_too_long(self, app):
        with app.app_context():
            from app.auth import register_user
            user, error = register_user('a' * 33, 'password123')
            assert user is None
            assert 'Username' in error

    def test_register_username_min_length_allowed(self, app):
        # Boundary: 3 chars is the documented minimum and must be accepted.
        with app.app_context():
            from app.auth import register_user
            user, error = register_user('abc', 'password123')
            assert user is not None
            assert error is None

    def test_register_password_exactly_72_allowed(self, app):
        # Boundary: 72 chars is the bcrypt limit and must still be accepted.
        with app.app_context():
            from app.auth import register_user
            user, error = register_user('boundaryuser', 'a' * 72)
            assert user is not None
            assert error is None

    def test_register_username_with_underscore_allowed(self, app):
        with app.app_context():
            from app.auth import register_user
            user, error = register_user('test_user_1', 'password123')
            assert user is not None
            assert error is None

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

    def test_authenticate_none_password_does_not_crash(self, app):
        # A missing password field must not raise (previously crashed on
        # None.encode); it should just fail authentication.
        with app.app_context():
            from app.auth import register_user, authenticate_user
            register_user('testuser', 'password123')
            user, error = authenticate_user('testuser', None)
            assert user is None
            assert 'Invalid' in error
            user, error = authenticate_user('nonexistent', None)
            assert user is None
            assert 'Invalid' in error


class TestSSRFGuard:
    """_is_internal_address underpins BLOCK_INTERNAL_SSH; it must catch internal
    targets given as literal IPs *and* as hostnames that resolve to them."""

    def test_literal_loopback_blocked(self):
        from app.socket_events import _is_internal_address
        assert _is_internal_address('127.0.0.1')
        assert _is_internal_address('::1')

    def test_literal_private_and_metadata_blocked(self):
        from app.socket_events import _is_internal_address
        assert _is_internal_address('10.0.0.5')
        assert _is_internal_address('192.168.1.1')
        assert _is_internal_address('172.16.0.1')
        assert _is_internal_address('169.254.169.254')  # cloud metadata

    def test_localhost_name_blocked(self):
        from app.socket_events import _is_internal_address
        assert _is_internal_address('localhost')

    def test_hostname_resolving_to_loopback_blocked(self, monkeypatch):
        import app.socket_events as se
        monkeypatch.setattr(
            se.socket, 'getaddrinfo',
            lambda *a, **k: [(2, 1, 6, '', ('127.0.0.1', 0))]
        )
        assert se._is_internal_address('evil.example.com')

    def test_public_address_allowed(self, monkeypatch):
        import app.socket_events as se
        assert not se._is_internal_address('8.8.8.8')
        monkeypatch.setattr(
            se.socket, 'getaddrinfo',
            lambda *a, **k: [(2, 1, 6, '', ('93.184.216.34', 0))]
        )
        assert not se._is_internal_address('example.com')

    def test_unresolvable_host_not_flagged(self, monkeypatch):
        import app.socket_events as se
        def _boom(*a, **k):
            raise se.socket.gaierror('nope')
        monkeypatch.setattr(se.socket, 'getaddrinfo', _boom)
        assert not se._is_internal_address('does-not-exist.invalid')
