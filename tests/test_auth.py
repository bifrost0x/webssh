"""Tests for authentication and rate limiting."""

import pytest
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone


class TestRateLimiter:
    """Tests for the in-memory rate limiter."""

    def test_allow_within_limit(self):
        from app.rate_limiter import InMemoryRateLimiter
        limiter = InMemoryRateLimiter()
        for _ in range(5):
            assert limiter.allow('test_key', 5, 60) is True

    def test_block_over_limit(self):
        from app.rate_limiter import InMemoryRateLimiter
        limiter = InMemoryRateLimiter()
        for _ in range(5):
            limiter.allow('test_key', 5, 60)
        assert limiter.allow('test_key', 5, 60) is False

    def test_different_keys_independent(self):
        from app.rate_limiter import InMemoryRateLimiter
        limiter = InMemoryRateLimiter()
        for _ in range(5):
            limiter.allow('key_a', 5, 60)
        assert limiter.allow('key_a', 5, 60) is False
        assert limiter.allow('key_b', 5, 60) is True

    def test_cleanup_stale_keys(self):
        from collections import deque
        from app.rate_limiter import InMemoryRateLimiter
        limiter = InMemoryRateLimiter()
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

    def test_first_registered_user_is_an_administrator(self, app):
        with app.app_context():
            from app.auth import register_user

            user, error = register_user('firstuser', 'password123')

            assert error is None
            assert user is not None
            assert user.is_admin is True

    def test_only_first_registered_user_is_an_administrator(self, app):
        with app.app_context():
            from app.auth import register_user

            first, first_error = register_user('firstuser', 'password123')
            second, second_error = register_user('seconduser', 'password123')

            assert first_error is None
            assert second_error is None
            assert first.is_admin is True
            assert second.is_admin is False

    def test_initial_admin_repair_preserves_existing_administrators(self, app):
        with app.app_context():
            from app.auth import ensure_initial_admin
            from app.models import User, db

            first = User(username='firstuser', is_admin=True)
            first.set_password('password123')
            second = User(username='seconduser', is_admin=True)
            second.set_password('password123')
            db.session.add_all([first, second])
            db.session.commit()

            result = ensure_initial_admin()

            assert result.id == first.id
            assert User.query.filter_by(is_admin=True).order_by(User.id).all() == [
                first,
                second,
            ]

    def test_initial_admin_repair_promotes_only_oldest_user(self, app):
        with app.app_context():
            from app.auth import ensure_initial_admin
            from app.models import User, db

            first = User(username='firstuser', is_admin=False)
            first.set_password('password123')
            second = User(username='seconduser', is_admin=False)
            second.set_password('password123')
            db.session.add_all([first, second])
            db.session.commit()

            promoted = ensure_initial_admin()
            repeated = ensure_initial_admin()

            assert promoted.id == first.id
            assert repeated.id == first.id
            assert db.session.get(User, first.id).is_admin is True
            assert db.session.get(User, second.id).is_admin is False

    def test_parallel_first_registrations_create_exactly_one_admin(self, app):
        from app.auth import register_user
        from app.models import User

        worker_count = 4
        start = threading.Barrier(worker_count)

        def register(index):
            with app.app_context():
                start.wait(timeout=5)
                user, error = register_user(
                    f'parallel{index}',
                    'password123',
                )
                return user.id if user is not None else None, error

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            results = list(executor.map(register, range(worker_count)))

        assert all(error is None for _, error in results)
        assert all(user_id is not None for user_id, _ in results)
        with app.app_context():
            assert User.query.count() == worker_count
            assert User.query.filter_by(is_admin=True).count() == 1

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

    def test_register_password_exactly_72_utf8_bytes_allowed(self, app):
        password = ('a' * 70) + '\u00e9'
        assert len(password) == 71
        assert len(password.encode('utf-8')) == 72

        with app.app_context():
            from app.auth import register_user
            user, error = register_user('utf8boundary', password)
            assert user is not None
            assert error is None

    def test_register_password_over_72_utf8_bytes_rejected(self, app):
        password = ('a' * 70) + '\u00e9X'
        assert len(password) == 72
        assert len(password.encode('utf-8')) == 73

        with app.app_context():
            from app.auth import register_user
            user, error = register_user('utf8toolong', password)
            assert user is None
            assert '72 bytes' in error

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

    def test_login_rejects_overlong_utf8_password_for_existing_and_missing_users(self, app, client):
        """The login route must turn bcrypt-length inputs into invalid credentials."""
        with app.app_context():
            from app.auth import register_user
            register_user('existing', 'correct-password')

        overlong_password = '\u00e9' * 37
        responses = [
            client.post('/login', data={'username': username, 'password': overlong_password})
            for username in ('existing', 'missing')
        ]

        for response in responses:
            assert response.status_code == 200
            assert b'Invalid username or password' in response.data

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

    def test_authenticate_rejects_overlong_password_for_existing_user(self, app):
        with app.app_context():
            from app.auth import register_user, authenticate_user
            register_user('existing', 'correct-password')
            user, error = authenticate_user('existing', 'x' * 73)
            assert user is None
            assert error == 'Invalid username or password'

    def test_authenticate_rejects_overlong_password_for_missing_user(self, app):
        with app.app_context():
            from app.auth import authenticate_user
            user, error = authenticate_user('missing', '\u00e9' * 37)
            assert user is None
            assert error == 'Invalid username or password'

    def test_authenticate_rejects_unpaired_surrogate_for_existing_user(self, app):
        with app.app_context():
            from app.auth import register_user, authenticate_user
            register_user('existing', 'correct-password')
            user, error = authenticate_user('existing', '\ud800')
            assert user is None
            assert error == 'Invalid username or password'

    def test_authenticate_rejects_unpaired_surrogate_for_missing_user(self, app):
        with app.app_context():
            from app.auth import authenticate_user
            user, error = authenticate_user('missing', '\ud800')
            assert user is None
            assert error == 'Invalid username or password'


class TestPasswordChange:
    """Password changes must enforce bcrypt's byte-based input boundary."""

    def test_change_password_rejects_overlong_current_password(self, app, client):
        with app.app_context():
            from app.auth import register_user
            register_user('changeuser', 'current-password')

        login_response = client.post('/login', data={
            'username': 'changeuser',
            'password': 'current-password',
        })
        assert login_response.status_code == 302

        response = client.post('/change-password', data={
            'current_password': 'x' * 73,
            'new_password': 'changed-password',
            'confirm_password': 'changed-password',
        })

        assert response.status_code == 200
        assert b'Current password is incorrect' in response.data

        with app.app_context():
            from app.models import User
            user = User.query.filter_by(username='changeuser').one()
            assert user.check_password('current-password')

    def test_change_password_rejects_more_than_72_utf8_bytes(self, app, client):
        with app.app_context():
            from app.auth import register_user
            register_user('changeuser', 'current-password')

        login_response = client.post('/login', data={
            'username': 'changeuser',
            'password': 'current-password',
        })
        assert login_response.status_code == 302

        new_password = ('a' * 70) + '\u00e9X'
        response = client.post('/change-password', data={
            'current_password': 'current-password',
            'new_password': new_password,
            'confirm_password': new_password,
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b'72 bytes' in response.data
        with app.app_context():
            from app.models import User
            user = User.query.filter_by(username='changeuser').one()
            assert user.check_password('current-password')


class TestSSHParameterValidation:
    """Socket input validation is syntactic; network policy owns DNS."""

    def test_canonicalizes_idna_hostname_without_resolving(self, monkeypatch):
        import socket
        from app.socket_events import _validate_ssh_params

        monkeypatch.setattr(
            socket,
            'getaddrinfo',
            lambda *args, **kwargs: pytest.fail('validation triggered DNS'),
        )

        assert _validate_ssh_params(
            'BÜCHER.Example.', '2222', 'alice'
        ) == ('xn--bcher-kva.example', 2222, 'alice', None)

    def test_accepts_and_normalizes_bracketed_ipv6(self):
        from app.socket_events import _validate_ssh_params

        assert _validate_ssh_params(
            '[2606:4700:4700::1111]', 22, 'alice'
        ) == ('2606:4700:4700::1111', 22, 'alice', None)
