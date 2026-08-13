from datetime import datetime, timezone
from types import SimpleNamespace

from app.browser_identity import connection_history_scope


def _user(*, user_id=7, created_at=None, password_hash='hash-a'):
    return SimpleNamespace(
        id=user_id,
        created_at=created_at or datetime(2026, 8, 13, tzinfo=timezone.utc),
        password_hash=password_hash,
    )


def test_connection_history_scope_is_stable_and_opaque_for_one_account():
    user = _user()

    first = connection_history_scope(user, 'instance-secret')
    second = connection_history_scope(user, 'instance-secret')

    assert first == second
    assert len(first) == 64
    assert first != str(user.id)
    assert user.password_hash not in first


def test_reused_numeric_user_id_does_not_reuse_browser_history_scope():
    original = _user(password_hash='hash-original')
    replacement = _user(
        password_hash='hash-replacement',
        created_at=datetime(2026, 8, 14, tzinfo=timezone.utc),
    )

    assert connection_history_scope(original, 'instance-secret') != (
        connection_history_scope(replacement, 'instance-secret')
    )


def test_scope_is_bound_to_the_webssh_instance_secret():
    user = _user()

    assert connection_history_scope(user, 'instance-a') != (
        connection_history_scope(user, 'instance-b')
    )
