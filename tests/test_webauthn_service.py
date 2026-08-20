"""Server-side challenge and credential safety for WebAuthn."""

from datetime import datetime, timedelta, timezone

import pytest


def _user(app, username="passkey_user"):
    from app.auth import register_user
    from app.models import db

    with app.app_context():
        user, error = register_user(username, "password123")
        assert error is None
        db.session.commit()
        return user.id


def test_challenge_is_bound_to_user_session_and_consumed_once(app):
    from app.webauthn_service import ChallengeError, create_challenge, consume_challenge

    user_id = _user(app)
    now = datetime.now(timezone.utc)
    with app.app_context():
        create_challenge(
            user_id=user_id,
            purpose="register",
            session_binding="browser-a-binding",
            challenge=b"registration-challenge",
            now=now,
        )

        assert consume_challenge(
            user_id=user_id,
            purpose="register",
            session_binding="browser-a-binding",
            now=now,
        ) == b"registration-challenge"
        with pytest.raises(ChallengeError, match="not available"):
            consume_challenge(
                user_id=user_id,
                purpose="register",
                session_binding="browser-a-binding",
                now=now,
            )


def test_challenge_rejects_wrong_user_wrong_session_and_expiry(app):
    from app.webauthn_service import ChallengeError, create_challenge, consume_challenge

    user_id = _user(app)
    other_id = _user(app, "other_passkey_user")
    now = datetime.now(timezone.utc)
    with app.app_context():
        create_challenge(
            user_id=user_id,
            purpose="login",
            session_binding="browser-a-binding",
            challenge=b"authentication-challenge",
            now=now,
            ttl=timedelta(seconds=30),
        )

        for kwargs in (
            {
                "user_id": other_id,
                "session_binding": "browser-a-binding",
                "now": now,
            },
            {
                "user_id": user_id,
                "session_binding": "browser-b-binding",
                "now": now,
            },
            {
                "user_id": user_id,
                "session_binding": "browser-a-binding",
                "now": now + timedelta(seconds=31),
            },
        ):
            with pytest.raises(ChallengeError):
                consume_challenge(
                    purpose="login",
                    **kwargs,
                )


def test_creating_challenge_prunes_expired_rows_for_other_bindings(app):
    from app.models import WebAuthnChallenge
    from app.webauthn_service import create_challenge

    now = datetime.now(timezone.utc)
    with app.app_context():
        create_challenge(
            user_id=None,
            purpose="login",
            session_binding="expired-browser-binding",
            challenge=b"expired-authentication-challenge",
            now=now - timedelta(minutes=10),
            ttl=timedelta(minutes=5),
        )
        create_challenge(
            user_id=None,
            purpose="login",
            session_binding="live-browser-binding",
            challenge=b"live-authentication-challenge",
            now=now,
        )
        create_challenge(
            user_id=None,
            purpose="login",
            session_binding="new-browser-binding",
            challenge=b"new-authentication-challenge",
            now=now,
        )

        rows = WebAuthnChallenge.query.order_by(
            WebAuthnChallenge.id.asc()
        ).all()

    assert [bytes(row.challenge) for row in rows] == [
        b"live-authentication-challenge",
        b"new-authentication-challenge",
    ]


@pytest.mark.parametrize("purpose", ("login", "mfa_login", "step_up"))
def test_authentication_challenge_purposes_are_explicit(app, purpose):
    from app.webauthn_service import create_challenge

    with app.app_context():
        row = create_challenge(
            user_id=None,
            purpose=purpose,
            session_binding="browser-purpose-binding",
            challenge=b"purpose-specific-challenge",
        )
        assert row.purpose == purpose
