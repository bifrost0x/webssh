"""Server-side OIDC state and stable identity-link behavior."""

from datetime import datetime, timedelta, timezone

import pytest


def _create_user(app, username):
    from app.auth import register_user
    from app.models import db

    with app.app_context():
        user, error = register_user(username, "password123")
        assert error is None
        db.session.commit()
        return user.id


def test_oidc_state_is_session_bound_expiring_and_single_use(app):
    from app.oidc_service import OIDCStateError, consume_login_state, create_login_state

    now = datetime.now(timezone.utc)
    with app.app_context():
        create_login_state(
            state="state-token",
            nonce="nonce-token",
            session_binding="browser-a-binding",
            code_verifier="pkce-verifier",
            now=now,
            ttl=timedelta(seconds=30),
        )

        assert consume_login_state(
            state="state-token",
            session_binding="browser-a-binding",
            now=now,
        ) == ("nonce-token", "pkce-verifier")
        with pytest.raises(OIDCStateError):
            consume_login_state(
                state="state-token",
                session_binding="browser-a-binding",
                now=now,
            )


def test_oidc_identity_resolution_never_uses_email(app):
    from app.models import OIDCIdentity, db
    from app.oidc_service import resolve_identity

    alice_id = _create_user(app, "oidc_alice")
    _create_user(app, "same_email_name")
    with app.app_context():
        db.session.add(OIDCIdentity(
            user_id=alice_id,
            issuer="https://issuer.example",
            subject="subject-1",
        ))
        db.session.commit()

        assert resolve_identity(
            "https://issuer.example",
            "subject-1",
        ).id == alice_id
        assert resolve_identity(
            "https://issuer.example",
            "same_email_name",
        ) is None


def test_new_oidc_state_replaces_prior_state_for_same_browser(app):
    from app.models import OIDCLoginState
    from app.oidc_service import create_login_state

    with app.app_context():
        for suffix in ("first", "second"):
            create_login_state(
                state=f"state-{suffix}-token",
                nonce=f"nonce-{suffix}-token",
                session_binding="same-browser-binding",
                code_verifier=f"verifier-{suffix}-token",
            )

        rows = OIDCLoginState.query.all()
        assert len(rows) == 1
        assert rows[0].nonce == "nonce-second-token"


def test_as_naive_utc_normalizes_aware_and_preserves_naive_values():
    from app.models import as_naive_utc

    naive = datetime(2026, 7, 30, 12, 0)
    aware = datetime(
        2026, 7, 30, 14, 0,
        tzinfo=timezone(timedelta(hours=2)),
    )

    assert as_naive_utc(naive) is naive
    assert as_naive_utc(aware) == naive
