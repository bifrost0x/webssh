"""Persistent account step-up intents and single-use grant issuance."""

from datetime import datetime, timedelta, timezone

import pytest


def _user_and_session(*, mfa_enabled=False, methods='["password"]'):
    from app.models import AuthenticationSession, User, db

    now = datetime.now(timezone.utc)
    user = User(
        username=f"account-step-up-{methods}-{mfa_enabled}",
        mfa_enabled=mfa_enabled,
    )
    user.set_password("correct horse battery staple")
    db.session.add(user)
    db.session.flush()
    auth_session = AuthenticationSession(
        session_hash=(str(user.id) * 64)[:64],
        user_id=user.id,
        assurance="MFA" if mfa_enabled else "BASIC",
        methods_json=methods,
        authenticated_at=now,
        strong_authenticated_at=now if mfa_enabled else None,
        auth_generation=0,
        expires_at=now + timedelta(hours=1),
    )
    db.session.add(auth_session)
    db.session.commit()
    return user, auth_session


def test_account_intent_is_hashed_bound_and_contains_no_raw_evidence(app):
    from app.models import StepUpIntent
    from app.step_up import create_account_step_up_intent, hash_step_up_target

    with app.app_context():
        user, auth_session = _user_and_session()

        token, intent = create_account_step_up_intent(
            auth_session,
            "recovery.rotate",
            user.id,
        )

        stored = StepUpIntent.query.one()
        assert stored.id == intent.id
        assert stored.token_hash != token
        assert token not in stored.token_hash
        assert stored.authentication_session_id == auth_session.id
        assert stored.user_id == user.id
        assert stored.scope == "account"
        assert stored.action == "recovery.rotate"
        assert stored.target_hash == hash_step_up_target(user.id)
        assert stored.required_assurance == "BASIC"
        assert stored.status == "pending"
        assert not hasattr(stored, "password")
        assert not hasattr(stored, "credential")
        assert not hasattr(stored, "grant")


def test_account_intent_rejects_admin_actions_before_writing(app):
    from app.models import StepUpIntent
    from app.step_up import StepUpError, create_account_step_up_intent

    with app.app_context():
        _user, auth_session = _user_and_session()

        with pytest.raises(StepUpError):
            create_account_step_up_intent(
                auth_session,
                "settings.update",
                "global",
            )

        assert StepUpIntent.query.count() == 0


def test_account_intent_uses_mfa_policy_when_mfa_is_enabled(app):
    from app.step_up import create_account_step_up_intent

    with app.app_context():
        user, auth_session = _user_and_session(
            mfa_enabled=True,
            methods='["password", "totp"]',
        )

        _token, intent = create_account_step_up_intent(
            auth_session,
            "passkey.enroll",
            user.id,
        )

        assert intent.required_assurance == "MFA"


def test_account_intents_are_bounded_per_authentication_session(app):
    from app.models import StepUpIntent
    from app.step_up import StepUpError, create_account_step_up_intent

    with app.app_context():
        user, auth_session = _user_and_session()
        for _index in range(8):
            create_account_step_up_intent(
                auth_session,
                "recovery.rotate",
                user.id,
            )

        with pytest.raises(StepUpError):
            create_account_step_up_intent(
                auth_session,
                "recovery.rotate",
                user.id,
            )

        assert StepUpIntent.query.filter_by(status="pending").count() == 8


def test_approved_account_intent_issues_exactly_one_bound_grant(app):
    from app.models import StepUpGrant, StepUpIntent, db
    from app.step_up import (
        StepUpError,
        approve_account_step_up_intent,
        claim_account_step_up_grant,
        consume_step_up_grant,
        create_account_step_up_intent,
    )

    with app.app_context():
        user, auth_session = _user_and_session()
        token, intent = create_account_step_up_intent(
            auth_session,
            "recovery.rotate",
            user.id,
        )
        approve_account_step_up_intent(
            token,
            auth_session,
            assurance="BASIC",
            method="password",
        )

        grant = claim_account_step_up_grant(token, auth_session)
        assert isinstance(grant, str) and grant
        assert db.session.get(StepUpIntent, intent.id).status == "completed"
        assert StepUpGrant.query.count() == 1

        with pytest.raises(StepUpError):
            claim_account_step_up_grant(token, auth_session)

        assert consume_step_up_grant(
            grant,
            auth_session,
            "recovery.rotate",
            user.id,
        ) is True
        assert StepUpGrant.query.count() == 0


def test_account_intent_cannot_cross_browser_authentication_sessions(app):
    from app.models import AuthenticationSession, db
    from app.step_up import (
        StepUpError,
        approve_account_step_up_intent,
        create_account_step_up_intent,
    )

    with app.app_context():
        user, auth_session = _user_and_session()
        now = datetime.now(timezone.utc)
        other = AuthenticationSession(
            session_hash="f" * 64,
            user_id=user.id,
            assurance="BASIC",
            methods_json='["password"]',
            authenticated_at=now,
            auth_generation=0,
            expires_at=now + timedelta(hours=1),
        )
        db.session.add(other)
        db.session.commit()
        token, _intent = create_account_step_up_intent(
            auth_session,
            "recovery.rotate",
            user.id,
        )

        with pytest.raises(StepUpError):
            approve_account_step_up_intent(
                token,
                other,
                assurance="BASIC",
                method="password",
            )


def test_expired_account_intents_are_removed_by_bounded_cleanup(app):
    from app.models import StepUpIntent, cleanup_expired_security_rows, db

    with app.app_context():
        user, auth_session = _user_and_session()
        now = datetime.now(timezone.utc)
        db.session.add(StepUpIntent(
            token_hash="a" * 64,
            authentication_session_id=auth_session.id,
            user_id=user.id,
            scope="account",
            action="recovery.rotate",
            target_hash="b" * 64,
            required_assurance="BASIC",
            status="pending",
            created_at=now - timedelta(minutes=6),
            expires_at=now - timedelta(seconds=1),
        ))
        db.session.commit()

        assert cleanup_expired_security_rows(limit=1, now=now) == 1
        assert StepUpIntent.query.count() == 0
