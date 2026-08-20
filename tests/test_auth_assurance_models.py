from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.exc import IntegrityError


def _create_user():
    from app.models import User, db

    user = User(username='assurance-model-user')
    user.set_password('correct horse battery staple')
    db.session.add(user)
    db.session.commit()
    return user


def test_existing_user_upgrade_does_not_enable_mfa(app):
    from app.models import User, db

    with app.app_context():
        user = User(username='existing-assurance-user')
        user.set_password('correct horse battery staple')
        db.session.add(user)
        db.session.commit()

        assert user.mfa_enabled is False


def test_pending_authentication_token_hash_is_unique(app):
    from app.models import PendingAuthentication, db

    with app.app_context():
        user = _create_user()
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        first = PendingAuthentication(
            token_hash='a' * 64,
            user_id=user.id,
            primary_method='password',
            assurance='BASIC',
            session_binding_hash='b' * 64,
            expires_at=expires_at,
        )
        second = PendingAuthentication(
            token_hash='a' * 64,
            user_id=user.id,
            primary_method='password',
            assurance='BASIC',
            session_binding_hash='c' * 64,
            expires_at=expires_at,
        )
        db.session.add_all([first, second])

        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()


def test_security_state_tokens_and_secrets_are_persisted_as_hashes_or_bytes(app):
    from app.models import (
        AuthenticationSession,
        SecurityFeatureState,
        StepUpGrant,
        TOTPAuthenticator,
        TOTPEnrollment,
        db,
    )

    with app.app_context():
        user = _create_user()
        now = datetime.now(timezone.utc)
        auth_session = AuthenticationSession(
            session_hash='d' * 64,
            user_id=user.id,
            assurance='MFA',
            methods_json='["password", "totp"]',
            authenticated_at=now,
            strong_authenticated_at=now,
            auth_generation=0,
            expires_at=now + timedelta(minutes=30),
        )
        db.session.add(auth_session)
        db.session.flush()
        db.session.add_all([
            SecurityFeatureState(
                feature='totp', enabled=False, updated_by=user.id,
            ),
            TOTPAuthenticator(
                user_id=user.id,
                encrypted_secret=b'encrypted-active-secret',
                label='Phone',
                active=True,
            ),
            TOTPEnrollment(
                token_hash='e' * 64,
                user_id=user.id,
                session_binding_hash='f' * 64,
                encrypted_secret=b'encrypted-pending-secret',
                expires_at=now + timedelta(minutes=5),
            ),
            StepUpGrant(
                token_hash='1' * 64,
                authentication_session_id=auth_session.id,
                action='user.lock',
                target_hash='2' * 64,
                assurance='MFA',
                expires_at=now + timedelta(minutes=5),
            ),
        ])
        db.session.commit()

        assert TOTPAuthenticator.query.one().encrypted_secret == (
            b'encrypted-active-secret'
        )
        assert TOTPEnrollment.query.one().encrypted_secret == (
            b'encrypted-pending-secret'
        )
        assert StepUpGrant.query.one().token_hash == '1' * 64


def test_expired_security_cleanup_is_bounded_and_preserves_live_rows(app):
    from app.models import (
        PendingAuthentication,
        cleanup_expired_security_rows,
        db,
    )

    with app.app_context():
        user = _create_user()
        now = datetime.now(timezone.utc)
        for index in range(3):
            db.session.add(PendingAuthentication(
                token_hash=str(index) * 64,
                user_id=user.id,
                primary_method='password',
                assurance='BASIC',
                session_binding_hash=str(index + 3) * 64,
                expires_at=now - timedelta(seconds=1),
            ))
        db.session.add(PendingAuthentication(
            token_hash='9' * 64,
            user_id=user.id,
            primary_method='password',
            assurance='BASIC',
            session_binding_hash='8' * 64,
            expires_at=now + timedelta(minutes=5),
        ))
        db.session.commit()

        assert cleanup_expired_security_rows(limit=2, now=now) == 2
        assert PendingAuthentication.query.count() == 2
        assert cleanup_expired_security_rows(limit=2, now=now) == 1
        assert PendingAuthentication.query.one().token_hash == '9' * 64


def test_security_cleanup_expires_rows_at_the_exact_deadline(app):
    from app.models import (
        PendingAuthentication,
        cleanup_expired_security_rows,
        db,
    )

    with app.app_context():
        user = _create_user()
        now = datetime.now(timezone.utc)
        db.session.add(PendingAuthentication(
            token_hash='7' * 64,
            user_id=user.id,
            primary_method='password',
            assurance='BASIC',
            session_binding_hash='6' * 64,
            expires_at=now,
        ))
        db.session.commit()

        assert cleanup_expired_security_rows(limit=1, now=now) == 1
        assert PendingAuthentication.query.count() == 0
