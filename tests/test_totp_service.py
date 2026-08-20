"""Encrypted TOTP enrollment, activation, and replay protection."""

from datetime import datetime, timedelta, timezone

import pyotp
import pytest


def _create_user(app, username="totp_user"):
    from app.auth import register_user
    from app.models import db

    with app.app_context():
        user, error = register_user(username, "password123")
        assert error is None
        db.session.commit()
        return user.id


def test_enrollment_is_short_lived_encrypted_and_locally_rendered(app):
    from app.models import TOTPEnrollment
    from app.totp_service import begin_totp_enrollment

    user_id = _create_user(app)
    with app.app_context():
        view = begin_totp_enrollment(user_id, "browser-binding")
        row = TOTPEnrollment.query.one()

        assert len(view.secret) == 32
        assert view.provisioning_uri.startswith("otpauth://totp/WebSSH:")
        assert "issuer=WebSSH" in view.provisioning_uri
        assert "<svg" in view.qr_svg
        assert view.secret.encode("ascii") not in bytes(row.encrypted_secret)
        assert row.expires_at - row.created_at == timedelta(minutes=5)


def test_activation_requires_bound_valid_code_and_enables_mfa_atomically(app):
    from app.models import RecoveryCode, TOTPAuthenticator, TOTPEnrollment, User, db
    from app.totp_service import (
        TOTPEnrollmentError,
        activate_totp_enrollment,
        begin_totp_enrollment,
    )

    user_id = _create_user(app, "activate_totp")
    with app.app_context():
        view = begin_totp_enrollment(user_id, "correct-binding")
        code = pyotp.TOTP(view.secret).now()

        with pytest.raises(TOTPEnrollmentError):
            activate_totp_enrollment(view.token, code, "wrong-binding")

        authenticator = activate_totp_enrollment(
            view.token,
            code,
            "correct-binding",
        )
        user = db.session.get(User, user_id)

        assert authenticator.active is True
        assert authenticator.activated_at is not None
        assert user.mfa_enabled is True
        assert TOTPEnrollment.query.count() == 0
        assert TOTPAuthenticator.query.count() == 1
        assert RecoveryCode.query.filter_by(user_id=user_id).count() == 10
        assert len(authenticator.recovery_codes) == 10
        assert len(set(authenticator.recovery_codes)) == 10


def test_totp_accepts_adjacent_steps_once_and_tracks_exact_timecode(app):
    from app.models import TOTPAuthenticator, db
    from app.totp_service import (
        activate_totp_enrollment,
        begin_totp_enrollment,
        verify_totp,
    )

    user_id = _create_user(app, "totp_replay")
    activation_time = datetime.now(timezone.utc)
    reference = activation_time + timedelta(minutes=5)
    with app.app_context():
        view = begin_totp_enrollment(user_id, "binding")
        activation_code = pyotp.TOTP(view.secret).at(activation_time)
        authenticator = activate_totp_enrollment(
            view.token,
            activation_code,
            "binding",
            now=activation_time,
        )
        previous_code = pyotp.TOTP(view.secret).at(reference - timedelta(seconds=30))

        assert verify_totp(user_id, previous_code, now=reference) is True
        db.session.refresh(authenticator)
        accepted_step = int((reference - timedelta(seconds=30)).timestamp()) // 30
        assert authenticator.last_accepted_step == accepted_step
        assert verify_totp(user_id, previous_code, now=reference) is False

        current_code = pyotp.TOTP(view.secret).at(reference)
        assert verify_totp(user_id, current_code, now=reference) is True
        assert verify_totp(user_id, current_code, now=reference) is False


def test_parallel_totp_enrollments_keep_their_own_tokens_and_labels(app):
    from app.models import TOTPAuthenticator, TOTPEnrollment
    from app.totp_service import (
        activate_totp_enrollment,
        begin_totp_enrollment,
    )

    user_id = _create_user(app, "parallel_totp")
    with app.app_context():
        phone = begin_totp_enrollment(
            user_id,
            "shared-browser-binding",
            label="Phone",
        )
        tablet = begin_totp_enrollment(
            user_id,
            "shared-browser-binding",
            label="Tablet",
        )

        assert TOTPEnrollment.query.count() == 2
        activate_totp_enrollment(
            phone.token,
            pyotp.TOTP(phone.secret).now(),
            "shared-browser-binding",
        )
        activate_totp_enrollment(
            tablet.token,
            pyotp.TOTP(tablet.secret).now(),
            "shared-browser-binding",
        )

        assert {
            row.label for row in TOTPAuthenticator.query.all()
        } == {"Phone", "Tablet"}


def test_totp_ciphertext_is_user_and_domain_separated(app):
    from cryptography.fernet import InvalidToken

    from app.mfa_crypto import decrypt_totp_secret, encrypt_totp_secret

    with app.app_context():
        ciphertext = encrypt_totp_secret(11, "ABCDEFGHIJKLMNOPQRSTUVWX23456789")
        assert decrypt_totp_secret(11, ciphertext) == "ABCDEFGHIJKLMNOPQRSTUVWX23456789"
        with pytest.raises(InvalidToken):
            decrypt_totp_secret(12, ciphertext)
