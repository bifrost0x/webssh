"""Encrypted TOTP enrollment, activation, and replay protection."""

import base64
from datetime import datetime, timedelta, timezone

import pytest

from app.totp_service import _provisioning_uri, _random_base32, _totp_code
from tests.totp_helpers import totp_at, totp_now


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
        code = totp_now(view.secret)

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
    from app.models import db
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
        activation_code = totp_at(view.secret, activation_time)
        authenticator = activate_totp_enrollment(
            view.token,
            activation_code,
            "binding",
            now=activation_time,
        )
        previous_code = totp_at(view.secret, reference - timedelta(seconds=30))

        assert verify_totp(user_id, previous_code, now=reference) is True
        db.session.refresh(authenticator)
        accepted_step = int((reference - timedelta(seconds=30)).timestamp()) // 30
        assert authenticator.last_accepted_step == accepted_step
        assert verify_totp(user_id, previous_code, now=reference) is False

        current_code = totp_at(view.secret, reference)
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
            totp_now(phone.secret),
            "shared-browser-binding",
        )
        activate_totp_enrollment(
            tablet.token,
            totp_now(tablet.secret),
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


def test_totp_decrypt_failure_is_logged(app, caplog):
    from app.models import TOTPAuthenticator, db
    from app.totp_service import (
        activate_totp_enrollment,
        begin_totp_enrollment,
        verify_totp,
    )

    user_id = _create_user(app, "totp_decrypt_logged")
    activation_time = datetime.now(timezone.utc)
    with app.app_context():
        view = begin_totp_enrollment(user_id, "binding")
        activate_totp_enrollment(
            view.token,
            totp_at(view.secret, activation_time),
            "binding",
            now=activation_time,
        )
        row = TOTPAuthenticator.query.filter_by(user_id=user_id).one()
        row.encrypted_secret = b"not-a-valid-ciphertext"
        db.session.commit()
        code = totp_at(view.secret, activation_time + timedelta(minutes=5))

        caplog.clear()
        with caplog.at_level("WARNING"):
            result = verify_totp(
                user_id, code, now=activation_time + timedelta(minutes=5)
            )

    assert result is False
    records = [
        record for record in caplog.records
        if record.getMessage() == "TOTP secret could not be decrypted"
    ]
    assert len(records) == 1
    assert records[0].extra_data["user_id"] == user_id
    assert records[0].extra_data["error_type"]
    assert view.secret not in caplog.text
    assert "not-a-valid-ciphertext" not in caplog.text


def test_totp_commit_failure_logs_without_touching_the_failed_session(
    app, monkeypatch, caplog
):
    from sqlalchemy import event

    from app.models import TOTPAuthenticator, db
    from app.totp_service import (
        activate_totp_enrollment,
        begin_totp_enrollment,
        verify_totp,
    )

    user_id = _create_user(app, "totp_commit_logged")
    activation_time = datetime.now(timezone.utc)
    reference = activation_time + timedelta(minutes=5)
    with app.app_context():
        view = begin_totp_enrollment(user_id, "binding")
        activate_totp_enrollment(
            view.token,
            totp_at(view.secret, activation_time),
            "binding",
            now=activation_time,
        )
        code = totp_at(view.secret, reference)

        def failing_commit():
            raise RuntimeError("database unavailable")

        def failing_refresh(*_args, **_kwargs):
            raise RuntimeError("refresh against failed database")

        monkeypatch.setattr(db.session, "commit", failing_commit)
        event.listen(TOTPAuthenticator, "refresh", failing_refresh)
        try:
            caplog.clear()
            with caplog.at_level("WARNING"):
                assert verify_totp(user_id, code, now=reference) is False
        finally:
            event.remove(TOTPAuthenticator, "refresh", failing_refresh)

    records = [
        record for record in caplog.records
        if record.getMessage() == "TOTP replay state could not be saved"
    ]
    assert len(records) == 1
    assert records[0].extra_data == {
        "user_id": user_id,
        "error_type": "RuntimeError",
    }


# Reference values captured from PyOTP 2.12.1 before it was dropped.
_REFERENCE_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
_REFERENCE_CODES = ((0, "702218"), (1, "503347"), (59_259_259, "671954"))
_RFC6238_SECRET = base64.b32encode(b"12345678901234567890").decode("ascii")


@pytest.mark.parametrize(("step", "expected"), _REFERENCE_CODES)
def test_totp_code_matches_reference_values(step, expected):
    assert _totp_code(_REFERENCE_SECRET, step) == expected


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    ((59, "287082"), (1111111109, "081804"), (1234567890, "005924")),
)
def test_totp_code_matches_rfc6238_sha1_vectors(timestamp, expected):
    assert _totp_code(_RFC6238_SECRET, timestamp // 30) == expected


def test_totp_code_accepts_lowercase_and_unpadded_secrets():
    assert _totp_code(_REFERENCE_SECRET.lower(), 1) == "503347"
    assert _totp_code("JBSWY3DPEHPK3PXPJBSWY3DPEH", 1000) == "078585"


def test_totp_code_rejects_secrets_below_112_bits():
    with pytest.raises(ValueError):
        _totp_code("JBSWY3DPEHPK3PXP", 1)


def test_provisioning_uri_matches_reference_format():
    assert _provisioning_uri(_REFERENCE_SECRET, "alice@example.com", "WebSSH") == (
        "otpauth://totp/WebSSH:alice%40example.com"
        "?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=WebSSH"
    )
    assert _provisioning_uri(_REFERENCE_SECRET, "a b/ü", "WebSSH") == (
        "otpauth://totp/WebSSH:a%20b/%C3%BC"
        "?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=WebSSH"
    )


def test_random_base32_secret_uses_the_base32_alphabet():
    secrets = {_random_base32() for _ in range(20)}

    assert len(secrets) == 20
    for secret in secrets:
        assert len(secret) == 32
        assert set(secret) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        assert len(_totp_code(secret, 1)) == 6
