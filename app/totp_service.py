"""Encrypted TOTP enrollment and serialized replay-safe verification."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import io
import secrets
from threading import RLock

import pyotp
import qrcode
from qrcode.image.svg import SvgPathImage

from .mfa_crypto import decrypt_totp_secret, encrypt_totp_secret
from .models import (
    TOTPAuthenticator,
    TOTPEnrollment,
    User,
    as_naive_utc,
    db,
)


_ENROLLMENT_TTL = timedelta(minutes=5)
_MAX_AUTHENTICATORS_PER_USER = 5
_MAX_ENROLLMENTS_PER_USER = 5
_totp_lock = RLock()


class TOTPEnrollmentError(RuntimeError):
    """The enrollment token, binding, or first code was invalid."""


@dataclass(frozen=True)
class EnrollmentView:
    token: str
    secret: str
    provisioning_uri: str
    qr_svg: str
    expires_at: datetime


def _digest(value):
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _utc_now(now=None):
    value = now or datetime.now(timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _accepted_step(secret, code, now):
    candidate = str(code or "").strip()
    if len(candidate) != 6 or not candidate.isascii() or not candidate.isdigit():
        return None
    totp = pyotp.TOTP(secret, digits=6, interval=30)
    base_step = int(now.timestamp()) // 30
    for offset in (-1, 0, 1):
        step = base_step + offset
        if secrets.compare_digest(totp.at(step * 30), candidate):
            return step
    return None


def _qr_svg(provisioning_uri):
    image = qrcode.make(provisioning_uri, image_factory=SvgPathImage)
    output = io.BytesIO()
    image.save(output)
    return output.getvalue().decode("utf-8")


def begin_totp_enrollment(user_id, session_binding, *, label="Authenticator"):
    """Create a five-minute enrollment and return its one-time setup view."""
    binding = str(session_binding or "")
    if not binding or len(binding) > 512:
        raise ValueError("invalid TOTP enrollment binding")
    user = db.session.get(User, int(user_id))
    if user is None or user.is_locked:
        raise TOTPEnrollmentError("account is unavailable")
    normalized_label = str(label or "Authenticator").strip()
    if not normalized_label or len(normalized_label) > 80:
        raise TOTPEnrollmentError("TOTP label is invalid")
    account_name = user.username
    now = as_naive_utc(datetime.now(timezone.utc))
    token = secrets.token_urlsafe(32)
    secret = pyotp.random_base32(length=32)
    provisioning_uri = pyotp.TOTP(secret).provisioning_uri(
        name=account_name,
        issuer_name="WebSSH",
    )

    with _totp_lock:
        TOTPEnrollment.query.filter(
            TOTPEnrollment.expires_at <= now
        ).delete(synchronize_session=False)
        live_rows = (
            TOTPEnrollment.query
            .filter_by(user_id=user.id)
            .order_by(TOTPEnrollment.created_at.desc(), TOTPEnrollment.id.desc())
            .all()
        )
        for stale in live_rows[_MAX_ENROLLMENTS_PER_USER - 1:]:
            db.session.delete(stale)
        row = TOTPEnrollment(
            token_hash=_digest(token),
            user_id=user.id,
            session_binding_hash=_digest(binding),
            encrypted_secret=encrypt_totp_secret(user.id, secret),
            label=normalized_label,
            created_at=now,
            expires_at=now + _ENROLLMENT_TTL,
        )
        db.session.add(row)
        db.session.commit()

    return EnrollmentView(
        token=token,
        secret=secret,
        provisioning_uri=provisioning_uri,
        qr_svg=_qr_svg(provisioning_uri),
        expires_at=row.expires_at,
    )


def activate_totp_enrollment(token, code, session_binding, *, now=None, label=None):
    """Verify the first code, activate MFA, and rotate recovery codes once."""
    from .recovery_service import _recovery_lock, _replace_codes_uncommitted

    now_aware = _utc_now(now)
    now_db = as_naive_utc(now_aware)
    token_hash = _digest(token)
    binding_hash = _digest(session_binding)
    with _totp_lock, _recovery_lock:
        enrollment = TOTPEnrollment.query.filter_by(
            token_hash=token_hash,
            session_binding_hash=binding_hash,
        ).first()
        if enrollment is None or enrollment.expires_at <= now_db:
            raise TOTPEnrollmentError("TOTP enrollment is invalid or expired")
        user = db.session.get(User, enrollment.user_id)
        if user is None or user.is_locked:
            raise TOTPEnrollmentError("account is unavailable")
        if TOTPAuthenticator.query.filter_by(user_id=user.id).count() >= (
            _MAX_AUTHENTICATORS_PER_USER
        ):
            raise TOTPEnrollmentError("TOTP authenticator limit reached")

        secret = decrypt_totp_secret(user.id, enrollment.encrypted_secret)
        accepted_step = _accepted_step(secret, code, now_aware)
        if accepted_step is None:
            raise TOTPEnrollmentError("TOTP code is invalid")

        normalized_label = str(label or enrollment.label or "Authenticator").strip()
        if not normalized_label or len(normalized_label) > 80:
            raise TOTPEnrollmentError("TOTP label is invalid")
        first_activation = not bool(user.mfa_enabled)
        authenticator = TOTPAuthenticator(
            user_id=user.id,
            encrypted_secret=enrollment.encrypted_secret,
            label=normalized_label,
            active=True,
            last_accepted_step=accepted_step,
            created_at=enrollment.created_at,
            activated_at=now_db,
        )
        db.session.add(authenticator)
        db.session.delete(enrollment)
        recovery_codes = (
            _replace_codes_uncommitted(user.id, count=10)
            if first_activation
            else []
        )
        user.mfa_enabled = True
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise
        authenticator.recovery_codes = tuple(recovery_codes)
        return authenticator


def verify_totp(user_id, code, *, now=None):
    """Accept a nearby TOTP step once across concurrent requests."""
    now_aware = _utc_now(now)
    now_db = as_naive_utc(now_aware)
    with _totp_lock:
        rows = TOTPAuthenticator.query.filter_by(
            user_id=int(user_id),
            active=True,
        ).order_by(TOTPAuthenticator.id.asc()).all()
        matched = None
        matched_step = None
        for row in rows:
            try:
                secret = decrypt_totp_secret(row.user_id, row.encrypted_secret)
            except Exception:
                continue
            step = _accepted_step(secret, code, now_aware)
            if step is None or (
                row.last_accepted_step is not None
                and step <= int(row.last_accepted_step)
            ):
                continue
            matched = row
            matched_step = step
            break
        if matched is None:
            return False
        matched.last_accepted_step = matched_step
        matched.last_used_at = now_db
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            return False
        return True
