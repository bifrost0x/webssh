"""WebAuthn ceremony helpers with server-side, one-use challenges."""

import hashlib
from datetime import datetime, timedelta, timezone
from threading import Lock

from .models import WebAuthnChallenge, as_naive_utc, db


class ChallengeError(ValueError):
    """Raised when ceremony state is missing, mismatched, expired, or replayed."""


_challenge_lock = Lock()


def _binding_hash(session_binding):
    if not isinstance(session_binding, str) or len(session_binding) < 16:
        raise ChallengeError("Invalid WebAuthn session binding")
    return hashlib.sha256(session_binding.encode("utf-8")).hexdigest()


def create_challenge(
    *,
    user_id,
    purpose,
    session_binding,
    challenge,
    now=None,
    ttl=timedelta(minutes=5),
):
    if purpose not in {"register", "authenticate"}:
        raise ChallengeError("Invalid WebAuthn challenge purpose")
    if not isinstance(challenge, bytes) or len(challenge) < 16:
        raise ChallengeError("Invalid WebAuthn challenge")
    now = as_naive_utc(now or datetime.now(timezone.utc))
    binding_hash = _binding_hash(session_binding)
    with _challenge_lock:
        WebAuthnChallenge.query.filter(
            WebAuthnChallenge.expires_at < now
        ).delete(synchronize_session=False)
        WebAuthnChallenge.query.filter_by(
            user_id=user_id,
            purpose=purpose,
            session_binding_hash=binding_hash,
        ).delete()
        row = WebAuthnChallenge(
            user_id=user_id,
            purpose=purpose,
            session_binding_hash=binding_hash,
            challenge=challenge,
            expires_at=now + ttl,
        )
        db.session.add(row)
        db.session.commit()
    return row


def consume_challenge(
    *,
    user_id,
    purpose,
    session_binding,
    now=None,
):
    now = as_naive_utc(now or datetime.now(timezone.utc))
    with _challenge_lock:
        row = WebAuthnChallenge.query.filter_by(
            user_id=user_id,
            purpose=purpose,
            session_binding_hash=_binding_hash(session_binding),
        ).order_by(WebAuthnChallenge.id.desc()).first()
        if row is None:
            raise ChallengeError("WebAuthn challenge is not available")
        challenge = bytes(row.challenge)
        expires_at = row.expires_at
        db.session.delete(row)
        db.session.commit()
        if expires_at < now:
            raise ChallengeError("WebAuthn challenge has expired")
        return challenge
