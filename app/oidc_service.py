"""Server-side OIDC login state and stable identity resolution."""

import hashlib
from datetime import datetime, timedelta, timezone
from threading import Lock

from .models import OIDCIdentity, OIDCLoginState, as_naive_utc, db


class OIDCStateError(ValueError):
    """Raised for missing, mismatched, expired, or replayed OIDC state."""


_oidc_state_lock = Lock()


def _hash(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def create_login_state(
    *,
    state,
    nonce,
    session_binding,
    code_verifier,
    now=None,
    ttl=timedelta(minutes=5),
):
    if min(
        len(state),
        len(nonce),
        len(session_binding),
        len(code_verifier),
    ) < 8:
        raise OIDCStateError("OIDC state values are too short")
    now = as_naive_utc(now or datetime.now(timezone.utc))
    binding_hash = _hash(session_binding)
    with _oidc_state_lock:
        OIDCLoginState.query.filter(
            OIDCLoginState.expires_at < now
        ).delete(synchronize_session=False)
        OIDCLoginState.query.filter_by(
            session_binding_hash=binding_hash
        ).delete(synchronize_session=False)
        row = OIDCLoginState(
            state_hash=_hash(state),
            session_binding_hash=binding_hash,
            nonce=nonce,
            code_verifier=code_verifier,
            expires_at=now + ttl,
        )
        db.session.add(row)
        db.session.commit()
    return row


def consume_login_state(*, state, session_binding, now=None):
    now = as_naive_utc(now or datetime.now(timezone.utc))
    with _oidc_state_lock:
        row = OIDCLoginState.query.filter_by(
            state_hash=_hash(state),
            session_binding_hash=_hash(session_binding),
        ).first()
        if row is None:
            raise OIDCStateError("OIDC login state is not available")
        nonce = row.nonce
        verifier = row.code_verifier
        expires_at = row.expires_at
        db.session.delete(row)
        db.session.commit()
        if expires_at < now:
            raise OIDCStateError("OIDC login state has expired")
        return nonce, verifier


def discard_login_state(*, state, session_binding):
    with _oidc_state_lock:
        deleted = OIDCLoginState.query.filter_by(
            state_hash=_hash(state),
            session_binding_hash=_hash(session_binding),
        ).delete(synchronize_session=False)
        db.session.commit()
        return bool(deleted)


def resolve_identity(issuer, subject):
    mapping = OIDCIdentity.query.filter_by(
        issuer=issuer.rstrip("/"),
        subject=subject,
    ).first()
    return mapping.user if mapping is not None else None
