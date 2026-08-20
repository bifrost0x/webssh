"""Server-side OIDC login state and stable identity resolution."""

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import Lock
from urllib.parse import urlsplit

from .auth_assurance import AssuranceLevel
from .models import OIDCIdentity, OIDCLoginState, as_naive_utc, db


class OIDCStateError(ValueError):
    """Raised for missing, mismatched, expired, or replayed OIDC state."""


_oidc_state_lock = Lock()
_STATE_PURPOSES = frozenset({"login", "step_up"})
_ACTION_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,95}$")
_TARGET_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_MAX_AMR_VALUES = 16
_MAX_AMR_VALUE_LENGTH = 128
_MAX_ACR_LENGTH = 256
_MAX_AUTH_TIME = 253_402_300_799


@dataclass(frozen=True)
class OIDCLoginIntent:
    """Consumed server-owned OIDC authorization intent."""

    nonce: str
    code_verifier: str
    purpose: str
    continuation: str
    requested_acr: str | None
    step_up_action: str | None
    step_up_target_hash: str | None


@dataclass(frozen=True)
class OIDCAssurance:
    """Bounded assurance evidence normalized from a validated ID Token."""

    level: AssuranceLevel
    acr: str | None
    amr: tuple[str, ...]
    auth_time: int | None
    reason: str


def _hash(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_continuation(value):
    candidate = str(value or "/")
    parsed = urlsplit(candidate)
    if (
        not candidate.startswith("/")
        or candidate.startswith("//")
        or "\\" in candidate
        or parsed.scheme
        or parsed.netloc
        or parsed.fragment
        or len(candidate) > 512
    ):
        return "/"
    return candidate


def _normalize_requested_acr(value):
    if value is None:
        return None
    if not isinstance(value, str):
        raise OIDCStateError("requested ACR is invalid")
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > 512:
        raise OIDCStateError("requested ACR is invalid")
    return normalized


def _normalize_state_intent(
    *,
    purpose,
    continuation,
    requested_acr,
    step_up_action,
    step_up_target_hash,
):
    purpose = str(purpose or "")
    if purpose not in _STATE_PURPOSES:
        raise OIDCStateError("OIDC state purpose is invalid")
    continuation = _safe_continuation(continuation)
    requested_acr = _normalize_requested_acr(requested_acr)
    if purpose == "login":
        if step_up_action is not None or step_up_target_hash is not None:
            raise OIDCStateError("login state contains step-up context")
        return purpose, continuation, requested_acr, None, None
    action = str(step_up_action or "")
    target_hash = str(step_up_target_hash or "")
    if not _ACTION_PATTERN.fullmatch(action):
        raise OIDCStateError("step-up action is invalid")
    if not _TARGET_HASH_PATTERN.fullmatch(target_hash):
        raise OIDCStateError("step-up target is invalid")
    return purpose, continuation, requested_acr, action, target_hash


def create_login_state(
    *,
    state,
    nonce,
    session_binding,
    code_verifier,
    purpose="login",
    continuation="/",
    requested_acr=None,
    step_up_action=None,
    step_up_target_hash=None,
    now=None,
    ttl=timedelta(minutes=5),
):
    values = (state, nonce, session_binding, code_verifier)
    if any(not isinstance(value, str) for value in values) or min(
        len(value) for value in values
    ) < 8:
        raise OIDCStateError("OIDC state values are too short")
    if (
        len(state) > 256
        or len(nonce) > 128
        or len(session_binding) > 512
        or len(code_verifier) > 128
    ):
        raise OIDCStateError("OIDC state values are too long")
    (
        purpose,
        continuation,
        requested_acr,
        step_up_action,
        step_up_target_hash,
    ) = _normalize_state_intent(
        purpose=purpose,
        continuation=continuation,
        requested_acr=requested_acr,
        step_up_action=step_up_action,
        step_up_target_hash=step_up_target_hash,
    )
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
            purpose=purpose,
            continuation=continuation,
            requested_acr=requested_acr,
            step_up_action=step_up_action,
            step_up_target_hash=step_up_target_hash,
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
        intent_values = {
            "nonce": row.nonce,
            "code_verifier": row.code_verifier,
            "purpose": row.purpose,
            "continuation": row.continuation,
            "requested_acr": row.requested_acr,
            "step_up_action": row.step_up_action,
            "step_up_target_hash": row.step_up_target_hash,
        }
        expires_at = row.expires_at
        db.session.delete(row)
        db.session.commit()
        if expires_at < now:
            raise OIDCStateError("OIDC login state has expired")
        (
            intent_values["purpose"],
            intent_values["continuation"],
            intent_values["requested_acr"],
            intent_values["step_up_action"],
            intent_values["step_up_target_hash"],
        ) = _normalize_state_intent(
            purpose=intent_values["purpose"],
            continuation=intent_values["continuation"],
            requested_acr=intent_values["requested_acr"],
            step_up_action=intent_values["step_up_action"],
            step_up_target_hash=intent_values["step_up_target_hash"],
        )
        return OIDCLoginIntent(**intent_values)


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


def _configured_values(settings, name):
    if isinstance(settings, Mapping):
        values = settings.get(name, ())
    else:
        values = getattr(settings, name, ())
    if not isinstance(values, (set, frozenset, list, tuple)):
        return frozenset()
    normalized = []
    for value in values:
        if not isinstance(value, str) or not value or len(value) > 256:
            return frozenset()
        normalized.append(value)
    return frozenset(normalized)


def _normalize_assurance_claims(claims):
    if not isinstance(claims, Mapping):
        return None, (), None, False
    acr = claims.get("acr")
    if acr is not None and (
        not isinstance(acr, str)
        or not acr
        or len(acr) > _MAX_ACR_LENGTH
    ):
        return None, (), None, False
    raw_amr = claims.get("amr")
    if raw_amr is None:
        amr = ()
    elif not isinstance(raw_amr, (list, tuple)) or (
        len(raw_amr) > _MAX_AMR_VALUES
    ):
        return acr, (), None, False
    else:
        normalized_amr = []
        for value in raw_amr:
            if (
                not isinstance(value, str)
                or not value
                or len(value) > _MAX_AMR_VALUE_LENGTH
            ):
                return acr, (), None, False
            if value not in normalized_amr:
                normalized_amr.append(value)
        amr = tuple(normalized_amr)
    auth_time = claims.get("auth_time")
    if auth_time is not None and (
        type(auth_time) is not int
        or not 0 < auth_time <= _MAX_AUTH_TIME
    ):
        return acr, amr, None, False
    return acr, amr, auth_time, True


def _claim_level(value, *, mfa_values, phishing_values):
    if value in mfa_values and value in phishing_values:
        return None, True
    if value in phishing_values:
        return AssuranceLevel.PHISHING_RESISTANT, False
    if value in mfa_values:
        return AssuranceLevel.MFA, False
    return AssuranceLevel.BASIC, False


def evaluate_oidc_assurance(claims, settings):
    """Map only bounded, explicitly configured ID Token claims to assurance."""
    acr, amr, auth_time, valid = _normalize_assurance_claims(claims)
    if not valid:
        return OIDCAssurance(
            AssuranceLevel.BASIC,
            acr,
            amr,
            auth_time,
            "malformed_evidence",
        )
    mfa_acr = _configured_values(settings, "OIDC_MFA_ACR_VALUES")
    mfa_amr = _configured_values(settings, "OIDC_MFA_AMR_VALUES")
    phishing_acr = _configured_values(
        settings,
        "OIDC_PHISHING_RESISTANT_ACR_VALUES",
    )
    phishing_amr = _configured_values(
        settings,
        "OIDC_PHISHING_RESISTANT_AMR_VALUES",
    )
    acr_level, acr_conflict = _claim_level(
        acr,
        mfa_values=mfa_acr,
        phishing_values=phishing_acr,
    )
    amr_levels = []
    amr_conflict = False
    for value in amr:
        level, conflict = _claim_level(
            value,
            mfa_values=mfa_amr,
            phishing_values=phishing_amr,
        )
        amr_levels.append(level)
        amr_conflict = amr_conflict or conflict
    if acr_conflict or amr_conflict:
        return OIDCAssurance(
            AssuranceLevel.BASIC,
            acr,
            amr,
            auth_time,
            "conflicting_evidence",
        )
    ranking = {
        AssuranceLevel.BASIC: 0,
        AssuranceLevel.MFA: 1,
        AssuranceLevel.PHISHING_RESISTANT: 2,
    }
    amr_level = max(
        amr_levels or [AssuranceLevel.BASIC],
        key=ranking.get,
    )
    if (
        acr_level is not AssuranceLevel.BASIC
        and amr_level is not AssuranceLevel.BASIC
        and acr_level is not amr_level
    ):
        return OIDCAssurance(
            AssuranceLevel.BASIC,
            acr,
            amr,
            auth_time,
            "conflicting_evidence",
        )
    level = max((acr_level, amr_level), key=ranking.get)
    if level is not AssuranceLevel.BASIC and auth_time is None:
        return OIDCAssurance(
            AssuranceLevel.BASIC,
            acr,
            amr,
            None,
            "missing_auth_time",
        )
    reason = (
        "explicit_match"
        if level is not AssuranceLevel.BASIC
        else "no_configured_match"
    )
    return OIDCAssurance(level, acr, amr, auth_time, reason)
