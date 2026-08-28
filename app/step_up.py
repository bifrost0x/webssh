"""Short-lived, action-bound administrator authorization grants."""

from datetime import datetime, timedelta, timezone
from functools import wraps
import hashlib
import re
import secrets
from threading import Lock

from flask import jsonify, request
from flask_login import current_user
from sqlalchemy import delete

import config

from .auth_assurance import (
    AssuranceLevel,
    current_authentication_session,
)
from .models import (
    AuthenticationSession,
    StepUpGrant,
    StepUpIntent,
    User,
    as_naive_utc,
    db,
)


_GRANT_TTL = timedelta(minutes=5)
_INTENT_TTL = timedelta(minutes=5)
_MAX_GRANTS_PER_SESSION = 32
_MAX_ACCOUNT_INTENTS_PER_SESSION = 8
_ACTION_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,95}$")
_METHOD_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,23}$")
_MAX_TARGET_BYTES = 1024
_TARGET_DOMAIN = b"webssh-step-up-target-v1\x00"
_grant_lock = Lock()
_intent_lock = Lock()

ACCOUNT_STEP_UP_ACTIONS = frozenset({
    "passkey.enroll",
    "passkey.delete",
    "mfa.enable",
    "totp.enroll",
    "totp.delete",
    "mfa.disable",
    "recovery.rotate",
    "github.link",
    "github.unlink",
})


class StepUpError(RuntimeError):
    """A grant or its requested authorization context is invalid."""


class SecurityUIUpgradeRequired(StepUpError):
    """A cached client attempted the removed inline reauthentication flow."""


def normalize_action(value):
    action = str(value or "").strip()
    if not _ACTION_PATTERN.fullmatch(action):
        raise StepUpError("step-up authorization is invalid")
    return action


def hash_step_up_target(value):
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        raise StepUpError("step-up authorization is invalid")
    target = str(value)
    encoded = target.encode("utf-8")
    if not encoded or len(encoded) > _MAX_TARGET_BYTES:
        raise StepUpError("step-up authorization is invalid")
    return hashlib.sha256(_TARGET_DOMAIN + encoded).hexdigest()


def _token_hash(value):
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _assurance_rank(value):
    try:
        assurance = AssuranceLevel(value)
    except ValueError as exc:
        raise StepUpError("step-up authorization is invalid") from exc
    return {
        AssuranceLevel.BASIC: 0,
        AssuranceLevel.MFA: 1,
        AssuranceLevel.PHISHING_RESISTANT: 2,
    }[assurance]


def required_assurance_for_user(user):
    return AssuranceLevel.MFA if user.mfa_enabled else AssuranceLevel.BASIC


def _valid_authentication_session(auth_session, now):
    if not isinstance(auth_session, AuthenticationSession):
        return None
    user = db.session.get(User, auth_session.user_id, populate_existing=True)
    if (
        auth_session.id is None
        or auth_session.expires_at <= now
        or user is None
        or auth_session.auth_generation != int(user.auth_generation or 0)
    ):
        return None
    return user


def create_account_step_up_intent(auth_session, action, target):
    """Create one opaque, persistent intent for a permitted account action."""
    action = normalize_action(action)
    if action not in ACCOUNT_STEP_UP_ACTIONS:
        raise StepUpError("step-up authorization is invalid")
    target_hash = hash_step_up_target(target)
    now = as_naive_utc(datetime.now(timezone.utc))
    user = _valid_authentication_session(auth_session, now)
    if user is None:
        raise StepUpError("step-up authorization is invalid")
    required_assurance = required_assurance_for_user(user)
    token = secrets.token_urlsafe(32)
    with _intent_lock:
        StepUpIntent.query.filter(
            StepUpIntent.expires_at <= now
        ).delete(synchronize_session=False)
        live_count = StepUpIntent.query.filter(
            StepUpIntent.authentication_session_id == auth_session.id,
            StepUpIntent.scope == "account",
            StepUpIntent.status.in_(("pending", "approved")),
            StepUpIntent.expires_at > now,
        ).count()
        if live_count >= _MAX_ACCOUNT_INTENTS_PER_SESSION:
            db.session.rollback()
            raise StepUpError("step-up authorization is invalid")
        intent = StepUpIntent(
            token_hash=_token_hash(token),
            authentication_session_id=auth_session.id,
            user_id=user.id,
            scope="account",
            action=action,
            target_hash=target_hash,
            required_assurance=required_assurance.value,
            status="pending",
            created_at=now,
            expires_at=now + _INTENT_TTL,
        )
        db.session.add(intent)
        db.session.commit()
    return token, intent


def _bound_account_intent(token, auth_session, *, status):
    if not isinstance(token, str) or not token or len(token) > 256:
        raise StepUpError("step-up authorization is invalid")
    now = as_naive_utc(datetime.now(timezone.utc))
    user = _valid_authentication_session(auth_session, now)
    if user is None:
        raise StepUpError("step-up authorization is invalid")
    intent = StepUpIntent.query.filter_by(
        token_hash=_token_hash(token),
        authentication_session_id=auth_session.id,
        user_id=user.id,
        scope="account",
        status=status,
    ).first()
    if (
        intent is None
        or intent.expires_at <= now
        or intent.action not in ACCOUNT_STEP_UP_ACTIONS
        or intent.required_assurance != required_assurance_for_user(user).value
    ):
        raise StepUpError("step-up authorization is invalid")
    return intent, user, now


def account_step_up_intent(token, auth_session, *, status="pending"):
    """Return one valid account intent in the explicitly requested state."""
    if status not in {"pending", "approved"}:
        raise StepUpError("step-up authorization is invalid")
    intent, _user, _now = _bound_account_intent(
        token, auth_session, status=status
    )
    return intent


def account_step_up_status(token, auth_session):
    """Return a valid bound intent state without issuing a grant."""
    if not isinstance(token, str) or not token or len(token) > 256:
        raise StepUpError("step-up authorization is invalid")
    now = as_naive_utc(datetime.now(timezone.utc))
    user = _valid_authentication_session(auth_session, now)
    if user is None:
        raise StepUpError("step-up authorization is invalid")
    intent = StepUpIntent.query.filter_by(
        token_hash=_token_hash(token),
        authentication_session_id=auth_session.id,
        user_id=user.id,
        scope="account",
    ).first()
    if (
        intent is None
        or intent.expires_at <= now
        or intent.action not in ACCOUNT_STEP_UP_ACTIONS
        or intent.required_assurance != required_assurance_for_user(user).value
    ):
        raise StepUpError("step-up authorization is invalid")
    return intent.status


def _approve_bound_account_intent(intent, assurance, method, now):
    if _assurance_rank(assurance) < _assurance_rank(
        intent.required_assurance
    ):
        raise StepUpError("step-up authorization is invalid")
    intent.status = "approved"
    intent.approved_assurance = assurance.value
    intent.approved_method = method
    intent.approved_at = now
    db.session.commit()
    return intent


def approve_account_step_up_intent(
    token,
    auth_session,
    *,
    assurance,
    method,
):
    """Persist verified evidence without ever persisting the evidence itself."""
    try:
        assurance = AssuranceLevel(assurance)
    except ValueError as exc:
        raise StepUpError("step-up authorization is invalid") from exc
    method = str(method or "").strip().lower()
    if not _METHOD_PATTERN.fullmatch(method):
        raise StepUpError("step-up authorization is invalid")
    with _intent_lock:
        intent, _user, now = _bound_account_intent(
            token, auth_session, status="pending"
        )
        return _approve_bound_account_intent(
            intent, assurance, method, now
        )


def approve_account_step_up_intent_by_id(
    intent_id,
    auth_session,
    *,
    assurance,
    method,
):
    """Approve a provider callback using only its server-owned intent id."""
    if not isinstance(intent_id, int) or isinstance(intent_id, bool):
        raise StepUpError("step-up authorization is invalid")
    try:
        assurance = AssuranceLevel(assurance)
    except ValueError as exc:
        raise StepUpError("step-up authorization is invalid") from exc
    method = str(method or "").strip().lower()
    if not _METHOD_PATTERN.fullmatch(method):
        raise StepUpError("step-up authorization is invalid")
    with _intent_lock:
        now = as_naive_utc(datetime.now(timezone.utc))
        user = _valid_authentication_session(auth_session, now)
        if user is None:
            raise StepUpError("step-up authorization is invalid")
        intent = StepUpIntent.query.filter_by(
            id=intent_id,
            authentication_session_id=auth_session.id,
            user_id=user.id,
            scope="account",
            status="pending",
        ).first()
        if (
            intent is None
            or intent.expires_at <= now
            or intent.action not in ACCOUNT_STEP_UP_ACTIONS
            or intent.required_assurance
            != required_assurance_for_user(user).value
        ):
            raise StepUpError("step-up authorization is invalid")
        return _approve_bound_account_intent(
            intent, assurance, method, now
        )


def claim_account_step_up_grant(token, auth_session):
    """Atomically complete an approved intent and issue its sole raw grant."""
    with _intent_lock, _grant_lock:
        intent, user, now = _bound_account_intent(
            token, auth_session, status="approved"
        )
        if (
            intent.approved_assurance is None
            or _assurance_rank(intent.approved_assurance)
            < _assurance_rank(intent.required_assurance)
        ):
            raise StepUpError("step-up authorization is invalid")
        live_rows = (
            StepUpGrant.query
            .filter_by(authentication_session_id=auth_session.id)
            .order_by(StepUpGrant.created_at.desc(), StepUpGrant.id.desc())
            .all()
        )
        for stale in live_rows[_MAX_GRANTS_PER_SESSION - 1:]:
            db.session.delete(stale)
        grant = secrets.token_urlsafe(32)
        db.session.add(StepUpGrant(
            token_hash=_token_hash(grant),
            authentication_session_id=auth_session.id,
            action=intent.action,
            target_hash=intent.target_hash,
            assurance=intent.approved_assurance,
            created_at=now,
            expires_at=now + _GRANT_TTL,
        ))
        intent.status = "completed"
        intent.completed_at = now
        if auth_session.auth_generation != int(user.auth_generation or 0):
            db.session.rollback()
            raise StepUpError("step-up authorization is invalid")
        db.session.commit()
    return grant


def create_step_up_grant(auth_session, action, target, assurance):
    return create_step_up_grant_for_hash(
        auth_session,
        action,
        hash_step_up_target(target),
        assurance,
    )


def create_step_up_grant_for_hash(
    auth_session,
    action,
    target_hash,
    assurance,
):
    """Create an opaque grant after authentication evidence was verified."""
    if not isinstance(auth_session, AuthenticationSession):
        raise StepUpError("step-up authorization is invalid")
    action = normalize_action(action)
    if not re.fullmatch(r"[0-9a-f]{64}", str(target_hash or "")):
        raise StepUpError("step-up authorization is invalid")
    try:
        assurance = AssuranceLevel(assurance)
    except ValueError as exc:
        raise StepUpError("step-up authorization is invalid") from exc
    now = as_naive_utc(datetime.now(timezone.utc))
    user = _valid_authentication_session(auth_session, now)
    if (
        user is None
        or _assurance_rank(assurance) < _assurance_rank(
            required_assurance_for_user(user)
        )
    ):
        raise StepUpError("step-up authorization is invalid")
    token = secrets.token_urlsafe(32)
    with _grant_lock:
        StepUpGrant.query.filter(
            StepUpGrant.expires_at <= now
        ).delete(synchronize_session=False)
        live_rows = (
            StepUpGrant.query
            .filter_by(authentication_session_id=auth_session.id)
            .order_by(StepUpGrant.created_at.desc(), StepUpGrant.id.desc())
            .all()
        )
        for stale in live_rows[_MAX_GRANTS_PER_SESSION - 1:]:
            db.session.delete(stale)
        db.session.add(StepUpGrant(
            token_hash=_token_hash(token),
            authentication_session_id=auth_session.id,
            action=action,
            target_hash=str(target_hash),
            assurance=assurance.value,
            created_at=now,
            expires_at=now + _GRANT_TTL,
        ))
        db.session.commit()
    return token


def consume_step_up_grant(token, auth_session, action, target):
    """Consume first, then validate every binding using one generic failure."""
    if not isinstance(token, str) or not token or len(token) > 256:
        raise StepUpError("step-up authorization is invalid")
    try:
        action = normalize_action(action)
        target_hash = hash_step_up_target(target)
    except StepUpError:
        action = ""
        target_hash = ""
    now = as_naive_utc(datetime.now(timezone.utc))
    with _grant_lock:
        statement = (
            delete(StepUpGrant)
            .where(StepUpGrant.token_hash == _token_hash(token))
            .returning(*StepUpGrant.__table__.c)
            .execution_options(synchronize_session=False)
        )
        row = db.session.execute(statement).mappings().one_or_none()
        if row is None:
            db.session.rollback()
            raise StepUpError("step-up authorization is invalid")
        db.session.commit()
    if (
        auth_session is None
        or row["authentication_session_id"] != auth_session.id
        or row["action"] != action
        or row["target_hash"] != target_hash
        or row["expires_at"] <= now
        or _assurance_rank(row["assurance"]) < _assurance_rank(
            required_assurance_for_user(
                db.session.get(
                    User, auth_session.user_id, populate_existing=True
                )
            )
        )
    ):
        raise StepUpError("step-up authorization is invalid")
    return True


def consume_account_step_up_grant(action, target):
    """Consume the exact account grant supplied by a current browser request."""
    action = normalize_action(action)
    if action not in ACCOUNT_STEP_UP_ACTIONS:
        raise StepUpError("step-up authorization is invalid")
    token = request.headers.get("X-WebSSH-Step-Up", "")
    if not token:
        raise SecurityUIUpgradeRequired(
            "security interface upgrade is required"
        )
    return consume_step_up_grant(
        token,
        current_authentication_session(),
        action,
        target,
    )


def step_up_required(action, target):
    """Require one exact X-WebSSH-Step-Up grant for a mutating route."""
    normalized_action = normalize_action(action)

    def decorator(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            resolved_target = target(*args, **kwargs) if callable(target) else target
            try:
                consume_step_up_grant(
                    request.headers.get("X-WebSSH-Step-Up", ""),
                    current_authentication_session(),
                    normalized_action,
                    resolved_target,
                )
            except StepUpError:
                return jsonify({
                    "error": "Additional authentication is required",
                    "code": "step_up_required",
                }), 403
            return function(*args, **kwargs)
        return wrapped
    return decorator


def recent_strong_assurance(auth_session):
    """Return fresh MFA/PR evidence, or None when a new ceremony is needed."""
    if auth_session is None or auth_session.strong_authenticated_at is None:
        return None
    now = as_naive_utc(datetime.now(timezone.utc))
    age = (now - auth_session.strong_authenticated_at).total_seconds()
    try:
        assurance = AssuranceLevel(auth_session.assurance)
    except ValueError:
        return None
    if (
        0 <= age <= config.STEP_UP_MAX_AGE_SECONDS
        and assurance is not AssuranceLevel.BASIC
    ):
        return assurance
    return None
