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
from .models import AuthenticationSession, StepUpGrant, User, as_naive_utc, db


_GRANT_TTL = timedelta(minutes=5)
_MAX_GRANTS_PER_SESSION = 32
_ACTION_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,95}$")
_MAX_TARGET_BYTES = 1024
_TARGET_DOMAIN = b"webssh-step-up-target-v1\x00"
_grant_lock = Lock()


class StepUpError(RuntimeError):
    """A grant or its requested authorization context is invalid."""


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
    user = db.session.get(User, auth_session.user_id, populate_existing=True)
    now = as_naive_utc(datetime.now(timezone.utc))
    if (
        auth_session.id is None
        or auth_session.expires_at <= now
        or user is None
        or auth_session.auth_generation != int(user.auth_generation or 0)
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
                db.session.get(User, current_user.id, populate_existing=True)
            )
        )
    ):
        raise StepUpError("step-up authorization is invalid")
    return True


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
