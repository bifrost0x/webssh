"""Central pending-authentication and finalized browser-session boundary."""

from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import json
import re
import secrets
from urllib.parse import urlsplit

from flask import current_app, session
from flask_login import current_user, login_user, logout_user
from sqlalchemy import delete

import config

from .audit_logger import log_security_event
from .models import (
    AuthenticationSession,
    PendingAuthentication,
    RecoveryCode,
    TOTPAuthenticator,
    User,
    as_naive_utc,
    db,
)
from .session_epoch import current_epoch
from .totp_service import disable_totp_mfa


_PENDING_TTL = timedelta(minutes=5)
_MAX_PENDING_PER_USER = 5
_MAX_EVIDENCE_BYTES = 4096
_MAX_METHODS = 8
_METHOD_PATTERN = re.compile(r'[a-z][a-z0-9_-]{0,23}')


class AssuranceLevel(str, Enum):
    BASIC = 'BASIC'
    MFA = 'MFA'
    PHISHING_RESISTANT = 'PHISHING_RESISTANT'


class PendingAuthenticationError(RuntimeError):
    """A pending authentication token is invalid, expired, or already used."""


class AuthenticationFinalizationError(RuntimeError):
    """A verified authentication could not be finalized safely."""


def _digest(value):
    return hashlib.sha256(str(value).encode('utf-8')).hexdigest()


def _normalize_assurance(value):
    try:
        return AssuranceLevel(value).value
    except ValueError as exc:
        raise ValueError('unsupported assurance level') from exc


def _safe_continuation(value):
    candidate = str(value or '/')
    if len(candidate) > 512 or '\\' in candidate or any(
        ord(character) < 0x20 for character in candidate
    ):
        return '/'
    parsed = urlsplit(candidate)
    if (
        parsed.scheme
        or parsed.netloc
        or parsed.fragment
        or not parsed.path.startswith('/')
        or parsed.path.startswith('//')
    ):
        return '/'
    return candidate


def _evidence_json(user, evidence):
    if evidence is None:
        payload = {}
    elif isinstance(evidence, dict):
        payload = dict(evidence)
    else:
        raise TypeError('evidence must be a dictionary')
    if any(str(key).startswith('_') for key in payload):
        raise ValueError('reserved evidence key')
    sensitive_suffixes = ('password', 'secret', 'token', 'code')
    if any(
        str(key).strip().lower().endswith(sensitive_suffixes)
        for key in payload
    ):
        raise ValueError('sensitive authentication evidence is not permitted')
    payload['_auth_generation'] = int(user.auth_generation or 0)
    try:
        serialized = json.dumps(
            payload,
            separators=(',', ':'),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError('evidence is not JSON serializable') from exc
    if len(serialized.encode('utf-8')) > _MAX_EVIDENCE_BYTES:
        raise ValueError('evidence exceeds the size limit')
    return serialized


def browser_session_binding():
    """Return a random binding stored only in the signed Flask session."""
    binding = session.get('_auth_binding')
    if not isinstance(binding, str) or len(binding) < 32 or len(binding) > 256:
        binding = secrets.token_urlsafe(32)
        session['_auth_binding'] = binding
    return binding


def begin_authentication(
    user,
    primary_method,
    *,
    assurance,
    session_binding,
    remember,
    continuation,
    evidence=None,
    recovery_required=False,
):
    """Create one bounded, opaque pending-authentication transaction."""
    if not isinstance(user, User) or user.id is None:
        raise TypeError('user must be persistent')
    method = str(primary_method or '').strip().lower()
    if not _METHOD_PATTERN.fullmatch(method):
        raise ValueError('invalid primary authentication method')
    binding = str(session_binding or '')
    if not binding or len(binding) > 512:
        raise ValueError('invalid browser session binding')
    if type(remember) is not bool:
        raise TypeError('remember must be a boolean')
    if type(recovery_required) is not bool:
        raise TypeError('recovery_required must be a boolean')

    now = as_naive_utc(datetime.now(timezone.utc))
    PendingAuthentication.query.filter(
        PendingAuthentication.expires_at <= now
    ).delete(synchronize_session=False)
    live_rows = (
        PendingAuthentication.query
        .filter_by(user_id=user.id)
        .order_by(PendingAuthentication.created_at.desc())
        .all()
    )
    for stale in live_rows[_MAX_PENDING_PER_USER - 1:]:
        db.session.delete(stale)

    token = secrets.token_urlsafe(32)
    db.session.add(PendingAuthentication(
        token_hash=_digest(token),
        user_id=user.id,
        primary_method=method,
        assurance=_normalize_assurance(assurance),
        evidence_json=_evidence_json(user, evidence),
        session_binding_hash=_digest(binding),
        remember=remember,
        continuation=_safe_continuation(continuation),
        recovery_required=recovery_required,
        created_at=now,
        expires_at=now + _PENDING_TTL,
    ))
    db.session.commit()
    return token


def consume_pending(token, session_binding):
    """Atomically consume a pending token bound to the same browser session."""
    token_value = str(token or '')
    binding_value = str(session_binding or '')
    if not token_value or not binding_value:
        raise PendingAuthenticationError('pending authentication is invalid')
    now = as_naive_utc(datetime.now(timezone.utc))
    statement = (
        delete(PendingAuthentication)
        .where(
            PendingAuthentication.token_hash == _digest(token_value),
            PendingAuthentication.session_binding_hash
            == _digest(binding_value),
            PendingAuthentication.expires_at > now,
        )
        .returning(*PendingAuthentication.__table__.c)
        .execution_options(synchronize_session=False)
    )
    row = db.session.execute(statement).mappings().one_or_none()
    if row is None:
        db.session.rollback()
        raise PendingAuthenticationError('pending authentication is invalid')
    db.session.commit()
    pending = PendingAuthentication(**dict(row))
    pending._consumed_for_finalization = True
    return pending


def pending_authentication(token, session_binding):
    """Return a valid bound pending transaction without consuming it."""
    token_value = str(token or '')
    binding_value = str(session_binding or '')
    if not token_value or not binding_value:
        raise PendingAuthenticationError('pending authentication is invalid')
    now = as_naive_utc(datetime.now(timezone.utc))
    pending = PendingAuthentication.query.filter_by(
        token_hash=_digest(token_value),
        session_binding_hash=_digest(binding_value),
    ).first()
    if pending is None or pending.expires_at <= now:
        raise PendingAuthenticationError('pending authentication is invalid')
    return pending


def _normalize_methods(methods, primary_method):
    if not isinstance(methods, (list, tuple)):
        raise TypeError('methods must be a list or tuple')
    normalized = []
    for value in methods:
        method = str(value or '').strip().lower()
        if not _METHOD_PATTERN.fullmatch(method):
            raise ValueError('invalid authentication method')
        if method not in normalized:
            normalized.append(method)
    if (
        not normalized
        or len(normalized) > _MAX_METHODS
        or primary_method not in normalized
    ):
        raise ValueError('authentication methods do not match the primary method')
    return normalized


def _session_lifetime(remember):
    key = 'REMEMBER_COOKIE_DURATION' if remember else (
        'PERMANENT_SESSION_LIFETIME'
    )
    value = current_app.config.get(key, timedelta(minutes=30))
    if isinstance(value, timedelta):
        return value
    return timedelta(seconds=max(1, int(value)))


def clear_browser_authentication():
    """Clear browser auth state while preserving remember-cookie removal."""
    logout_user()
    clear_remember_cookie = session.get('_remember') == 'clear'
    session.clear()
    if clear_remember_cookie:
        session['_remember'] = 'clear'


def finalize_login(pending, *, methods, strong_authenticated_at=None):
    """Create the sole authenticated browser-session record."""
    if not isinstance(pending, PendingAuthentication):
        raise TypeError('pending must be a consumed authentication')
    if (
        not getattr(pending, '_consumed_for_finalization', False)
        or getattr(pending, '_finalized', False)
        or db.session.get(PendingAuthentication, pending.id) is not None
    ):
        raise AuthenticationFinalizationError(
            'pending authentication was not consumed exactly once'
        )
    try:
        evidence = json.loads(pending.evidence_json or '{}')
        expected_generation = int(evidence['_auth_generation'])
        assurance = AssuranceLevel(pending.assurance)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise AuthenticationFinalizationError(
            'pending authentication evidence is invalid'
        ) from exc

    user = db.session.get(User, pending.user_id)
    if (
        user is None
        or user.is_locked
        or (user.is_admin and user.is_ldap_managed)
        or int(user.auth_generation or 0) != expected_generation
    ):
        raise AuthenticationFinalizationError('account is no longer eligible')
    normalized_methods = _normalize_methods(
        methods,
        pending.primary_method,
    )
    now = as_naive_utc(datetime.now(timezone.utc))
    if strong_authenticated_at is not None:
        strong_authenticated_at = as_naive_utc(strong_authenticated_at)
    elif assurance is not AssuranceLevel.BASIC:
        strong_authenticated_at = now

    opaque_session_id = secrets.token_urlsafe(32)
    row = AuthenticationSession(
        session_hash=_digest(opaque_session_id),
        user_id=user.id,
        assurance=assurance.value,
        methods_json=json.dumps(normalized_methods, separators=(',', ':')),
        authenticated_at=now,
        strong_authenticated_at=strong_authenticated_at,
        auth_generation=int(user.auth_generation or 0),
        expires_at=now + _session_lifetime(bool(pending.remember)),
    )

    session.clear()
    login_user(user, remember=bool(pending.remember))
    session['_user_id'] = (
        f'{user.id}:{int(user.auth_generation or 0)}:{opaque_session_id}'
    )
    session['_auth_session'] = opaque_session_id
    session['_auth_epoch'] = current_epoch()
    if pending.primary_method == 'ldap':
        verified_at = evidence.get('verified_at')
        if type(verified_at) is int and verified_at > 0:
            session['_ldap_verified_at'] = verified_at

    db.session.add(row)
    user.last_login = now
    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        clear_browser_authentication()
        raise AuthenticationFinalizationError(
            'authentication session could not be stored'
        ) from exc

    log_security_event(
        'AUTHENTICATION_SUCCESS',
        user=user.username,
        primary_method=pending.primary_method,
        assurance=assurance.value,
        methods=','.join(normalized_methods),
    )
    pending._finalized = True
    return row


def finalize_pending_with_factor(
    token,
    session_binding,
    *,
    user_id,
    factor,
    assurance,
):
    """Consume a bound primary login and finish it with one verified factor."""
    pending = consume_pending(token, session_binding)
    if pending.user_id != int(user_id):
        raise PendingAuthenticationError('pending authentication is invalid')
    upgraded = AssuranceLevel(assurance)
    current = AssuranceLevel(pending.assurance)
    ranking = {
        AssuranceLevel.BASIC: 0,
        AssuranceLevel.MFA: 1,
        AssuranceLevel.PHISHING_RESISTANT: 2,
    }
    if ranking[upgraded] < ranking[current]:
        raise AuthenticationFinalizationError(
            'authentication assurance cannot be downgraded'
        )
    pending.assurance = upgraded.value
    continuation = pending.continuation
    row = finalize_login(
        pending,
        methods=[pending.primary_method, factor],
    )
    return row, continuation


def authentication_session_for_token(token, user_id, auth_generation):
    """Validate an auth-session token embedded in a signed login identifier."""
    if not isinstance(token, str) or not token:
        return None
    row = AuthenticationSession.query.filter_by(
        session_hash=_digest(token)
    ).first()
    if row is None:
        return None
    now = as_naive_utc(datetime.now(timezone.utc))
    if (
        row.expires_at <= now
        or row.user_id != int(user_id)
        or row.auth_generation != int(auth_generation)
    ):
        return None
    return row


def current_authentication_session():
    """Return the valid server-side row for the current browser login."""
    if not current_user.is_authenticated:
        return None
    opaque_session_id = session.get('_auth_session')
    if not isinstance(opaque_session_id, str) or not opaque_session_id:
        return None
    row = AuthenticationSession.query.filter_by(
        session_hash=_digest(opaque_session_id)
    ).first()
    if row is None:
        return None
    now = as_naive_utc(datetime.now(timezone.utc))
    if row.expires_at <= now:
        db.session.delete(row)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
        return None
    if (
        row.user_id != current_user.id
        or row.auth_generation != int(current_user.auth_generation or 0)
    ):
        return None
    return row


def delete_current_authentication_session():
    opaque_session_id = session.get('_auth_session')
    if not isinstance(opaque_session_id, str) or not opaque_session_id:
        return False
    deleted = AuthenticationSession.query.filter_by(
        session_hash=_digest(opaque_session_id)
    ).delete(synchronize_session=False)
    db.session.commit()
    return bool(deleted)


def authentication_methods(row):
    """Return bounded methods from one trusted AuthenticationSession row."""
    if row is None:
        return ()
    try:
        values = json.loads(row.methods_json or "[]")
    except (TypeError, json.JSONDecodeError):
        return ()
    if not isinstance(values, list) or len(values) > _MAX_METHODS:
        return ()
    methods = []
    for value in values:
        method = str(value or "").strip().lower()
        if not _METHOD_PATTERN.fullmatch(method) or method in methods:
            return ()
        methods.append(method)
    return tuple(methods)


def recovery_session_required(row=None):
    """Return whether the current server-side login still needs factor repair."""
    row = current_authentication_session() if row is None else row
    return "recovery_code" in authentication_methods(row)


def recovery_route_allowed(path, method):
    """Allow only factor repair and logout during a Recovery session."""
    path = str(path or "")
    method = str(method or "GET").upper()
    if path == "/security" or path == "/logout" or path.startswith("/static/"):
        return True
    if path in {
        "/api/webauthn/register/options",
        "/api/webauthn/register/verify",
    }:
        return method == "POST"
    if path == "/api/webauthn/credentials":
        return method == "GET"
    if path == "/api/account/security-state":
        return method == "GET"
    if path in {"/api/totp/enroll", "/api/totp/enroll/verify"}:
        return method == "POST"
    if path == "/api/totp/authenticators":
        return method == "GET"
    if path in {"/api/totp/disable", "/api/auth/mfa/disable"}:
        return method == "POST"
    return False


def clear_recovery_restriction(*, replacement_factor=None, disable_mfa=False):
    """Atomically release a Recovery session after repair or explicit disable."""
    if type(disable_mfa) is not bool:
        raise TypeError("disable_mfa must be a boolean")
    row = current_authentication_session()
    methods = list(authentication_methods(row))
    if row is None or "recovery_code" not in methods:
        return False
    methods.remove("recovery_code")
    if replacement_factor is not None:
        factor = str(replacement_factor or "").strip().lower()
        if not _METHOD_PATTERN.fullmatch(factor):
            raise ValueError("invalid replacement factor")
        if factor not in methods:
            methods.append(factor)
    if not methods:
        raise AuthenticationFinalizationError("authentication methods are invalid")
    row.methods_json = json.dumps(methods, separators=(",", ":"))
    user = db.session.get(User, row.user_id)
    if user is None:
        raise AuthenticationFinalizationError("account is no longer eligible")
    if disable_mfa:
        disable_totp_mfa(user)
        row.assurance = AssuranceLevel.BASIC.value
    db.session.commit()
    log_security_event(
        "RECOVERY_RESTRICTION_CLEARED",
        user=user.username,
        replacement_factor=replacement_factor,
    )
    return True


def available_mfa_methods(user):
    """Return enrolled factors that are both deployed and admin-active."""
    from .security_features import feature_is_active

    methods = []
    if feature_is_active('passkey') and user.webauthn_credentials.count():
        methods.append('passkey')
    if feature_is_active('totp') and TOTPAuthenticator.query.filter_by(
        user_id=user.id,
        active=True,
    ).first() is not None:
        methods.append('totp')
    if feature_is_active('recovery') and RecoveryCode.query.filter_by(
        user_id=user.id,
    ).first() is not None:
        methods.append('recovery')
    return tuple(methods)
