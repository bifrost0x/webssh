"""Out-of-band bootstrap for a GitHub-provisioned user's first factor."""

from datetime import datetime, timedelta, timezone
import hashlib
import re
import secrets

from .models import FactorBootstrapToken, TOTPAuthenticator, as_naive_utc, db


FACTOR_BOOTSTRAP_ACTIONS = frozenset({
    'passkey.enroll',
    'totp.enroll',
})
_TOKEN_TTL = timedelta(minutes=10)
_TOKEN_DOMAIN = b'webssh-factor-bootstrap-v1\x00'
_TOKEN_PATTERN = re.compile(r'[A-Za-z0-9_-]{40,128}')


class FactorBootstrapError(RuntimeError):
    """The requested initial-factor bootstrap is not eligible."""


def _token_hash(token):
    return hashlib.sha256(
        _TOKEN_DOMAIN + str(token).encode('utf-8')
    ).hexdigest()


def _normalize_action(action):
    action = str(action or '').strip()
    if action not in FACTOR_BOOTSTRAP_ACTIONS:
        raise FactorBootstrapError('Unsupported factor enrollment action.')
    return action


def user_is_eligible(user, action):
    """Allow only the first durable factor for an active GitHub-only user."""
    try:
        action = _normalize_action(action)
    except FactorBootstrapError:
        return False
    return bool(
        user is not None
        and user.id is not None
        and not user.is_locked
        and not user.mfa_enabled
        and user.is_github_managed
        and user.github_identity is not None
        and user.webauthn_credentials.count() == 0
        and TOTPAuthenticator.query.filter_by(
            user_id=user.id,
            active=True,
        ).count() == 0
        and action in FACTOR_BOOTSTRAP_ACTIONS
    )


def issue_factor_bootstrap(user, action, *, now=None):
    """Issue one short-lived code, replacing all prior codes for the user."""
    action = _normalize_action(action)
    if not user_is_eligible(user, action):
        raise FactorBootstrapError(
            'Only a factorless GitHub-provisioned account is eligible.'
        )
    issued_at = as_naive_utc(now or datetime.now(timezone.utc))
    token = secrets.token_urlsafe(32)
    FactorBootstrapToken.query.filter_by(user_id=user.id).delete(
        synchronize_session=False
    )
    row = FactorBootstrapToken(
        token_hash=_token_hash(token),
        user_id=user.id,
        auth_generation=int(user.auth_generation or 0),
        action=action,
        created_at=issued_at,
        expires_at=issued_at + _TOKEN_TTL,
    )
    db.session.add(row)
    db.session.commit()
    return token, row.expires_at


def has_live_factor_bootstrap(user, action, *, now=None):
    """Return whether this user/action currently has a redeemable code."""
    if not user_is_eligible(user, action):
        return False
    cutoff = as_naive_utc(now or datetime.now(timezone.utc))
    return FactorBootstrapToken.query.filter(
        FactorBootstrapToken.user_id == user.id,
        FactorBootstrapToken.auth_generation
        == int(user.auth_generation or 0),
        FactorBootstrapToken.action == action,
        FactorBootstrapToken.consumed_at.is_(None),
        FactorBootstrapToken.expires_at > cutoff,
    ).first() is not None


def consume_factor_bootstrap(user, action, token, *, now=None):
    """Atomically redeem one code for its exact user and enrollment action."""
    if (
        not isinstance(token, str)
        or _TOKEN_PATTERN.fullmatch(token) is None
        or not user_is_eligible(user, action)
    ):
        return False
    cutoff = as_naive_utc(now or datetime.now(timezone.utc))
    updated = FactorBootstrapToken.query.filter(
        FactorBootstrapToken.token_hash == _token_hash(token),
        FactorBootstrapToken.user_id == user.id,
        FactorBootstrapToken.auth_generation
        == int(user.auth_generation or 0),
        FactorBootstrapToken.action == action,
        FactorBootstrapToken.consumed_at.is_(None),
        FactorBootstrapToken.expires_at > cutoff,
    ).update(
        {FactorBootstrapToken.consumed_at: cutoff},
        synchronize_session=False,
    )
    if updated != 1:
        db.session.rollback()
        return False
    db.session.commit()
    return True
