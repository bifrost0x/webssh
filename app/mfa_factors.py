"""Shared invariants for account MFA factor mutations."""

from contextlib import contextmanager
from threading import RLock

from .models import TOTPAuthenticator, WebAuthnCredential
from .security_features import feature_is_active


_factor_mutation_lock = RLock()


@contextmanager
def factor_mutation():
    """Serialize durable-factor removal checks within this process."""
    with _factor_mutation_lock:
        yield


def durable_factor_counts(
    user_id,
    *,
    excluding_passkey_id=None,
    excluding_totp_id=None,
):
    """Count currently usable durable factors after optional exclusions."""
    passkey_count = 0
    if feature_is_active("passkey"):
        query = WebAuthnCredential.query.filter_by(user_id=int(user_id))
        if excluding_passkey_id is not None:
            query = query.filter(WebAuthnCredential.id != int(excluding_passkey_id))
        passkey_count = query.count()

    totp_count = 0
    if feature_is_active("totp"):
        query = TOTPAuthenticator.query.filter_by(
            user_id=int(user_id),
            active=True,
        )
        if excluding_totp_id is not None:
            query = query.filter(TOTPAuthenticator.id != int(excluding_totp_id))
        totp_count = query.count()

    return {
        "passkey_count": passkey_count,
        "totp_count": totp_count,
        "total": passkey_count + totp_count,
    }


def account_security_state(user):
    """Return the public factor state used by the Security Center."""
    counts = durable_factor_counts(user.id)
    return {
        "mfa_enabled": bool(user.mfa_enabled),
        **counts,
        "can_enable_mfa": (
            not user.mfa_enabled
            and counts["passkey_count"] > 0
            and feature_is_active("recovery")
        ),
        "can_disable_mfa": bool(user.mfa_enabled),
    }
