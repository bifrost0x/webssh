"""Persistent backoff for consecutive rejected one-time codes.

A TOTP code accepts three of a million values per attempt, so the request
rate limits alone allow a slow online search. Failed codes are counted per
account in the database, which keeps the count across restarts, workers and
new pending logins.

Two counters are kept apart on purpose. Sign-in codes come from whoever holds
the password; step-up codes come from an already signed-in session. Failures
in one never delay the other, so a password holder cannot block step-up in
the owner's existing sessions and a stolen session cannot block the owner's
fresh sign-in.

The wait grows exponentially up to a cap and the count decays: every full
``QUIET_PERIOD_SECONDS`` since the last failure halves it, so the backoff never
turns into a lockout, while pausing between guesses does not buy back the
free attempts at once. Proving possession another
way (Recovery Code, passkey) or replacing the factors clears both counters.
The remaining trade-off is
that someone who holds the password can keep delaying new TOTP sign-ins by
submitting wrong codes; Recovery Codes and passkeys stay available, and a
password change from an existing session is not affected.
"""

import math
from datetime import datetime, timedelta, timezone

from flask import jsonify
from sqlalchemy import select, update

from .models import User, as_naive_utc, db

# Consecutive failures that are answered without any wait.
FREE_ATTEMPTS = 3
BACKOFF_BASE_SECONDS = 30
BACKOFF_MAX_SECONDS = 15 * 60
# Each full period without a failure halves the count.
QUIET_PERIOD_SECONDS = 2 * BACKOFF_MAX_SECONDS
# From this many consecutive failures on, every further failure discards the
# pending login, so the next code requires the password step again.
PENDING_DISCARD_FAILURES = 5
_CLAIM_RETRIES = 5

LOGIN = "login"
STEP_UP = "step_up"
_COLUMNS = {
    LOGIN: (User.mfa_failed_attempts, User.mfa_last_failed_at),
    STEP_UP: (
        User.mfa_step_up_failed_attempts,
        User.mfa_step_up_last_failed_at,
    ),
}


class MFAAttemptThrottled(Exception):
    """The account must wait before another code is checked."""

    def __init__(self, retry_after, failures):
        super().__init__("one-time code attempts are throttled")
        self.retry_after = int(retry_after)
        self.failures = int(failures)


def backoff_seconds(failures):
    """Return the wait required after ``failures`` consecutive rejections."""
    failures = max(0, int(failures or 0))
    if failures < FREE_ATTEMPTS:
        return 0
    exponent = min(failures - FREE_ATTEMPTS, 16)
    return min(BACKOFF_BASE_SECONDS * (2 ** exponent), BACKOFF_MAX_SECONDS)


def _now(now=None):
    value = now or datetime.now(timezone.utc)
    return as_naive_utc(value)


def _columns(scope):
    try:
        return _COLUMNS[scope]
    except KeyError:
        raise ValueError(f"unknown one-time code scope: {scope!r}") from None


def claim_attempt(user_id, *, scope=LOGIN, now=None):
    """Reserve one code check for ``user_id`` and return the failure count.

    The attempt is counted as a failure before the code is checked and
    cleared by :func:`record_success`, so concurrent requests cannot slip
    past the backoff together. Raises :class:`MFAAttemptThrottled` while the
    account has to wait.

    The claim is committed on its own, so it must not run while the shared
    session holds unrelated pending changes; it raises ``RuntimeError``
    instead of committing or rolling them back.
    """
    if db.session.new or db.session.dirty or db.session.deleted:
        raise RuntimeError(
            "claim_attempt requires a session without pending changes"
        )
    count_column, failed_at_column = _columns(scope)
    user_id = int(user_id)
    current_time = _now(now)
    failures = 0
    for _attempt in range(_CLAIM_RETRIES):
        row = db.session.execute(
            select(count_column, failed_at_column).where(User.id == user_id)
        ).first()
        if row is None:
            raise MFAAttemptThrottled(BACKOFF_BASE_SECONDS, 0)
        stored_failures, last_failed_at = row[0], row[1]
        failures = int(stored_failures or 0)
        if last_failed_at is not None:
            last_failed_at = as_naive_utc(last_failed_at)
            quiet = (current_time - last_failed_at).total_seconds()
            quiet_periods = int(max(0.0, quiet) // QUIET_PERIOD_SECONDS)
            if quiet_periods:
                # The quiet period exceeds the longest wait, so a decayed
                # count never has to wait for its own backoff.
                failures >>= min(quiet_periods, 64)
            else:
                wait = backoff_seconds(failures)
                ready_at = last_failed_at + timedelta(seconds=wait)
                if wait and ready_at > current_time:
                    remaining = (ready_at - current_time).total_seconds()
                    raise MFAAttemptThrottled(
                        max(1, math.ceil(remaining)), failures,
                    )
        # Compare against the stored value, not the decayed one, so a
        # concurrent claim still makes this update miss and re-read.
        result = db.session.execute(
            update(User)
            .where(User.id == user_id)
            .where(count_column == stored_failures)
            .values({
                count_column: failures + 1,
                failed_at_column: current_time,
            })
            .execution_options(synchronize_session=False)
        )
        if result.rowcount == 1:
            db.session.commit()
            return failures + 1
        db.session.rollback()
    raise MFAAttemptThrottled(1, failures)


def record_success(user_id, *, scope=LOGIN):
    """Clear the consecutive failure count after an accepted code."""
    count_column, failed_at_column = _columns(scope)
    db.session.execute(
        update(User)
        .where(User.id == int(user_id))
        .where(count_column != 0)
        .values({count_column: 0, failed_at_column: None})
        .execution_options(synchronize_session=False)
    )
    db.session.commit()


def clear_all_uncommitted(user):
    """Clear both counters on ``user`` as part of the caller's transaction.

    Used when the owner proved possession another way or the factor set was
    replaced, so earlier rejections no longer describe the current factors.
    """
    user.mfa_failed_attempts = 0
    user.mfa_last_failed_at = None
    user.mfa_step_up_failed_attempts = 0
    user.mfa_step_up_last_failed_at = None


def reset_all(user_id):
    """Clear both counters after the owner authenticated with another factor."""
    db.session.execute(
        update(User)
        .where(User.id == int(user_id))
        .where(
            (User.mfa_failed_attempts != 0)
            | (User.mfa_step_up_failed_attempts != 0)
        )
        .values(
            mfa_failed_attempts=0,
            mfa_last_failed_at=None,
            mfa_step_up_failed_attempts=0,
            mfa_step_up_last_failed_at=None,
        )
        .execution_options(synchronize_session=False)
    )
    db.session.commit()


def pending_should_be_discarded(failures):
    return int(failures) >= PENDING_DISCARD_FAILURES


def throttled_response(exc):
    """Build the 429 answer shared by login and step-up code checks."""
    retry_after = max(1, int(exc.retry_after))
    if retry_after >= 60:
        minutes = math.ceil(retry_after / 60)
        message = (
            f"Too many attempts. Try again in {minutes} "
            f"minute{'s' if minutes != 1 else ''}."
        )
    else:
        message = (
            f"Too many attempts. Try again in {retry_after} "
            f"second{'s' if retry_after != 1 else ''}."
        )
    response = jsonify({
        "error": message,
        "code": "rate_limited",
        "retry_after": retry_after,
    })
    response.status_code = 429
    response.headers["Retry-After"] = str(retry_after)
    return response
