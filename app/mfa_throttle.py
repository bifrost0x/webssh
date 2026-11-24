"""Persistent backoff for consecutive rejected one-time codes.

A TOTP code accepts three of a million values per attempt, so the request
rate limits alone allow a slow online search. Failed codes are counted per
account in the database, which keeps the count across restarts, workers and
new pending logins. Waiting is exponential but capped and never becomes a
lockout: only someone who already holds the password or a signed-in session
can submit a code, and the account owner can always continue later.
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
# From this many consecutive failures on, every further failure discards the
# pending login, so the next code requires the password step again.
PENDING_DISCARD_FAILURES = 5
_CLAIM_RETRIES = 5


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


def claim_attempt(user_id, *, now=None):
    """Reserve one code check for ``user_id`` and return the failure count.

    The attempt is counted as a failure before the code is checked and
    cleared by :func:`record_success`, so concurrent requests cannot slip
    past the backoff together. Raises :class:`MFAAttemptThrottled` while the
    account has to wait.
    """
    user_id = int(user_id)
    current_time = _now(now)
    for _attempt in range(_CLAIM_RETRIES):
        row = db.session.execute(
            select(User.mfa_failed_attempts, User.mfa_last_failed_at)
            .where(User.id == user_id)
        ).first()
        if row is None:
            raise MFAAttemptThrottled(BACKOFF_BASE_SECONDS, 0)
        failures = int(row.mfa_failed_attempts or 0)
        last_failed_at = row.mfa_last_failed_at
        wait = backoff_seconds(failures)
        if wait and last_failed_at is not None:
            if last_failed_at.tzinfo is not None:
                last_failed_at = as_naive_utc(last_failed_at)
            ready_at = last_failed_at + timedelta(seconds=wait)
            if ready_at > current_time:
                remaining = (ready_at - current_time).total_seconds()
                raise MFAAttemptThrottled(max(1, math.ceil(remaining)), failures)
        result = db.session.execute(
            update(User)
            .where(User.id == user_id)
            .where(User.mfa_failed_attempts == row.mfa_failed_attempts)
            .values(
                mfa_failed_attempts=failures + 1,
                mfa_last_failed_at=current_time,
            )
            .execution_options(synchronize_session=False)
        )
        if result.rowcount == 1:
            db.session.commit()
            return failures + 1
        db.session.rollback()
    raise MFAAttemptThrottled(1, failures)


def record_success(user_id):
    """Clear the consecutive failure count after an accepted code."""
    db.session.execute(
        update(User)
        .where(User.id == int(user_id))
        .where(User.mfa_failed_attempts != 0)
        .values(mfa_failed_attempts=0, mfa_last_failed_at=None)
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
