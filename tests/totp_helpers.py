"""Compute TOTP codes for test clients the way an authenticator app would."""

from datetime import datetime
import time

from app.totp_service import _totp_code


def totp_at(secret, when):
    timestamp = when.timestamp() if isinstance(when, datetime) else when
    return _totp_code(secret, int(timestamp) // 30)


def totp_now(secret):
    return totp_at(secret, time.time())
