"""Known-device cookies for password sign-in.

After a successful password step the browser receives a signed cookie that
names the account and the submitted username. A later request that presents
a valid cookie for the same username skips the global per-username ceiling,
so a sender spread over many sources cannot keep the owner out of a browser
that signed in before. Per-source limits still apply.

The cookie is bound to the account's ``auth_generation``; a password change,
reset, lock or MFA reset therefore invalidates every issued
cookie. Failures presented with one cookie spend that cookie's own small
budget, after which it no longer grants the exemption, so a stolen cookie
cannot be used for unlimited guessing.
"""

import hashlib
import secrets
from datetime import timedelta

from flask import after_this_request, current_app, request
from itsdangerous import BadData, URLSafeTimedSerializer

from .models import User, db

MAX_AGE = timedelta(days=90)
# Failed attempts one cookie may present before it stops being trusted.
FAILURE_BUDGET = 5
FAILURE_WINDOW_SECONDS = 3600
_SALT = "webssh-login-device"


def cookie_name():
    return f"{current_app.config['SESSION_COOKIE_NAME']}_device"


def _serializer():
    return URLSafeTimedSerializer(current_app.secret_key, salt=_SALT)


def _username_digest(username):
    normalized = str(username or "").strip().casefold()
    return hashlib.sha256(
        normalized.encode("utf-8", "surrogatepass")
    ).hexdigest()


def trusted_device(username):
    """Return the device nonce when this request presents a valid cookie.

    The cookie must be well signed, younger than ``MAX_AGE``, issued for the
    submitted username, and still match the account's authentication
    generation. Anything else is treated as no cookie at all.
    """
    raw_value = request.cookies.get(cookie_name())
    if not raw_value or not str(username or "").strip():
        return None
    try:
        payload = _serializer().loads(
            raw_value, max_age=int(MAX_AGE.total_seconds()),
        )
    except BadData:
        return None
    if not isinstance(payload, dict):
        return None
    nonce = payload.get("n")
    user_id = payload.get("i")
    generation = payload.get("g")
    if (
        not isinstance(nonce, str)
        or type(user_id) is not int
        or type(generation) is not int
        or payload.get("u") != _username_digest(username)
    ):
        return None
    user = db.session.get(User, user_id)
    if (
        user is None
        or user.is_locked
        or int(user.auth_generation or 0) != generation
    ):
        return None
    return nonce


def failure_budget_key(endpoint, nonce):
    return f"{endpoint}:device:{nonce}"


def remember_device(user, username):
    """Issue a fresh cookie with the response of a successful password step."""
    value = _serializer().dumps({
        "u": _username_digest(username),
        "i": int(user.id),
        "g": int(user.auth_generation or 0),
        "n": secrets.token_urlsafe(16),
    })
    app = current_app._get_current_object()

    @after_this_request
    def _set_cookie(response):
        response.set_cookie(
            cookie_name(),
            value,
            max_age=int(MAX_AGE.total_seconds()),
            path=app.session_interface.get_cookie_path(app),
            secure=bool(app.config.get("SESSION_COOKIE_SECURE")),
            httponly=True,
            samesite="Lax",
        )
        return response
