"""Limits for password sign-in per source network and per account.

The source limit alone does not stop guessing from many addresses, for
example rotating IPv6 addresses. Each account name therefore also has a
budget for browsers that never signed in to it. A browser that did gets a
signed cookie and is exempt from that budget, so an attacker who exhausts it
cannot lock the owner out of the devices they already use.
"""

import hashlib
import hmac
import unicodedata

from flask import current_app, request
from itsdangerous import BadSignature, URLSafeTimedSerializer

import config
from .audit_logger import log_rate_limit_exceeded
from .auth import check_rate_limit

_DEVICE_SALT = 'webssh.sign-in-device'
_DEVICE_MAX_AGE_SECONDS = 90 * 24 * 3600
_DEVICE_MAX_ACCOUNTS = 8


def _device_cookie_name():
    return f'{config.SESSION_COOKIE_NAME}_device'


def _serializer():
    return URLSafeTimedSerializer(current_app.secret_key, salt=_DEVICE_SALT)


def _account_tag(source, username):
    """Keyed digest of an account name; raw names never reach the limiter."""
    name = unicodedata.normalize('NFKC', str(username or '').strip()).casefold()
    key = hashlib.sha256(
        f'{_DEVICE_SALT}:{current_app.secret_key}'.encode('utf-8', 'surrogatepass')
    ).digest()
    message = f'{source}\0{name}'.encode('utf-8', 'surrogatepass')
    return hmac.new(key, message, hashlib.sha256).hexdigest()[:32]


def _known_tags():
    raw = request.cookies.get(_device_cookie_name())
    if not raw:
        return []
    try:
        tags = _serializer().loads(raw, max_age=_DEVICE_MAX_AGE_SECONDS)
    except BadSignature:
        return []
    if not isinstance(tags, list):
        return []
    return [tag for tag in tags if isinstance(tag, str)][:_DEVICE_MAX_ACCOUNTS]


def sign_in_throttled(endpoint, source, username, source_limit):
    """Return True when this password attempt must be refused unchecked.

    Unknown and existing names are counted alike, so the answer does not
    reveal whether an account exists.
    """
    if not config.RATELIMIT_ENABLED:
        return False
    client_ip = request.remote_addr or 'unknown'
    if check_rate_limit(client_ip, endpoint, source_limit):
        log_rate_limit_exceeded(endpoint, client_ip)
        return True
    tag = _account_tag(source, username)
    if tag in _known_tags():
        return False
    if check_rate_limit(tag, f'{endpoint}_account', config.RATELIMIT_LOGIN_ACCOUNT_LIMIT):
        log_rate_limit_exceeded(f'{endpoint}_account', client_ip, user=username)
        return True
    return False


def remember_sign_in_device(response, source, username):
    """Mark this browser as known for ``username`` after a correct password."""
    tag = _account_tag(source, username)
    tags = [tag] + [known for known in _known_tags() if known != tag]
    response.set_cookie(
        _device_cookie_name(),
        _serializer().dumps(tags[:_DEVICE_MAX_ACCOUNTS]),
        max_age=_DEVICE_MAX_AGE_SECONDS,
        path=getattr(config, 'APPLICATION_ROOT', '') or '/',
        secure=config.SESSION_COOKIE_SECURE,
        httponly=True,
        samesite='Lax',
    )
    return response
