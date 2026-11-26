"""Flask session cookies issued by the real login route and signer.

Cookie format (Flask 3.1.3 flask/sessions.py SecureCookieSessionInterface,
itsdangerous 2.2.0 url_safe.py, timed.py, signer.py):

    [.]base64url(payload) "." base64url(int_to_bytes(unix_ts)) "." base64url(sig)

* payload: TaggedJSONSerializer (flask/json/tag.py), compact JSON; zlib
  compressed and prefixed with "." when that is shorter.
* key: HMAC-SHA1(SECRET_KEY, b"cookie-session") (key_derivation "hmac").
* sig: HMAC-SHA1(key, payload_part "." timestamp_part).
* max age on load: PERMANENT_SESSION_LIFETIME (8 h, config.py), independent
  of session.permanent. The app then checks _auth_epoch against the
  session_epoch file and _auth_session against authentication_sessions.
"""

import datetime as dt

USER_AGENT = 'golden-fixture-browser/1'
ENVIRON = {'REMOTE_ADDR': '127.0.0.1'}


def _client(application):
    client = application.test_client()
    client.environ_base.update(ENVIRON)
    client.environ_base['HTTP_USER_AGENT'] = USER_AGENT
    return client


def login_cookie(application, username, password):
    """Log in through POST /login and return the session cookie value."""
    import config
    from . import runtime

    from app.models import db

    # A fresh app context keeps Flask-Login's per-context user cache (g) and
    # the ORM session of the caller out of the request.
    with application.app_context():
        client = _client(application)
        response = runtime.password_login(client, username, password)
    db.session.expire_all()
    if response.status_code != 302:
        raise RuntimeError(f'login for {username} failed: {response.status_code}')
    cookie = client.get_cookie(config.SESSION_COOKIE_NAME)
    if cookie is None:
        raise RuntimeError('login did not set a session cookie')
    device = client.get_cookie(config.SESSION_COOKIE_NAME + '_device')
    LAST_DEVICE_COOKIE[username] = None if device is None else device.value
    return cookie.value


# The login also sets the "<session>_device" cookie (app/login_devices.py).
LAST_DEVICE_COOKIE = {}


def serializer(application):
    return application.session_interface.get_signing_serializer(application)


def decode(application, value):
    """Payload without verification (itsdangerous loads_unsafe)."""
    ok, payload = serializer(application).loads_unsafe(value)
    return payload


def timestamp_of(value):
    from itsdangerous.encoding import base64_decode, bytes_to_int
    return bytes_to_int(base64_decode(value.rsplit('.', 2)[-2]))


def resign_at(application, value, clock, moment):
    """Same payload, signed by the app's serializer at another instant."""
    payload = decode(application, value)
    saved = clock.now
    clock.set(moment)
    try:
        return serializer(application).dumps(payload)
    finally:
        clock.set(saved)


def tamper_signature(value):
    head, signature = value.rsplit('.', 1)
    flipped = ('A' if signature[0] != 'A' else 'B') + signature[1:]
    return f'{head}.{flipped}'


def tamper_payload(application, value, *, user_id_prefix):
    """Swap the account id in _user_id, keep timestamp and signature."""
    s = serializer(application)
    payload = decode(application, value)
    _, generation, opaque = payload['_user_id'].split(':', 2)
    payload['_user_id'] = f'{user_id_prefix}:{generation}:{opaque}'
    encoded = s.dump_payload(payload).decode('ascii')
    _, timestamp, signature = value.rsplit('.', 2)
    return f'{encoded}.{timestamp}.{signature}'


def foreign_key(application, value):
    """Valid structure, signed with a different secret key."""
    from itsdangerous import URLSafeTimedSerializer
    interface = application.session_interface
    other = URLSafeTimedSerializer(
        'golden-foreign-secret-key-not-the-fixture-key',
        salt=interface.salt, serializer=interface.serializer,
        signer_kwargs={'key_derivation': interface.key_derivation,
                       'digest_method': interface.digest_method},
    )
    return other.dumps(decode(application, value))


def describe(application, name, value, expectation, note):
    return {
        'name': name,
        'value': value,
        'issued_at_unix': timestamp_of(value),
        'issued_at': dt.datetime.fromtimestamp(
            timestamp_of(value), dt.timezone.utc).isoformat(),
        'compressed': value.startswith('.'),
        'decoded_payload': decode(application, value),
        'expected': expectation,
        'note': note,
    }
