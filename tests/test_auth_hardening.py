"""TOTP backoff, source and username login limits, and identity unlink revocation."""

from datetime import datetime, timedelta, timezone
import logging
import time
from urllib.parse import urlsplit

import pyotp
import pytest

from tests.step_up_helpers import (
    account_password_step_up_headers,
    mint_account_step_up_headers,
    password_step_up_headers,
)


def _create_user(app, username, *, is_admin=False):
    from app.auth import register_user
    from app.models import db

    with app.app_context():
        user, error = register_user(username, "password123")
        assert error is None
        user.is_admin = is_admin
        db.session.commit()
        return user.id


def _password_login(client, username, *, ip=None):
    return client.post(
        "/login",
        data={"username": username, "password": "password123"},
        environ_base={"REMOTE_ADDR": ip} if ip else {},
    )


@pytest.fixture
def generous_request_limits(monkeypatch):
    """Keep the in-memory request limits out of the way of the backoff tests."""
    import config

    monkeypatch.setattr(config, "RATELIMIT_LOGIN_LIMIT", "1000 per minute")
    monkeypatch.setattr(config, "RATELIMIT_LOGIN_USERNAME_LIMIT", "1000 per minute")
    monkeypatch.setattr(config, "RATELIMIT_REAUTH", "1000 per minute")


def _enroll_totp(app, client, monkeypatch, username):
    import config
    from app.models import SecurityFeatureState, db

    user_id = _create_user(app, username)
    monkeypatch.setattr(config, "TOTP_ENABLED", True)
    with app.app_context():
        db.session.merge(SecurityFeatureState(feature="totp", enabled=True))
        db.session.commit()
    assert _password_login(client, username).status_code == 302
    headers, _verified = account_password_step_up_headers(
        client, "totp.enroll", user_id,
    )
    started = client.post(
        "/api/totp/enroll", json={}, headers=headers,
    ).get_json()
    secret = started["secret"]
    assert client.post("/api/totp/enroll/verify", json={
        "token": started["token"],
        "code": pyotp.TOTP(secret).now(),
        "confirm_enable_mfa": True,
    }).status_code == 200
    client.post("/logout")
    return user_id, secret


def _wrong_code(secret):
    valid = {
        pyotp.TOTP(secret).at(time.time() + offset)
        for offset in (-60, -30, 0, 30, 60)
    }
    return next(
        candidate for candidate in ("000000", "111111", "222222")
        if candidate not in valid
    )


def _failure_state(app, user_id):
    from app.models import User, db

    with app.app_context():
        db.session.expire_all()
        user = db.session.get(User, user_id)
        return int(user.mfa_failed_attempts), user.mfa_last_failed_at


def _set_failure_state(app, user_id, failures, *, seconds_ago):
    from app.models import User, db

    with app.app_context():
        user = db.session.get(User, user_id)
        user.mfa_failed_attempts = failures
        user.mfa_last_failed_at = (
            datetime.now(timezone.utc).replace(tzinfo=None)
            - timedelta(seconds=seconds_ago)
        )
        db.session.commit()


# --- backoff schedule and storage ------------------------------------------


def test_backoff_grows_exponentially_and_is_capped():
    from app.mfa_throttle import backoff_seconds

    assert [backoff_seconds(count) for count in range(11)] == [
        0, 0, 0, 30, 60, 120, 240, 480, 900, 900, 900,
    ]
    assert backoff_seconds(10_000) == 900


def test_claim_counts_before_the_check_and_success_resets(app):
    from app import mfa_throttle

    user_id = _create_user(app, "claim_user")
    start = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    with app.app_context():
        assert [
            mfa_throttle.claim_attempt(user_id, now=start) for _ in range(3)
        ] == [1, 2, 3]
        with pytest.raises(mfa_throttle.MFAAttemptThrottled) as throttled:
            mfa_throttle.claim_attempt(
                user_id, now=start + timedelta(seconds=10),
            )
        assert throttled.value.retry_after == 20
        assert throttled.value.failures == 3
        assert mfa_throttle.claim_attempt(
            user_id, now=start + timedelta(seconds=30),
        ) == 4
        with pytest.raises(mfa_throttle.MFAAttemptThrottled) as throttled:
            mfa_throttle.claim_attempt(
                user_id, now=start + timedelta(seconds=31),
            )
        assert throttled.value.retry_after == 59
        mfa_throttle.record_success(user_id)
        assert mfa_throttle.claim_attempt(
            user_id, now=start + timedelta(seconds=32),
        ) == 1


def test_claim_is_atomic_against_a_concurrent_change(app, monkeypatch):
    """A lost compare-and-set re-reads the count instead of overwriting it."""
    from sqlalchemy import update
    from app import mfa_throttle
    from app.models import User, db

    user_id = _create_user(app, "claim_race_user")
    original_execute = db.session.execute
    raced = []

    def execute(statement, *args, **kwargs):
        if getattr(statement, "is_update", False) and not raced:
            raced.append(True)
            # Another request commits first on its own connection.
            with db.engine.begin() as connection:
                connection.execute(
                    update(User).where(User.id == user_id).values(
                        mfa_failed_attempts=7,
                        mfa_last_failed_at=datetime.now(
                            timezone.utc
                        ).replace(tzinfo=None),
                    )
                )
        return original_execute(statement, *args, **kwargs)

    with app.app_context():
        monkeypatch.setattr(db.session, "execute", execute)
        with pytest.raises(mfa_throttle.MFAAttemptThrottled) as throttled:
            mfa_throttle.claim_attempt(user_id)
        monkeypatch.undo()
    assert throttled.value.failures == 7
    assert _failure_state(app, user_id)[0] == 7


# --- login TOTP ---------------------------------------------------------------


def test_login_totp_failures_back_off_and_success_resets(
    app, client, monkeypatch, caplog, generous_request_limits,
):
    from app.models import User, db

    user_id, secret = _enroll_totp(app, client, monkeypatch, "backoff_login")
    wrong = _wrong_code(secret)
    assert _password_login(client, "backoff_login").status_code == 200

    for expected in (1, 2, 3):
        rejected = client.post("/api/totp/auth/verify", json={"code": wrong})
        assert rejected.status_code == 401
        assert rejected.get_json()["error"] == "TOTP code is invalid"
        assert _failure_state(app, user_id)[0] == expected

    valid = pyotp.TOTP(secret).at(time.time() + 30)
    with caplog.at_level(logging.WARNING, logger="security_audit"):
        throttled = client.post("/api/totp/auth/verify", json={"code": valid})
    assert throttled.status_code == 429
    body = throttled.get_json()
    assert body["code"] == "rate_limited"
    assert 1 <= body["retry_after"] <= 30
    assert throttled.headers["Retry-After"] == str(body["retry_after"])
    assert "Try again in" in body["error"]
    assert _failure_state(app, user_id)[0] == 3
    assert any(
        record.getMessage().startswith("MFA_ATTEMPT_THROTTLED")
        and "flow=login" in record.getMessage()
        for record in caplog.records
    )

    _set_failure_state(app, user_id, 3, seconds_ago=31)
    accepted = client.post("/api/totp/auth/verify", json={"code": valid})
    assert accepted.status_code == 200
    assert _failure_state(app, user_id) == (0, None)
    with app.app_context():
        assert db.session.get(User, user_id).is_locked is False


def test_new_password_step_does_not_reset_the_failure_count(
    app, client, monkeypatch, generous_request_limits,
):
    user_id, secret = _enroll_totp(app, client, monkeypatch, "backoff_renew")
    wrong = _wrong_code(secret)

    for _attempt in range(3):
        assert _password_login(client, "backoff_renew").status_code == 200
        assert client.post(
            "/api/totp/auth/verify", json={"code": wrong},
        ).status_code == 401

    assert _password_login(client, "backoff_renew").status_code == 200
    throttled = client.post(
        "/api/totp/auth/verify",
        json={"code": pyotp.TOTP(secret).at(time.time() + 30)},
    )
    assert throttled.status_code == 429
    assert _failure_state(app, user_id)[0] == 3


def test_pending_login_is_discarded_after_repeated_failures(
    app, client, monkeypatch, caplog, generous_request_limits,
):
    from app.models import PendingAuthentication

    user_id, secret = _enroll_totp(app, client, monkeypatch, "backoff_discard")
    wrong = _wrong_code(secret)
    _set_failure_state(app, user_id, 4, seconds_ago=3600)
    assert _password_login(client, "backoff_discard").status_code == 200

    with caplog.at_level(logging.WARNING, logger="security_audit"):
        discarded = client.post("/api/totp/auth/verify", json={"code": wrong})

    assert discarded.status_code == 401
    assert discarded.get_json()["code"] == "mfa_restart"
    with client.session_transaction() as browser_session:
        assert "_pending_authentication" not in browser_session
    with app.app_context():
        assert PendingAuthentication.query.filter_by(user_id=user_id).count() == 0
    assert any(
        record.getMessage().startswith("MFA_PENDING_LOGIN_DISCARDED")
        for record in caplog.records
    )

    _set_failure_state(app, user_id, 5, seconds_ago=3600)
    retried = client.post(
        "/api/totp/auth/verify",
        json={"code": pyotp.TOTP(secret).at(time.time() + 30)},
    )
    assert retried.status_code == 401
    assert retried.get_json()["error"] == "Pending authentication is invalid"


def test_failures_below_the_discard_threshold_keep_the_pending_login(
    app, client, monkeypatch, generous_request_limits,
):
    user_id, secret = _enroll_totp(app, client, monkeypatch, "backoff_keep")
    _set_failure_state(app, user_id, 3, seconds_ago=3600)
    assert _password_login(client, "backoff_keep").status_code == 200

    rejected = client.post(
        "/api/totp/auth/verify", json={"code": _wrong_code(secret)},
    )

    assert rejected.status_code == 401
    assert rejected.get_json() == {"error": "TOTP code is invalid"}
    with client.session_transaction() as browser_session:
        assert "_pending_authentication" in browser_session


def test_backoff_never_locks_the_account(
    app, client, monkeypatch, generous_request_limits,
):
    from app.models import User, db

    user_id, secret = _enroll_totp(app, client, monkeypatch, "backoff_nolock")
    _set_failure_state(app, user_id, 500, seconds_ago=0)
    assert _password_login(client, "backoff_nolock").status_code == 200
    throttled = client.post(
        "/api/totp/auth/verify",
        json={"code": pyotp.TOTP(secret).at(time.time() + 30)},
    )
    assert throttled.status_code == 429
    assert throttled.get_json()["retry_after"] <= 900

    _set_failure_state(app, user_id, 500, seconds_ago=901)
    accepted = client.post(
        "/api/totp/auth/verify",
        json={"code": pyotp.TOTP(secret).at(time.time() + 30)},
    )
    assert accepted.status_code == 200
    with app.app_context():
        assert db.session.get(User, user_id).is_locked is False
    assert _failure_state(app, user_id)[0] == 0


# --- step-up variants ---------------------------------------------------------


def test_admin_totp_step_up_backs_off_and_resets(
    app, client, monkeypatch, generous_request_limits,
):
    import app.step_up_routes as step_up_routes

    user_id = _create_user(app, "backoff_admin", is_admin=True)
    assert _password_login(client, "backoff_admin").status_code == 302
    monkeypatch.setattr(
        step_up_routes, "_factor_available", lambda name: name == "totp",
    )
    monkeypatch.setattr(
        step_up_routes, "verify_totp", lambda _user_id, code: code == "123456",
    )

    def attempt(code):
        return client.post("/api/step-up/totp", json={
            "action": "settings.update", "target": "global", "code": code,
        })

    assert [attempt("000000").status_code for _ in range(3)] == [403] * 3
    throttled = attempt("123456")
    assert throttled.status_code == 429
    assert throttled.get_json()["code"] == "rate_limited"
    assert throttled.get_json()["retry_after"] >= 1

    _set_failure_state(app, user_id, 3, seconds_ago=31)
    accepted = attempt("123456")
    assert accepted.status_code == 200
    assert accepted.get_json()["grant"]
    assert _failure_state(app, user_id)[0] == 0


def test_account_totp_step_up_backs_off_and_resets(
    app, client, monkeypatch, generous_request_limits,
):
    import config
    import app.account_step_up_routes as routes
    from app.models import SecurityFeatureState, TOTPAuthenticator, User, db

    monkeypatch.setattr(config, "TOTP_ENABLED", True)
    app.extensions["security_feature_readiness"]["totp"] = (True, None)
    user_id = _create_user(app, "backoff_account")
    assert _password_login(client, "backoff_account").status_code == 302
    with app.app_context():
        user = db.session.get(User, user_id)
        user.mfa_enabled = True
        db.session.add(SecurityFeatureState(feature="totp", enabled=True))
        db.session.add(TOTPAuthenticator(
            user_id=user_id,
            encrypted_secret=b"encrypted-test-secret",
            active=True,
        ))
        db.session.commit()
    monkeypatch.setattr(
        routes, "verify_totp", lambda _user_id, code: code == "123456",
    )

    started = client.post("/api/account/step-up/intents", json={
        "action": "recovery.rotate", "target": user_id,
    })
    assert started.status_code == 200
    intent = started.get_json()["intent"]

    def attempt(code):
        return client.post("/api/account/step-up/totp", json={
            "intent": intent, "code": code,
        })

    assert [attempt("000000").status_code for _ in range(3)] == [403] * 3
    throttled = attempt("123456")
    assert throttled.status_code == 429
    assert throttled.get_json()["code"] == "rate_limited"
    assert throttled.headers["Retry-After"] == str(
        throttled.get_json()["retry_after"]
    )

    _set_failure_state(app, user_id, 3, seconds_ago=31)
    accepted = attempt("123456")
    assert accepted.status_code == 200
    assert accepted.get_json()["method"] == "totp"
    assert _failure_state(app, user_id)[0] == 0


def test_step_up_failures_count_toward_login_backoff(
    app, client, monkeypatch, generous_request_limits,
):
    """One counter per account: switching flows does not buy more guesses."""
    import app.step_up_routes as step_up_routes

    user_id = _create_user(app, "backoff_shared", is_admin=True)
    assert _password_login(client, "backoff_shared").status_code == 302
    monkeypatch.setattr(
        step_up_routes, "_factor_available", lambda name: name == "totp",
    )
    monkeypatch.setattr(step_up_routes, "verify_totp", lambda *_args: False)
    for _attempt in range(3):
        client.post("/api/step-up/totp", json={
            "action": "settings.update", "target": "global", "code": "000000",
        })
    assert _failure_state(app, user_id)[0] == 3


# --- source address and username limits --------------------------------------


@pytest.mark.parametrize(("address", "bucket"), [
    ("192.0.2.7", "192.0.2.7"),
    ("::ffff:192.0.2.7", "192.0.2.7"),
    ("2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64"),
    ("2001:db8:1:2::1", "2001:db8:1:2::/64"),
    ("2001:db8:1:3::1", "2001:db8:1:3::/64"),
    ("fe80::1%eth0", "fe80::/64"),
    ("unknown", "unknown"),
    ("7:192.0.2.7", "7:192.0.2.7"),
])
def test_rate_limit_address_buckets_ipv6_per_64(address, bucket):
    from app.auth import rate_limit_address

    assert rate_limit_address(address) == bucket


def test_rotating_ipv6_addresses_in_one_64_share_the_login_limit(
    app, client, monkeypatch,
):
    import config

    monkeypatch.setattr(config, "RATELIMIT_LOGIN_LIMIT", "5 per minute")
    monkeypatch.setattr(config, "RATELIMIT_LOGIN_USERNAME_LIMIT", "1000 per minute")

    statuses = []
    for index in range(1, 8):
        response = client.post(
            "/login",
            data={"username": f"ghost{index}", "password": "wrong-password"},
            environ_base={"REMOTE_ADDR": f"2001:db8:aa:bb::{index:x}"},
        )
        statuses.append(
            "Too many login attempts" in response.get_data(as_text=True)
        )
    other_prefix = client.post(
        "/login",
        data={"username": "ghost-other", "password": "wrong-password"},
        environ_base={"REMOTE_ADDR": "2001:db8:aa:bc::1"},
    )

    assert statuses == [False] * 5 + [True] * 2
    assert "Too many login attempts" not in other_prefix.get_data(as_text=True)


def test_distinct_ipv4_addresses_keep_separate_login_limits(
    app, client, monkeypatch,
):
    import config

    monkeypatch.setattr(config, "RATELIMIT_LOGIN_LIMIT", "2 per minute")
    monkeypatch.setattr(config, "RATELIMIT_LOGIN_USERNAME_LIMIT", "1000 per minute")

    def limited(address, username):
        response = client.post(
            "/login",
            data={"username": username, "password": "wrong-password"},
            environ_base={"REMOTE_ADDR": address},
        )
        return "Too many login attempts" in response.get_data(as_text=True)

    assert [limited("198.51.100.1", "a1") for _ in range(3)] == [False, False, True]
    assert limited("198.51.100.2", "a2") is False
    # An IPv4-mapped IPv6 source shares the IPv4 bucket.
    assert limited("::ffff:198.51.100.1", "a3") is True


def test_username_limit_applies_across_addresses_without_revealing_accounts(
    app, client, monkeypatch, caplog,
):
    import config

    _create_user(app, "existing_target")
    monkeypatch.setattr(config, "RATELIMIT_LOGIN_LIMIT", "1000 per minute")
    monkeypatch.setattr(config, "RATELIMIT_LOGIN_USERNAME_LIMIT", "3 per minute")

    def attempts(username):
        bodies = []
        for index in range(4):
            response = client.post(
                "/login",
                data={"username": username, "password": "wrong-password"},
                environ_base={"REMOTE_ADDR": f"203.0.113.{index + 1}"},
            )
            bodies.append((
                response.status_code,
                "Too many login attempts" in response.get_data(as_text=True),
            ))
        return bodies

    with caplog.at_level(logging.WARNING, logger="security_audit"):
        existing = attempts("existing_target")
    missing = attempts("missing_target")

    assert existing == missing == [(200, False)] * 3 + [(200, True)]
    assert any(
        "endpoint=login_username" in record.getMessage()
        for record in caplog.records
    )


def test_username_limit_normalizes_case_and_whitespace(app, client, monkeypatch):
    import config

    monkeypatch.setattr(config, "RATELIMIT_LOGIN_LIMIT", "1000 per minute")
    monkeypatch.setattr(config, "RATELIMIT_LOGIN_USERNAME_LIMIT", "2 per minute")

    results = []
    for index, name in enumerate(("Casey", "casey", " CASEY ")):
        response = client.post(
            "/login",
            data={"username": name, "password": "wrong-password"},
            environ_base={"REMOTE_ADDR": f"203.0.113.{index + 50}"},
        )
        results.append("Too many login attempts" in response.get_data(as_text=True))

    assert results == [False, False, True]


def test_username_limit_does_not_block_other_usernames(app, client, monkeypatch):
    import config

    _create_user(app, "unaffected_user")
    monkeypatch.setattr(config, "RATELIMIT_LOGIN_LIMIT", "1000 per minute")
    monkeypatch.setattr(config, "RATELIMIT_LOGIN_USERNAME_LIMIT", "1 per minute")
    client.post(
        "/login",
        data={"username": "noisy_name", "password": "wrong-password"},
        environ_base={"REMOTE_ADDR": "203.0.113.90"},
    )

    response = _password_login(client, "unaffected_user", ip="203.0.113.90")

    assert response.status_code == 302


def test_ldap_login_is_limited_per_username(app, client, monkeypatch):
    import config
    from app.ldap_service import LDAPLookupRejected
    from tests.test_ldap_auth import _enable_ldap_blueprint

    calls = []

    class _Directory:
        def lookup(self, username):
            calls.append(username)
            raise LDAPLookupRejected("not found")

    _enable_ldap_blueprint(app, monkeypatch, _Directory())
    monkeypatch.setattr(config, "LDAP_LOGIN_RATE_LIMIT", "1000 per minute")
    monkeypatch.setattr(config, "RATELIMIT_LOGIN_USERNAME_LIMIT", "2 per minute")

    statuses = [
        client.post(
            "/login/ldap",
            data={"username": "Directory_User", "password": "secret-value"},
            environ_base={"REMOTE_ADDR": f"203.0.113.{index + 100}"},
        ).status_code
        for index in range(3)
    ]

    assert statuses[2] == 429
    assert statuses[:2] != [429, 429]
    assert len(calls) == 2


# --- identity unlink revocation ----------------------------------------------


@pytest.fixture
def browsers(app, monkeypatch):
    """Return a factory for clients that each behave like a separate browser."""
    from flask.testing import FlaskClient

    class BrowserClient(FlaskClient):
        def open(self, *args, **kwargs):
            with app.app_context():
                return super().open(*args, **kwargs)

    monkeypatch.setattr(app, "test_client_class", BrowserClient)
    return app.test_client


def _signed_in_client(app, username):
    other = app.test_client()
    assert _password_login(other, username).status_code == 302
    return other


def _is_signed_out(test_client):
    response = test_client.get("/")
    return (
        response.status_code == 302
        and urlsplit(response.headers["Location"]).path == "/login"
    )


def test_oidc_unlink_revokes_the_target_sessions(app, browsers, monkeypatch):
    import config
    import app.user_lifecycle as user_lifecycle
    from app.models import AuthenticationSession, OIDCIdentity, User, db

    client = browsers()
    _create_user(app, "oidc_unlink_admin", is_admin=True)
    target_id = _create_user(app, "oidc_unlink_target")
    target_client = _signed_in_client(app, "oidc_unlink_target")
    assert _password_login(client, "oidc_unlink_admin").status_code == 302
    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    revoked = []
    monkeypatch.setattr(
        user_lifecycle, "revoke_user_access",
        lambda user_id, *_args, **_kwargs: revoked.append(user_id),
    )
    with app.app_context():
        identity = OIDCIdentity(
            user_id=target_id,
            issuer="https://issuer.example",
            subject="revoked-subject",
        )
        db.session.add(identity)
        db.session.commit()
        identity_id = identity.id
        generation_before = db.session.get(User, target_id).auth_generation

    headers = password_step_up_headers(
        client, "oidc.unlink", f"{target_id}:{identity_id}",
    )[0]
    removed = client.delete(
        f"/admin/api/users/{target_id}/oidc-identities/{identity_id}",
        json={"confirm_username": "oidc_unlink_target"},
        headers=headers,
    )

    assert removed.status_code == 200
    assert revoked == [target_id]
    with app.app_context():
        assert db.session.get(OIDCIdentity, identity_id) is None
        assert db.session.get(User, target_id).auth_generation == (
            generation_before + 1
        )
        assert AuthenticationSession.query.filter_by(
            user_id=target_id
        ).count() == 0
    assert _is_signed_out(target_client)
    assert not _is_signed_out(client)


def test_admin_unlinking_own_oidc_identity_keeps_the_current_browser(
    app, browsers, monkeypatch,
):
    import config
    import app.user_lifecycle as user_lifecycle
    from app.models import OIDCIdentity, db

    client = browsers()
    admin_id = _create_user(app, "oidc_self_admin", is_admin=True)
    other_browser = _signed_in_client(app, "oidc_self_admin")
    assert _password_login(client, "oidc_self_admin").status_code == 302
    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    monkeypatch.setattr(user_lifecycle, "revoke_user_access", lambda *_a, **_k: None)
    with app.app_context():
        identity = OIDCIdentity(
            user_id=admin_id,
            issuer="https://issuer.example",
            subject="self-subject",
        )
        db.session.add(identity)
        db.session.commit()
        identity_id = identity.id

    removed = client.delete(
        f"/admin/api/users/{admin_id}/oidc-identities/{identity_id}",
        json={"confirm_username": "oidc_self_admin"},
        headers=password_step_up_headers(
            client, "oidc.unlink", f"{admin_id}:{identity_id}",
        )[0],
    )

    assert removed.status_code == 200
    assert _is_signed_out(other_browser)
    assert not _is_signed_out(client)


def test_github_unlink_revokes_other_sessions_and_keeps_this_browser(
    app, browsers, monkeypatch,
):
    import app.user_lifecycle as user_lifecycle
    from app.models import GitHubIdentity, User, db
    from tests.test_github_auth_routes import _configure

    client = browsers()
    admin_id = _create_user(app, "github_unlink_admin", is_admin=True)
    user_id = _create_user(app, "github_unlink_user")
    _configure(app, admin_id)
    with app.app_context():
        db.session.add(GitHubIdentity(
            user_id=user_id, github_user_id="626262", login="unlink-user",
        ))
        db.session.commit()
        generation_before = db.session.get(User, user_id).auth_generation
    other_browser = _signed_in_client(app, "github_unlink_user")
    assert _password_login(client, "github_unlink_user").status_code == 302
    revoked = []
    monkeypatch.setattr(
        user_lifecycle, "revoke_user_access",
        lambda revoked_id, *_args, **_kwargs: revoked.append(revoked_id),
    )

    headers = mint_account_step_up_headers(app, client, "github.unlink", user_id)
    response = client.delete("/api/account/github", headers=headers)

    assert response.status_code == 200
    assert revoked == [user_id]
    with app.app_context():
        assert GitHubIdentity.query.filter_by(user_id=user_id).count() == 0
        assert db.session.get(User, user_id).auth_generation == (
            generation_before + 1
        )
    assert _is_signed_out(other_browser)
    assert client.get("/api/account/github").status_code == 200
