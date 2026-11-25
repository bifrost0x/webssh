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


def _set_username_limits(*, per_source=None, global_limit=None):
    """Store the Admin sign-in protection limits in the test's settings file."""
    from app import app_settings

    values = {}
    if per_source is not None:
        values["login_username_limit"] = per_source
        if global_limit is None:
            # The ceiling across sources may not be lower than the per-source
            # limit; keep the stored ceiling unless the new limit exceeds it.
            current = app_settings.sign_in_protection()["login_username_global_limit"]
            values["login_username_global_limit"] = max(current, per_source)
    if global_limit is not None:
        values["login_username_global_limit"] = global_limit
    assert app_settings.set_sign_in_protection(values)


@pytest.fixture
def generous_request_limits(app, monkeypatch):
    """Keep the in-memory request limits out of the way of the backoff tests."""
    import config

    monkeypatch.setattr(config, "RATELIMIT_LOGIN_LIMIT", "1000 per minute")
    _set_username_limits(per_source=1000, global_limit=1000)
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


_SCOPE_COLUMNS = {
    "login": ("mfa_failed_attempts", "mfa_last_failed_at"),
    "step_up": ("mfa_step_up_failed_attempts", "mfa_step_up_last_failed_at"),
}


def _failure_state(app, user_id, scope="login"):
    from app.models import User, db

    count, failed_at = _SCOPE_COLUMNS[scope]
    with app.app_context():
        db.session.expire_all()
        user = db.session.get(User, user_id)
        return int(getattr(user, count)), getattr(user, failed_at)


def _set_failure_state(app, user_id, failures, *, seconds_ago, scope="login"):
    from app.models import User, db

    count, failed_at = _SCOPE_COLUMNS[scope]
    with app.app_context():
        user = db.session.get(User, user_id)
        setattr(user, count, failures)
        setattr(user, failed_at, (
            datetime.now(timezone.utc).replace(tzinfo=None)
            - timedelta(seconds=seconds_ago)
        ))
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
    _set_failure_state(app, user_id, 4, seconds_ago=120)
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

    _set_failure_state(app, user_id, 5, seconds_ago=300)
    retried = client.post(
        "/api/totp/auth/verify",
        json={"code": pyotp.TOTP(secret).at(time.time() + 30)},
    )
    assert retried.status_code == 401
    assert retried.get_json()["error"] == "Pending authentication is invalid"


def test_discarded_login_prefills_the_username_once_without_a_url(
    app, client, monkeypatch, generous_request_limits,
):
    user_id, secret = _enroll_totp(app, client, monkeypatch, "prefill_restart")
    _set_failure_state(app, user_id, 4, seconds_ago=120)
    assert _password_login(client, "prefill_restart").status_code == 200

    discarded = client.post("/api/totp/auth/verify", json={"code": _wrong_code(secret)})
    assert discarded.get_json()["code"] == "mfa_restart"
    assert "prefill_restart" not in str(discarded.get_json())

    page = client.get("/login")
    html = page.get_data(as_text=True)
    assert page.status_code == 200
    assert 'id="username" name="username"' in html
    assert 'value="prefill_restart"' in html
    assert 'alert-login_username' not in html
    assert 'data-i18n="auth.mfaRestart"' in html
    assert 'value="prefill_restart"' not in client.get("/login").get_data(as_text=True)


def test_failures_below_the_discard_threshold_keep_the_pending_login(
    app, client, monkeypatch, generous_request_limits,
):
    user_id, secret = _enroll_totp(app, client, monkeypatch, "backoff_keep")
    _set_failure_state(app, user_id, 3, seconds_ago=60)
    assert _password_login(client, "backoff_keep").status_code == 200

    rejected = client.post(
        "/api/totp/auth/verify", json={"code": _wrong_code(secret)},
    )

    assert rejected.status_code == 401
    assert rejected.get_json() == {"error": "TOTP code is invalid", "code": "invalid_code"}
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

    _set_failure_state(app, user_id, 3, seconds_ago=31, scope="step_up")
    accepted = attempt("123456")
    assert accepted.status_code == 200
    assert accepted.get_json()["grant"]
    assert _failure_state(app, user_id, "step_up")[0] == 0


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

    _set_failure_state(app, user_id, 3, seconds_ago=31, scope="step_up")
    accepted = attempt("123456")
    assert accepted.status_code == 200
    assert accepted.get_json()["method"] == "totp"
    assert _failure_state(app, user_id, "step_up")[0] == 0


def test_step_up_failures_do_not_delay_a_fresh_login(
    app, client, monkeypatch, generous_request_limits,
):
    """A stolen session guessing at step-up must not block the owner's sign-in."""
    import app.step_up_routes as step_up_routes
    from app.models import TOTPAuthenticator, User, db

    user_id, secret = _enroll_totp(app, client, monkeypatch, "split_step_up")
    with app.app_context():
        db.session.get(User, user_id).is_admin = True
        db.session.commit()
    monkeypatch.setattr(
        step_up_routes, "_factor_available", lambda name: name == "totp",
    )
    monkeypatch.setattr(step_up_routes, "verify_totp", lambda *_args: False)
    stolen = client
    assert _password_login(stolen, "split_step_up").status_code == 200
    assert stolen.post("/api/totp/auth/verify", json={
        "code": pyotp.TOTP(secret).at(time.time() + 30),
    }).status_code == 200
    statuses = [
        stolen.post("/api/step-up/totp", json={
            "action": "settings.update", "target": "global", "code": "000000",
        }).status_code
        for _attempt in range(5)
    ]
    assert statuses == [403, 403, 403, 429, 429]

    stolen.post("/logout")
    with app.app_context():
        # Let the owner reuse the next time step in this test.
        for row in TOTPAuthenticator.query.filter_by(user_id=user_id):
            row.last_accepted_step = None
        db.session.commit()
    assert _password_login(client, "split_step_up").status_code == 200
    accepted = client.post(
        "/api/totp/auth/verify",
        json={"code": pyotp.TOTP(secret).at(time.time() + 30)},
    )

    assert accepted.status_code == 200
    assert _failure_state(app, user_id, "step_up")[0] == 3
    assert _failure_state(app, user_id) == (0, None)


def test_login_failures_do_not_delay_step_up_of_existing_sessions(
    app, client, monkeypatch, generous_request_limits,
):
    """A password holder guessing at sign-in must not block the owner's step-up."""
    import app.step_up_routes as step_up_routes

    user_id = _create_user(app, "split_login", is_admin=True)
    assert _password_login(client, "split_login").status_code == 302
    _set_failure_state(app, user_id, 50, seconds_ago=0)
    monkeypatch.setattr(
        step_up_routes, "_factor_available", lambda name: name == "totp",
    )
    monkeypatch.setattr(
        step_up_routes, "verify_totp", lambda _user_id, code: code == "123456",
    )

    rejected = client.post("/api/step-up/totp", json={
        "action": "settings.update", "target": "global", "code": "000000",
    })
    accepted = client.post("/api/step-up/totp", json={
        "action": "settings.update", "target": "global", "code": "123456",
    })

    assert rejected.status_code == 403
    assert accepted.status_code == 200
    assert _failure_state(app, user_id)[0] == 50
    assert _failure_state(app, user_id, "step_up")[0] == 0


def test_failure_count_decays_after_the_quiet_period(app):
    """One wrong code every cap interval must not keep the account throttled."""
    from app import mfa_throttle

    user_id = _create_user(app, "decay_user")
    start = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    with app.app_context():
        for scope in (mfa_throttle.LOGIN, mfa_throttle.STEP_UP):
            # An attacker who submits one wrong code just as each wait ends.
            moment = start
            for _attempt in range(12):
                failures = mfa_throttle.claim_attempt(
                    user_id, scope=scope, now=moment,
                )
                moment += timedelta(seconds=mfa_throttle.backoff_seconds(failures))
            assert failures == 12
            with pytest.raises(mfa_throttle.MFAAttemptThrottled):
                mfa_throttle.claim_attempt(
                    user_id, scope=scope,
                    now=moment - timedelta(seconds=1),
                )
            last_failure = moment - timedelta(
                seconds=mfa_throttle.backoff_seconds(failures)
            )
            quiet = timedelta(seconds=mfa_throttle.QUIET_PERIOD_SECONDS)
            # Four quiet periods halve twelve failures down to zero.
            assert mfa_throttle.claim_attempt(
                user_id, scope=scope, now=last_failure + 4 * quiet,
            ) == 1


@pytest.mark.parametrize(("stored", "periods", "expected"), [
    (12, 1, 7),
    (12, 2, 4),
    (12, 3, 2),
    (12, 4, 1),
    (5, 1, 3),
    (1, 1, 1),
    (12, 1000, 1),
])
def test_each_quiet_period_halves_the_failure_count(app, stored, periods, expected):
    """A pause halves the count instead of restoring every free attempt."""
    from app import mfa_throttle

    user_id = _create_user(app, f"halve_{stored}_{periods}")
    _set_failure_state(
        app, user_id, stored,
        seconds_ago=periods * mfa_throttle.QUIET_PERIOD_SECONDS + 5,
    )
    with app.app_context():
        assert mfa_throttle.claim_attempt(user_id) == expected
    assert _failure_state(app, user_id)[0] == expected


def test_a_pause_at_the_cap_does_not_restore_the_free_attempts(app):
    """Waiting one quiet period after many failures leaves the backoff on."""
    from app import mfa_throttle

    user_id = _create_user(app, "halve_pause_user")
    start = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    _set_failure_state(app, user_id, 0, seconds_ago=0)
    with app.app_context():
        moment = start
        for _attempt in range(10):
            failures = mfa_throttle.claim_attempt(user_id, now=moment)
            moment += timedelta(seconds=mfa_throttle.backoff_seconds(failures))
        last_failure = moment - timedelta(
            seconds=mfa_throttle.backoff_seconds(failures)
        )
        resumed = last_failure + timedelta(
            seconds=mfa_throttle.QUIET_PERIOD_SECONDS,
        )
        assert mfa_throttle.claim_attempt(user_id, now=resumed) == 6
        with pytest.raises(mfa_throttle.MFAAttemptThrottled) as throttled:
            mfa_throttle.claim_attempt(
                user_id, now=resumed + timedelta(seconds=1),
            )
        assert throttled.value.retry_after == mfa_throttle.backoff_seconds(6) - 1


def test_claim_refuses_a_session_with_pending_changes(app):
    """The claim commits on its own and must not take foreign changes along."""
    from app import mfa_throttle
    from app.models import User, db

    user_id = _create_user(app, "claim_dirty_user")
    with app.app_context():
        user = db.session.get(User, user_id)
        user.is_locked = True
        with pytest.raises(RuntimeError):
            mfa_throttle.claim_attempt(user_id)
        db.session.rollback()
        assert db.session.get(User, user_id).is_locked is False
    assert _failure_state(app, user_id) == (0, None)


def test_decayed_claim_still_loses_a_concurrent_update(app, monkeypatch):
    """The compare-and-set uses the stored count even after decay."""
    from sqlalchemy import update
    from app import mfa_throttle
    from app.models import User, db

    user_id = _create_user(app, "decay_race_user")
    old = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=2)
    _set_failure_state(app, user_id, 9, seconds_ago=7200)
    original_execute = db.session.execute
    raced = []

    def execute(statement, *args, **kwargs):
        if getattr(statement, "is_update", False) and not raced:
            raced.append(True)
            with db.engine.begin() as connection:
                connection.execute(
                    update(User).where(User.id == user_id).values(
                        mfa_failed_attempts=1,
                        mfa_last_failed_at=old + timedelta(hours=2),
                    )
                )
        return original_execute(statement, *args, **kwargs)

    with app.app_context():
        monkeypatch.setattr(db.session, "execute", execute)
        failures = mfa_throttle.claim_attempt(user_id)
        monkeypatch.undo()
    # The concurrent claim's failure is kept instead of being overwritten.
    assert failures == 2
    assert _failure_state(app, user_id)[0] == 2


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
    _set_username_limits(per_source=1000)

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
    _set_username_limits(per_source=1000)

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


def _login_attempts(client, username, addresses, password="wrong-password"):
    results = []
    for address in addresses:
        response = client.post(
            "/login",
            data={"username": username, "password": password},
            environ_base={"REMOTE_ADDR": address},
        )
        results.append((
            response.status_code,
            "Too many login attempts" in response.get_data(as_text=True),
        ))
    return results


def test_username_limit_is_per_source_without_revealing_accounts(
    app, client, monkeypatch, caplog,
):
    import config

    _create_user(app, "existing_target")
    monkeypatch.setattr(config, "RATELIMIT_LOGIN_LIMIT", "1000 per minute")
    _set_username_limits(per_source=3)
    _set_username_limits(global_limit=1000)

    with caplog.at_level(logging.WARNING, logger="security_audit"):
        existing = _login_attempts(client, "existing_target", ["203.0.113.1"] * 4)
    missing = _login_attempts(client, "missing_target", ["203.0.113.1"] * 4)

    assert existing == missing == [(200, False)] * 3 + [(200, True)]
    assert any(
        "endpoint=login_username" in record.getMessage()
        for record in caplog.records
    )


def test_one_source_cannot_lock_a_username_out_for_another_source(
    app, client, monkeypatch,
):
    import config

    _create_user(app, "targeted_admin")
    monkeypatch.setattr(config, "RATELIMIT_LOGIN_LIMIT", "1000 per minute")
    _set_username_limits(per_source=3)
    _set_username_limits(global_limit=1000)
    # Two attacking sources, one IPv4 and one IPv6 /64, exhaust their budgets.
    _login_attempts(client, "targeted_admin", ["198.51.100.7"] * 5)
    _login_attempts(
        client, "targeted_admin",
        [f"2001:db8:66:1::{index}" for index in range(1, 6)],
    )

    owner = _password_login(client, "targeted_admin", ip="203.0.113.44")

    assert owner.status_code == 302


def test_global_username_ceiling_slows_distributed_guessing(
    app, client, monkeypatch,
):
    import config

    _create_user(app, "spread_target")
    monkeypatch.setattr(config, "RATELIMIT_LOGIN_LIMIT", "1000 per minute")
    # Each source sends one attempt per name, so only the ceiling can trip.
    _set_username_limits(per_source=4, global_limit=4)
    sources = [f"192.0.2.{index}" for index in range(1, 7)]

    existing = _login_attempts(client, "spread_target", sources)
    missing = _login_attempts(client, "spread_missing", sources)

    assert existing == missing == [(200, False)] * 4 + [(200, True)] * 2


def test_username_limit_normalizes_case_and_whitespace(app, client, monkeypatch):
    import config

    monkeypatch.setattr(config, "RATELIMIT_LOGIN_LIMIT", "1000 per minute")
    _set_username_limits(per_source=2)

    results = []
    for name in ("Casey", "casey", " CASEY "):
        response = client.post(
            "/login",
            data={"username": name, "password": "wrong-password"},
            environ_base={"REMOTE_ADDR": "203.0.113.50"},
        )
        results.append("Too many login attempts" in response.get_data(as_text=True))

    assert results == [False, False, True]


def test_username_limit_does_not_block_other_usernames(app, client, monkeypatch):
    import config

    _create_user(app, "unaffected_user")
    monkeypatch.setattr(config, "RATELIMIT_LOGIN_LIMIT", "1000 per minute")
    _set_username_limits(per_source=1)
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
    _set_username_limits(per_source=2)

    statuses = [
        client.post(
            "/login/ldap",
            data={"username": "Directory_User", "password": "secret-value"},
            environ_base={"REMOTE_ADDR": "203.0.113.100"},
        ).status_code
        for _attempt in range(3)
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


def _device_trusted(app, test_client, username):
    from app import login_devices

    cookie = test_client.get_cookie(_DEVICE_COOKIE)
    if cookie is None:
        return False
    with app.test_request_context(
        headers={"Cookie": f"{_DEVICE_COOKIE}={cookie.value}"},
    ):
        return login_devices.trusted_device(username) is not None


def _sets_device_cookie(response):
    return any(
        value.startswith(f"{_DEVICE_COOKIE}=")
        for value in response.headers.getlist("Set-Cookie")
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
        lambda user_id, *_args, **kwargs: revoked.append(
            (user_id, kwargs.get("kill_tmux", True))
        ),
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
    assert not _sets_device_cookie(removed)
    assert revoked == [(target_id, True)]
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
    revoked = []
    monkeypatch.setattr(
        user_lifecycle, "revoke_user_access",
        lambda user_id, *_args, **kwargs: revoked.append(
            (user_id, kwargs.get("kill_tmux", True))
        ),
    )
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
    assert revoked == [(admin_id, False)]
    assert _is_signed_out(other_browser)
    assert not _is_signed_out(client)
    # Only the browser that stays signed in gets a cookie for the new state.
    assert _device_trusted(app, client, "oidc_self_admin")
    assert not _device_trusted(app, other_browser, "oidc_self_admin")


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
        lambda revoked_id, *_args, **kwargs: revoked.append(
            (revoked_id, kwargs.get("kill_tmux", True))
        ),
    )

    headers = mint_account_step_up_headers(app, client, "github.unlink", user_id)
    response = client.delete("/api/account/github", headers=headers)

    assert response.status_code == 200
    assert revoked == [(user_id, False)]
    with app.app_context():
        assert GitHubIdentity.query.filter_by(user_id=user_id).count() == 0
        assert db.session.get(User, user_id).auth_generation == (
            generation_before + 1
        )
    assert _is_signed_out(other_browser)
    assert client.get("/api/account/github").status_code == 200
    assert _device_trusted(app, client, "github_unlink_user")
    assert not _device_trusted(app, other_browser, "github_unlink_user")


# --- counter resets by other proofs of possession -----------------------------


def _set_both_counters(app, user_id, failures=7):
    _set_failure_state(app, user_id, failures, seconds_ago=0)
    _set_failure_state(app, user_id, failures, seconds_ago=0, scope="step_up")


def _both_counters(app, user_id):
    return (
        _failure_state(app, user_id)[0],
        _failure_state(app, user_id, "step_up")[0],
    )


def test_recovery_code_login_clears_the_counters(
    app, client, monkeypatch, generous_request_limits,
):
    from tests.test_recovery_service import _enable_recovery_mfa

    user_id = _create_user(app, "reset_recovery")
    code = _enable_recovery_mfa(app, user_id, count=1)[0]
    _set_both_counters(app, user_id)
    assert _password_login(client, "reset_recovery").status_code == 200

    assert client.post(
        "/api/auth/recovery", json={"code": code},
    ).status_code == 200
    assert _both_counters(app, user_id) == (0, 0)


def test_passkey_step_up_clears_the_counters(
    app, client, monkeypatch, generous_request_limits,
):
    import base64
    from types import SimpleNamespace

    import app.step_up_routes as step_up_routes
    from app.models import User, WebAuthnCredential, db

    user_id = _create_user(app, "reset_passkey", is_admin=True)
    assert _password_login(client, "reset_passkey").status_code == 302
    credential_id = b"reset-passkey-credential"
    with app.app_context():
        db.session.get(User, user_id).mfa_enabled = True
        db.session.add(WebAuthnCredential(
            user_id=user_id,
            credential_id=credential_id,
            public_key=b"public-key",
            sign_count=0,
            transports="[]",
        ))
        db.session.commit()
    _set_both_counters(app, user_id)
    monkeypatch.setattr(
        step_up_routes, "_factor_available", lambda name: name == "passkey",
    )
    monkeypatch.setattr(
        step_up_routes,
        "verify_authentication_response",
        lambda **_kwargs: SimpleNamespace(new_sign_count=1),
    )

    assert client.post("/api/step-up/passkey/options", json={
        "action": "settings.update", "target": "global",
    }).status_code == 200
    verified = client.post("/api/step-up/passkey/verify", json={
        "credential": {
            "id": base64.urlsafe_b64encode(credential_id).decode().rstrip("="),
        },
    })

    assert verified.status_code == 200
    assert _both_counters(app, user_id) == (0, 0)


def test_totp_enrollment_and_disable_clear_the_counters(app):
    from app.models import User, db
    from app.totp_service import (
        activate_totp_enrollment,
        begin_totp_enrollment,
        disable_totp_mfa,
    )

    user_id = _create_user(app, "reset_enrollment")
    _set_both_counters(app, user_id)
    with app.app_context():
        view = begin_totp_enrollment(user_id, "reset-binding")
        activate_totp_enrollment(
            view.token, pyotp.TOTP(view.secret).now(), "reset-binding",
        )
    assert _both_counters(app, user_id) == (0, 0)

    _set_both_counters(app, user_id)
    with app.app_context():
        disable_totp_mfa(db.session.get(User, user_id))
        db.session.commit()
    assert _both_counters(app, user_id) == (0, 0)


def test_admin_mfa_reset_clears_the_counters(app, client, monkeypatch):
    import app.user_lifecycle as user_lifecycle

    _create_user(app, "reset_admin", is_admin=True)
    target_id = _create_user(app, "reset_target")
    assert _password_login(client, "reset_admin").status_code == 302
    monkeypatch.setattr(user_lifecycle, "revoke_user_access", lambda *_a, **_k: None)
    _set_both_counters(app, target_id)

    response = client.delete(
        f"/admin/api/users/{target_id}/mfa",
        json={"confirm_username": "reset_target"},
        headers=password_step_up_headers(client, "user.mfa_reset", target_id)[0],
    )

    assert response.status_code == 200
    assert _both_counters(app, target_id) == (0, 0)


# --- username limit counts failures only --------------------------------------


def test_successful_logins_do_not_consume_the_username_budget(
    app, client, monkeypatch,
):
    import config

    _create_user(app, "frequent_user")
    monkeypatch.setattr(config, "RATELIMIT_LOGIN_LIMIT", "1000 per minute")
    _set_username_limits(per_source=2)
    _set_username_limits(global_limit=3)

    for _attempt in range(5):
        assert _password_login(
            client, "frequent_user", ip="203.0.113.70",
        ).status_code == 302
        client.post("/logout")

    failures = _login_attempts(client, "frequent_user", ["203.0.113.70"] * 3)
    assert failures == [(200, False)] * 2 + [(200, True)]


def test_ldap_success_does_not_consume_the_username_budget(
    app, client, monkeypatch,
):
    import config
    import app.ldap_session as ldap_session
    from app.models import LDAPIdentity, db
    from tests.test_ldap_auth import (
        _DirectoryIdentity,
        _FakeDirectory,
        _enable_ldap_blueprint,
    )

    _create_user(app, "local_break_glass", is_admin=True)
    user_id = _create_user(app, "ldap_frequent")
    identity = _DirectoryIdentity(
        provider="default",
        subject="ldap-frequent-id",
        distinguished_name="uid=ldap_frequent,dc=example,dc=com",
    )
    with app.app_context():
        db.session.add(LDAPIdentity(
            user_id=user_id,
            provider=identity.provider,
            subject=identity.subject,
            directory_username="ldap_frequent",
            distinguished_name=identity.distinguished_name,
        ))
        db.session.commit()
    _enable_ldap_blueprint(app, monkeypatch, _FakeDirectory(identity))
    monkeypatch.setattr(ldap_session, "revalidate_user", lambda _user: None)
    monkeypatch.setattr(config, "LDAP_LOGIN_RATE_LIMIT", "1000 per minute")
    _set_username_limits(per_source=1)

    statuses = []
    for _attempt in range(3):
        statuses.append(client.post(
            "/login/ldap",
            data={"username": "ldap_frequent", "password": "directory-secret"},
            environ_base={"REMOTE_ADDR": "203.0.113.80"},
        ).status_code)
        client.post("/logout")

    assert statuses == [302, 302, 302]


@pytest.mark.parametrize("limiter_kind", ["memory", "redis"])
def test_release_returns_one_reservation(limiter_kind):
    from app.rate_limiter import InMemoryRateLimiter, RedisRateLimiter

    if limiter_kind == "memory":
        limiter = InMemoryRateLimiter()
    else:
        class _SortedSetRedis:
            def __init__(self):
                self.members = {}

            def eval(self, _script, _numkeys, key, _start, now, limit, _ttl, member):
                entries = self.members.setdefault(key, [])
                if len(entries) >= int(limit):
                    return 0
                entries.append((float(now), member))
                return 1

            def zpopmax(self, key):
                entries = self.members.get(key, [])
                return [entries.pop()] if entries else []

        limiter = RedisRateLimiter(_SortedSetRedis())

    assert limiter.allow("bucket", 1, 60) is True
    assert limiter.allow("bucket", 1, 60) is False
    limiter.release("bucket")
    assert limiter.allow("bucket", 1, 60) is True
    limiter.release("missing")


# --- configurable IPv6 prefix and restart UI ------------------------------------


@pytest.mark.parametrize(("prefix", "bucket"), [
    (128, "2001:db8:1:2:aaaa:bbbb:cccc:dddd/128"),
    (56, "2001:db8:1::/56"),
    (48, "2001:db8:1::/48"),
])
def test_ipv6_prefix_is_configurable(tmp_path, monkeypatch, prefix, bucket):
    from app import app_settings
    from app.auth import rate_limit_address

    monkeypatch.setattr(app_settings, "_SETTINGS_FILE", tmp_path / "app_settings.json")
    assert rate_limit_address("2001:db8:1:2:aaaa:bbbb:cccc:dddd") == "2001:db8:1:2::/64"

    assert app_settings.set_sign_in_protection({"ratelimit_ipv6_prefix": prefix})

    assert rate_limit_address("2001:db8:1:2:aaaa:bbbb:cccc:dddd") == bucket
    assert rate_limit_address("::ffff:192.0.2.9") == "192.0.2.9"
    assert rate_limit_address("192.0.2.9") == "192.0.2.9"


def test_ipv6_prefix_change_moves_the_login_limit_to_the_new_bucket(
    app, client, monkeypatch,
):
    import config
    from app import app_settings

    monkeypatch.setattr(config, "RATELIMIT_LOGIN_LIMIT", "1 per minute")
    _set_username_limits(per_source=1000)

    def limited(address):
        response = client.post(
            "/login",
            data={"username": "prefix-ghost", "password": "wrong-password"},
            environ_base={"REMOTE_ADDR": address},
        )
        return "Too many login attempts" in response.get_data(as_text=True)

    assert limited("2001:db8:77:1::1") is False
    assert limited("2001:db8:77:1::2") is True
    assert app_settings.set_sign_in_protection({"ratelimit_ipv6_prefix": 128})
    # Per-address buckets apply to the next request without a restart.
    assert limited("2001:db8:77:1::3") is False
    assert limited("2001:db8:77:1::3") is True


def test_discarded_pending_login_returns_to_the_password_form(
    app, client, monkeypatch, generous_request_limits,
):
    user_id, secret = _enroll_totp(app, client, monkeypatch, "restart_form")
    _set_failure_state(app, user_id, 4, seconds_ago=120)
    assert _password_login(client, "restart_form").status_code == 200

    discarded = client.post(
        "/api/totp/auth/verify", json={"code": _wrong_code(secret)},
    )
    page = client.get("/login").get_data(as_text=True)

    assert discarded.get_json()["code"] == "mfa_restart"
    assert 'data-i18n="auth.mfaRestart"' in page
    assert 'id="totpMfaPanel"' not in page


# --- known-device cookies ------------------------------------------------------


_DEVICE_COOKIE = "session_device"


def _distributed_lockout(client, username, *, path="/login", sources=20):
    """Twenty sources at the default 5/min each fill the 100/min name ceiling."""
    device = client.get_cookie(_DEVICE_COOKIE)
    client.delete_cookie(_DEVICE_COOKIE)
    for source in range(1, sources + 1):
        for _attempt in range(5):
            client.post(
                path,
                data={"username": username, "password": "wrong-password"},
                environ_base={"REMOTE_ADDR": f"198.18.{source}.1"},
            )
    if device is not None:
        client.set_cookie(_DEVICE_COOKIE, device.value)


def _limited(response):
    return (
        response.status_code == 429
        or "Too many login attempts" in response.get_data(as_text=True)
    )


def test_device_cookie_keeps_the_owner_in_during_a_distributed_lockout(
    app, client,
):
    _create_user(app, "device_owner")
    assert _password_login(client, "device_owner", ip="203.0.113.5").status_code == 302
    client.post("/logout")
    _distributed_lockout(client, "device_owner")

    with_cookie = _password_login(client, "device_owner", ip="203.0.113.5")
    client.post("/logout")
    client.delete_cookie(_DEVICE_COOKIE)
    without_cookie = _password_login(client, "device_owner", ip="203.0.113.6")

    assert with_cookie.status_code == 302
    assert _limited(without_cookie)


def test_device_cookie_is_issued_with_restrictive_attributes(app, client):
    _create_user(app, "device_attributes")

    response = _password_login(client, "device_attributes")

    header = next(
        value for value in response.headers.getlist("Set-Cookie")
        if value.startswith(f"{_DEVICE_COOKIE}=")
    )
    assert "HttpOnly" in header
    assert "SameSite=Lax" in header
    assert "Path=/" in header
    assert f"Max-Age={90 * 24 * 3600}" in header


def test_device_cookie_and_limiter_keys_use_a_keyed_username_digest(
    app, client, monkeypatch,
):
    """A plain hash of the name could be reversed by trying usernames."""
    import hashlib

    import app.auth as auth
    import app.login_devices as login_devices

    _create_user(app, "device_digest")
    _password_login(client, "device_digest")
    raw = client.get_cookie(_DEVICE_COOKIE).value
    with app.app_context():
        payload = login_devices._serializer().loads(raw)
    plain = hashlib.sha256(b"device_digest").hexdigest()
    assert payload["u"] != plain
    assert len(payload["u"]) == 64
    assert type(payload["i"]) is int

    original_secret = app.secret_key
    with app.test_request_context():
        keyed = login_devices.username_digest(" Device_Digest ")
        app.secret_key = "another-instance-secret"
        try:
            assert login_devices.username_digest("device_digest") != keyed
        finally:
            app.secret_key = original_secret
    assert payload["u"] == keyed

    reserved = []

    class _Limiter:
        def allow(self, key, _limit, _window):
            reserved.append(key)
            return True

    monkeypatch.setattr(auth, "_get_rate_limiter", lambda: _Limiter())
    with app.test_request_context():
        auth.reserve_login_username_attempt(
            "device_digest", "203.0.113.90", "login", "5 per minute", "100 per minute",
        )
    assert reserved
    assert all(plain not in key and keyed in key for key in reserved)


def test_device_cookie_rotates_on_each_success(app, client):
    _create_user(app, "device_rotation")
    _password_login(client, "device_rotation")
    first = client.get_cookie(_DEVICE_COOKIE).value
    client.post("/logout")
    _password_login(client, "device_rotation")

    assert client.get_cookie(_DEVICE_COOKIE).value != first


def test_device_cookie_for_another_username_is_ignored(app, client):
    _create_user(app, "device_alice")
    _create_user(app, "device_bob")
    assert _password_login(client, "device_alice").status_code == 302
    client.post("/logout")
    _distributed_lockout(client, "device_bob")

    response = _password_login(client, "device_bob", ip="203.0.113.7")

    assert _limited(response)


def test_tampered_and_expired_device_cookies_are_ignored(
    app, client, monkeypatch,
):
    import app.login_devices as login_devices

    _create_user(app, "device_tamper")
    _password_login(client, "device_tamper")
    client.post("/logout")
    valid = client.get_cookie(_DEVICE_COOKIE).value
    _distributed_lockout(client, "device_tamper")

    client.set_cookie(_DEVICE_COOKIE, valid[:-2] + ("AA" if valid[-2:] != "AA" else "BB"))
    tampered = _password_login(client, "device_tamper", ip="203.0.113.8")
    client.set_cookie(_DEVICE_COOKIE, valid)
    monkeypatch.setattr(login_devices, "MAX_AGE", timedelta(seconds=-1))
    expired = _password_login(client, "device_tamper", ip="203.0.113.9")

    assert _limited(tampered)
    assert _limited(expired)


def test_password_change_invalidates_device_cookies(app, client):
    from app.auth_assurance import invalidate_user_authentication
    from app.models import User, db

    user_id = _create_user(app, "device_rotated")
    _password_login(client, "device_rotated")
    client.post("/logout")
    with app.app_context():
        invalidate_user_authentication(db.session.get(User, user_id))
        db.session.commit()
    _distributed_lockout(client, "device_rotated")

    assert _limited(_password_login(client, "device_rotated", ip="203.0.113.10"))


def test_stolen_device_cookie_has_its_own_failure_budget(app, client):
    import app.login_devices as login_devices

    _create_user(app, "device_stolen")
    _password_login(client, "device_stolen")
    client.post("/logout")
    _distributed_lockout(client, "device_stolen")

    guesses = []
    for index in range(login_devices.FAILURE_BUDGET + 1):
        response = client.post(
            "/login",
            data={"username": "device_stolen", "password": "wrong-password"},
            environ_base={"REMOTE_ADDR": f"203.0.113.{index + 20}"},
        )
        guesses.append(_limited(response))
    owner = _password_login(client, "device_stolen", ip="203.0.113.60")

    assert guesses == [False] * login_devices.FAILURE_BUDGET + [True]
    assert _limited(owner)


def test_device_cookie_keeps_per_source_limits(app, client, monkeypatch):
    import config

    _create_user(app, "device_source")
    _password_login(client, "device_source")
    client.post("/logout")
    monkeypatch.setattr(config, "RATELIMIT_LOGIN_LIMIT", "1000 per minute")
    _set_username_limits(per_source=2)

    results = _login_attempts(client, "device_source", ["203.0.113.70"] * 3)

    assert results == [(200, False)] * 2 + [(200, True)]


def test_ldap_device_cookie_survives_a_distributed_lockout(
    app, client, monkeypatch,
):
    import app.ldap_session as ldap_session
    from app.models import LDAPIdentity, db
    from tests.test_ldap_auth import (
        _DirectoryIdentity,
        _FakeDirectory,
        _enable_ldap_blueprint,
    )

    _create_user(app, "ldap_device_admin", is_admin=True)
    user_id = _create_user(app, "ldap_device")
    identity = _DirectoryIdentity(
        provider="default",
        subject="ldap-device-id",
        distinguished_name="uid=ldap_device,dc=example,dc=com",
    )
    with app.app_context():
        db.session.add(LDAPIdentity(
            user_id=user_id,
            provider=identity.provider,
            subject=identity.subject,
            directory_username="ldap_device",
            distinguished_name=identity.distinguished_name,
        ))
        db.session.commit()
    directory = _FakeDirectory(identity)
    _enable_ldap_blueprint(app, monkeypatch, directory)
    monkeypatch.setattr(ldap_session, "revalidate_user", lambda _user: None)

    def ldap_login(address, password="directory-secret"):
        return client.post(
            "/login/ldap",
            data={"username": "ldap_device", "password": password},
            environ_base={"REMOTE_ADDR": address},
        )

    assert ldap_login("203.0.113.90").status_code == 302
    client.post("/logout")
    directory.password_valid = False
    _distributed_lockout(client, "ldap_device", path="/login/ldap")
    directory.password_valid = True

    with_cookie = ldap_login("203.0.113.90")
    client.post("/logout")
    client.delete_cookie(_DEVICE_COOKIE)
    without_cookie = ldap_login("203.0.113.91")

    assert with_cookie.status_code == 302
    assert without_cookie.status_code == 429
