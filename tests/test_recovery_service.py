"""Recovery Codes are bound second factors, never standalone login tokens."""

import hmac
import io
import json
import time

import pyotp
from werkzeug.test import EnvironBuilder

from tests.step_up_helpers import (
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


def _login(client, username, *, expected=302):
    response = client.post(
        "/login",
        data={"username": username, "password": "password123"},
    )
    assert response.status_code == expected
    return response


def _enable_recovery_mfa(app, user_id, *, count=3):
    from app.models import User, db
    from app.recovery_service import generate_codes

    with app.app_context():
        user = db.session.get(User, user_id)
        user.mfa_enabled = True
        codes = generate_codes(user_id, count=count)
        db.session.commit()
        return codes


def test_recovery_codes_are_hashed_single_use_and_regeneration_invalidates(app):
    from app.models import RecoveryCode
    from app.recovery_service import consume_code, generate_codes

    user_id = _create_user(app, "recovery_user")
    with app.app_context():
        first = generate_codes(user_id, count=3)
        stored = RecoveryCode.query.filter_by(user_id=user_id).all()

        assert len(first) == 3
        assert len(stored) == 3
        assert all(
            code.encode("utf-8") not in row.code_hash
            for code in first
            for row in stored
        )
        assert consume_code(user_id, first[0]) is True
        assert consume_code(user_id, first[0]) is False

        second = generate_codes(user_id, count=3)
        assert consume_code(user_id, first[1]) is False
        assert consume_code(user_id, second[0]) is True


def test_recovery_code_without_primary_factor_never_logs_in_or_consumes(app, client):
    user_id = _create_user(app, "no_standalone_recovery")
    code = _enable_recovery_mfa(app, user_id, count=1)[0]

    standalone = client.post(
        "/login/recovery",
        json={"username": "no_standalone_recovery", "code": code},
    )
    with client.session_transaction() as browser_session:
        assert "_user_id" not in browser_session

    primary = _login(client, "no_standalone_recovery", expected=200)
    accepted = client.post("/api/auth/recovery", json={"code": code})

    assert standalone.status_code == 400
    assert "primary" in standalone.get_json()["error"].lower()
    assert 'id="recoveryMfaPanel"' in primary.get_data(as_text=True)
    assert accepted.status_code == 200


def test_password_then_recovery_is_restricted_until_factor_replacement(
    app,
    client,
):
    from app.models import AuthenticationSession

    user_id = _create_user(app, "restricted_recovery")
    code = _enable_recovery_mfa(app, user_id, count=1)[0]
    _login(client, "restricted_recovery", expected=200)

    recovered = client.post("/api/auth/recovery", json={"code": code})

    assert recovered.status_code == 200
    assert recovered.get_json() == {
        "ok": True,
        "recovery_required": True,
        "continuation": "/security",
    }
    assert client.get("/").status_code == 403
    assert client.get("/api/host-keys").status_code == 403
    security = client.get("/security")
    assert security.status_code == 200
    assert b'id="recoveryRequiredNotice"' in security.data
    assert b'id="recoveryLogoutBtn"' in security.data
    assert b'Back to terminal' not in security.data
    settings_alias = client.get("/settings")
    assert settings_alias.status_code == 200
    assert b'id="recoveryRequiredNotice"' in settings_alias.data
    security_state = client.get("/api/account/security-state")
    assert security_state.status_code == 200
    assert security_state.get_json()["mfa_enabled"] is True
    assert client.post("/api/account/security-state").status_code == 403
    with app.app_context():
        row = AuthenticationSession.query.one()
        assert row.user_id == user_id
        assert row.assurance == "MFA"
        assert row.methods_json == '["password","recovery_code"]'


def test_recovery_restricted_session_cannot_open_terminal_socket(
    app,
    client,
    monkeypatch,
):
    from flask import request, session
    from app.models import SocketSession
    import app.socket_events as socket_events

    user_id = _create_user(app, "restricted_recovery_socket")
    code = _enable_recovery_mfa(app, user_id, count=1)[0]
    _login(client, "restricted_recovery_socket", expected=200)
    assert client.post("/api/auth/recovery", json={"code": code}).status_code == 200
    with client.session_transaction() as browser_session:
        browser_state = dict(browser_session)
    emitted = []
    disconnected = []
    monkeypatch.setattr(
        socket_events,
        "emit",
        lambda event, payload=None: emitted.append((event, payload)),
    )
    monkeypatch.setattr(
        socket_events,
        "disconnect",
        lambda: disconnected.append(True),
    )

    with app.test_request_context("/socket.io"):
        request.sid = "restricted-recovery-socket"
        session.update(browser_state)
        rejected = socket_events.handle_connect()

    assert rejected is False
    assert emitted == [("connected", {"status": "recovery_required"})]
    assert disconnected == [True]
    with app.app_context():
        assert SocketSession.query.filter_by(user_id=user_id).count() == 0


def test_recovery_pending_and_code_are_bound_to_the_primary_browser(app):
    user_id = _create_user(app, "bound_recovery")
    code = _enable_recovery_mfa(app, user_id, count=1)[0]
    first = app.test_client()
    second = app.test_client()
    _login(first, "bound_recovery", expected=200)

    rejected = second.post("/api/auth/recovery", json={"code": code})
    accepted = first.post("/api/auth/recovery", json={"code": code})

    assert rejected.status_code == 401
    assert accepted.status_code == 200


def test_recovery_code_cannot_be_replayed_after_restricted_logout(app, client):
    user_id = _create_user(app, "replay_recovery")
    code = _enable_recovery_mfa(app, user_id, count=1)[0]
    _login(client, "replay_recovery", expected=200)
    assert client.post("/api/auth/recovery", json={"code": code}).status_code == 200
    assert client.post("/logout").status_code == 302

    _login(client, "replay_recovery", expected=200)
    replayed = client.post("/api/auth/recovery", json={"code": code})

    assert replayed.status_code == 401


def test_explicit_mfa_disable_releases_restricted_session(app, client):
    from app.models import TOTPAuthenticator, User, db

    user_id = _create_user(app, "disable_recovered_mfa")
    code = _enable_recovery_mfa(app, user_id, count=1)[0]
    with app.app_context():
        db.session.add_all((
            TOTPAuthenticator(
                user_id=user_id,
                encrypted_secret=b"active-recovery-totp-secret",
                label="Phone",
                active=True,
            ),
            TOTPAuthenticator(
                user_id=user_id,
                encrypted_secret=b"inactive-recovery-totp-secret",
                label="Retired phone",
                active=False,
            ),
        ))
        db.session.commit()
    _login(client, "disable_recovered_mfa", expected=200)
    assert client.post("/api/auth/recovery", json={"code": code}).status_code == 200

    unconfirmed = client.post(
        "/api/auth/mfa/disable",
        json={"confirm_username": "wrong"},
    )
    disabled = client.post(
        "/api/auth/mfa/disable",
        json={"confirm_username": "disable_recovered_mfa"},
    )

    assert unconfirmed.status_code == 400
    assert disabled.status_code == 200
    assert client.get("/").status_code == 200
    with app.app_context():
        assert db.session.get(User, user_id).mfa_enabled is False
        assert TOTPAuthenticator.query.filter_by(user_id=user_id).count() == 0


def test_verified_totp_replacement_releases_restricted_session(
    app,
    client,
    monkeypatch,
):
    import config
    from app.models import AuthenticationSession, SecurityFeatureState, db

    user_id = _create_user(app, "replace_with_totp")
    code = _enable_recovery_mfa(app, user_id, count=1)[0]
    monkeypatch.setattr(config, "TOTP_ENABLED", True)
    with app.app_context():
        db.session.merge(SecurityFeatureState(feature="totp", enabled=True))
        db.session.commit()
    _login(client, "replace_with_totp", expected=200)
    assert client.post("/api/auth/recovery", json={"code": code}).status_code == 200

    enrollment = client.post(
        "/api/totp/enroll",
        json={"password": "password123", "label": "Replacement"},
    ).get_json()
    activated = client.post(
        "/api/totp/enroll/verify",
        json={
            "token": enrollment["token"],
            "code": pyotp.TOTP(enrollment["secret"]).now(),
            "confirm_enable_mfa": True,
        },
    )

    assert activated.status_code == 200
    assert client.get("/").status_code == 200
    with app.app_context():
        row = AuthenticationSession.query.one()
        assert row.methods_json == '["password","totp"]'


def test_ldap_verified_pending_can_use_recovery_without_password_storage(
    app,
    client,
    monkeypatch,
):
    import config
    from app.auth_assurance import AssuranceLevel, begin_authentication
    from app.models import LDAPIdentity, User, db

    user_id = _create_user(app, "ldap_recovery")
    code = _enable_recovery_mfa(app, user_id, count=1)[0]
    verified_at = int(time.time())
    monkeypatch.setattr(config, "LDAP_ENABLED", True)
    with app.app_context():
        user = db.session.get(User, user_id)
        db.session.add(LDAPIdentity(
            user_id=user.id,
            provider="default",
            subject="ldap-recovery-subject",
            directory_username=user.username,
            distinguished_name="uid=ldap_recovery,dc=example,dc=com",
        ))
        db.session.commit()
        token = begin_authentication(
            user,
            "ldap",
            assurance=AssuranceLevel.BASIC,
            session_binding="ldap-browser-binding",
            remember=False,
            continuation="/",
            evidence={"provider": "default", "verified_at": verified_at},
        )
    with client.session_transaction() as browser_session:
        browser_session["_pending_authentication"] = token
        browser_session["_auth_binding"] = "ldap-browser-binding"

    response = client.post("/api/auth/recovery", json={"code": code})

    assert response.status_code == 200
    with client.session_transaction() as browser_session:
        assert browser_session["_ldap_verified_at"] == verified_at


def test_oidc_pending_cannot_exchange_a_recovery_code(app, client):
    from app.auth_assurance import AssuranceLevel, begin_authentication
    from app.models import RecoveryCode, User, db

    user_id = _create_user(app, "oidc_recovery_rejected")
    code = _enable_recovery_mfa(app, user_id, count=1)[0]
    with app.app_context():
        user = db.session.get(User, user_id)
        token = begin_authentication(
            user,
            "oidc",
            assurance=AssuranceLevel.BASIC,
            session_binding="oidc-recovery-binding",
            remember=False,
            continuation="/",
        )
    with client.session_transaction() as browser_session:
        browser_session["_pending_authentication"] = token
        browser_session["_auth_binding"] = "oidc-recovery-binding"

    rejected = client.post("/api/auth/recovery", json={"code": code})

    assert rejected.status_code == 401
    with app.app_context():
        assert RecoveryCode.query.filter_by(user_id=user_id).count() == 1


def test_recovery_code_regeneration_supports_recent_ldap_reauthentication(
    app,
    client,
    monkeypatch,
):
    import config
    from flask import g
    from app.models import LDAPIdentity, User, db

    user_id = _create_user(app, "ldap_codes")
    _login(client, "ldap_codes")
    monkeypatch.setattr(config, "LDAP_ENABLED", True)
    with app.app_context():
        user = db.session.get(User, user_id)
        db.session.add(LDAPIdentity(
            user_id=user.id,
            provider="default",
            subject="ldap-codes-subject",
            directory_username=user.username,
            distinguished_name="uid=ldap_codes,dc=example,dc=com",
        ))
        db.session.commit()
    g.pop("_login_user", None)
    with client.session_transaction() as browser_session:
        browser_session["_ldap_verified_at"] = int(time.time())

    headers = mint_account_step_up_headers(
        app,
        client,
        "recovery.rotate",
        user_id,
        method="ldap",
    )

    response = client.post(
        "/api/recovery-codes",
        json={},
        headers=headers,
    )

    assert response.status_code == 200
    assert len(response.get_json()["codes"]) == 10


def test_recovery_code_regeneration_does_not_repeat_password_verification(
    app,
    client,
    monkeypatch,
):
    from app.models import User

    user_id = _create_user(app, "limited_recovery_user")
    _login(client, "limited_recovery_user")
    headers = mint_account_step_up_headers(
        app,
        client,
        "recovery.rotate",
        user_id,
    )
    monkeypatch.setattr(
        User,
        "check_password",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("bcrypt must not run after reauth throttling")
        ),
    )

    response = client.post(
        "/api/recovery-codes",
        json={},
        headers=headers,
    )

    assert response.status_code == 200


def test_recovery_mfa_is_rate_limited_before_code_verification(
    app,
    client,
    monkeypatch,
):
    import app.recovery_routes as recovery_routes

    user_id = _create_user(app, "limited_recovery_mfa")
    _enable_recovery_mfa(app, user_id, count=1)
    _login(client, "limited_recovery_mfa", expected=200)
    monkeypatch.setattr(recovery_routes, "check_rate_limit", lambda *_args: True)
    monkeypatch.setattr(
        recovery_routes,
        "consume_code",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("code verification must not run after throttling")
        ),
    )

    response = client.post("/api/auth/recovery", json={"code": "invalid"})

    assert response.status_code == 429


def test_recovery_mfa_rejects_oversized_json_before_code_verification(
    app,
    client,
    monkeypatch,
):
    import app.recovery_routes as recovery_routes

    verification_calls = []
    monkeypatch.setattr(
        recovery_routes,
        "consume_code",
        lambda *args: verification_calls.append(args),
    )
    payload = json.dumps({"code": "invalid", "padding": "x" * 5000})

    response = client.post(
        "/api/auth/recovery",
        data=payload,
        content_type="application/json",
    )

    assert response.status_code == 413
    assert verification_calls == []


def test_recovery_mfa_bounds_chunked_json_without_content_length(app, client):
    payload = json.dumps({
        "code": "invalid",
        "padding": "x" * 5000,
    }).encode("utf-8")
    builder = EnvironBuilder(
        path="/api/auth/recovery",
        method="POST",
        input_stream=io.BytesIO(payload),
        content_type="application/json",
    )
    environ = builder.get_environ()
    environ.pop("CONTENT_LENGTH", None)
    environ["wsgi.input_terminated"] = True

    response = client.open(environ)

    assert response.status_code == 413


def test_recovery_verification_equalizes_missing_and_existing_account_work(
    app,
    monkeypatch,
):
    import app.recovery_service as recovery_service

    user_id = _create_user(app, "timing_recovery_user")
    with app.app_context():
        recovery_service.generate_codes(user_id, count=3)
        real_compare_digest = hmac.compare_digest
        comparisons = []
        expensive = []

        def record_comparison(left, right):
            comparisons.append((left, right))
            return real_compare_digest(left, right)

        monkeypatch.setattr(recovery_service.hmac, "compare_digest", record_comparison)
        monkeypatch.setattr(
            recovery_service,
            "_equalize_verification_cost",
            lambda candidate: expensive.append(candidate),
        )
        assert recovery_service.consume_code(None, "invalid") is False
        missing_counts = (len(comparisons), len(expensive))
        comparisons.clear()
        expensive.clear()
        assert recovery_service.consume_code(user_id, "invalid") is False

        assert missing_counts == (20, 1)
        assert (len(comparisons), len(expensive)) == missing_counts


def test_admin_recovery_requires_reauthentication_and_exact_target_confirmation(
    app,
    client,
):
    admin_id = _create_user(app, "recovery_admin", is_admin=True)
    target_id = _create_user(app, "recovery_target")
    assert admin_id != target_id
    _login(client, "recovery_admin")

    _headers, wrong_password = password_step_up_headers(
        client,
        "recovery.reset",
        target_id,
        password="wrong",
        expected_status=403,
    )
    wrong_headers = password_step_up_headers(
        client, "recovery.reset", target_id
    )[0]
    wrong_target = client.post(
        f"/admin/api/users/{target_id}/recovery",
        json={"confirm_username": "other"},
        headers=wrong_headers,
    )
    accepted_headers = password_step_up_headers(
        client, "recovery.reset", target_id
    )[0]
    accepted = client.post(
        f"/admin/api/users/{target_id}/recovery",
        json={"confirm_username": "recovery_target"},
        headers=accepted_headers,
    )

    assert wrong_password.status_code == 403
    assert wrong_target.status_code == 400
    assert accepted.status_code == 200
    assert len(accepted.get_json()["codes"]) == 10
