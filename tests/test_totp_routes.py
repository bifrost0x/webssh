"""Optional TOTP enrollment and pending-login routes."""

import time

import pyotp

from tests.step_up_helpers import (
    account_password_step_up_headers,
    mint_account_step_up_headers,
)


def _create_user(app, username="totp_route_user"):
    from app.auth import register_user
    from app.models import db

    with app.app_context():
        user, error = register_user(username, "password123")
        assert error is None
        db.session.commit()
        return user.id


def _activate_totp_feature(app, monkeypatch):
    import config
    from app.models import SecurityFeatureState, db

    monkeypatch.setattr(config, "TOTP_ENABLED", True)
    with app.app_context():
        db.session.merge(SecurityFeatureState(feature="totp", enabled=True))
        db.session.commit()


def _activate_passkey_feature(app, monkeypatch):
    import config
    from app.models import SecurityFeatureState, db

    monkeypatch.setattr(config, "WEBAUTHN_ENABLED", True)
    with app.app_context():
        db.session.merge(SecurityFeatureState(feature="passkey", enabled=True))
        db.session.commit()


def _login(client, username="totp_route_user"):
    response = client.post(
        "/login",
        data={"username": username, "password": "password123"},
    )
    assert response.status_code == 302


def test_totp_routes_are_hidden_below_deployment_ceiling(app, client):
    _create_user(app)
    _login(client)

    response = client.post("/api/totp/enroll", json={"password": "password123"})

    assert response.status_code == 404


def test_user_explicitly_enrolls_totp_and_receives_one_time_recovery_codes(
    app,
    client,
    monkeypatch,
    caplog,
):
    from app.models import TOTPAuthenticator, User, db

    user_id = _create_user(app)
    _activate_totp_feature(app, monkeypatch)
    _login(client)

    headers, _verified = account_password_step_up_headers(
        client,
        "totp.enroll",
        user_id,
    )

    started = client.post(
        "/api/totp/enroll",
        json={"label": "Phone"},
        headers=headers,
    )
    assert started.status_code == 200
    assert started.headers["Cache-Control"] == "no-store"
    enrollment = started.get_json()
    assert enrollment["qr_svg"].startswith("<?xml")
    assert enrollment["secret"] not in caplog.text

    unconfirmed = client.post(
        "/api/totp/enroll/verify",
        json={
            "token": enrollment["token"],
            "code": pyotp.TOTP(enrollment["secret"]).now(),
            "confirm_enable_mfa": False,
        },
    )
    assert unconfirmed.status_code == 400

    invalid = client.post(
        "/api/totp/enroll/verify",
        json={
            "token": enrollment["token"],
            "code": "invalid",
            "confirm_enable_mfa": True,
        },
    )
    assert invalid.status_code == 400

    activated = client.post(
        "/api/totp/enroll/verify",
        json={
            "token": enrollment["token"],
            "code": pyotp.TOTP(enrollment["secret"]).now(),
            "confirm_enable_mfa": True,
        },
    )

    assert activated.status_code == 200
    payload = activated.get_json()
    assert payload["ok"] is True
    assert len(payload["recovery_codes"]) == 10
    assert activated.headers["Cache-Control"] == "no-store"
    with app.app_context():
        assert db.session.get(User, user_id).mfa_enabled is True
        assert TOTPAuthenticator.query.filter_by(
            user_id=user_id,
            active=True,
            label="Phone",
        ).count() == 1


def test_totp_completes_pending_password_login(app, client, monkeypatch):
    from app.models import AuthenticationSession, User, db

    user_id = _create_user(app, "totp_login_user")
    _activate_totp_feature(app, monkeypatch)
    _login(client, "totp_login_user")
    headers, _verified = account_password_step_up_headers(
        client,
        "totp.enroll",
        user_id,
    )
    started = client.post(
        "/api/totp/enroll",
        json={},
        headers=headers,
    ).get_json()
    secret = started["secret"]
    assert client.post(
        "/api/totp/enroll/verify",
        json={
            "token": started["token"],
            "code": pyotp.TOTP(secret).now(),
            "confirm_enable_mfa": True,
        },
    ).status_code == 200
    client.post("/logout")

    primary = client.post(
        "/login?next=/security",
        data={"username": "totp_login_user", "password": "password123"},
    )
    assert primary.status_code == 200
    assert 'id="totpMfaPanel"' in primary.get_data(as_text=True)

    next_code = pyotp.TOTP(secret).at(time.time() + 30)
    verified = client.post(
        "/api/totp/auth/verify",
        json={"code": next_code},
    )

    assert verified.status_code == 200
    assert verified.get_json()["continuation"] == "/security"
    with client.session_transaction() as browser_session:
        assert "_pending_authentication" not in browser_session
        assert browser_session["_user_id"].startswith(f"{user_id}:0:")
    with app.app_context():
        row = AuthenticationSession.query.order_by(
            AuthenticationSession.id.desc()
        ).first()
        assert row.assurance == "MFA"
        assert row.methods_json == '["password","totp"]'
        assert db.session.get(User, user_id).mfa_enabled is True


def test_passkey_remains_visible_as_an_alternative_mfa_method(
    app,
    client,
    monkeypatch,
):
    import config
    from app.models import (
        SecurityFeatureState,
        TOTPAuthenticator,
        User,
        WebAuthnCredential,
        db,
    )

    user_id = _create_user(app, "mixed_factor_user")
    _activate_totp_feature(app, monkeypatch)
    monkeypatch.setattr(config, "WEBAUTHN_ENABLED", True)
    with app.app_context():
        db.session.merge(SecurityFeatureState(feature="passkey", enabled=True))
        user = db.session.get(User, user_id)
        user.mfa_enabled = True
        db.session.add(TOTPAuthenticator(
            user_id=user_id,
            encrypted_secret=b"encrypted-mixed-factor-secret",
            active=True,
        ))
        db.session.add(WebAuthnCredential(
            user_id=user_id,
            credential_id=b"mixed-factor-credential",
            public_key=b"public-key",
            transports="[]",
            name="Passkey",
        ))
        db.session.commit()

    response = client.post(
        "/login",
        data={"username": "mixed_factor_user", "password": "password123"},
    )

    html = response.get_data(as_text=True)
    assert response.status_code == 200
    assert 'id="passkeyLoginBtn"' in html
    assert 'id="cancelMfaLogin"' in html
    assert 'action="/login/cancel"' in html
    assert 'id="passwordAuthenticationForms" class="hidden"' in html
    assert 'id="authMfaMethodSwitcher"' in html
    assert 'data-auth-mode="totp" aria-selected="true"' in html
    assert 'data-auth-mode="passkey" aria-selected="false"' in html
    assert (
        'id="totpMfaPanel" class="login-mode" '
        'data-auth-mode-panel="totp" aria-hidden="false"'
    ) in html
    assert (
        'id="passkeyLoginMode" class="login-mode auth-provider-mode hidden" '
        'data-auth-mode-panel="passkey" aria-hidden="true"'
    ) in html
    assert 'data-mfa-layout="compact"' in html
    assert 'id="totpMfaTab"' in html
    assert 'aria-labelledby="totpMfaTab"' in html


def test_deleting_last_totp_keeps_mfa_when_passkey_remains(
    app,
    client,
    monkeypatch,
):
    from app.models import TOTPAuthenticator, User, WebAuthnCredential, db

    user_id = _create_user(app, "delete_mixed_totp_user")
    _activate_totp_feature(app, monkeypatch)
    _activate_passkey_feature(app, monkeypatch)
    _login(client, "delete_mixed_totp_user")
    with app.app_context():
        user = db.session.get(User, user_id)
        user.mfa_enabled = True
        authenticator = TOTPAuthenticator(
            user_id=user_id,
            encrypted_secret=b"delete-mixed-totp-secret",
            label="Phone",
            active=True,
        )
        db.session.add_all((
            authenticator,
            WebAuthnCredential(
                user_id=user_id,
                credential_id=b"delete-mixed-passkey",
                public_key=b"public-key",
                transports="[]",
                name="Laptop",
            ),
        ))
        db.session.commit()
        authenticator_id = authenticator.id
    headers = mint_account_step_up_headers(
        app,
        client,
        "totp.delete",
        authenticator_id,
        assurance="MFA",
        method="passkey",
    )

    response = client.delete(
        f"/api/totp/authenticators/{authenticator_id}",
        headers=headers,
    )

    assert response.status_code == 200
    assert response.get_json()["mfa_enabled"] is True
    with app.app_context():
        assert db.session.get(User, user_id).mfa_enabled is True
        assert TOTPAuthenticator.query.filter_by(user_id=user_id).count() == 0
        assert WebAuthnCredential.query.filter_by(user_id=user_id).count() == 1


def test_deleting_last_durable_totp_factor_is_blocked(
    app,
    client,
    monkeypatch,
):
    from app.models import TOTPAuthenticator, User, db

    user_id = _create_user(app, "delete_last_totp_user")
    _activate_totp_feature(app, monkeypatch)
    _login(client, "delete_last_totp_user")
    with app.app_context():
        user = db.session.get(User, user_id)
        user.mfa_enabled = True
        authenticator = TOTPAuthenticator(
            user_id=user_id,
            encrypted_secret=b"delete-last-totp-secret",
            label="Only phone",
            active=True,
        )
        db.session.add(authenticator)
        db.session.commit()
        authenticator_id = authenticator.id
    headers = mint_account_step_up_headers(
        app,
        client,
        "totp.delete",
        authenticator_id,
        assurance="MFA",
        method="totp",
    )

    response = client.delete(
        f"/api/totp/authenticators/{authenticator_id}",
        headers=headers,
    )

    assert response.status_code == 409
    assert response.get_json()["code"] == "last_factor_required"
    with app.app_context():
        assert db.session.get(User, user_id).mfa_enabled is True
        assert db.session.get(TOTPAuthenticator, authenticator_id) is not None


def test_security_state_reports_active_durable_factor_inventory(
    app,
    client,
    monkeypatch,
):
    from app.models import TOTPAuthenticator, User, WebAuthnCredential, db

    user_id = _create_user(app, "factor_state_user")
    _activate_totp_feature(app, monkeypatch)
    _activate_passkey_feature(app, monkeypatch)
    _login(client, "factor_state_user")
    with app.app_context():
        user = db.session.get(User, user_id)
        user.mfa_enabled = True
        db.session.add_all((
            TOTPAuthenticator(
                user_id=user_id,
                encrypted_secret=b"state-totp-secret",
                active=True,
            ),
            WebAuthnCredential(
                user_id=user_id,
                credential_id=b"state-passkey",
                public_key=b"public-key",
                transports="[]",
            ),
        ))
        db.session.commit()

    response = client.get("/api/account/security-state")

    assert response.status_code == 200
    assert response.get_json() == {
        "can_disable_mfa": True,
        "can_enable_mfa": False,
        "mfa_enabled": True,
        "passkey_count": 1,
        "total": 2,
        "totp_count": 1,
    }


def test_mfa_disable_is_explicit_and_recently_reauthenticated(
    app,
    client,
    monkeypatch,
):
    from app.models import TOTPAuthenticator, User, db

    user_id = _create_user(app, "disable_totp_user")
    _activate_totp_feature(app, monkeypatch)
    _login(client, "disable_totp_user")
    enrollment_headers, _verified = account_password_step_up_headers(
        client,
        "totp.enroll",
        user_id,
    )
    started = client.post(
        "/api/totp/enroll",
        json={},
        headers=enrollment_headers,
    ).get_json()
    assert client.post(
        "/api/totp/enroll/verify",
        json={
            "token": started["token"],
            "code": pyotp.TOTP(started["secret"]).now(),
            "confirm_enable_mfa": True,
        },
    ).status_code == 200
    with app.app_context():
        db.session.add(TOTPAuthenticator(
            user_id=user_id,
            encrypted_secret=b"inactive-totp-secret",
            label="Retired phone",
            active=False,
        ))
        db.session.commit()

    rejected = client.post(
        "/api/totp/disable",
        json={"password": "wrong", "confirm_disable_mfa": True},
    )
    disable_headers = mint_account_step_up_headers(
        app,
        client,
        "mfa.disable",
        user_id,
        assurance="MFA",
        method="totp",
    )
    unconfirmed = client.post(
        "/api/totp/disable",
        json={"confirm_disable_mfa": False},
        headers=disable_headers,
    )
    accepted = client.post(
        "/api/totp/disable",
        json={"confirm_disable_mfa": True},
        headers=disable_headers,
    )

    assert rejected.status_code == 409
    assert unconfirmed.status_code == 400
    assert accepted.status_code == 200
    with app.app_context():
        assert db.session.get(User, user_id).mfa_enabled is False
        assert TOTPAuthenticator.query.filter_by(user_id=user_id).count() == 0


def test_totp_enrollment_verification_is_rate_limited_before_code_check(
    app,
    client,
    monkeypatch,
):
    import app.totp_routes as totp_routes

    _create_user(app, "limited_totp_user")
    _activate_totp_feature(app, monkeypatch)
    _login(client, "limited_totp_user")
    monkeypatch.setattr(
        totp_routes,
        "check_reauth_rate_limit",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        totp_routes,
        "activate_totp_enrollment",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("TOTP verification must not run after throttling")
        ),
    )

    response = client.post(
        "/api/totp/enroll/verify",
        json={
            "token": "not-checked",
            "code": "123456",
            "confirm_enable_mfa": True,
        },
    )

    assert response.status_code == 429
