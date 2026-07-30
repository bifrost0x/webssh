"""Feature flags and ceremony option boundaries for WebAuthn routes."""

import base64
import logging
from types import SimpleNamespace


def _create_user(app, username="passkey_user"):
    from app.auth import register_user
    from app.models import db

    with app.app_context():
        user, error = register_user(username, "password123")
        assert error is None
        db.session.commit()
        return user.id


def _login(client, username="passkey_user"):
    response = client.post(
        "/login",
        data={"username": username, "password": "password123"},
    )
    assert response.status_code == 302


def test_webauthn_routes_are_hidden_when_disabled(app, client):
    _create_user(app)
    _login(client)

    response = client.post(
        "/api/webauthn/register/options",
        json={"password": "password123"},
    )

    assert response.status_code == 404


def test_registration_options_require_current_password_and_exact_rp(
    app, client, monkeypatch
):
    import config

    _create_user(app)
    _login(client)
    monkeypatch.setattr(config, "WEBAUTHN_ENABLED", True)
    monkeypatch.setattr(config, "WEBAUTHN_RP_ID", "localhost")
    monkeypatch.setattr(config, "WEBAUTHN_RP_NAME", "WebSSH Test")
    monkeypatch.setattr(config, "WEBAUTHN_ORIGIN", "https://localhost")

    rejected = client.post(
        "/api/webauthn/register/options",
        json={"password": "wrong"},
    )
    accepted = client.post(
        "/api/webauthn/register/options",
        json={"password": "password123"},
    )

    assert rejected.status_code == 403
    assert accepted.status_code == 200
    options = accepted.get_json()
    assert options["rp"]["id"] == "localhost"
    assert options["rp"]["name"] == "WebSSH Test"
    assert options["user"]["name"] == "passkey_user"
    assert options["authenticatorSelection"]["residentKey"] == "required"
    assert options["authenticatorSelection"]["userVerification"] == "required"
    assert base64.urlsafe_b64decode(options["challenge"] + "==")


def test_registration_options_rate_limit_before_bcrypt(
    app, client, monkeypatch
):
    import config
    import app.webauthn_routes as webauthn_routes
    from app.models import User

    _create_user(app)
    _login(client)
    monkeypatch.setattr(config, "WEBAUTHN_ENABLED", True)
    monkeypatch.setattr(
        webauthn_routes,
        "check_reauth_rate_limit",
        lambda *_args, **_kwargs: True,
        raising=False,
    )
    monkeypatch.setattr(
        User,
        "check_password",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("bcrypt must not run after reauth throttling")
        ),
    )

    response = client.post(
        "/api/webauthn/register/options",
        json={"password": "password123"},
    )

    assert response.status_code == 429
    assert response.get_json() == {"error": "Too many password attempts"}


def test_authentication_options_are_username_less(
    app, client, monkeypatch
):
    import config
    from app.models import WebAuthnCredential, db

    user_id = _create_user(app)
    with app.app_context():
        db.session.add(WebAuthnCredential(
            user_id=user_id,
            credential_id=b"variable-length-id",
            public_key=b"public-key",
            sign_count=0,
            transports="[]",
            name="test",
        ))
        db.session.commit()
    monkeypatch.setattr(config, "WEBAUTHN_ENABLED", True)
    monkeypatch.setattr(config, "WEBAUTHN_RP_ID", "localhost")

    known = client.post(
        "/api/webauthn/auth/options",
        json={"username": "passkey_user"},
    )
    unknown = client.post(
        "/api/webauthn/auth/options",
        json={"username": "missing-user"},
    )

    assert known.status_code == 200
    assert unknown.status_code == 200
    known_options = known.get_json()
    unknown_options = unknown.get_json()
    assert known_options.get("allowCredentials", []) == []
    assert unknown_options.get("allowCredentials", []) == []
    assert {
        key: value
        for key, value in known_options.items()
        if key != "challenge"
    } == {
        key: value
        for key, value in unknown_options.items()
        if key != "challenge"
    }
    with client.session_transaction() as browser_session:
        assert "webauthn_auth_username" not in browser_session


def test_webauthn_login_rate_limit_can_be_disabled(
    app, client, monkeypatch
):
    import config
    import app.webauthn_routes as webauthn_routes

    monkeypatch.setattr(config, "WEBAUTHN_ENABLED", True)
    monkeypatch.setattr(config, "RATELIMIT_ENABLED", False)
    monkeypatch.setattr(config, "WEBAUTHN_RP_ID", "localhost")
    monkeypatch.setattr(
        webauthn_routes,
        "check_rate_limit",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("disabled rate limiting must not be called")
        ),
    )

    response = client.post("/api/webauthn/auth/options", json={})

    assert response.status_code == 200


def test_existing_credentials_have_a_password_authenticated_upgrade_path(
    app, client, monkeypatch
):
    import config
    from app.models import WebAuthnCredential, db

    user_id = _create_user(app)
    legacy_id = b"legacy-non-resident-credential"
    with app.app_context():
        db.session.add(WebAuthnCredential(
            user_id=user_id,
            credential_id=legacy_id,
            public_key=b"legacy-public-key",
            sign_count=0,
            transports="[]",
            name="Legacy passkey",
        ))
        db.session.commit()
    _login(client)
    monkeypatch.setattr(config, "WEBAUTHN_ENABLED", True)
    monkeypatch.setattr(config, "WEBAUTHN_RP_ID", "localhost")
    monkeypatch.setattr(config, "WEBAUTHN_RP_NAME", "WebSSH Test")

    response = client.post(
        "/api/webauthn/register/options",
        json={
            "password": "password123",
            "legacy_upgrade": True,
        },
    )

    assert response.status_code == 200
    options = response.get_json()
    assert options["authenticatorSelection"]["residentKey"] == "required"
    assert options["excludeCredentials"] == []


def test_webauthn_registration_commit_failure_is_not_a_duplicate(
    app, client, monkeypatch
):
    import config
    import app.webauthn_routes as webauthn_routes
    from app.models import db

    _create_user(app)
    _login(client)
    monkeypatch.setattr(config, "WEBAUTHN_ENABLED", True)
    monkeypatch.setattr(config, "WEBAUTHN_RP_ID", "localhost")
    monkeypatch.setattr(config, "WEBAUTHN_ORIGIN", "https://localhost")
    monkeypatch.setattr(
        webauthn_routes,
        "consume_challenge",
        lambda **_kwargs: b"challenge",
    )
    monkeypatch.setattr(
        webauthn_routes,
        "verify_registration_response",
        lambda **_kwargs: SimpleNamespace(
            credential_id=b"new-credential",
            credential_public_key=b"public-key",
            sign_count=0,
        ),
    )
    monkeypatch.setattr(
        db.session,
        "commit",
        lambda: (_ for _ in ()).throw(RuntimeError("database unavailable")),
    )

    response = client.post(
        "/api/webauthn/register/verify",
        json={"credential": {"response": {"transports": []}}},
    )

    assert response.status_code == 503
    assert response.get_json() == {
        "error": "Passkey storage is temporarily unavailable"
    }


def test_authentication_resolves_account_from_discoverable_credential(
    app, client, monkeypatch
):
    import config
    import app.webauthn_routes as webauthn_routes
    from app.models import WebAuthnCredential, db

    user_id = _create_user(app)
    credential_id = b"discoverable-credential-id"
    with app.app_context():
        db.session.add(WebAuthnCredential(
            user_id=user_id,
            credential_id=credential_id,
            public_key=b"verified-public-key",
            sign_count=4,
            transports="[]",
            name="test",
        ))
        db.session.commit()
    monkeypatch.setattr(config, "WEBAUTHN_ENABLED", True)
    monkeypatch.setattr(config, "WEBAUTHN_RP_ID", "localhost")
    monkeypatch.setattr(config, "WEBAUTHN_ORIGIN", "https://localhost")
    monkeypatch.setattr(
        webauthn_routes,
        "verify_authentication_response",
        lambda **_kwargs: SimpleNamespace(new_sign_count=5),
    )

    options = client.post("/api/webauthn/auth/options", json={})
    assert options.status_code == 200
    encoded_id = base64.urlsafe_b64encode(credential_id).decode().rstrip("=")
    verified = client.post(
        "/api/webauthn/auth/verify",
        json={"credential": {"id": encoded_id}},
    )

    assert verified.status_code == 200
    assert verified.get_json() == {"ok": True}
    with client.session_transaction() as browser_session:
        assert browser_session["_user_id"] == str(user_id)
    with app.app_context():
        row = WebAuthnCredential.query.one()
        assert row.sign_count == 5
        assert row.last_used_at is not None


def test_rejected_webauthn_ceremonies_are_security_audited(
    app, client, monkeypatch, caplog
):
    import config

    _create_user(app)
    _login(client)
    monkeypatch.setattr(config, "WEBAUTHN_ENABLED", True)
    monkeypatch.setattr(config, "WEBAUTHN_RP_ID", "localhost")
    monkeypatch.setattr(config, "WEBAUTHN_ORIGIN", "https://localhost")

    with caplog.at_level(logging.WARNING, logger="security_audit"):
        registration = client.post(
            "/api/webauthn/register/verify",
            json={"credential": {"secret": "must-not-be-logged"}},
        )
        client.post("/logout")
        authentication = client.post(
            "/api/webauthn/auth/verify",
            json={"credential": {"id": "must-not-be-logged"}},
        )

    messages = [record.getMessage() for record in caplog.records]
    assert registration.status_code == 400
    assert authentication.status_code == 401
    assert any(
        message.startswith("WEBAUTHN_REGISTRATION_REJECTED")
        for message in messages
    )
    assert any(
        message.startswith("WEBAUTHN_AUTHENTICATION_REJECTED")
        for message in messages
    )
    assert all("must-not-be-logged" not in message for message in messages)


def test_webauthn_verify_rate_limit_bounds_rejection_audit_writes(
    app, client, monkeypatch, caplog
):
    import config
    import app.webauthn_routes as webauthn_routes

    monkeypatch.setattr(config, "WEBAUTHN_ENABLED", True)
    limited = iter((False, True))
    monkeypatch.setattr(
        webauthn_routes,
        "check_rate_limit",
        lambda *_args, **_kwargs: next(limited),
    )

    with caplog.at_level(logging.WARNING, logger="security_audit"):
        rejected = client.post(
            "/api/webauthn/auth/verify",
            json={"credential": {"id": "invalid"}},
        )
        throttled = client.post(
            "/api/webauthn/auth/verify",
            json={"credential": {"id": "invalid"}},
        )

    rejection_events = [
        record for record in caplog.records
        if record.getMessage().startswith(
            "WEBAUTHN_AUTHENTICATION_REJECTED"
        )
    ]
    assert rejected.status_code == 401
    assert throttled.status_code == 429
    assert len(rejection_events) == 1
