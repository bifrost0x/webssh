"""Action-bound administrator step-up authorization."""

from datetime import datetime, timezone


def _create_admin(app, username="stepup_admin", *, mfa_enabled=False):
    from app.auth import register_user
    from app.models import db

    with app.app_context():
        user, error = register_user(username, "password123")
        assert error is None
        user.is_admin = True
        user.mfa_enabled = mfa_enabled
        db.session.commit()
        return user.id


def _login(client, username="stepup_admin"):
    response = client.post("/login", data={
        "username": username,
        "password": "password123",
    })
    assert response.status_code == 302


def _password_grant(client, action, target):
    response = client.post("/api/step-up/password", json={
        "action": action,
        "target": target,
        "password": "password123",
    })
    assert response.status_code == 200
    return response.get_json()["grant"]


def test_sensitive_route_requires_step_up(app, client):
    _create_admin(app)
    _login(client)

    response = client.post(
        "/admin/api/settings",
        json={"registration_enabled": False},
    )

    assert response.status_code == 403
    assert response.get_json() == {
        "error": "Additional authentication is required",
        "code": "step_up_required",
    }


def test_password_grant_is_exact_and_single_use(app, client):
    _create_admin(app)
    _login(client)
    grant = _password_grant(client, "settings.update", "global")

    accepted = client.post(
        "/admin/api/settings",
        json={"registration_enabled": False},
        headers={"X-WebSSH-Step-Up": grant},
    )
    replayed = client.post(
        "/admin/api/settings",
        json={"registration_enabled": False},
        headers={"X-WebSSH-Step-Up": grant},
    )

    assert accepted.status_code == 200
    assert replayed.status_code == 403


def test_wrong_target_consumes_grant(app, client):
    _create_admin(app)
    _login(client)
    grant = _password_grant(client, "security_feature.update", "totp")

    wrong = client.post(
        "/admin/api/security-features/passkey",
        json={"enabled": False},
        headers={"X-WebSSH-Step-Up": grant},
    )
    replay = client.post(
        "/admin/api/security-features/totp",
        json={"enabled": False},
        headers={"X-WebSSH-Step-Up": grant},
    )

    assert wrong.status_code == 403
    assert replay.status_code == 403


def test_grant_is_bound_to_authentication_session(app, client):
    import hashlib
    import secrets

    from app.models import AuthenticationSession, db

    _create_admin(app)
    _login(client)
    grant = _password_grant(client, "settings.update", "global")
    other = app.test_client()
    opaque = secrets.token_urlsafe(32)
    with app.app_context():
        first = AuthenticationSession.query.order_by(
            AuthenticationSession.id.asc()
        ).first()
        second = AuthenticationSession(
            session_hash=hashlib.sha256(opaque.encode()).hexdigest(),
            user_id=first.user_id,
            assurance=first.assurance,
            methods_json=first.methods_json,
            authenticated_at=first.authenticated_at,
            strong_authenticated_at=first.strong_authenticated_at,
            auth_generation=first.auth_generation,
            expires_at=first.expires_at,
        )
        db.session.add(second)
        db.session.commit()
        user_id = second.user_id
        generation = second.auth_generation
    with other.session_transaction() as browser:
        browser["_user_id"] = f"{user_id}:{generation}:{opaque}"
        browser["_auth_session"] = opaque
        browser["_fresh"] = True

    response = other.post(
        "/admin/api/settings",
        json={"registration_enabled": False},
        headers={"X-WebSSH-Step-Up": grant},
    )

    assert response.status_code == 403


def test_password_step_up_is_disabled_when_account_uses_mfa(app, client):
    from app.models import User, db

    user_id = _create_admin(app)
    _login(client)
    with app.app_context():
        user = db.session.get(User, user_id)
        user.mfa_enabled = True
        db.session.commit()
        db.session.remove()

    response = client.post("/api/step-up/password", json={
        "action": "settings.update",
        "target": "global",
        "password": "password123",
    })

    assert response.status_code == 403
    assert response.get_json()["error"] == "Step-up authentication failed"


def test_administrator_step_up_cannot_mint_account_factor_grants(app, client):
    _create_admin(app)
    _login(client)

    response = client.post("/api/step-up/password", json={
        "action": "recovery.rotate",
        "target": 1,
        "password": "password123",
    })

    assert response.status_code == 400
    assert "grant" not in response.get_json()


def test_recent_phishing_resistant_login_can_mint_exact_grant(app, client):
    _create_admin(app)
    _login(client)
    from app.models import db
    with client.session_transaction() as browser:
        auth_token = browser["_auth_session"]
    from app.auth_assurance import authentication_session_for_token
    with app.app_context():
        row = authentication_session_for_token(auth_token, 1, 0)
        assert row is not None
        row.assurance = "PHISHING_RESISTANT"
        row.strong_authenticated_at = datetime.now(timezone.utc)
        db.session.commit()

    response = client.post("/api/step-up/intents", json={
        "action": "settings.update",
        "target": "global",
    })

    assert response.status_code == 200
    assert response.get_json()["grant"]
    assert response.get_json()["method"] == "recent"


def test_totp_step_up_can_authorize_mfa_account(
    app, client, monkeypatch
):
    import app.step_up_routes as step_up_routes
    from app.models import User, db

    user_id = _create_admin(app)
    _login(client)
    with app.app_context():
        user = db.session.get(User, user_id)
        user.mfa_enabled = True
        db.session.commit()
        db.session.remove()
    monkeypatch.setattr(step_up_routes, "_factor_available", lambda name: name == "totp")
    monkeypatch.setattr(step_up_routes, "verify_totp", lambda user_id, code: code == "123456")

    verified = client.post("/api/step-up/totp", json={
        "action": "settings.update",
        "target": "global",
        "code": "123456",
    })
    changed = client.post(
        "/admin/api/settings",
        json={"registration_enabled": False},
        headers={"X-WebSSH-Step-Up": verified.get_json()["grant"]},
    )

    assert verified.status_code == 200
    assert changed.status_code == 200


def test_passkey_step_up_requires_exact_owned_credential(
    app, client, monkeypatch
):
    import base64
    from types import SimpleNamespace

    import app.step_up_routes as step_up_routes
    from app.models import User, WebAuthnCredential, db

    user_id = _create_admin(app)
    _login(client)
    credential_id = b"step-up-credential"
    with app.app_context():
        user = db.session.get(User, user_id)
        user.mfa_enabled = True
        db.session.add(WebAuthnCredential(
            user_id=user_id,
            credential_id=credential_id,
            public_key=b"public-key",
            sign_count=0,
            transports="[]",
        ))
        db.session.commit()
        db.session.remove()
    monkeypatch.setattr(
        step_up_routes, "_factor_available", lambda name: name == "passkey"
    )
    monkeypatch.setattr(
        step_up_routes,
        "verify_authentication_response",
        lambda **_kwargs: SimpleNamespace(new_sign_count=1),
    )
    encoded_id = base64.urlsafe_b64encode(credential_id).decode().rstrip("=")

    options = client.post("/api/step-up/passkey/options", json={
        "action": "settings.update",
        "target": "global",
    })
    verified = client.post("/api/step-up/passkey/verify", json={
        "credential": {"id": encoded_id},
    })

    assert options.status_code == 200
    assert verified.status_code == 200
    assert verified.get_json()["grant"]
