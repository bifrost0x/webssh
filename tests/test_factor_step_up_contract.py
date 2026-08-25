"""Factor mutations consume exact account grants instead of inline passwords."""

from tests.step_up_helpers import account_password_step_up_headers


def _create_login(app, client, username):
    from app.auth import register_user
    from app.models import db

    with app.app_context():
        user, error = register_user(username, "password123")
        assert error is None
        db.session.commit()
        user_id = user.id
    response = client.post("/login", data={
        "username": username,
        "password": "password123",
    })
    assert response.status_code == 302
    return user_id


def _strong_account_headers(app, client, action, target):
    from app.auth_assurance import authentication_session_for_token
    from app.models import User, db
    from app.step_up import (
        approve_account_step_up_intent,
        claim_account_step_up_grant,
        create_account_step_up_intent,
    )

    with client.session_transaction() as browser:
        opaque = browser["_auth_session"]
        login_id = browser["_user_id"]
    user_id = int(str(login_id).split(":", 1)[0])
    with app.app_context():
        user = db.session.get(User, user_id)
        auth_session = authentication_session_for_token(
            opaque,
            user.id,
            user.auth_generation,
        )
        token, _intent = create_account_step_up_intent(
            auth_session,
            action,
            target,
        )
        approve_account_step_up_intent(
            token,
            auth_session,
            assurance="MFA",
            method="totp",
        )
        grant = claim_account_step_up_grant(token, auth_session)
    return {"X-WebSSH-Step-Up": grant}


def test_cached_inline_password_contract_is_rejected_for_passkey_enrollment(
    app,
    client,
    monkeypatch,
):
    import config

    monkeypatch.setattr(config, "WEBAUTHN_ENABLED", True)
    user_id = _create_login(app, client, "legacy_passkey_contract")

    rejected = client.post(
        "/api/webauthn/register/options",
        json={"password": "password123"},
    )
    headers, _verified = account_password_step_up_headers(
        client,
        "passkey.enroll",
        user_id,
    )
    accepted = client.post(
        "/api/webauthn/register/options",
        json={},
        headers=headers,
    )

    assert rejected.status_code == 409
    assert rejected.get_json()["code"] == "security_ui_upgrade_required"
    assert accepted.status_code == 200


def test_wrong_account_grant_is_consumed_before_factor_mutation(
    app,
    client,
    monkeypatch,
):
    import config

    monkeypatch.setattr(config, "WEBAUTHN_ENABLED", True)
    user_id = _create_login(app, client, "wrong_factor_grant")
    headers, _verified = account_password_step_up_headers(
        client,
        "recovery.rotate",
        user_id,
    )

    wrong = client.post(
        "/api/webauthn/register/options",
        json={},
        headers=headers,
    )
    replay = client.post(
        "/api/recovery-codes",
        json={},
        headers=headers,
    )

    assert wrong.status_code == 403
    assert wrong.get_json()["code"] == "step_up_required"
    assert replay.status_code == 403


def test_totp_enrollment_and_recovery_rotation_use_exact_account_grants(
    app,
    client,
    monkeypatch,
):
    import config
    from app.models import SecurityFeatureState, db

    monkeypatch.setattr(config, "TOTP_ENABLED", True)
    app.extensions["security_feature_readiness"]["totp"] = (True, None)
    user_id = _create_login(app, client, "factor_grant_user")
    with app.app_context():
        db.session.add(SecurityFeatureState(feature="totp", enabled=True))
        db.session.commit()

    totp_headers, _verified = account_password_step_up_headers(
        client,
        "totp.enroll",
        user_id,
    )
    totp = client.post(
        "/api/totp/enroll",
        json={"label": "Phone"},
        headers=totp_headers,
    )
    recovery_headers, _verified = account_password_step_up_headers(
        client,
        "recovery.rotate",
        user_id,
    )
    recovery = client.post(
        "/api/recovery-codes",
        json={},
        headers=recovery_headers,
    )

    assert totp.status_code == 200
    assert recovery.status_code == 200
    assert len(recovery.get_json()["codes"]) == 10


def test_last_local_factor_cannot_be_deleted_while_mfa_is_enabled(
    app,
    client,
    monkeypatch,
):
    import config
    from app.models import User, WebAuthnCredential, db

    monkeypatch.setattr(config, "WEBAUTHN_ENABLED", True)
    user_id = _create_login(app, client, "last_factor_user")
    with app.app_context():
        user = db.session.get(User, user_id)
        user.mfa_enabled = True
        credential = WebAuthnCredential(
            user_id=user_id,
            credential_id=b"last-local-factor",
            public_key=b"public-key",
            sign_count=0,
            transports="[]",
        )
        db.session.add(credential)
        db.session.commit()
        credential_id = credential.id
    headers = _strong_account_headers(
        app,
        client,
        "passkey.delete",
        credential_id,
    )

    response = client.delete(
        f"/api/webauthn/credentials/{credential_id}",
        json={},
        headers=headers,
    )

    assert response.status_code == 409
    assert response.get_json()["code"] == "last_factor_required"
    with app.app_context():
        assert db.session.get(WebAuthnCredential, credential_id) is not None


def test_mfa_disable_requires_strong_grant_and_removes_all_totp_authenticators(
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

    monkeypatch.setattr(config, "TOTP_ENABLED", True)
    app.extensions["security_feature_readiness"]["totp"] = (True, None)
    user_id = _create_login(app, client, "disable_mfa_grant")
    with app.app_context():
        user = db.session.get(User, user_id)
        user.mfa_enabled = True
        db.session.add(SecurityFeatureState(feature="totp", enabled=True))
        db.session.add_all((
            TOTPAuthenticator(
                user_id=user_id,
                encrypted_secret=b"encrypted-secret-a",
                label="Phone",
                active=True,
            ),
            TOTPAuthenticator(
                user_id=user_id,
                encrypted_secret=b"encrypted-secret-b",
                label="Tablet",
                active=True,
            ),
            WebAuthnCredential(
                user_id=user_id,
                credential_id=b"unrelated-passkey",
                public_key=b"public-key",
                sign_count=0,
                transports="[]",
            ),
        ))
        db.session.commit()
    headers = _strong_account_headers(
        app,
        client,
        "mfa.disable",
        user_id,
    )

    response = client.post(
        "/api/account/mfa/disable",
        json={"confirm_disable_mfa": True},
        headers=headers,
    )

    assert response.status_code == 200
    with app.app_context():
        assert db.session.get(User, user_id).mfa_enabled is False
        assert TOTPAuthenticator.query.filter_by(user_id=user_id).count() == 0
        assert WebAuthnCredential.query.filter_by(
            user_id=user_id,
            credential_id=b"unrelated-passkey",
        ).count() == 1
