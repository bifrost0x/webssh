"""Account step-up HTTP contracts select the current login method."""

from datetime import datetime, timedelta, timezone
import time
from types import SimpleNamespace

import base64


def _create_and_login(app, client, username="account_step_route"):
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


def _set_login_methods(app, client, user_id, methods):
    from app.auth_assurance import authentication_session_for_token
    from app.models import User, db

    with client.session_transaction() as browser:
        opaque = browser["_auth_session"]
    with app.app_context():
        user = db.session.get(User, user_id)
        row = authentication_session_for_token(
            opaque,
            user_id,
            user.auth_generation,
        )
        assert row is not None
        row.methods_json = methods
        db.session.commit()


def _set_passkey_login(app, client, user_id, *, strong_authenticated_at):
    from app.auth_assurance import authentication_session_for_token
    from app.models import User, as_naive_utc, db

    with client.session_transaction() as browser:
        opaque = browser["_auth_session"]
    with app.app_context():
        user = db.session.get(User, user_id)
        row = authentication_session_for_token(
            opaque,
            user_id,
            user.auth_generation,
        )
        assert row is not None
        row.methods_json = '["passkey"]'
        row.assurance = "PHISHING_RESISTANT"
        row.strong_authenticated_at = as_naive_utc(strong_authenticated_at)
        db.session.commit()


def test_local_account_intent_uses_password_and_returns_bound_grant(
    app,
    client,
):
    from app.models import StepUpGrant, StepUpIntent

    user_id = _create_and_login(app, client)

    started = client.post("/api/account/step-up/intents", json={
        "action": "recovery.rotate",
        "target": user_id,
    })
    assert started.status_code == 200
    body = started.get_json()
    assert body["required_assurance"] == "BASIC"
    assert body["preferred_method"] == "password"
    assert body["methods"] == ["password"]
    assert isinstance(body["intent"], str) and body["intent"]

    verified = client.post("/api/account/step-up/password", json={
        "intent": body["intent"],
        "password": "password123",
    })

    assert verified.status_code == 200
    assert isinstance(verified.get_json()["grant"], str)
    with app.app_context():
        assert StepUpIntent.query.one().status == "completed"
        grant = StepUpGrant.query.one()
        assert grant.action == "recovery.rotate"


def test_recent_passkey_login_authorizes_initial_totp_enrollment(
    app,
    client,
    monkeypatch,
):
    import config
    from app.models import SecurityFeatureState, db

    monkeypatch.setattr(config, "TOTP_ENABLED", True)
    app.extensions["security_feature_readiness"]["totp"] = (True, None)
    user_id = _create_and_login(app, client, "passkey_totp_enrollment")
    _set_passkey_login(
        app,
        client,
        user_id,
        strong_authenticated_at=datetime.now(timezone.utc),
    )
    with app.app_context():
        db.session.add(SecurityFeatureState(feature="totp", enabled=True))
        db.session.commit()

    started = client.post("/api/account/step-up/intents", json={
        "action": "totp.enroll",
        "target": user_id,
    })

    assert started.status_code == 200
    body = started.get_json()
    assert body["method"] == "recent"
    assert isinstance(body["grant"], str) and body["grant"]


def test_stale_passkey_login_offers_passkey_for_initial_totp_enrollment(
    app,
    client,
    monkeypatch,
):
    import config
    from app.models import SecurityFeatureState, WebAuthnCredential, db

    monkeypatch.setattr(config, "TOTP_ENABLED", True)
    monkeypatch.setattr(config, "WEBAUTHN_ENABLED", True)
    app.extensions["security_feature_readiness"]["totp"] = (True, None)
    app.extensions["security_feature_readiness"]["passkey"] = (True, None)
    user_id = _create_and_login(app, client, "stale_passkey_totp")
    _set_passkey_login(
        app,
        client,
        user_id,
        strong_authenticated_at=(
            datetime.now(timezone.utc)
            - timedelta(seconds=config.STEP_UP_MAX_AGE_SECONDS + 1)
        ),
    )
    with app.app_context():
        db.session.add(SecurityFeatureState(feature="totp", enabled=True))
        db.session.add(WebAuthnCredential(
            user_id=user_id,
            credential_id=b"stale-passkey-totp-enrollment",
            public_key=b"public-key",
            sign_count=0,
            transports="[]",
        ))
        db.session.commit()

    started = client.post("/api/account/step-up/intents", json={
        "action": "totp.enroll",
        "target": user_id,
    })

    assert started.status_code == 200
    body = started.get_json()
    assert body["required_assurance"] == "BASIC"
    assert body["preferred_method"] == "passkey"
    assert body["methods"] == ["passkey"]
    assert isinstance(body["intent"], str) and body["intent"]


def test_account_password_rate_limit_runs_before_bcrypt(
    app,
    client,
    monkeypatch,
):
    import app.account_step_up_routes as routes
    from app.models import User

    user_id = _create_and_login(app, client, "limited_account_step")
    started = client.post("/api/account/step-up/intents", json={
        "action": "recovery.rotate",
        "target": user_id,
    }).get_json()
    monkeypatch.setattr(
        routes,
        "check_reauth_rate_limit",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        User,
        "check_password",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("bcrypt must not run after throttling")
        ),
    )

    response = client.post("/api/account/step-up/password", json={
        "intent": started["intent"],
        "password": "password123",
    })

    assert response.status_code == 429
    assert response.get_json()["code"] == "rate_limited"
    assert response.headers["Retry-After"] == "60"


def test_oidc_session_never_offers_or_accepts_local_password(
    app,
    client,
    monkeypatch,
):
    import config
    from app.models import OIDCIdentity, db

    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    app.extensions["security_feature_readiness"]["oidc"] = (True, None)
    user_id = _create_and_login(app, client, "oidc_step_route")
    _set_login_methods(app, client, user_id, '["oidc"]')
    with app.app_context():
        db.session.add(OIDCIdentity(
            user_id=user_id,
            issuer="https://issuer.example",
            subject="oidc-step-subject",
        ))
        db.session.commit()

    started = client.post("/api/account/step-up/intents", json={
        "action": "recovery.rotate",
        "target": user_id,
    })

    assert started.status_code == 200
    body = started.get_json()
    assert body["preferred_method"] == "oidc"
    assert body["methods"] == ["oidc"]
    assert "password" not in body["methods"]

    rejected = client.post("/api/account/step-up/password", json={
        "intent": body["intent"],
        "password": "password123",
    })
    assert rejected.status_code == 403
    assert rejected.get_json()["code"] == "step_up_failed"


def test_oidc_account_starts_are_bound_to_independent_persistent_intents(
    app,
    client,
    monkeypatch,
):
    from flask import redirect
    import config
    import app.oidc_routes as oidc_routes
    from app.models import OIDCIdentity, OIDCLoginState, db

    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    app.extensions["security_feature_readiness"]["oidc"] = (True, None)
    user_id = _create_and_login(app, client, "oidc_parallel_step")
    _set_login_methods(app, client, user_id, '["oidc"]')
    with app.app_context():
        db.session.add(OIDCIdentity(
            user_id=user_id,
            issuer="https://issuer.example",
            subject="parallel-subject",
        ))
        db.session.commit()

    class Provider:
        def authorize_redirect(self, _callback, **kwargs):
            return redirect(f"https://issuer.example/authorize?state={kwargs['state']}")

    monkeypatch.setattr(oidc_routes, "_client", lambda: Provider())
    first = client.post("/api/account/step-up/intents", json={
        "action": "recovery.rotate",
        "target": user_id,
    }).get_json()
    second = client.post("/api/account/step-up/intents", json={
        "action": "recovery.rotate",
        "target": user_id,
    }).get_json()

    first_started = client.post("/api/account/step-up/oidc/start", json={
        "intent": first["intent"],
        "continuation": "/security",
    })
    second_started = client.post("/api/account/step-up/oidc/start", json={
        "intent": second["intent"],
        "continuation": "/security",
    })

    assert first_started.status_code == 200
    assert second_started.status_code == 200
    with app.app_context():
        rows = OIDCLoginState.query.order_by(OIDCLoginState.id).all()
        assert len(rows) == 2
        assert rows[0].step_up_intent_id != rows[1].step_up_intent_id
        assert all(row.step_up_action is None for row in rows)
        assert all(row.step_up_target_hash is None for row in rows)


def test_ldap_session_uses_fresh_directory_resolution_and_bind(
    app,
    client,
    monkeypatch,
):
    import config
    import app.account_step_up_routes as routes
    from app.models import LDAPIdentity, StepUpIntent, db

    monkeypatch.setattr(config, "LDAP_ENABLED", True)
    app.extensions["security_feature_readiness"]["ldap"] = (True, None)
    user_id = _create_and_login(app, client, "ldap_step_route")
    _set_login_methods(app, client, user_id, '["ldap"]')
    with app.app_context():
        db.session.add(LDAPIdentity(
            user_id=user_id,
            provider="default",
            subject="stable-directory-subject",
            directory_username="ldap_step_route",
            distinguished_name="uid=old,dc=example,dc=com",
        ))
        db.session.commit()
    with client.session_transaction() as browser:
        browser["_ldap_verified_at"] = int(time.time())

    calls = []

    class Directory:
        settings = SimpleNamespace(provider="default")

        def lookup(self, username):
            calls.append(("lookup", username))
            return SimpleNamespace(
                provider="default",
                subject="stable-directory-subject",
                distinguished_name="uid=current,dc=example,dc=com",
            )

        def verify_password(self, distinguished_name, password):
            calls.append(("bind", distinguished_name, password))
            return password == "directory-password"

    monkeypatch.setattr(routes, "LDAPDirectory", Directory)

    started = client.post("/api/account/step-up/intents", json={
        "action": "recovery.rotate",
        "target": user_id,
    })
    assert started.status_code == 200
    body = started.get_json()
    assert body["preferred_method"] == "ldap"
    assert body["methods"] == ["ldap"]

    verified = client.post("/api/account/step-up/ldap", json={
        "intent": body["intent"],
        "password": "directory-password",
    })

    assert verified.status_code == 200
    assert calls == [
        ("lookup", "ldap_step_route"),
        ("bind", "uid=current,dc=example,dc=com", "directory-password"),
    ]
    with app.app_context():
        mapping = LDAPIdentity.query.filter_by(user_id=user_id).one()
        assert mapping.distinguished_name == "uid=current,dc=example,dc=com"
        assert StepUpIntent.query.one().approved_method == "ldap"


def test_ldap_reauth_rejects_changed_stable_subject_before_user_bind(
    app,
    client,
    monkeypatch,
):
    import config
    import app.account_step_up_routes as routes
    from app.models import LDAPIdentity, db

    monkeypatch.setattr(config, "LDAP_ENABLED", True)
    app.extensions["security_feature_readiness"]["ldap"] = (True, None)
    user_id = _create_and_login(app, client, "ldap_subject_change")
    _set_login_methods(app, client, user_id, '["ldap"]')
    with app.app_context():
        db.session.add(LDAPIdentity(
            user_id=user_id,
            provider="default",
            subject="expected-subject",
            directory_username="ldap_subject_change",
            distinguished_name="uid=old,dc=example,dc=com",
        ))
        db.session.commit()
    with client.session_transaction() as browser:
        browser["_ldap_verified_at"] = int(time.time())

    class Directory:
        settings = SimpleNamespace(provider="default")

        def lookup(self, _username):
            return SimpleNamespace(
                provider="default",
                subject="different-subject",
                distinguished_name="uid=replaced,dc=example,dc=com",
            )

        def verify_password(self, *_args):
            raise AssertionError("bind must not run after subject mismatch")

    monkeypatch.setattr(routes, "LDAPDirectory", Directory)
    started = client.post("/api/account/step-up/intents", json={
        "action": "recovery.rotate",
        "target": user_id,
    }).get_json()

    rejected = client.post("/api/account/step-up/ldap", json={
        "intent": started["intent"],
        "password": "directory-password",
    })

    assert rejected.status_code == 403
    assert rejected.get_json()["code"] == "step_up_failed"


def test_totp_can_complete_mfa_account_intent(app, client, monkeypatch):
    import config
    import app.account_step_up_routes as routes
    from app.models import SecurityFeatureState, TOTPAuthenticator, User, db

    monkeypatch.setattr(config, "TOTP_ENABLED", True)
    app.extensions["security_feature_readiness"]["totp"] = (True, None)
    user_id = _create_and_login(app, client, "totp_step_route")
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
        routes,
        "verify_totp",
        lambda received_user_id, code: (
            received_user_id == user_id and code == "123456"
        ),
    )

    started = client.post("/api/account/step-up/intents", json={
        "action": "recovery.rotate",
        "target": user_id,
    })
    assert started.status_code == 200
    body = started.get_json()
    assert body["required_assurance"] == "MFA"
    assert body["methods"] == ["totp"]

    verified = client.post("/api/account/step-up/totp", json={
        "intent": body["intent"],
        "code": "123456",
    })

    assert verified.status_code == 200
    assert verified.get_json()["method"] == "totp"


def test_passkey_challenges_are_independent_per_account_intent(
    app,
    client,
    monkeypatch,
):
    import config
    import app.account_step_up_routes as routes
    from app.models import User, WebAuthnCredential, db

    monkeypatch.setattr(config, "WEBAUTHN_ENABLED", True)
    app.extensions["security_feature_readiness"]["passkey"] = (True, None)
    user_id = _create_and_login(app, client, "passkey_step_route")
    credential_id = b"account-step-up-passkey"
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
    monkeypatch.setattr(
        routes,
        "verify_authentication_response",
        lambda **kwargs: SimpleNamespace(
            new_sign_count=kwargs["credential_current_sign_count"] + 1
        ),
    )

    first = client.post("/api/account/step-up/intents", json={
        "action": "recovery.rotate",
        "target": user_id,
    }).get_json()
    second = client.post("/api/account/step-up/intents", json={
        "action": "passkey.enroll",
        "target": user_id,
    }).get_json()

    first_options = client.post(
        "/api/account/step-up/passkey/options",
        json={"intent": first["intent"]},
    )
    second_options = client.post(
        "/api/account/step-up/passkey/options",
        json={"intent": second["intent"]},
    )
    assert first_options.status_code == 200
    assert second_options.status_code == 200

    encoded = base64.urlsafe_b64encode(credential_id).decode().rstrip("=")
    first_verified = client.post(
        "/api/account/step-up/passkey/verify",
        json={
            "intent": first["intent"],
            "credential": {"id": encoded},
        },
    )
    second_verified = client.post(
        "/api/account/step-up/passkey/verify",
        json={
            "intent": second["intent"],
            "credential": {"id": encoded},
        },
    )

    assert first_verified.status_code == 200
    assert second_verified.status_code == 200
    assert first_verified.get_json()["grant"] != (
        second_verified.get_json()["grant"]
    )
