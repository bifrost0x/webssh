"""Feature flag, linking, and local-login resilience for OIDC."""

import logging

from tests.step_up_helpers import password_step_up_headers


def _create_user(app, username, *, is_admin=False):
    from app.auth import register_user
    from app.models import db

    with app.app_context():
        user, error = register_user(username, "password123")
        assert error is None
        user.is_admin = is_admin
        db.session.commit()
        return user.id


def _login(client, username):
    response = client.post(
        "/login",
        data={"username": username, "password": "password123"},
    )
    assert response.status_code == 302


def _step_up(client, action, target):
    return password_step_up_headers(client, action, target)[0]


def _prepare_oidc_callback(app, client, user_id, *, state, subject):
    from app.models import OIDCIdentity, db
    from app.oidc_service import create_login_state

    binding = f"binding-{state}"
    with app.app_context():
        db.session.add(OIDCIdentity(
            user_id=user_id,
            issuer="https://issuer.example",
            subject=subject,
        ))
        create_login_state(
            state=state,
            nonce=f"nonce-{state}",
            session_binding=binding,
            code_verifier=f"verifier-{state}",
        )
        db.session.commit()
    with client.session_transaction() as browser_session:
        browser_session["oidc_binding"] = binding


def _signed_provider(state, claims):
    class SignedProvider:
        def authorize_access_token(self, *, code_verifier, redirect_uri):
            assert code_verifier == f"verifier-{state}"
            assert redirect_uri == "https://localhost/oidc/callback"
            return {"id_token": "validated-by-provider-client"}

        def parse_id_token(self, token, *, nonce):
            assert token["id_token"] == "validated-by-provider-client"
            assert nonce == f"nonce-{state}"
            return claims

    return SignedProvider()


def test_oidc_routes_are_hidden_when_disabled_but_local_login_works(
    app, client
):
    _create_user(app, "local_admin", is_admin=True)

    oidc = client.get("/oidc/login")
    local = client.post(
        "/login",
        data={"username": "local_admin", "password": "password123"},
    )

    assert oidc.status_code == 404
    assert local.status_code == 302


def test_admin_link_requires_password_confirmation_and_stable_subject(
    app, client, monkeypatch
):
    import config
    from app.models import OIDCIdentity

    admin_id = _create_user(app, "oidc_admin", is_admin=True)
    target_id = _create_user(app, "oidc_target")
    assert admin_id != target_id
    _login(client, "oidc_admin")
    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    monkeypatch.setattr(config, "OIDC_ISSUER", "https://issuer.example")

    rejected = client.post(
        f"/admin/api/users/{target_id}/oidc-link",
        json={
            "password": "wrong",
            "confirm_username": "oidc_target",
            "subject": "stable-subject",
        },
    )
    linked = client.post(
        f"/admin/api/users/{target_id}/oidc-link",
        json={
            "confirm_username": "oidc_target",
            "subject": "stable-subject",
        },
        headers=_step_up(client, "oidc.link", target_id),
    )

    assert rejected.status_code == 403
    assert linked.status_code == 201
    with app.app_context():
        identity = OIDCIdentity.query.one()
        assert identity.user_id == target_id
        assert identity.issuer == "https://issuer.example"
        assert identity.subject == "stable-subject"


def test_admin_can_list_and_unlink_the_exact_oidc_identity(
    app, client, monkeypatch
):
    import config
    from app.models import OIDCIdentity, db

    _create_user(app, "unlink_oidc_admin", is_admin=True)
    target_id = _create_user(app, "unlink_oidc_target")
    other_id = _create_user(app, "unlink_oidc_other")
    _login(client, "unlink_oidc_admin")
    monkeypatch.setattr(config, "OIDC_ENABLED", True)

    with app.app_context():
        target_identity = OIDCIdentity(
            user_id=target_id,
            issuer="https://issuer.example",
            subject="target-subject",
        )
        other_identity = OIDCIdentity(
            user_id=other_id,
            issuer="https://issuer.example",
            subject="other-subject",
        )
        db.session.add_all([target_identity, other_identity])
        db.session.commit()
        target_identity_id = target_identity.id
        other_identity_id = other_identity.id

    listed = client.get(
        f"/admin/api/users/{target_id}/oidc-identities"
    )
    wrong_target = client.delete(
        f"/admin/api/users/{target_id}/oidc-identities/{other_identity_id}",
        json={
            "confirm_username": "unlink_oidc_target",
        },
        headers=_step_up(
            client, "oidc.unlink", f"{target_id}:{other_identity_id}"
        ),
    )
    removed = client.delete(
        f"/admin/api/users/{target_id}/oidc-identities/{target_identity_id}",
        json={
            "confirm_username": "unlink_oidc_target",
        },
        headers=_step_up(
            client, "oidc.unlink", f"{target_id}:{target_identity_id}"
        ),
    )

    assert listed.status_code == 200
    assert listed.get_json() == {
        "identities": [{
            "id": target_identity_id,
            "issuer": "https://issuer.example",
            "subject": "target-subject",
            "created_at": listed.get_json()["identities"][0]["created_at"],
        }]
    }
    assert listed.get_json()["identities"][0]["created_at"]
    assert wrong_target.status_code == 404
    assert removed.status_code == 200
    assert removed.get_json() == {"ok": True}
    with app.app_context():
        assert db.session.get(OIDCIdentity, target_identity_id) is None
        assert db.session.get(OIDCIdentity, other_identity_id) is not None


def test_oidc_unlink_requires_admin_reauthentication_and_confirmation(
    app, client, monkeypatch
):
    import config
    from app.models import OIDCIdentity, db

    _create_user(app, "reauth_oidc_admin", is_admin=True)
    target_id = _create_user(app, "reauth_oidc_target")
    _login(client, "reauth_oidc_admin")
    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    with app.app_context():
        identity = OIDCIdentity(
            user_id=target_id,
            issuer="https://issuer.example",
            subject="reauth-subject",
        )
        db.session.add(identity)
        db.session.commit()
        identity_id = identity.id

    _headers, wrong_password = password_step_up_headers(
        client,
        "oidc.unlink",
        f"{target_id}:{identity_id}",
        password="wrong",
        expected_status=403,
    )
    wrong_confirmation = client.delete(
        f"/admin/api/users/{target_id}/oidc-identities/{identity_id}",
        json={
            "confirm_username": "someone-else",
        },
        headers=_step_up(
            client, "oidc.unlink", f"{target_id}:{identity_id}"
        ),
    )

    assert wrong_password.status_code == 403
    assert wrong_confirmation.status_code == 400
    with app.app_context():
        assert db.session.get(OIDCIdentity, identity_id) is not None


def test_oidc_unlink_step_up_rate_limits_before_bcrypt(
    app, client, monkeypatch
):
    import config
    import app.step_up_routes as step_up_routes
    from app.models import User

    _create_user(app, "limited_unlink_admin", is_admin=True)
    target_id = _create_user(app, "limited_unlink_target")
    _login(client, "limited_unlink_admin")
    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    monkeypatch.setattr(
        step_up_routes,
        "check_reauth_rate_limit",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        User,
        "check_password",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("bcrypt must not run after reauth throttling")
        ),
    )

    response = client.post("/api/step-up/password", json={
        "action": "oidc.unlink",
        "target": f"{target_id}:1",
        "password": "password123",
    })

    assert response.status_code == 429


def test_oidc_unlink_commit_failure_preserves_the_mapping(
    app, client, monkeypatch
):
    import config
    from app.models import OIDCIdentity, db

    _create_user(app, "failing_unlink_admin", is_admin=True)
    target_id = _create_user(app, "failing_unlink_target")
    _login(client, "failing_unlink_admin")
    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    with app.app_context():
        identity = OIDCIdentity(
            user_id=target_id,
            issuer="https://issuer.example",
            subject="failure-subject",
        )
        db.session.add(identity)
        db.session.commit()
        identity_id = identity.id

    headers = _step_up(client, "oidc.unlink", f"{target_id}:{identity_id}")
    original_commit = db.session.commit
    commit_calls = 0

    def fail_identity_commit():
        nonlocal commit_calls
        commit_calls += 1
        if commit_calls == 2:
            raise RuntimeError("database unavailable")
        return original_commit()

    monkeypatch.setattr(
        db.session,
        "commit",
        fail_identity_commit,
    )
    response = client.delete(
        f"/admin/api/users/{target_id}/oidc-identities/{identity_id}",
        json={
            "confirm_username": "failing_unlink_target",
        },
        headers=headers,
    )

    assert response.status_code == 503
    assert response.get_json() == {
        "error": "OIDC identity storage is temporarily unavailable"
    }
    with app.app_context():
        assert db.session.get(OIDCIdentity, identity_id) is not None


def test_oidc_link_step_up_rate_limits_before_bcrypt(
    app, client, monkeypatch
):
    import config
    import app.step_up_routes as step_up_routes
    from app.models import User

    _create_user(app, "limited_oidc_admin", is_admin=True)
    target_id = _create_user(app, "limited_oidc_target")
    _login(client, "limited_oidc_admin")
    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    monkeypatch.setattr(
        step_up_routes,
        "check_reauth_rate_limit",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        User,
        "check_password",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("bcrypt must not run after reauth throttling")
        ),
    )

    response = client.post("/api/step-up/password", json={
        "action": "oidc.link",
        "target": target_id,
        "password": "password123",
    })

    assert response.status_code == 429
    assert response.get_json() == {"error": "Step-up authentication failed"}


def test_oidc_link_commit_failure_is_not_a_duplicate(
    app, client, monkeypatch
):
    import config
    from app.models import db

    _create_user(app, "failing_oidc_admin", is_admin=True)
    target_id = _create_user(app, "failing_oidc_target")
    _login(client, "failing_oidc_admin")
    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    monkeypatch.setattr(config, "OIDC_ISSUER", "https://issuer.example")
    headers = _step_up(client, "oidc.link", target_id)
    original_commit = db.session.commit
    commit_calls = 0

    def fail_identity_commit():
        nonlocal commit_calls
        commit_calls += 1
        if commit_calls == 2:
            raise RuntimeError("database unavailable")
        return original_commit()

    monkeypatch.setattr(
        db.session,
        "commit",
        fail_identity_commit,
    )

    response = client.post(
        f"/admin/api/users/{target_id}/oidc-link",
        json={
            "confirm_username": "failing_oidc_target",
            "subject": "stable-subject",
        },
        headers=headers,
    )

    assert response.status_code == 503
    assert response.get_json() == {
        "error": "OIDC identity storage is temporarily unavailable"
    }


def test_oidc_login_rate_limit_can_be_disabled(app, client, monkeypatch):
    import config
    import app.oidc_routes as oidc_routes

    class FakeClient:
        @staticmethod
        def authorize_redirect(callback, **_kwargs):
            assert callback == "https://localhost/oidc/callback"
            return "redirected", 200

    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    monkeypatch.setattr(config, "RATELIMIT_ENABLED", False)
    monkeypatch.setattr(
        oidc_routes,
        "check_rate_limit",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("disabled rate limiting must not be called")
        ),
    )
    monkeypatch.setattr(oidc_routes, "_client", lambda: FakeClient())

    response = client.get("/oidc/login")

    assert response.status_code == 200
    assert response.get_data(as_text=True) == "redirected"


def test_linked_oidc_callback_is_single_use_and_normalizes_issuer(
    app, client, monkeypatch
):
    import config
    import app.oidc_routes as oidc_routes
    from app.models import OIDCIdentity, db
    from app.oidc_service import create_login_state

    user_id = _create_user(app, "linked_oidc_user")
    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    monkeypatch.setattr(config, "OIDC_ISSUER", "https://issuer.example/")
    monkeypatch.setattr(config, "OIDC_ALLOWED_SUBJECTS", set())
    monkeypatch.setattr(config, "OIDC_ALLOWED_DOMAINS", set())

    with app.app_context():
        db.session.add(OIDCIdentity(
            user_id=user_id,
            issuer="https://issuer.example",
            subject="stable-subject",
        ))
        create_login_state(
            state="callback-state-token",
            nonce="callback-nonce",
            session_binding="browser-oidc-binding",
            code_verifier="callback-pkce-verifier",
        )
        db.session.commit()

    with client.session_transaction() as browser_session:
        browser_session["oidc_binding"] = "browser-oidc-binding"

    class FakeProvider:
        def authorize_access_token(self, *, code_verifier, redirect_uri):
            assert code_verifier == "callback-pkce-verifier"
            assert redirect_uri == "https://localhost/oidc/callback"
            return {
                "userinfo": {
                    "iss": "https://issuer.example/",
                    "sub": "stable-subject",
                    "email": "mutable@example.test",
                }
            }

    monkeypatch.setattr(oidc_routes, "_client", lambda: FakeProvider())

    accepted = client.get("/oidc/callback?state=callback-state-token")
    replayed = client.get("/oidc/callback?state=callback-state-token")

    assert accepted.status_code == 302
    assert replayed.status_code == 400


def test_basic_oidc_cannot_bypass_user_enabled_mfa(app, client, monkeypatch):
    import config
    import app.oidc_routes as oidc_routes
    from app.models import (
        AuthenticationSession,
        PendingAuthentication,
        User,
        WebAuthnCredential,
        db,
    )

    state = "basic-assurance-state"
    subject = "basic-assurance-subject"
    user_id = _create_user(app, "oidc_basic_mfa_user")
    with app.app_context():
        user = db.session.get(User, user_id)
        user.mfa_enabled = True
        db.session.add(WebAuthnCredential(
            user_id=user_id,
            credential_id=b"oidc-local-passkey",
            public_key=b"verified-public-key",
            sign_count=0,
            transports="[]",
            name="OIDC fallback passkey",
        ))
        db.session.commit()
    _prepare_oidc_callback(
        app,
        client,
        user_id,
        state=state,
        subject=subject,
    )
    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    monkeypatch.setattr(config, "OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setattr(config, "OIDC_ALLOWED_SUBJECTS", set())
    monkeypatch.setattr(config, "OIDC_ALLOWED_DOMAINS", set())
    monkeypatch.setattr(config, "OIDC_MFA_AMR_VALUES", frozenset({"mfa"}))
    monkeypatch.setattr(config, "WEBAUTHN_ENABLED", True)
    monkeypatch.setattr(
        oidc_routes,
        "_client",
        lambda: _signed_provider(state, {
            "iss": "https://issuer.example",
            "sub": subject,
            "amr": ["pwd"],
            "auth_time": 1234,
        }),
    )

    response = client.get(f"/oidc/callback?state={state}")

    assert response.status_code == 200
    assert b'id="passkeyLoginBtn"' in response.data
    assert b'id="recoveryMfaPanel"' not in response.data
    with client.session_transaction() as browser_session:
        assert "_user_id" not in browser_session
        assert browser_session.get("_pending_authentication")
    with app.app_context():
        pending = PendingAuthentication.query.one()
        assert pending.primary_method == "oidc"
        assert pending.assurance == "BASIC"
        assert AuthenticationSession.query.count() == 0


def test_basic_oidc_with_only_recovery_codes_fails_closed(
    app,
    client,
    monkeypatch,
):
    import config
    import app.oidc_routes as oidc_routes
    from app.models import (
        AuthenticationSession,
        PendingAuthentication,
        RecoveryCode,
        User,
        db,
    )
    from app.recovery_service import generate_codes

    state = "oidc-recovery-only-state"
    subject = "oidc-recovery-only-subject"
    user_id = _create_user(app, "oidc_recovery_only_user")
    with app.app_context():
        user = db.session.get(User, user_id)
        user.mfa_enabled = True
        generate_codes(user_id, count=1)
        db.session.commit()
    _prepare_oidc_callback(
        app,
        client,
        user_id,
        state=state,
        subject=subject,
    )
    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    monkeypatch.setattr(config, "OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setattr(config, "OIDC_ALLOWED_SUBJECTS", set())
    monkeypatch.setattr(config, "OIDC_ALLOWED_DOMAINS", set())
    monkeypatch.setattr(
        oidc_routes,
        "_client",
        lambda: _signed_provider(state, {
            "iss": "https://issuer.example",
            "sub": subject,
            "amr": ["pwd"],
            "auth_time": 1234,
        }),
    )

    response = client.get(f"/oidc/callback?state={state}")

    assert response.status_code == 403
    with client.session_transaction() as browser_session:
        assert "_user_id" not in browser_session
        assert "_pending_authentication" not in browser_session
    with app.app_context():
        assert PendingAuthentication.query.count() == 0
        assert AuthenticationSession.query.count() == 0
        assert RecoveryCode.query.filter_by(user_id=user_id).count() == 1


def test_explicit_signed_oidc_mfa_finalizes_without_local_prompt(
    app,
    client,
    monkeypatch,
):
    from datetime import datetime, timezone
    import config
    import app.oidc_routes as oidc_routes
    from app.models import AuthenticationSession, User, db

    state = "strong-assurance-state"
    subject = "strong-assurance-subject"
    user_id = _create_user(app, "oidc_strong_mfa_user")
    with app.app_context():
        user = db.session.get(User, user_id)
        user.mfa_enabled = True
        db.session.commit()
    _prepare_oidc_callback(
        app,
        client,
        user_id,
        state=state,
        subject=subject,
    )
    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    monkeypatch.setattr(config, "OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setattr(config, "OIDC_ALLOWED_SUBJECTS", set())
    monkeypatch.setattr(config, "OIDC_ALLOWED_DOMAINS", set())
    monkeypatch.setattr(config, "OIDC_MFA_AMR_VALUES", frozenset({"mfa"}))
    monkeypatch.setattr(
        oidc_routes,
        "_client",
        lambda: _signed_provider(state, {
            "iss": "https://issuer.example",
            "sub": subject,
            "amr": ["pwd", "mfa"],
            "auth_time": 1_700_000_000,
        }),
    )

    response = client.get(f"/oidc/callback?state={state}")

    assert response.status_code == 302
    with client.session_transaction() as browser_session:
        assert browser_session["_user_id"].startswith(f"{user_id}:0:")
    with app.app_context():
        row = AuthenticationSession.query.one()
        assert row.assurance == "MFA"
        assert row.methods_json == '["oidc"]'
        assert row.strong_authenticated_at == datetime.fromtimestamp(
            1_700_000_000,
            timezone.utc,
        ).replace(tzinfo=None)


def test_unsigned_userinfo_assurance_claims_remain_basic(
    app,
    client,
    monkeypatch,
):
    import config
    import app.oidc_routes as oidc_routes
    from app.models import AuthenticationSession

    state = "userinfo-assurance-state"
    subject = "userinfo-assurance-subject"
    user_id = _create_user(app, "oidc_userinfo_basic_user")
    _prepare_oidc_callback(
        app,
        client,
        user_id,
        state=state,
        subject=subject,
    )
    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    monkeypatch.setattr(config, "OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setattr(config, "OIDC_ALLOWED_SUBJECTS", set())
    monkeypatch.setattr(config, "OIDC_ALLOWED_DOMAINS", set())
    monkeypatch.setattr(config, "OIDC_MFA_AMR_VALUES", frozenset({"mfa"}))

    class UserinfoOnlyProvider:
        def authorize_access_token(self, **_kwargs):
            return {"userinfo": {
                "iss": "https://issuer.example",
                "sub": subject,
                "amr": ["mfa"],
                "auth_time": 1_700_000_000,
            }}

    monkeypatch.setattr(
        oidc_routes,
        "_client",
        lambda: UserinfoOnlyProvider(),
    )

    response = client.get(f"/oidc/callback?state={state}")

    assert response.status_code == 302
    with app.app_context():
        assert AuthenticationSession.query.one().assurance == "BASIC"


def test_oidc_provider_outage_does_not_break_local_login(
    app, client, monkeypatch
):
    import config
    import app.oidc_routes as oidc_routes
    from app.models import OIDCLoginState

    _create_user(app, "outage_admin", is_admin=True)
    monkeypatch.setattr(config, "OIDC_ENABLED", True)

    class UnavailableProvider:
        def authorize_redirect(self, *_args, **_kwargs):
            raise ConnectionError("provider unavailable")

    monkeypatch.setattr(oidc_routes, "_client", lambda: UnavailableProvider())

    outage = client.get("/oidc/login")
    local = client.post(
        "/login",
        data={"username": "outage_admin", "password": "password123"},
    )

    assert outage.status_code == 503
    assert local.status_code == 302
    with app.app_context():
        assert OIDCLoginState.query.count() == 0


def test_oidc_authorization_uses_server_side_pkce_verifier(
    app, client, monkeypatch
):
    import config
    import app.oidc_routes as oidc_routes

    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    observed = {}

    class Provider:
        def authorize_redirect(self, _callback, **kwargs):
            observed.update(kwargs)
            return "redirected"

    monkeypatch.setattr(oidc_routes, "_client", lambda: Provider())

    response = client.get("/oidc/login")

    assert response.status_code == 200
    assert response.get_data(as_text=True) == "redirected"
    assert "code_verifier" not in observed
    assert observed["code_challenge_method"] == "S256"
    assert len(observed["code_challenge"]) == 43


def test_oidc_step_up_requests_fresh_provider_authentication(
    app,
    monkeypatch,
):
    from flask import session
    import config
    import app.oidc_routes as oidc_routes
    from app.models import OIDCLoginState

    observed = {}

    class Provider:
        def authorize_redirect(self, _callback, **kwargs):
            observed.update(kwargs)
            return "redirected"

    monkeypatch.setattr(
        config,
        "OIDC_STEP_UP_ACR_VALUES",
        frozenset({"urn:example:aal3", "urn:example:aal2"}),
    )
    monkeypatch.setattr(oidc_routes, "_client", lambda: Provider())

    with app.test_request_context("/api/step-up/oidc"):
        response = oidc_routes.begin_oidc_step_up(
            action="user.lock",
            target_hash="b" * 64,
            continuation="/admin",
        )
        assert session.get("oidc_binding")
    with app.app_context():
        row = OIDCLoginState.query.one()
        assert row.purpose == "step_up"
        assert row.step_up_action == "user.lock"
        assert row.step_up_target_hash == "b" * 64

    assert response == "redirected"
    assert observed["prompt"] == "login"
    assert observed["max_age"] == 0
    assert observed["acr_values"] == (
        "urn:example:aal2 urn:example:aal3"
    )
    assert "code_verifier" not in observed


def test_oidc_step_up_state_cannot_be_replayed_as_a_login(
    app,
    client,
    monkeypatch,
):
    import config
    import app.oidc_routes as oidc_routes
    from app.models import OIDCLoginState
    from app.oidc_service import create_login_state

    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    with app.app_context():
        create_login_state(
            state="step-up-callback-state",
            nonce="step-up-callback-nonce",
            session_binding="step-up-callback-binding",
            code_verifier="step-up-callback-verifier",
            purpose="step_up",
            requested_acr="urn:example:aal2",
            step_up_action="user.lock",
            step_up_target_hash="c" * 64,
        )
    with client.session_transaction() as browser_session:
        browser_session["oidc_binding"] = "step-up-callback-binding"
    monkeypatch.setattr(
        oidc_routes,
        "_client",
        lambda: (_ for _ in ()).throw(
            AssertionError("provider must not receive a login callback")
        ),
    )

    rejected = client.get(
        "/oidc/callback?state=step-up-callback-state"
    )

    assert rejected.status_code == 403
    with app.app_context():
        assert OIDCLoginState.query.count() == 0


def test_oidc_step_up_issues_one_exact_grant_for_same_admin(
    app,
    client,
    monkeypatch,
):
    import time

    import config
    import app.oidc_routes as oidc_routes
    from app.models import OIDCIdentity, db
    from app.oidc_service import create_login_state
    from app.step_up import hash_step_up_target

    user_id = _create_user(app, "stepup_oidc_admin", is_admin=True)
    _login(client, "stepup_oidc_admin")
    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    monkeypatch.setattr(config, "OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setattr(
        config, "OIDC_MFA_ACR_VALUES", frozenset({"urn:example:aal2"})
    )
    state = "successful-step-up-state"
    binding = "successful-step-up-binding"
    with app.app_context():
        db.session.add(OIDCIdentity(
            user_id=user_id,
            issuer="https://issuer.example",
            subject="stepup-admin-subject",
        ))
        create_login_state(
            state=state,
            nonce=f"nonce-{state}",
            session_binding=binding,
            code_verifier=f"verifier-{state}",
            purpose="step_up",
            continuation="/admin",
            requested_acr="urn:example:aal2",
            step_up_action="settings.update",
            step_up_target_hash=hash_step_up_target("global"),
        )
        db.session.commit()
    with client.session_transaction() as browser_session:
        browser_session["oidc_binding"] = binding
    monkeypatch.setattr(
        oidc_routes,
        "_client",
        lambda: _signed_provider(state, {
            "iss": "https://issuer.example",
            "sub": "stepup-admin-subject",
            "acr": "urn:example:aal2",
            "amr": ["mfa"],
            "auth_time": int(time.time()),
        }),
    )

    callback = client.get(f"/oidc/callback?state={state}")
    result = client.get("/api/step-up/oidc/result")
    changed = client.post(
        "/admin/api/settings",
        json={"registration_enabled": False},
        headers={"X-WebSSH-Step-Up": result.get_json()["grant"]},
    )

    assert callback.status_code == 302
    assert callback.headers["Location"].endswith("/admin")
    assert result.status_code == 200
    assert changed.status_code == 200
    assert client.get("/api/step-up/oidc/result").status_code == 404


def test_oidc_callback_rejections_are_security_audited(
    app, client, monkeypatch, caplog
):
    import config
    import app.oidc_routes as oidc_routes
    from app.models import db
    from app.oidc_service import create_login_state

    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    monkeypatch.setattr(config, "OIDC_ISSUER", "https://issuer.example")

    with caplog.at_level(logging.WARNING, logger="security_audit"):
        invalid_state = client.get(
            "/oidc/callback?state=must-not-be-logged"
        )

        with app.app_context():
            create_login_state(
                state="provider-failure-state",
                nonce="provider-failure-nonce",
                session_binding="provider-failure-binding",
                code_verifier="provider-failure-verifier",
            )
            db.session.commit()
        with client.session_transaction() as browser_session:
            browser_session["oidc_binding"] = "provider-failure-binding"

        class FailingProvider:
            def authorize_access_token(self, **_kwargs):
                raise ConnectionError("provider-secret-must-not-be-logged")

        monkeypatch.setattr(
            oidc_routes,
            "_client",
            lambda: FailingProvider(),
        )
        provider_failure = client.get(
            "/oidc/callback?state=provider-failure-state"
        )

    messages = [record.getMessage() for record in caplog.records]
    assert invalid_state.status_code == 400
    assert provider_failure.status_code == 503
    assert any(
        message.startswith("OIDC_STATE_REJECTED")
        for message in messages
    )
    assert any(
        message.startswith("OIDC_CALLBACK_REJECTED")
        for message in messages
    )
    assert all("must-not-be-logged" not in message for message in messages)


def test_oidc_callback_rate_limit_bounds_rejection_audit_writes(
    app, client, monkeypatch, caplog
):
    import config
    import app.oidc_routes as oidc_routes

    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    limited = iter((False, True))
    monkeypatch.setattr(
        oidc_routes,
        "check_rate_limit",
        lambda *_args, **_kwargs: next(limited),
    )

    with caplog.at_level(logging.WARNING, logger="security_audit"):
        rejected = client.get("/oidc/callback?state=invalid")
        throttled = client.get("/oidc/callback?state=invalid")

    rejection_events = [
        record for record in caplog.records
        if record.getMessage().startswith("OIDC_STATE_REJECTED")
    ]
    assert rejected.status_code == 400
    assert throttled.status_code == 429
    assert len(rejection_events) == 1
