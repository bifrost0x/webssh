"""Feature flag, linking, and local-login resilience for OIDC."""

import logging


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
            "password": "password123",
            "confirm_username": "oidc_target",
            "subject": "stable-subject",
        },
    )

    assert rejected.status_code == 403
    assert linked.status_code == 201
    with app.app_context():
        identity = OIDCIdentity.query.one()
        assert identity.user_id == target_id
        assert identity.issuer == "https://issuer.example"
        assert identity.subject == "stable-subject"


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
        def authorize_access_token(self, *, code_verifier):
            assert code_verifier == "callback-pkce-verifier"
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
