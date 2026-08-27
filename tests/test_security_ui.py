"""Visibility and authentication boundaries for security management UI."""

import time


def _create_user(app, username, *, is_admin=False):
    from app.auth import register_user
    from app.models import db

    with app.app_context():
        user, error = register_user(username, "password123")
        assert error is None
        user.is_admin = is_admin
        db.session.commit()


def _login(client, username):
    response = client.post(
        "/login",
        data={"username": username, "password": "password123"},
    )
    assert response.status_code == 302


def test_security_center_requires_login_and_exposes_management_controls(
    app, client, monkeypatch
):
    import config

    _create_user(app, "security_user")
    monkeypatch.setattr(config, "WEBAUTHN_ENABLED", True)

    anonymous = client.get("/security")
    _login(client, "security_user")
    authenticated = client.get("/security")

    assert anonymous.status_code == 302
    assert authenticated.status_code == 200
    for control in (
        b'id="hostKeyList"',
        b'id="recoveryGenerateBtn"',
        b'id="passkeyList"',
        b'id="passkeyUpgradeBtn"',
        b'id="securityConfirmationModal"',
        b'id="securityConfirmationPassword"',
    ):
        assert control in authenticated.data
    assert b'js/security-ui.js' in authenticated.data
    assert b'non-discoverable passkey' in authenticated.data
    assert b'id="securityAssuranceOverview"' in authenticated.data
    assert b'id="securityCurrentMethod"' in authenticated.data
    assert b'WebSSH password' in authenticated.data
    assert b'How security changes are confirmed' in authenticated.data
    assert b'WebSSH password from this sign-in' in authenticated.data
    assert b'id="securityCurrentAssurance"' not in authenticated.data
    assert b'BASIC' not in authenticated.data


def test_settings_center_combines_preferences_security_and_admin_navigation(
    app, client
):
    _create_user(app, "settings_admin", is_admin=True)
    _login(client, "settings_admin")

    response = client.get("/settings")

    assert response.status_code == 200
    assert b'Settings Center' in response.data
    assert b'data-account-section="preferences"' in response.data
    assert b'data-account-section="security-overview"' in response.data
    assert b'data-account-section="factors"' in response.data
    assert b'id="settingsSecurityMethodsTitle"' in response.data
    assert b'data-account-jump="factors"' in response.data
    assert b'data-tab="users"' in response.data
    assert b'id="tab-users"' in response.data
    assert b'id="securityFeatureList"' in response.data
    assert b'class="settings-context-rail"' in response.data
    assert b'static/images/webssh-logo.svg' in response.data
    assert b'settings-back-link' in response.data
    assert b'id="settingsMobileSection"' in response.data
    assert b'id="adminUserFilterStatus"' in response.data
    assert b'href="/admin#' not in response.data
    assert b'id="settingsModal"' not in response.data


def test_standard_user_settings_do_not_expose_administration_navigation(
    app, client
):
    _create_user(app, "settings_user")
    _login(client, "settings_user")

    response = client.get("/settings")

    assert response.status_code == 200
    assert b'data-account-section="preferences"' in response.data
    assert b'Administration' not in response.data
    assert b'data-tab="users"' not in response.data


def test_account_preferences_api_validates_and_persists_supported_values(
    app, client
):
    _create_user(app, "preferences_user")
    _login(client, "preferences_user")

    updated = client.post("/api/account/preferences", json={
        "theme": "obsidian",
        "confirm_session_close": True,
        "disconnect_session_action": "close",
    })
    invalid = client.post(
        "/api/account/preferences",
        json={"disconnect_session_action": "delete"},
    )
    rendered = client.get("/settings")

    assert updated.status_code == 200
    assert updated.get_json()["settings"] == {
        "theme": "obsidian",
        "notepad": "",
        "confirm_session_close": True,
        "disconnect_session_action": "close",
    }
    assert invalid.status_code == 400
    assert b'data-theme="obsidian"' in rendered.data
    assert b'data-confirm-session-close="true"' in rendered.data
    assert b'data-disconnect-session-action="close"' in rendered.data


def test_login_shows_only_enabled_external_authentication(
    app, client, monkeypatch
):
    import config

    _create_user(app, "login_options_user")
    disabled = client.get("/login")
    monkeypatch.setattr(config, "WEBAUTHN_ENABLED", True)
    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    enabled = client.get("/login")

    assert b'id="passkeyLoginBtn"' not in disabled.data
    assert b'id="oidcLoginBtn"' not in disabled.data
    assert b'id="authenticationSource"' not in disabled.data
    assert b'id="localLoginForm" class="auth-source-form"' in disabled.data
    assert b'id="recoveryLoginBtn"' not in disabled.data
    assert b'id="recoveryLoginPanel"' not in disabled.data
    assert b'id="recoveryMfaPanel"' not in disabled.data
    assert b'id="passkeyLoginBtn"' in enabled.data
    assert b'id="oidcLoginBtn"' in enabled.data
    assert b'name="webauthn-configured-origin"' in enabled.data
    assert b'id="authNotificationContainer"' in enabled.data


def test_ldap_managed_security_center_offers_passkeys_but_not_local_password(
    app,
    client,
    monkeypatch,
):
    import config
    from app import ldap_session
    from app.models import LDAPIdentity, User, db

    _create_user(app, "ldap_security_user")
    _login(client, "ldap_security_user")
    monkeypatch.setattr(config, "LDAP_ENABLED", True)
    monkeypatch.setattr(config, "WEBAUTHN_ENABLED", True)
    monkeypatch.setattr(ldap_session, "revalidate_user", lambda _user: True)
    with app.app_context():
        user = User.query.filter_by(username="ldap_security_user").one()
        db.session.add(LDAPIdentity(
            user_id=user.id,
            provider="default",
            subject="stable-security-id",
            directory_username="ldap_security_user",
            distinguished_name="uid=ldap_security_user,dc=example,dc=com",
        ))
        db.session.commit()
    from flask import g
    g.pop("_login_user", None)
    db.session.expire_all()
    with client.session_transaction() as browser_session:
        browser_session["_ldap_verified_at"] = int(time.time())

    response = client.get("/security")

    assert response.status_code == 200
    assert b'id="securityChangePasswordBtn"' not in response.data
    assert b'id="passkeyAddBtn"' in response.data
    assert b'id="passkeyUpgradeBtn"' in response.data
    assert b'id="recoveryGenerateBtn"' in response.data
    assert b'id="ldapManagedNotice"' in response.data


def test_admin_page_exposes_audit_and_global_host_key_controls(app, client):
    _create_user(app, "security_admin", is_admin=True)
    _login(client, "security_admin")

    response = client.get("/settings")

    assert response.status_code == 200
    assert b'id="auditExportBtn"' in response.data
    assert b'id="auditRetention"' in response.data
    assert b'id="globalHostKeyList"' in response.data
    assert b'id="securityActionModal"' in response.data
    assert b'id="securityActionConfirmation"' in response.data
    assert b'id="stepUpModal"' in response.data
    assert b'id="stepUpPassword"' in response.data
    assert b'id="stepUpTotp"' in response.data
    assert b'js/security-ui.js' in response.data


def test_security_features_can_be_rolled_back_independently(
    app, client, monkeypatch
):
    import config

    _create_user(app, "rollback_user", is_admin=True)
    _login(client, "rollback_user")
    monkeypatch.setattr(config, "RECOVERY_CODES_ENABLED", False)
    monkeypatch.setattr(config, "HOST_KEY_MANAGEMENT_ENABLED", False)
    monkeypatch.setattr(config, "AUDIT_EXPORT_ENABLED", False)

    security = client.get("/security")
    admin = client.get("/settings")
    client.post("/logout")
    login = client.get("/login")

    assert b'id="recoveryLoginBtn"' not in login.data
    assert b'id="recoveryGenerateBtn"' not in security.data
    assert b'id="hostKeyList"' not in security.data
    assert b'id="auditExportBtn"' not in admin.data
    assert b'id="globalHostKeyList"' not in admin.data
    assert client.post("/login/recovery", json={}).status_code == 404
    _login(client, "rollback_user")
    assert client.get("/api/host-keys").status_code == 404
    assert client.get("/admin/api/audit/export").status_code == 404


def test_security_center_offers_totp_only_when_effectively_active(
    app, client, monkeypatch
):
    import config
    from app.models import SecurityFeatureState, User, db

    _create_user(app, "optional_totp_user", is_admin=True)
    _login(client, "optional_totp_user")

    monkeypatch.setattr(config, "TOTP_ENABLED", True)
    deployment_only = client.get("/security")
    assert b'id="totpAddBtn"' not in deployment_only.data

    with app.app_context():
        admin = User.query.filter_by(username="optional_totp_user").one()
        db.session.add(SecurityFeatureState(
            feature="totp",
            enabled=True,
            updated_by=admin.id,
        ))
        db.session.commit()

    active = client.get("/security")
    assert b'id="totpAddBtn"' in active.data


def test_security_copy_keeps_mfa_optional(app, client):
    _create_user(app, "optional_mfa_user")
    _login(client, "optional_mfa_user")

    html = client.get("/security").get_data(as_text=True).lower()

    assert "required for all" not in html
    assert "mandatory for all" not in html
