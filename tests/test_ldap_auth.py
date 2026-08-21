"""Security boundaries for optional LDAP authentication."""

import sqlite3
from dataclasses import dataclass
from threading import Event, Thread
from urllib.parse import urlsplit

import pytest

from tests.step_up_helpers import password_step_up_headers


def _step_up(client, action, target):
    return password_step_up_headers(client, action, target)[0]


def _create_user(
    app,
    username,
    password="password123",
    *,
    is_admin=False,
    mfa_enabled=False,
):
    from app.auth import register_user
    from app.models import db

    with app.app_context():
        user, error = register_user(username, password)
        assert error is None
        user.is_admin = is_admin
        user.mfa_enabled = mfa_enabled
        db.session.commit()
        return user.id


def test_ldap_identity_is_explicit_and_blocks_local_password_fallback(app):
    from app.auth import authenticate_user
    from app.models import LDAPIdentity, User, db

    user_id = _create_user(app, "directory_user")
    with app.app_context():
        db.session.add(LDAPIdentity(
            user_id=user_id,
            provider="default",
            subject="86b4cc5f-3890-4f68-a32f-2b0e2b7381f1",
            directory_username="directory_user",
            distinguished_name="uid=directory_user,ou=people,dc=example,dc=com",
        ))
        db.session.commit()

        user = db.session.get(User, user_id)
        assert user.ldap_identity.subject == (
            "86b4cc5f-3890-4f68-a32f-2b0e2b7381f1"
        )

        authenticated, error = authenticate_user(
            "directory_user",
            "password123",
        )

    assert authenticated is None
    assert error == "Invalid username or password"


def test_login_identifier_rejects_stale_and_legacy_auth_generations(app):
    from app.auth import load_user
    from app.models import User, db

    user_id = _create_user(app, "session_generation_user")
    with app.app_context():
        user = db.session.get(User, user_id)
        stale_identifier = user.get_id()
        user.auth_generation += 1
        db.session.commit()
        current_identifier = user.get_id()

        assert load_user(stale_identifier) is None
        assert load_user(str(user_id)) is None
        assert load_user(current_identifier).id == user_id


def test_disabled_ldap_has_no_route_and_local_login_still_works(app, client):
    _create_user(app, "local_user")

    ldap_response = client.post(
        "/login/ldap",
        data={"username": "local_user", "password": "password123"},
    )
    local_response = client.post(
        "/login",
        data={"username": "local_user", "password": "password123"},
    )

    assert ldap_response.status_code == 404
    assert local_response.status_code == 302


@dataclass(frozen=True)
class _DirectoryIdentity:
    provider: str
    subject: str
    distinguished_name: str


class _FakeDirectory:
    def __init__(self, identity, *, password_valid=True):
        self.identity = identity
        self.password_valid = password_valid
        self.lookups = []
        self.binds = []
        self.probes = 0

    def lookup(self, username):
        self.lookups.append(username)
        return self.identity

    def verify_password(self, distinguished_name, password):
        self.binds.append((distinguished_name, password))
        return self.password_valid

    def probe(self):
        self.probes += 1
        return True


def _enable_ldap_blueprint(app, monkeypatch, directory):
    import config
    import app.ldap_routes as ldap_routes

    monkeypatch.setattr(config, "LDAP_ENABLED", True)
    monkeypatch.setattr(config, "LDAP_AUTO_PROVISION", False, raising=False)
    monkeypatch.setattr(config, "LDAP_URL", "ldap://directory.example.com:389")
    monkeypatch.setattr(ldap_routes, "get_directory", lambda: directory)
    app.register_blueprint(ldap_routes.ldap_blueprint)


def test_enabled_ldap_login_defaults_to_named_directory_source(
    app,
    client,
    monkeypatch,
):
    import config

    _create_user(app, "ldap_login_mode_user")
    directory = _FakeDirectory(_DirectoryIdentity(
        provider="default",
        subject="unused-id",
        distinguished_name="uid=unused,dc=example,dc=com",
    ))
    _enable_ldap_blueprint(app, monkeypatch, directory)
    monkeypatch.setattr(config, "LDAP_PROVIDER_ID", "corp-directory")

    response = client.get("/login")

    assert response.status_code == 200
    assert b'id="authenticationSource"' in response.data
    assert b'<option value="ldap" selected>corp-directory</option>' in response.data
    assert b'id="localLoginForm" class="auth-source-form hidden"' in response.data
    assert b'id="ldapLoginForm" class="auth-source-form"' in response.data
    assert b'id="ldapLoginBtn"' not in response.data
    assert b'id="ldapBackBtn"' not in response.data


def test_failed_local_login_keeps_local_source_selected(
    app,
    client,
    monkeypatch,
):
    _create_user(app, "local_login_user")
    directory = _FakeDirectory(_DirectoryIdentity(
        provider="default",
        subject="unused-id",
        distinguished_name="uid=unused,dc=example,dc=com",
    ))
    _enable_ldap_blueprint(app, monkeypatch, directory)

    response = client.post(
        "/login",
        data={"username": "local_login_user", "password": "wrong-password"},
    )

    assert response.status_code == 200
    assert (
        b'<option value="local" selected '
        b'data-i18n="auth.localAccount">Local account</option>'
    ) in response.data
    assert b'id="localLoginForm" class="auth-source-form"' in response.data
    assert b'id="ldapLoginForm" class="auth-source-form hidden"' in response.data


def test_ldap_login_accepts_only_matching_explicit_identity(
    app,
    client,
    monkeypatch,
):
    from app.models import LDAPIdentity, db

    user_id = _create_user(app, "alice")
    identity = _DirectoryIdentity(
        provider="default",
        subject="stable-alice-id",
        distinguished_name="uid=alice-new,ou=people,dc=example,dc=com",
    )
    with app.app_context():
        db.session.add(LDAPIdentity(
            user_id=user_id,
            provider="default",
            subject="stable-alice-id",
            directory_username="alice",
            distinguished_name="uid=alice-old,ou=people,dc=example,dc=com",
        ))
        db.session.commit()
    directory = _FakeDirectory(identity)
    _enable_ldap_blueprint(app, monkeypatch, directory)

    response = client.post(
        "/login/ldap",
        data={"username": "alice-renamed", "password": "directory-password"},
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")
    assert not any(
        header.startswith("remember_token=")
        for header in response.headers.getlist("Set-Cookie")
    )
    assert directory.lookups == ["alice-renamed"]
    assert directory.binds == [(
        "uid=alice-new,ou=people,dc=example,dc=com",
        "directory-password",
    )]
    with app.app_context():
        row = LDAPIdentity.query.one()
        assert row.directory_username == "alice-renamed"
        assert row.distinguished_name == identity.distinguished_name
        assert row.last_verified_at is not None


def test_ldap_password_stays_pending_when_user_enabled_mfa(
    app,
    client,
    monkeypatch,
):
    from app.models import (
        AuthenticationSession,
        LDAPIdentity,
        PendingAuthentication,
        WebAuthnCredential,
        db,
    )

    user_id = _create_user(app, "ldap_mfa_user", mfa_enabled=True)
    with app.app_context():
        db.session.add_all((
            LDAPIdentity(
                user_id=user_id,
                provider="default",
                subject="stable-ldap-mfa-id",
                directory_username="ldap_mfa_user",
                distinguished_name=(
                    "uid=ldap_mfa_user,ou=people,dc=example,dc=com"
                ),
            ),
            WebAuthnCredential(
                user_id=user_id,
                credential_id=b"ldap-mfa-credential",
                public_key=b"public-key",
                sign_count=0,
                transports="[]",
                name="LDAP passkey",
            ),
        ))
        db.session.commit()
    directory = _FakeDirectory(_DirectoryIdentity(
        provider="default",
        subject="stable-ldap-mfa-id",
        distinguished_name=(
            "uid=ldap_mfa_user,ou=people,dc=example,dc=com"
        ),
    ))
    _enable_ldap_blueprint(app, monkeypatch, directory)
    import config
    monkeypatch.setattr(config, "WEBAUTHN_ENABLED", True)

    response = client.post(
        "/login/ldap",
        data={
            "username": "ldap_mfa_user",
            "password": "directory-password",
        },
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 200
    assert response.get_json() == {
        "mfa_required": True,
        "methods": ["passkey"],
        "ok": True,
    }
    with client.session_transaction() as browser_session:
        assert "_user_id" not in browser_session
        assert browser_session.get("_pending_authentication")
    with app.app_context():
        assert PendingAuthentication.query.count() == 1
        assert AuthenticationSession.query.count() == 0


def test_ldap_login_auto_provisions_verified_non_admin_identity(
    app,
    client,
    monkeypatch,
):
    import config
    from app.models import LDAPIdentity, User

    _create_user(app, "local_admin", is_admin=True)
    identity = _DirectoryIdentity(
        provider="default",
        subject="stable-alice-id",
        distinguished_name="uid=alice,ou=people,dc=example,dc=com",
    )
    directory = _FakeDirectory(identity)
    _enable_ldap_blueprint(app, monkeypatch, directory)
    monkeypatch.setattr(config, "LDAP_AUTO_PROVISION", True)

    response = client.post(
        "/login/ldap",
        data={
            "username": "alice@example.com",
            "password": "directory-password",
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")
    assert directory.binds == [(
        identity.distinguished_name,
        "directory-password",
    )]
    with app.app_context():
        user = User.query.filter_by(username="alice@example.com").one()
        mapping = LDAPIdentity.query.filter_by(user_id=user.id).one()
        assert user.is_admin is False
        assert user.is_locked is False
        assert user.check_password("directory-password") is False
        assert mapping.provider == "default"
        assert mapping.subject == "stable-alice-id"
        assert mapping.directory_username == "alice@example.com"


def test_ldap_auto_provisioning_rejects_invalid_password_without_account(
    app,
    client,
    monkeypatch,
):
    import config
    from app.models import LDAPIdentity, User

    _create_user(app, "local_admin", is_admin=True)
    identity = _DirectoryIdentity(
        provider="default",
        subject="stable-alice-id",
        distinguished_name="uid=alice,ou=people,dc=example,dc=com",
    )
    directory = _FakeDirectory(identity, password_valid=False)
    _enable_ldap_blueprint(app, monkeypatch, directory)
    monkeypatch.setattr(config, "LDAP_AUTO_PROVISION", True)

    response = client.post(
        "/login/ldap",
        data={"username": "alice", "password": "wrong-password"},
    )

    assert response.status_code == 401
    assert directory.binds == [(
        identity.distinguished_name,
        "wrong-password",
    )]
    with app.app_context():
        assert User.query.count() == 1
        assert LDAPIdentity.query.count() == 0


def test_ldap_auto_provisioning_never_claims_existing_local_username(
    app,
    client,
    monkeypatch,
):
    import config
    from app.models import LDAPIdentity, User

    _create_user(app, "local_admin", is_admin=True)
    _create_user(app, "alice")
    identity = _DirectoryIdentity(
        provider="default",
        subject="stable-directory-alice-id",
        distinguished_name="uid=alice,ou=people,dc=example,dc=com",
    )
    directory = _FakeDirectory(identity)
    _enable_ldap_blueprint(app, monkeypatch, directory)
    monkeypatch.setattr(config, "LDAP_AUTO_PROVISION", True)

    response = client.post(
        "/login/ldap",
        data={"username": "alice", "password": "directory-password"},
    )

    assert response.status_code == 401
    assert directory.binds == [(
        identity.distinguished_name,
        "directory-password",
    )]
    with app.app_context():
        assert User.query.count() == 2
        assert LDAPIdentity.query.count() == 0


def test_ldap_auto_provisioning_rejects_casefolded_local_collision(
    app,
    client,
    monkeypatch,
):
    import config
    from app.models import LDAPIdentity, User

    _create_user(app, "local_admin", is_admin=True)
    _create_user(app, "Alice")
    identity = _DirectoryIdentity(
        provider="default",
        subject="stable-directory-alice-id",
        distinguished_name="uid=alice,ou=people,dc=example,dc=com",
    )
    directory = _FakeDirectory(identity)
    _enable_ldap_blueprint(app, monkeypatch, directory)
    monkeypatch.setattr(config, "LDAP_AUTO_PROVISION", True)

    response = client.post(
        "/login/ldap",
        data={"username": "alice", "password": "directory-password"},
    )

    assert response.status_code == 401
    with app.app_context():
        assert User.query.count() == 2
        assert LDAPIdentity.query.count() == 0


def test_local_registration_rejects_casefolded_ldap_collision(
    app,
    client,
    monkeypatch,
):
    import config
    from app.auth import register_user
    from app.models import db

    _create_user(app, "local_admin", is_admin=True)
    identity = _DirectoryIdentity(
        provider="default",
        subject="stable-directory-alice-id",
        distinguished_name="uid=Alice,ou=people,dc=example,dc=com",
    )
    directory = _FakeDirectory(identity)
    _enable_ldap_blueprint(app, monkeypatch, directory)
    monkeypatch.setattr(config, "LDAP_AUTO_PROVISION", True)

    response = client.post(
        "/login/ldap",
        data={"username": "Alice", "password": "directory-password"},
    )
    assert response.status_code == 302

    with app.app_context():
        user, error = register_user("alice", "different-password")
        transaction_still_open = db.session().in_transaction()

    assert user is None
    assert error == "Username already exists"
    assert transaction_still_open is False


def test_local_registration_serializes_casefold_check_across_connections(app):
    import config
    from app.auth import register_user

    _create_user(app, "local_admin", is_admin=True)
    connection = sqlite3.connect(config.DATA_DIR / "app.db", timeout=5)
    connection.execute("BEGIN IMMEDIATE")
    connection.execute(
        """
        INSERT INTO users (
            username,
            password_hash,
            is_admin,
            is_locked,
            auth_generation,
            mfa_enabled
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        ("Alice", "unused", False, False, 0, False),
    )
    completed = Event()
    result = {}

    def register_casefolded_name():
        with app.app_context():
            try:
                result["user"], result["error"] = register_user(
                    "alice",
                    "different-password",
                )
            finally:
                completed.set()

    worker = Thread(target=register_casefolded_name)
    worker.start()
    assert completed.wait(0.2) is False
    connection.commit()
    connection.close()

    worker.join(timeout=5)
    assert completed.is_set()
    assert result["user"] is None
    assert result["error"] == "Username already exists"


def test_ldap_auto_provisioning_uses_shared_user_creation_lock(app):
    from app.auth import user_creation_lock
    from app.ldap_routes import _auto_provision_ldap_identity
    from app.models import db

    _create_user(app, "local_admin", is_admin=True)
    identity = _DirectoryIdentity(
        provider="default",
        subject="stable-directory-alice-id",
        distinguished_name="uid=alice,ou=people,dc=example,dc=com",
    )
    completed = Event()
    result = {}

    def provision():
        with app.app_context():
            try:
                mapping = _auto_provision_ldap_identity(
                    "alice",
                    identity,
                )
                result["username"] = mapping.user.username
            finally:
                db.session.remove()
                completed.set()

    with user_creation_lock:
        worker = Thread(target=provision)
        worker.start()
        assert completed.wait(0.2) is False

    worker.join(timeout=5)
    assert completed.is_set()
    assert result["username"] == "alice"


def test_ldap_auto_provisioning_rolls_back_when_user_storage_fails(
    app,
    client,
    monkeypatch,
):
    import config
    from app.models import LDAPIdentity, User

    _create_user(app, "local_admin", is_admin=True)
    identity = _DirectoryIdentity(
        provider="default",
        subject="stable-directory-alice-id",
        distinguished_name="uid=alice,ou=people,dc=example,dc=com",
    )
    directory = _FakeDirectory(identity)
    _enable_ldap_blueprint(app, monkeypatch, directory)
    monkeypatch.setattr(config, "LDAP_AUTO_PROVISION", True)

    def fail_user_storage(_user):
        raise OSError("user storage unavailable")

    monkeypatch.setattr(User, "get_data_dir", fail_user_storage)

    response = client.post(
        "/login/ldap",
        data={"username": "alice", "password": "directory-password"},
    )

    assert response.status_code == 503
    with app.app_context():
        assert User.query.count() == 1
        assert LDAPIdentity.query.count() == 0


@pytest.mark.parametrize(
    'username',
    (
        'a' * 81,
        'alice\nadmin',
        'alice\n',
        '\talice',
        'alice\r',
        'ali\u200bce',
    ),
)
def test_ldap_auto_provisioning_rejects_unsafe_local_account_name(
    app,
    client,
    monkeypatch,
    username,
):
    import config
    from app.models import LDAPIdentity, User

    _create_user(app, "local_admin", is_admin=True)
    identity = _DirectoryIdentity(
        provider="default",
        subject="stable-alice-id",
        distinguished_name="uid=alice,ou=people,dc=example,dc=com",
    )
    directory = _FakeDirectory(identity)
    _enable_ldap_blueprint(app, monkeypatch, directory)
    monkeypatch.setattr(config, "LDAP_AUTO_PROVISION", True)

    response = client.post(
        "/login/ldap",
        data={"username": username, "password": "directory-password"},
    )

    assert response.status_code == 401
    with app.app_context():
        assert User.query.count() == 1
        assert LDAPIdentity.query.count() == 0


def test_ldap_auto_provisioning_requires_local_break_glass_admin(
    app,
    client,
    monkeypatch,
):
    import config
    from app.models import LDAPIdentity, User

    identity = _DirectoryIdentity(
        provider="default",
        subject="stable-alice-id",
        distinguished_name="uid=alice,ou=people,dc=example,dc=com",
    )
    directory = _FakeDirectory(identity)
    _enable_ldap_blueprint(app, monkeypatch, directory)
    monkeypatch.setattr(config, "LDAP_AUTO_PROVISION", True)

    response = client.post(
        "/login/ldap",
        data={"username": "alice", "password": "directory-password"},
    )

    assert response.status_code == 401
    assert directory.binds == [(
        identity.distinguished_name,
        "directory-password",
    )]
    with app.app_context():
        assert User.query.count() == 0
        assert LDAPIdentity.query.count() == 0


def test_ldap_login_rejects_subject_mismatch_before_password_bind(
    app,
    client,
    monkeypatch,
):
    from app.models import LDAPIdentity, db

    user_id = _create_user(app, "alice")
    with app.app_context():
        db.session.add(LDAPIdentity(
            user_id=user_id,
            provider="default",
            subject="approved-id",
            directory_username="alice",
            distinguished_name="uid=alice,dc=example,dc=com",
        ))
        db.session.commit()
    directory = _FakeDirectory(_DirectoryIdentity(
        provider="default",
        subject="different-id",
        distinguished_name="uid=attacker,dc=example,dc=com",
    ))
    _enable_ldap_blueprint(app, monkeypatch, directory)

    response = client.post(
        "/login/ldap",
        data={"username": "alice", "password": "directory-password"},
    )

    assert response.status_code == 401
    assert b"Invalid username or password" in response.data
    assert b'<option value="ldap" selected>default</option>' in response.data
    assert b'id="localLoginForm" class="auth-source-form hidden"' in response.data
    assert b'id="ldapLoginForm" class="auth-source-form"' in response.data
    assert directory.binds == []


def test_admin_link_is_explicit_reauthenticated_and_cannot_convert_admin(
    app,
    client,
    monkeypatch,
):
    from app.models import LDAPIdentity

    _create_user(app, "local_admin", is_admin=True)
    target_id = _create_user(app, "alice")
    second_admin_id = _create_user(app, "second_admin", is_admin=True)
    directory = _FakeDirectory(_DirectoryIdentity(
        provider="default",
        subject="stable-alice-id",
        distinguished_name="uid=alice,ou=people,dc=example,dc=com",
    ))
    _enable_ldap_blueprint(app, monkeypatch, directory)
    login = client.post(
        "/login",
        data={"username": "local_admin", "password": "password123"},
    )
    assert login.status_code == 302

    _headers, wrong_password = password_step_up_headers(
        client,
        "ldap.link",
        target_id,
        password="wrong",
        expected_status=403,
    )
    linked = client.post(
        f"/admin/api/users/{target_id}/ldap-link",
        json={
            "confirm_username": "alice",
            "directory_username": "alice",
        },
        headers=_step_up(client, "ldap.link", target_id),
    )
    admin_rejected = client.post(
        f"/admin/api/users/{second_admin_id}/ldap-link",
        json={
            "confirm_username": "second_admin",
            "directory_username": "second_admin",
        },
        headers=_step_up(client, "ldap.link", second_admin_id),
    )

    assert wrong_password.status_code == 403
    assert linked.status_code == 201
    assert admin_rejected.status_code == 400
    with app.app_context():
        row = LDAPIdentity.query.one()
        assert row.user_id == target_id
        assert row.directory_username == "alice"
        assert row.subject == "stable-alice-id"


def test_admin_ldap_link_preserves_native_factors_but_removes_oidc(
    app,
    client,
    monkeypatch,
):
    from app.models import (
        OIDCIdentity,
        RecoveryCode,
        WebAuthnCredential,
        db,
    )

    _create_user(app, "local_admin", is_admin=True)
    target_id = _create_user(app, "factor_user")
    with app.app_context():
        db.session.add_all((
            WebAuthnCredential(
                user_id=target_id,
                credential_id=b"preserved-credential",
                public_key=b"public-key",
                sign_count=0,
                transports="[]",
                name="Preserved passkey",
            ),
            RecoveryCode(user_id=target_id, code_hash=b"r" * 32),
            OIDCIdentity(
                user_id=target_id,
                issuer="https://issuer.example",
                subject="oidc-subject",
            ),
        ))
        db.session.commit()
    directory = _FakeDirectory(_DirectoryIdentity(
        provider="default",
        subject="stable-factor-id",
        distinguished_name="uid=factor_user,dc=example,dc=com",
    ))
    _enable_ldap_blueprint(app, monkeypatch, directory)
    assert client.post(
        "/login",
        data={"username": "local_admin", "password": "password123"},
    ).status_code == 302

    linked = client.post(
        f"/admin/api/users/{target_id}/ldap-link",
        json={
            "confirm_username": "factor_user",
            "directory_username": "factor_user",
        },
        headers=_step_up(client, "ldap.link", target_id),
    )

    assert linked.status_code == 201
    with app.app_context():
        assert WebAuthnCredential.query.filter_by(
            user_id=target_id,
        ).count() == 1
        assert RecoveryCode.query.filter_by(user_id=target_id).count() == 1
        assert OIDCIdentity.query.filter_by(user_id=target_id).count() == 0


def test_admin_link_invalidates_an_existing_local_browser_session(
    app,
    client,
    monkeypatch,
):
    import app.ldap_session as ldap_session
    from flask import g
    from app.models import User, db

    _create_user(app, "local_admin", is_admin=True)
    target_id = _create_user(app, "alice")
    directory = _FakeDirectory(_DirectoryIdentity(
        provider="default",
        subject="stable-alice-id",
        distinguished_name="uid=alice,ou=people,dc=example,dc=com",
    ))
    _enable_ldap_blueprint(app, monkeypatch, directory)
    monkeypatch.setattr(ldap_session, "revalidate_user", lambda _user: None)

    admin_login = client.post(
        "/login",
        data={"username": "local_admin", "password": "password123"},
    )
    assert admin_login.status_code == 302
    admin_login.close()
    with app.app_context():
        target_identifier = db.session.get(User, target_id).get_id()

    linked = client.post(
        f"/admin/api/users/{target_id}/ldap-link",
        json={
            "confirm_username": "alice",
            "directory_username": "alice",
        },
        headers=_step_up(client, "ldap.link", target_id),
    )
    assert linked.status_code == 201
    linked.close()
    with client.session_transaction() as browser_session:
        browser_session.clear()
        browser_session["_user_id"] = target_identifier
        browser_session["_fresh"] = True
    g.pop("_login_user", None)
    response = client.get("/")

    assert response.status_code == 302
    assert urlsplit(response.headers["Location"]).path == "/login"


def test_admin_ldap_link_rejects_oversized_json_before_reauthentication(
    app,
    client,
    monkeypatch,
):
    _create_user(app, "local_admin", is_admin=True)
    target_id = _create_user(app, "alice")
    _enable_ldap_blueprint(
        app,
        monkeypatch,
        _FakeDirectory(_DirectoryIdentity("default", "id", "uid=alice")),
    )
    assert client.post(
        "/login",
        data={"username": "local_admin", "password": "password123"},
    ).status_code == 302

    response = client.post(
        f"/admin/api/users/{target_id}/ldap-link",
        data=b'{"padding":"' + (b"x" * 5000) + b'"}',
        content_type="application/json",
        headers=_step_up(client, "ldap.link", target_id),
    )

    assert response.status_code == 413


def test_admin_unlink_requires_a_new_local_password_and_revokes_access(
    app,
    client,
    monkeypatch,
):
    import app.ldap_routes as ldap_routes
    from app.models import LDAPIdentity, User, db

    _create_user(app, "local_admin", is_admin=True)
    target_id = _create_user(app, "alice")
    with app.app_context():
        row = LDAPIdentity(
            user_id=target_id,
            provider="default",
            subject="stable-alice-id",
            directory_username="alice",
            distinguished_name="uid=alice,dc=example,dc=com",
        )
        db.session.add(row)
        db.session.commit()
        identity_id = row.id
        linked_identifier = db.session.get(User, target_id).get_id()
    _enable_ldap_blueprint(
        app,
        monkeypatch,
        _FakeDirectory(_DirectoryIdentity("default", "id", "uid=alice")),
    )
    assert client.post(
        "/login",
        data={"username": "local_admin", "password": "password123"},
    ).status_code == 302
    revoked = []
    monkeypatch.setattr(
        ldap_routes.user_lifecycle,
        "revoke_user_access",
        lambda user_id, socketio_instance=None: revoked.append(user_id),
    )

    missing_password = client.delete(
        f"/admin/api/users/{target_id}/ldap-identities/{identity_id}",
        json={
            "confirm_username": "alice",
        },
        headers=_step_up(
            client, "ldap.unlink", f"{target_id}:{identity_id}"
        ),
    )
    unlinked = client.delete(
        f"/admin/api/users/{target_id}/ldap-identities/{identity_id}",
        json={
            "confirm_username": "alice",
            "new_password": "new-local-password-123",
        },
        headers=_step_up(
            client, "ldap.unlink", f"{target_id}:{identity_id}"
        ),
    )

    assert missing_password.status_code == 400
    assert unlinked.status_code == 200
    assert revoked == [target_id]
    with app.app_context():
        assert LDAPIdentity.query.count() == 0
        target = db.session.get(User, target_id)
        assert target.get_id() != linked_identifier
        assert target.check_password(
            "new-local-password-123"
        )


def test_linked_user_cannot_use_recovery_code_without_primary_authentication(
    app,
    client,
    monkeypatch,
):
    from app.models import LDAPIdentity, RecoveryCode, User, db
    from app.recovery_service import generate_codes

    _create_user(app, "local_admin", is_admin=True)
    user_id = _create_user(app, "alice")
    with app.app_context():
        code = generate_codes(user_id, count=1)[0]
        db.session.add(LDAPIdentity(
            user_id=user_id,
            provider="default",
            subject="stable-alice-id",
            directory_username="alice",
            distinguished_name="uid=alice,dc=example,dc=com",
        ))
        db.session.commit()
        user = db.session.get(User, user_id)
        assert user.is_admin is False
        assert user.is_locked is False
    directory = _FakeDirectory(_DirectoryIdentity(
        provider="default",
        subject="stable-alice-id",
        distinguished_name="uid=alice,dc=example,dc=com",
    ))
    _enable_ldap_blueprint(app, monkeypatch, directory)

    recovery = client.post(
        "/login/recovery",
        json={"username": "alice", "code": code},
    )
    login = client.post(
        "/login/ldap",
        data={"username": "alice", "password": "directory-password"},
    )
    password_change = client.get("/change-password")

    assert recovery.status_code == 400
    assert login.status_code == 302
    assert password_change.status_code == 403, password_change.headers.get(
        "Location"
    )
    with app.app_context():
        assert RecoveryCode.query.filter_by(user_id=user_id).count() == 1


def test_linked_user_cannot_be_promoted_to_admin(app, client):
    from app.models import LDAPIdentity, User, db

    _create_user(app, "local_admin", is_admin=True)
    target_id = _create_user(app, "alice")
    with app.app_context():
        db.session.add(LDAPIdentity(
            user_id=target_id,
            provider="default",
            subject="stable-alice-id",
            directory_username="alice",
            distinguished_name="uid=alice,dc=example,dc=com",
        ))
        db.session.commit()
    assert client.post(
        "/login",
        data={"username": "local_admin", "password": "password123"},
    ).status_code == 302

    response = client.post(
        f"/admin/api/users/{target_id}/promote",
        headers=_step_up(client, "user.manage", f"{target_id}:promote"),
    )

    assert response.status_code == 400
    with app.app_context():
        assert db.session.get(User, target_id).is_admin is False


def test_disabling_ldap_invalidates_existing_linked_browser_session(app, client):
    from app.models import LDAPIdentity, db

    user_id = _create_user(app, "alice")
    with app.app_context():
        db.session.add(LDAPIdentity(
            user_id=user_id,
            provider="default",
            subject="stable-alice-id",
            directory_username="alice",
            distinguished_name="uid=alice,dc=example,dc=com",
        ))
        db.session.commit()
    with client.session_transaction() as browser_session:
        browser_session["_user_id"] = str(user_id)
        browser_session["_fresh"] = True

    response = client.get("/")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")
    with client.session_transaction() as browser_session:
        assert "_user_id" not in browser_session


def test_due_ldap_session_revalidation_fails_closed(
    app,
    client,
    monkeypatch,
):
    import config
    import app.ldap_session as ldap_session
    from app.ldap_service import LDAPUnavailable
    from app.models import LDAPIdentity, db

    user_id = _create_user(app, "alice")
    with app.app_context():
        db.session.add(LDAPIdentity(
            user_id=user_id,
            provider="default",
            subject="stable-alice-id",
            directory_username="alice",
            distinguished_name="uid=alice,dc=example,dc=com",
        ))
        db.session.commit()
    monkeypatch.setattr(config, "LDAP_ENABLED", True)
    monkeypatch.setattr(
        ldap_session,
        "revalidate_user",
        lambda _user: (_ for _ in ()).throw(LDAPUnavailable("offline")),
    )
    with client.session_transaction() as browser_session:
        browser_session["_user_id"] = str(user_id)
        browser_session["_fresh"] = True
        browser_session["_ldap_verified_at"] = 0

    response = client.get("/")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")
    with client.session_transaction() as browser_session:
        assert "_user_id" not in browser_session


def test_background_revalidation_revokes_invalid_linked_socket_owner(
    app,
    monkeypatch,
):
    import app.ldap_session as ldap_session
    from app.ldap_service import LDAPLookupRejected
    from app.models import LDAPIdentity, db

    user_id = _create_user(app, "alice")
    with app.app_context():
        db.session.add(LDAPIdentity(
            user_id=user_id,
            provider="default",
            subject="stable-alice-id",
            directory_username="alice",
            distinguished_name="uid=alice,dc=example,dc=com",
        ))
        db.session.commit()
    monkeypatch.setattr(
        ldap_session,
        "revalidate_user",
        lambda _user: (_ for _ in ()).throw(LDAPLookupRejected("removed")),
    )
    revoked = []
    monkeypatch.setattr(
        ldap_session.user_lifecycle,
        "revoke_user_access",
        lambda owner_id, socketio_instance=None: revoked.append(owner_id),
    )

    ldap_session.revalidate_all_linked_users(app, socketio_instance=object())

    assert revoked == [user_id]


def test_admin_can_run_redacted_ldap_readiness_probe(
    app,
    client,
    monkeypatch,
):
    _create_user(app, "local_admin", is_admin=True)
    directory = _FakeDirectory(_DirectoryIdentity("default", "id", "uid=test"))
    _enable_ldap_blueprint(app, monkeypatch, directory)
    assert client.post(
        "/login",
        data={"username": "local_admin", "password": "password123"},
    ).status_code == 302

    response = client.get("/admin/api/ldap/status")

    assert response.status_code == 200
    assert response.get_json() == {
        "enabled": True,
        "provider": "default",
        "ready": True,
        "transport": "ldap+StartTLS",
    }
    assert directory.probes == 1
    assert b"cn=webssh" not in response.data
