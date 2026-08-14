"""Security boundaries for optional LDAP authentication."""

from dataclasses import dataclass


def _create_user(app, username, password="password123", *, is_admin=False):
    from app.auth import register_user
    from app.models import db

    with app.app_context():
        user, error = register_user(username, password)
        assert error is None
        user.is_admin = is_admin
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
    monkeypatch.setattr(config, "LDAP_URL", "ldap://directory.example.com:389")
    monkeypatch.setattr(ldap_routes, "get_directory", lambda: directory)
    app.register_blueprint(ldap_routes.ldap_blueprint)


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
    assert b'id="ldapLoginForm" class="hidden"' not in response.data
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

    wrong_password = client.post(
        f"/admin/api/users/{target_id}/ldap-link",
        json={
            "password": "wrong",
            "confirm_username": "alice",
            "directory_username": "alice",
        },
    )
    linked = client.post(
        f"/admin/api/users/{target_id}/ldap-link",
        json={
            "password": "password123",
            "confirm_username": "alice",
            "directory_username": "alice",
        },
    )
    admin_rejected = client.post(
        f"/admin/api/users/{second_admin_id}/ldap-link",
        json={
            "password": "password123",
            "confirm_username": "second_admin",
            "directory_username": "second_admin",
        },
    )

    assert wrong_password.status_code == 403
    assert linked.status_code == 201
    assert admin_rejected.status_code == 400
    with app.app_context():
        row = LDAPIdentity.query.one()
        assert row.user_id == target_id
        assert row.directory_username == "alice"
        assert row.subject == "stable-alice-id"


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
            "password": "password123",
            "confirm_username": "alice",
        },
    )
    unlinked = client.delete(
        f"/admin/api/users/{target_id}/ldap-identities/{identity_id}",
        json={
            "password": "password123",
            "confirm_username": "alice",
            "new_password": "new-local-password-123",
        },
    )

    assert missing_password.status_code == 400
    assert unlinked.status_code == 200
    assert revoked == [target_id]
    with app.app_context():
        assert LDAPIdentity.query.count() == 0
        assert db.session.get(User, target_id).check_password(
            "new-local-password-123"
        )


def test_linked_user_cannot_use_recovery_code_or_change_password(
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

    assert recovery.status_code == 401
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

    response = client.post(f"/admin/api/users/{target_id}/promote")

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
