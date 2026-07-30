"""One-time account recovery code storage and route controls."""


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


def test_recovery_codes_are_hashed_single_use_and_regeneration_invalidates(app):
    from app.models import RecoveryCode
    from app.recovery_service import consume_code, generate_codes

    user_id = _create_user(app, "recovery_user")
    with app.app_context():
        first = generate_codes(user_id, count=3)
        stored = RecoveryCode.query.filter_by(user_id=user_id).all()

        assert len(first) == 3
        assert len(stored) == 3
        assert all(
            code.encode("utf-8") not in row.code_hash
            for code in first
            for row in stored
        )
        assert consume_code(user_id, first[0]) is True
        assert consume_code(user_id, first[0]) is False

        second = generate_codes(user_id, count=3)
        assert consume_code(user_id, first[1]) is False
        assert consume_code(user_id, second[0]) is True


def test_admin_recovery_requires_reauthentication_and_exact_target_confirmation(
    app, client
):
    admin_id = _create_user(app, "recovery_admin", is_admin=True)
    target_id = _create_user(app, "recovery_target")
    assert admin_id != target_id
    _login(client, "recovery_admin")

    wrong_password = client.post(
        f"/admin/api/users/{target_id}/recovery",
        json={
            "password": "wrong",
            "confirm_username": "recovery_target",
        },
    )
    wrong_target = client.post(
        f"/admin/api/users/{target_id}/recovery",
        json={
            "password": "password123",
            "confirm_username": "other",
        },
    )
    accepted = client.post(
        f"/admin/api/users/{target_id}/recovery",
        json={
            "password": "password123",
            "confirm_username": "recovery_target",
        },
    )

    assert wrong_password.status_code == 403
    assert wrong_target.status_code == 400
    assert accepted.status_code == 200
    codes = accepted.get_json()["codes"]
    assert len(codes) == 10
    assert len(set(codes)) == 10


def test_user_can_generate_and_consume_one_recovery_code(app, client):
    _create_user(app, "recoverable_user")
    _login(client, "recoverable_user")

    generated = client.post(
        "/api/recovery-codes",
        json={"password": "password123"},
    )
    assert generated.status_code == 200
    code = generated.get_json()["codes"][0]

    client.post("/logout")
    accepted = client.post(
        "/login/recovery",
        json={"username": "recoverable_user", "code": code},
    )
    client.post("/logout")
    replayed = client.post(
        "/login/recovery",
        json={"username": "recoverable_user", "code": code},
    )

    assert accepted.status_code == 200
    assert replayed.status_code == 401
