"""One-time account recovery code storage and route controls."""

import hmac


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


def test_recovery_code_regeneration_rate_limits_before_bcrypt(
    app, client, monkeypatch
):
    import app.recovery_routes as recovery_routes
    from app.models import User

    _create_user(app, "limited_recovery_user")
    _login(client, "limited_recovery_user")
    monkeypatch.setattr(
        recovery_routes,
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
        "/api/recovery-codes",
        json={"password": "password123"},
    )

    assert response.status_code == 429
    assert response.get_json() == {"error": "Too many password attempts"}


def test_recovery_login_is_rate_limited_like_password_login(
    app, client, monkeypatch
):
    import config

    monkeypatch.setattr(config, "RATELIMIT_LOGIN_LIMIT", "2 per minute")

    responses = [
        client.post(
            "/login/recovery",
            json={"username": "missing_user", "code": "invalid"},
        )
        for _ in range(3)
    ]

    assert [response.status_code for response in responses] == [401, 401, 429]
    assert responses[-1].get_json() == {
        "error": "Too many login attempts"
    }


def test_recovery_login_equalizes_verification_work(
    app, client, monkeypatch
):
    import config
    import app.recovery_service as recovery_service

    user_id = _create_user(app, "timing_recovery_user")
    with app.app_context():
        recovery_service.generate_codes(user_id, count=3)

    monkeypatch.setattr(config, "RATELIMIT_LOGIN_LIMIT", "100 per minute")
    real_compare_digest = hmac.compare_digest
    comparisons = []
    expensive_verifications = []

    def record_comparison(left, right):
        comparisons.append((left, right))
        return real_compare_digest(left, right)

    def record_expensive_verification(candidate):
        expensive_verifications.append(candidate)

    monkeypatch.setattr(
        recovery_service.hmac,
        "compare_digest",
        record_comparison,
    )
    monkeypatch.setattr(
        recovery_service,
        "_equalize_verification_cost",
        record_expensive_verification,
        raising=False,
    )

    missing = client.post(
        "/login/recovery",
        json={"username": "missing_user", "code": "invalid"},
    )
    missing_comparisons = len(comparisons)
    missing_expensive_verifications = len(expensive_verifications)
    comparisons.clear()
    expensive_verifications.clear()
    existing = client.post(
        "/login/recovery",
        json={"username": "timing_recovery_user", "code": "invalid"},
    )

    assert missing.status_code == 401
    assert existing.status_code == 401
    assert missing_comparisons == 20
    assert len(comparisons) == missing_comparisons
    assert missing_expensive_verifications == 1
    assert len(expensive_verifications) == missing_expensive_verifications


def test_locked_user_cannot_consume_valid_recovery_code(app, client):
    from app.models import User, db
    from app.recovery_service import generate_codes

    user_id = _create_user(app, "locked_recovery_user")
    with app.app_context():
        code = generate_codes(user_id, count=1)[0]
        user = db.session.get(User, user_id)
        user.is_locked = True
        db.session.commit()

    rejected = client.post(
        "/login/recovery",
        json={"username": "locked_recovery_user", "code": code},
    )

    with app.app_context():
        user = db.session.get(User, user_id)
        user.is_locked = False
        db.session.commit()

    accepted = client.post(
        "/login/recovery",
        json={"username": "locked_recovery_user", "code": code},
    )

    assert rejected.status_code == 401
    assert accepted.status_code == 200
