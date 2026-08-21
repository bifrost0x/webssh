"""Helpers for exercising protected administrator mutations."""


def password_step_up_headers(
    client,
    action,
    target,
    *,
    password="password123",
    expected_status=200,
):
    response = client.post("/api/step-up/password", json={
        "action": action,
        "target": target,
        "password": password,
    })
    assert response.status_code == expected_status
    if expected_status != 200:
        return {}, response
    return {"X-WebSSH-Step-Up": response.get_json()["grant"]}, response


def account_password_step_up_headers(
    client,
    action,
    target,
    *,
    password="password123",
    expected_status=200,
):
    started = client.post("/api/account/step-up/intents", json={
        "action": action,
        "target": target,
    })
    assert started.status_code == 200
    response = client.post("/api/account/step-up/password", json={
        "intent": started.get_json()["intent"],
        "password": password,
    })
    assert response.status_code == expected_status
    if expected_status != 200:
        return {}, response
    return {"X-WebSSH-Step-Up": response.get_json()["grant"]}, response


def mint_account_step_up_headers(
    app,
    client,
    action,
    target,
    *,
    assurance="BASIC",
    method="test",
):
    """Create verified server state for mutation-consumer unit tests."""
    from app.auth_assurance import authentication_session_for_token
    from app.models import User, db
    from app.step_up import (
        approve_account_step_up_intent,
        claim_account_step_up_grant,
        create_account_step_up_intent,
    )

    with client.session_transaction() as browser:
        opaque = browser["_auth_session"]
        user_id = int(str(browser["_user_id"]).split(":", 1)[0])
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
            assurance=assurance,
            method=method,
        )
        grant = claim_account_step_up_grant(token, auth_session)
    return {"X-WebSSH-Step-Up": grant}
