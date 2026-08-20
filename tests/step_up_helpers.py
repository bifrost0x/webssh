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
