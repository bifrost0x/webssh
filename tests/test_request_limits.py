"""Request-body limits that must run before CSRF or view decorators."""

import io
import json
import re

import pytest
from werkzeug.test import EnvironBuilder
from werkzeug.wrappers import Response


class TrackingInput(io.BytesIO):
    def __init__(self, data):
        super().__init__(data)
        self.bytes_read = 0

    def read(self, size=-1):
        data = super().read(size)
        self.bytes_read += len(data)
        return data

    def readinto(self, buffer):
        size = super().readinto(buffer)
        self.bytes_read += size or 0
        return size


def _multipart_environ(path, payload_size, method="POST"):
    builder = EnvironBuilder(
        path=path,
        method=method,
        data={
            "payload": (
                io.BytesIO(b"x" * payload_size),
                "oversized.bin",
            )
        },
    )
    environ = builder.get_environ()
    body = environ["wsgi.input"].read()
    tracking_input = TrackingInput(body)
    environ["wsgi.input"] = tracking_input
    return environ, tracking_input


@pytest.mark.parametrize(
    ("method", "path", "expects_json"),
    (
        pytest.param("POST", "/login", False, id="login-form"),
        pytest.param("POST", "/login/recovery", True, id="recovery"),
        pytest.param(
            "POST",
            "/api/webauthn/auth/verify",
            True,
            id="webauthn",
        ),
        pytest.param(
            "POST",
            "/admin/api/users/1/oidc-link",
            True,
            id="oidc",
        ),
        pytest.param(
            "POST",
            "/admin/api/audit/retention",
            True,
            id="audit-export",
        ),
        pytest.param(
            "DELETE",
            "/api/host-keys/fingerprint",
            True,
            id="host-keys",
        ),
        pytest.param("POST", "/admin/api/users", True, id="admin-api"),
    ),
)
def test_declared_oversized_control_body_is_rejected_before_csrf_reads_it(
    app, monkeypatch, method, path, expects_json
):
    import config

    monkeypatch.setattr(config, "RECOVERY_CODES_ENABLED", True)
    monkeypatch.setattr(config, "WEBAUTHN_ENABLED", True)
    environ, tracking_input = _multipart_environ(
        path,
        200000,
        method=method,
    )
    assert int(environ["CONTENT_LENGTH"]) > 64 * 1024

    app.config["WTF_CSRF_ENABLED"] = True
    try:
        response = Response.from_app(app.wsgi_app, environ)
    finally:
        app.config["WTF_CSRF_ENABLED"] = False

    assert response.status_code == 413
    if expects_json:
        assert response.get_json() == {"error": "Request body too large"}
    else:
        assert response.get_json(silent=True) is None
    assert tracking_input.bytes_read == 0


def test_lengthless_recovery_body_is_bounded_before_csrf(app, client):
    import config

    payload = json.dumps({
        "username": "missing_user",
        "code": "invalid",
        "padding": "x" * 5000,
    }).encode("utf-8")
    login_page = client.get("/login")
    token_match = re.search(
        r'name="csrf_token"[^>]*value="([^"]+)"',
        login_page.get_data(as_text=True),
    )
    assert token_match is not None
    session_cookie_name = app.config["SESSION_COOKIE_NAME"]
    session_cookie = client.get_cookie(session_cookie_name)
    assert session_cookie is not None
    builder = EnvironBuilder(
        path="/login/recovery",
        method="POST",
        input_stream=io.BytesIO(payload),
        content_type="application/json",
        headers={"X-CSRFToken": token_match.group(1)},
    )
    environ = builder.get_environ()
    environ.pop("CONTENT_LENGTH", None)
    environ["wsgi.input_terminated"] = True
    environ["HTTP_COOKIE"] = (
        f"{session_cookie_name}={session_cookie.value}"
    )
    tracking_input = TrackingInput(payload)
    environ["wsgi.input"] = tracking_input

    app.config["WTF_CSRF_ENABLED"] = True
    try:
        response = Response.from_app(app.wsgi_app, environ)
    finally:
        app.config["WTF_CSRF_ENABLED"] = False

    assert response.status_code == 413
    assert response.get_json() == {"error": "Request body too large"}
    assert tracking_input.bytes_read <= config.MAX_RECOVERY_JSON_SIZE + 1


def test_socketio_message_limit_tracks_control_payloads_not_http_uploads(app):
    import config
    from app import socketio

    assert socketio.server.eio.max_http_buffer_size == (
        config.SOCKETIO_MAX_MESSAGE_SIZE
    )
    assert config.SOCKETIO_MAX_MESSAGE_SIZE < config.MAX_UPLOAD_SIZE
    assert config.SOCKETIO_MAX_MESSAGE_SIZE >= (
        config.MAX_EDITOR_FILE_SIZE * 6 + 64 * 1024
    )
