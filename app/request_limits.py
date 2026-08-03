"""Early request-body limits applied before CSRF parses form data."""

from flask import abort, jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge

import config


CONTROL_REQUEST_LIMIT = 64 * 1024
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_JSON_BLUEPRINTS = frozenset({
    "audit_export",
    "host_keys",
    "oidc",
    "recovery",
    "transfers",
    "webauthn",
})
_STREAMING_ENDPOINTS = frozenset({
    "admin_backup.upload_backup",
    "transfers.upload_transfer",
})


def _policy_for_request():
    if request.blueprint == "recovery":
        limit = config.MAX_RECOVERY_JSON_SIZE
    elif request.blueprint == "webauthn":
        limit = config.MAX_WEBAUTHN_JSON_SIZE
    elif request.endpoint == "admin_backup.upload_backup":
        limit = config.BACKUP_UPLOAD_MAX_SIZE
    elif request.endpoint in _STREAMING_ENDPOINTS:
        limit = config.MAX_UPLOAD_SIZE
    else:
        limit = CONTROL_REQUEST_LIMIT

    streaming = request.endpoint in _STREAMING_ENDPOINTS
    json_error = (
        request.blueprint in _JSON_BLUEPRINTS
        or request.path.startswith("/admin/api/")
        or request.is_json
    )
    return limit, streaming, json_error


def _request_body_too_large(json_error):
    if json_error:
        return jsonify({"error": "Request body too large"}), 413
    abort(413)


def init_request_limits(app):
    """Register request limits before middleware can consume request bodies."""

    @app.before_request
    def enforce_request_limit():
        if request.method not in _UNSAFE_METHODS:
            return None

        limit, streaming, json_error = _policy_for_request()
        if (
            request.content_length is not None
            and request.content_length > limit
        ):
            return _request_body_too_large(json_error)

        request.max_content_length = limit + 1
        if streaming:
            return None

        try:
            raw_data = request.get_data(cache=True)
        except RequestEntityTooLarge:
            return _request_body_too_large(json_error)
        if len(raw_data) > limit:
            return _request_body_too_large(json_error)
        return None
