"""Recovery Code enrollment and primary-factor-bound account recovery."""

from datetime import datetime, timezone
import logging

import config
from flask import Blueprint, abort, jsonify, request, session
from flask_login import current_user, login_required
from werkzeug.exceptions import RequestEntityTooLarge

from .audit_logger import log_rate_limit_exceeded, log_security_event
from .auth import check_rate_limit, check_reauth_rate_limit
from .auth_assurance import (
    AssuranceLevel,
    AuthenticationFinalizationError,
    PendingAuthenticationError,
    clear_recovery_restriction,
    finalize_pending_with_factor,
    pending_authentication,
    recovery_session_required,
)
from .decorators import admin_required
from .models import User, db
from .recovery_service import consume_code, generate_codes


recovery_blueprint = Blueprint("recovery", __name__)


def _require_enabled():
    from .security_features import feature_is_active

    if not feature_is_active("recovery"):
        abort(404)


def _password_matches(user, password):
    if user.is_ldap_managed:
        return False
    try:
        return user.check_password(password)
    except (TypeError, ValueError):
        return False


def _factor_change_reauthenticated(user, data):
    if user.is_ldap_managed:
        try:
            verified_at = int(session.get("_ldap_verified_at", 0))
        except (TypeError, ValueError):
            return False
        age = int(datetime.now(timezone.utc).timestamp()) - verified_at
        return 0 <= age <= config.STEP_UP_MAX_AGE_SECONDS
    return _password_matches(user, data.get("password", ""))


def _bounded_json():
    """Parse one small recovery payload without materializing an unbounded body."""
    request.max_content_length = config.MAX_RECOVERY_JSON_SIZE
    if (
        request.content_length is not None
        and request.content_length > config.MAX_RECOVERY_JSON_SIZE
    ):
        return None
    try:
        data = request.get_json(silent=True)
    except RequestEntityTooLarge:
        return None
    return data if isinstance(data, dict) else {}


def _request_body_too_large():
    return jsonify({"error": "Request body too large"}), 413


def _no_store(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


@recovery_blueprint.post("/api/recovery-codes")
@login_required
def regenerate_own_recovery_codes():
    _require_enabled()
    client_ip = request.remote_addr or "unknown"
    if config.RATELIMIT_ENABLED and check_reauth_rate_limit(
        current_user.id,
        client_ip,
        "recovery_codes_reauth",
        config.RATELIMIT_REAUTH,
    ):
        log_rate_limit_exceeded("recovery_codes_reauth", client_ip)
        return jsonify({"error": "Too many authentication attempts"}), 429
    data = _bounded_json()
    if data is None:
        return _request_body_too_large()
    if not _factor_change_reauthenticated(current_user, data):
        return jsonify({"error": "Recent authentication is required"}), 403
    codes = generate_codes(current_user.id)
    log_security_event(
        "RECOVERY_CODES_REGENERATED",
        user=current_user.username,
    )
    return _no_store(jsonify({"codes": codes}))


@recovery_blueprint.post("/login/recovery")
def standalone_recovery_compatibility():
    """Reject the removed standalone contract without inspecting a code."""
    _require_enabled()
    return jsonify({
        "error": "Complete the primary sign-in before using a Recovery Code"
    }), 400


@recovery_blueprint.post("/api/auth/recovery")
def complete_pending_with_recovery():
    _require_enabled()
    client_ip = request.remote_addr or "unknown"
    if config.RATELIMIT_ENABLED and check_rate_limit(
        client_ip,
        "recovery_mfa",
        config.RATELIMIT_LOGIN_LIMIT,
    ):
        log_rate_limit_exceeded("recovery_mfa", client_ip)
        return jsonify({"error": "Too many authentication attempts"}), 429
    data = _bounded_json()
    if data is None:
        return _request_body_too_large()
    token = session.get("_pending_authentication")
    binding = session.get("_auth_binding")
    try:
        pending = pending_authentication(token, binding)
    except PendingAuthenticationError:
        return jsonify({"error": "Pending authentication is invalid"}), 401
    user = db.session.get(User, pending.user_id)
    if user is None or user.is_locked or not user.mfa_enabled:
        return jsonify({"error": "Recovery authentication failed"}), 401
    if not consume_code(user.id, data.get("code", "")):
        log_security_event(
            "RECOVERY_AUTHENTICATION_REJECTED",
            level=logging.WARNING,
            user=user.username,
            ip=client_ip,
        )
        return jsonify({"error": "Recovery authentication failed"}), 401
    try:
        _row, _continuation = finalize_pending_with_factor(
            token,
            binding,
            user_id=user.id,
            factor="recovery_code",
            assurance=AssuranceLevel.MFA,
        )
    except (PendingAuthenticationError, AuthenticationFinalizationError):
        db.session.rollback()
        return jsonify({"error": "Recovery authentication failed"}), 401
    log_security_event(
        "RECOVERY_RESTRICTED_SESSION_STARTED",
        user=user.username,
        ip=client_ip,
    )
    return jsonify({
        "ok": True,
        "recovery_required": True,
        "continuation": "/security",
    })


@recovery_blueprint.post("/api/auth/mfa/disable")
@login_required
def disable_mfa_after_recovery():
    _require_enabled()
    if not recovery_session_required():
        return jsonify({"error": "Recovery session is required"}), 403
    data = _bounded_json()
    if data is None:
        return _request_body_too_large()
    if data.get("confirm_username") != current_user.username:
        return jsonify({"error": "Account confirmation does not match"}), 400
    clear_recovery_restriction(disable_mfa=True)
    log_security_event(
        "MFA_DISABLED_AFTER_RECOVERY",
        user=current_user.username,
    )
    return jsonify({"ok": True})


@recovery_blueprint.post("/admin/api/users/<int:user_id>/recovery")
@admin_required
@login_required
def admin_recovery(user_id):
    _require_enabled()
    client_ip = request.remote_addr or "unknown"
    if config.RATELIMIT_ENABLED and check_reauth_rate_limit(
        current_user.id,
        client_ip,
        "admin_recovery_reauth",
        config.RATELIMIT_REAUTH,
    ):
        log_rate_limit_exceeded("admin_recovery_reauth", client_ip)
        return jsonify({"error": "Too many authentication attempts"}), 429
    data = _bounded_json()
    if data is None:
        return _request_body_too_large()
    if not _password_matches(current_user, data.get("password", "")):
        return jsonify({"error": "Administrator password is incorrect"}), 403
    target = db.session.get(User, user_id)
    if target is None:
        return jsonify({"error": "User not found"}), 404
    if data.get("confirm_username") != target.username:
        return jsonify({"error": "Target confirmation does not match"}), 400
    codes = generate_codes(target.id)
    log_security_event(
        "ADMIN_RECOVERY_CODES_REGENERATED",
        level=logging.WARNING,
        admin=current_user.username,
        user=target.username,
    )
    return _no_store(jsonify({"codes": codes}))
