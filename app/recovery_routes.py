"""Recovery code enrollment, login, and controlled admin recovery."""

import logging

import config
from flask import Blueprint, abort, jsonify, request, session
from flask_login import current_user, login_required, login_user

from .audit_logger import log_rate_limit_exceeded, log_security_event
from .auth import check_rate_limit
from .decorators import admin_required
from .models import User, db
from .recovery_service import consume_code, generate_codes


recovery_blueprint = Blueprint("recovery", __name__)


def _require_enabled():
    if not config.RECOVERY_CODES_ENABLED:
        abort(404)


def _password_matches(user, password):
    try:
        return user.check_password(password)
    except (TypeError, ValueError):
        return False


@recovery_blueprint.post("/api/recovery-codes")
@login_required
def regenerate_own_recovery_codes():
    _require_enabled()
    data = request.get_json(silent=True) or {}
    if not _password_matches(current_user, data.get("password", "")):
        return jsonify({"error": "Current password is incorrect"}), 403
    codes = generate_codes(current_user.id)
    log_security_event(
        "RECOVERY_CODES_REGENERATED",
        user=current_user.username,
    )
    return jsonify({"codes": codes})


@recovery_blueprint.post("/login/recovery")
def recovery_login():
    _require_enabled()
    client_ip = request.remote_addr or "unknown"
    if config.RATELIMIT_ENABLED and check_rate_limit(
        client_ip,
        "recovery_login",
        config.RATELIMIT_LOGIN_LIMIT,
    ):
        log_rate_limit_exceeded("recovery_login", client_ip)
        return jsonify({"error": "Too many login attempts"}), 429
    data = request.get_json(silent=True) or {}
    username = str(data.get("username") or "").strip()
    user = User.query.filter_by(username=username).first()
    active_user = user if user is not None and not user.is_locked else None
    code_valid = consume_code(
        active_user.id if active_user is not None else None,
        data.get("code", ""),
    )
    valid = active_user is not None and code_valid
    if not valid:
        log_security_event(
            "RECOVERY_LOGIN_REJECTED",
            level=logging.WARNING,
            user=username or None,
            ip=client_ip,
        )
        return jsonify({"error": "Invalid recovery credentials"}), 401
    session.clear()
    login_user(active_user)
    log_security_event(
        "RECOVERY_LOGIN_SUCCESS",
        user=active_user.username,
        ip=client_ip,
    )
    return jsonify({"ok": True})


@recovery_blueprint.post("/admin/api/users/<int:user_id>/recovery")
@admin_required
@login_required
def admin_recovery(user_id):
    _require_enabled()
    data = request.get_json(silent=True) or {}
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
    return jsonify({"codes": codes})
