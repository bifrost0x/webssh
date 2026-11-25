"""Optional TOTP enrollment and pending-login completion endpoints."""

import logging
import secrets

import config
from .auth_redirects import public_continuation
from flask import Blueprint, abort, flash, jsonify, request, session
from flask_login import current_user, login_required

from . import mfa_throttle
from .audit_logger import log_rate_limit_exceeded, log_security_event
from .auth import check_rate_limit, check_reauth_rate_limit
from .auth_assurance import (
    AssuranceLevel,
    AuthenticationFinalizationError,
    PendingAuthenticationError,
    browser_session_binding,
    cancel_pending_authentication,
    clear_recovery_restriction,
    finalize_pending_with_factor,
    pending_authentication,
    recovery_session_required,
)
from .models import TOTPAuthenticator, User, db
from .totp_service import (
    TOTPEnrollmentError,
    activate_totp_enrollment,
    begin_totp_enrollment,
    disable_totp_mfa,
    verify_totp,
)
from .step_up import (
    SecurityUIUpgradeRequired,
    StepUpError,
    consume_account_step_up_grant,
)


totp_blueprint = Blueprint("totp", __name__)


def _require_enabled():
    from .security_features import feature_is_active

    if not feature_is_active("totp"):
        abort(404)


def _bounded_json():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _no_store(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def _enrollment_binding():
    return session.setdefault("totp_binding", secrets.token_urlsafe(32))


def _consume_factor_grant(action, target=None, *, recovery_repair=False):
    if recovery_repair and recovery_session_required():
        return None
    try:
        consume_account_step_up_grant(
            action,
            current_user.id if target is None else target,
        )
    except SecurityUIUpgradeRequired:
        return jsonify({
            "error": "Reload the Security page before continuing",
            "code": "security_ui_upgrade_required",
        }), 409
    except StepUpError:
        return jsonify({
            "error": "Additional authentication is required",
            "code": "step_up_required",
        }), 403
    log_security_event(
        "ACCOUNT_STEP_UP_CONSUMED",
        user=current_user.username,
        action=action,
    )
    return None


def _reauth_rate_limited(action):
    client_ip = request.remote_addr or "unknown"
    limited = config.RATELIMIT_ENABLED and check_reauth_rate_limit(
        current_user.id,
        client_ip,
        action,
        config.RATELIMIT_REAUTH,
    )
    if limited:
        log_rate_limit_exceeded(action, client_ip)
    return limited


@totp_blueprint.get("/api/totp/authenticators")
@login_required
def list_totp_authenticators():
    _require_enabled()
    rows = TOTPAuthenticator.query.filter_by(
        user_id=current_user.id,
        active=True,
    ).order_by(TOTPAuthenticator.id.asc()).all()
    return jsonify({
        "mfa_enabled": bool(current_user.mfa_enabled),
        "authenticators": [{
            "id": row.id,
            "label": row.label,
            "created_at": row.created_at.isoformat(),
            "last_used_at": (
                row.last_used_at.isoformat() if row.last_used_at else None
            ),
        } for row in rows],
    })


@totp_blueprint.delete("/api/totp/authenticators/<int:authenticator_id>")
@login_required
def delete_totp_authenticator(authenticator_id):
    _require_enabled()
    row = db.session.get(TOTPAuthenticator, authenticator_id)
    if row is None or row.user_id != current_user.id:
        return jsonify({"error": "Authenticator not found"}), 404
    grant_error = _consume_factor_grant("totp.delete", authenticator_id)
    if grant_error is not None:
        return grant_error

    from .mfa_factors import durable_factor_counts, factor_mutation

    with factor_mutation():
        row = db.session.get(
            TOTPAuthenticator,
            authenticator_id,
            populate_existing=True,
        )
        user = db.session.get(User, current_user.id, populate_existing=True)
        if row is None or row.user_id != current_user.id:
            return jsonify({"error": "Authenticator not found"}), 404
        if user is None:
            return jsonify({"error": "Account is unavailable"}), 409
        remaining = durable_factor_counts(
            user.id,
            excluding_totp_id=(row.id if row.active else None),
        )
        if user.mfa_enabled and remaining["total"] == 0:
            return jsonify({
                "error": "Add a replacement factor or disable MFA first",
                "code": "last_factor_required",
            }), 409
        db.session.delete(row)
        db.session.commit()

    log_security_event(
        "TOTP_AUTHENTICATOR_DELETED",
        user=current_user.username,
        authenticator_id=authenticator_id,
    )
    return jsonify({"ok": True, "mfa_enabled": bool(user.mfa_enabled)})


@totp_blueprint.post("/api/totp/enroll")
@login_required
def start_totp_enrollment():
    _require_enabled()
    data = _bounded_json()
    grant_error = _consume_factor_grant(
        "totp.enroll",
        recovery_repair=True,
    )
    if grant_error is not None:
        return grant_error
    label = str(data.get("label") or "Authenticator").strip()
    if not label or len(label) > 80:
        return jsonify({"error": "Authenticator label is invalid"}), 400
    view = begin_totp_enrollment(
        current_user.id,
        _enrollment_binding(),
        label=label,
    )
    response = jsonify({
        "token": view.token,
        "secret": view.secret,
        "provisioning_uri": view.provisioning_uri,
        "qr_svg": view.qr_svg,
        "expires_at": view.expires_at.isoformat(),
    })
    log_security_event("TOTP_ENROLLMENT_STARTED", user=current_user.username)
    return _no_store(response)


@totp_blueprint.post("/api/totp/enroll/verify")
@login_required
def finish_totp_enrollment():
    _require_enabled()
    if _reauth_rate_limited("totp_enrollment_verify"):
        return jsonify({"error": "Too many authentication attempts"}), 429
    data = _bounded_json()
    if data.get("confirm_enable_mfa") is not True:
        return jsonify({"error": "MFA activation must be confirmed"}), 400
    try:
        authenticator = activate_totp_enrollment(
            data.get("token"),
            data.get("code"),
            _enrollment_binding(),
        )
    except TOTPEnrollmentError:
        log_security_event(
            "TOTP_ENROLLMENT_REJECTED",
            level=logging.WARNING,
            user=current_user.username,
        )
        return jsonify({"error": "TOTP enrollment could not be verified"}), 400
    clear_recovery_restriction(replacement_factor="totp")
    response = jsonify({
        "ok": True,
        "authenticator_id": authenticator.id,
        "recovery_codes": list(authenticator.recovery_codes),
    })
    log_security_event("MFA_ENABLED", user=current_user.username, factor="totp")
    return _no_store(response)


def _restart_username_hint(pending):
    """Return ``(source, name)`` for the form the discarded login started on.

    A local sign-in matches the account name exactly; an LDAP sign-in stores
    the directory name it was given on the identity. Logins that did not
    start with a typed name (OIDC, GitHub) get no hint.
    """
    user = db.session.get(User, pending.user_id)
    if user is None:
        return None
    if pending.primary_method == "password":
        return "local", user.username
    if pending.primary_method == "ldap" and user.ldap_identity is not None:
        return "ldap", user.ldap_identity.directory_username
    return None


@totp_blueprint.post("/api/totp/auth/verify")
def verify_totp_login():
    _require_enabled()
    client_ip = request.remote_addr or "unknown"
    if config.RATELIMIT_ENABLED and check_rate_limit(
        client_ip,
        "totp_login",
        config.RATELIMIT_LOGIN_LIMIT,
    ):
        log_rate_limit_exceeded("totp_login", client_ip)
        return jsonify({"error": "Too many authentication attempts"}), 429
    token = session.get("_pending_authentication")
    binding = browser_session_binding()
    try:
        pending = pending_authentication(token, binding)
    except (PendingAuthenticationError, AuthenticationFinalizationError):
        db.session.rollback()
        return jsonify({"error": "Pending authentication is invalid"}), 401
    if config.RATELIMIT_ENABLED and check_reauth_rate_limit(
        pending.user_id, client_ip, "totp_login_account", config.RATELIMIT_LOGIN_LIMIT,
    ):
        log_rate_limit_exceeded("totp_login_account", client_ip)
        return jsonify({"error": "Too many authentication attempts"}), 429
    data = _bounded_json()
    user_id = pending.user_id
    try:
        failures = mfa_throttle.claim_attempt(user_id, scope=mfa_throttle.LOGIN)
    except mfa_throttle.MFAAttemptThrottled as exc:
        log_security_event(
            "MFA_ATTEMPT_THROTTLED",
            level=logging.WARNING,
            user_id=user_id,
            method="totp",
            flow="login",
            failures=exc.failures,
            retry_after=exc.retry_after,
            ip=client_ip,
        )
        return mfa_throttle.throttled_response(exc)
    if not verify_totp(user_id, data.get("code")):
        log_security_event(
            "TOTP_AUTHENTICATION_REJECTED",
            level=logging.WARNING,
            user_id=user_id,
            failures=failures,
            ip=client_ip,
        )
        if mfa_throttle.pending_should_be_discarded(failures):
            hint = _restart_username_hint(pending)
            cancel_pending_authentication(token, binding)
            session.pop("_pending_authentication", None)
            flash("Too many invalid codes. Sign in again.", "error")
            # One-shot hint for the password form; the login page consumes it
            # with the other flashes, so it never reaches a URL or lingers.
            if hint is not None:
                flash(hint[0], "login_auth_source")
                flash(hint[1], "login_username")
            log_security_event(
                "MFA_PENDING_LOGIN_DISCARDED",
                level=logging.WARNING,
                user_id=user_id,
                method="totp",
                failures=failures,
                ip=client_ip,
            )
            return jsonify({
                "error": "Too many invalid codes. Sign in again.",
                "code": "mfa_restart",
            }), 401
        return jsonify({"error": "TOTP code is invalid", "code": "invalid_code"}), 401
    mfa_throttle.record_success(user_id, scope=mfa_throttle.LOGIN)
    try:
        _row, continuation = finalize_pending_with_factor(
            token,
            binding,
            user_id=user_id,
            factor="totp",
            assurance=AssuranceLevel.MFA,
        )
    except PendingAuthenticationError:
        return jsonify({"error": "Pending authentication is invalid"}), 401
    return jsonify({"ok": True, "continuation": public_continuation(continuation)})


@totp_blueprint.post("/api/totp/disable")
@login_required
def disable_mfa():
    _require_enabled()
    data = _bounded_json()
    if data.get("confirm_disable_mfa") is not True:
        return jsonify({"error": "MFA deactivation must be confirmed"}), 400
    grant_error = _consume_factor_grant("mfa.disable")
    if grant_error is not None:
        return grant_error
    user = db.session.get(User, current_user.id)
    disable_totp_mfa(user)
    db.session.commit()
    log_security_event("MFA_DISABLED", user=user.username)
    return jsonify({"ok": True})
