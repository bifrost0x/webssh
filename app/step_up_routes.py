"""Administrator step-up ceremonies and grant issuance."""

from datetime import datetime, timezone
import json
import secrets
import time
from threading import Lock

from flask import Blueprint, jsonify, request, session
from flask_login import current_user, login_required
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    options_to_json,
    verify_authentication_response,
)
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

import config

from .audit_logger import log_rate_limit_exceeded, log_security_event
from .auth import check_reauth_rate_limit, password_exceeds_bcrypt_limit
from .auth_assurance import (
    AssuranceLevel,
    authentication_methods,
    current_authentication_session,
)
from .decorators import admin_required
from .models import User, WebAuthnCredential, db
from .step_up import (
    StepUpError,
    create_step_up_grant,
    create_step_up_grant_for_hash,
    hash_step_up_target,
    normalize_action,
    recent_strong_assurance,
)
from .totp_service import verify_totp
from .webauthn_service import ChallengeError, consume_challenge, create_challenge


step_up_blueprint = Blueprint("step_up", __name__)
_passkey_lock = Lock()


def _intent():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise StepUpError("step-up request is invalid")
    action = normalize_action(data.get("action"))
    target = data.get("target")
    hash_step_up_target(target)
    return data, action, target


def _failure(status=403):
    return jsonify({"error": "Step-up authentication failed"}), status


def _factor_available(name):
    from .auth_assurance import available_mfa_methods

    return name in available_mfa_methods(
        db.session.get(User, current_user.id, populate_existing=True)
    )


@step_up_blueprint.post("/api/step-up/intents")
@admin_required
@login_required
def create_intent():
    try:
        _data, action, target = _intent()
    except StepUpError:
        return _failure(400)
    auth_session = current_authentication_session()
    assurance = recent_strong_assurance(auth_session)
    if assurance is not None:
        try:
            grant = create_step_up_grant(
                auth_session, action, target, assurance
            )
        except StepUpError:
            return _failure()
        return jsonify({"method": "recent", "grant": grant})

    methods = set(authentication_methods(auth_session))
    if "oidc" in methods and config.OIDC_ENABLED:
        return jsonify({"method": "oidc", "methods": ["oidc"]})
    account = db.session.get(User, current_user.id, populate_existing=True)
    if account.mfa_enabled:
        from .auth_assurance import available_mfa_methods
        available = [
            value for value in available_mfa_methods(account)
            if value in {"passkey", "totp"}
        ]
        if not available:
            return _failure()
        return jsonify({"method": available[0], "methods": available})
    return jsonify({"method": "password", "methods": ["password"]})


@step_up_blueprint.post("/api/step-up/password")
@admin_required
@login_required
def password_step_up():
    try:
        data, action, target = _intent()
    except StepUpError:
        return _failure(400)
    account = db.session.get(User, current_user.id, populate_existing=True)
    if account.mfa_enabled or account.is_ldap_managed:
        return _failure()
    client_ip = request.remote_addr or "unknown"
    if config.RATELIMIT_ENABLED and check_reauth_rate_limit(
        current_user.id,
        client_ip,
        "admin_step_up_password",
        config.RATELIMIT_REAUTH,
    ):
        log_rate_limit_exceeded("admin_step_up_password", client_ip)
        return _failure(429)
    password = data.get("password", "")
    try:
        matches = (
            isinstance(password, str)
            and not password_exceeds_bcrypt_limit(password)
            and account.check_password(password)
        )
    except (TypeError, ValueError):
        matches = False
    if not matches:
        log_security_event(
            "ADMIN_STEP_UP_REJECTED",
            user=current_user.username,
            method="password",
            ip=client_ip,
        )
        return _failure()
    try:
        grant = create_step_up_grant(
            current_authentication_session(),
            action,
            target,
            AssuranceLevel.BASIC,
        )
    except StepUpError:
        return _failure()
    log_security_event(
        "ADMIN_STEP_UP_GRANTED",
        user=current_user.username,
        method="password",
        action=action,
    )
    return jsonify({"grant": grant, "expires_in": 300})


@step_up_blueprint.post("/api/step-up/totp")
@admin_required
@login_required
def totp_step_up():
    try:
        data, action, target = _intent()
    except StepUpError:
        return _failure(400)
    if not _factor_available("totp"):
        return _failure()
    client_ip = request.remote_addr or "unknown"
    if config.RATELIMIT_ENABLED and check_reauth_rate_limit(
        current_user.id,
        client_ip,
        "admin_step_up_totp",
        config.RATELIMIT_REAUTH,
    ):
        log_rate_limit_exceeded("admin_step_up_totp", client_ip)
        return _failure(429)
    if not verify_totp(current_user.id, data.get("code", "")):
        log_security_event(
            "ADMIN_STEP_UP_REJECTED",
            user=current_user.username,
            method="totp",
            ip=client_ip,
        )
        return _failure()
    try:
        grant = create_step_up_grant(
            current_authentication_session(),
            action,
            target,
            AssuranceLevel.MFA,
        )
    except StepUpError:
        return _failure()
    log_security_event(
        "ADMIN_STEP_UP_GRANTED",
        user=current_user.username,
        method="totp",
        action=action,
    )
    return jsonify({"grant": grant, "expires_in": 300})


def _passkey_binding():
    return session.setdefault(
        "step_up_webauthn_binding",
        secrets.token_urlsafe(32),
    )


@step_up_blueprint.post("/api/step-up/passkey/options")
@admin_required
@login_required
def passkey_step_up_options():
    try:
        _data, action, target = _intent()
    except StepUpError:
        return _failure(400)
    if not _factor_available("passkey"):
        return _failure()
    rows = WebAuthnCredential.query.filter_by(user_id=current_user.id).all()
    options = generate_authentication_options(
        rp_id=config.WEBAUTHN_RP_ID,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=bytes(row.credential_id))
            for row in rows
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    create_challenge(
        user_id=current_user.id,
        purpose="step_up",
        session_binding=_passkey_binding(),
        challenge=bytes(options.challenge),
    )
    session["_step_up_passkey_intent"] = {
        "action": action,
        "target_hash": hash_step_up_target(target),
        "expires_at": int(time.time()) + 300,
    }
    return jsonify(json.loads(options_to_json(options)))


@step_up_blueprint.post("/api/step-up/passkey/verify")
@admin_required
@login_required
def passkey_step_up_verify():
    data = request.get_json(silent=True)
    intent = session.pop("_step_up_passkey_intent", None)
    client_ip = request.remote_addr or "unknown"
    try:
        if (
            not isinstance(data, dict)
            or not isinstance(intent, dict)
            or type(intent.get("expires_at")) is not int
            or intent["expires_at"] < int(time.time())
        ):
            raise ChallengeError("step-up intent is invalid")
        action = normalize_action(intent.get("action"))
        target_hash = str(intent.get("target_hash") or "")
        with _passkey_lock:
            challenge = consume_challenge(
                user_id=current_user.id,
                purpose="step_up",
                session_binding=_passkey_binding(),
            )
            credential = data.get("credential") or {}
            credential_id = base64url_to_bytes(str(credential.get("id") or ""))
            row = WebAuthnCredential.query.filter_by(
                credential_id=credential_id,
                user_id=current_user.id,
            ).first()
            if row is None:
                raise ChallengeError("credential is unavailable")
            verified = verify_authentication_response(
                credential=credential,
                expected_challenge=challenge,
                expected_rp_id=config.WEBAUTHN_RP_ID,
                expected_origin=config.WEBAUTHN_ORIGIN,
                credential_public_key=bytes(row.public_key),
                credential_current_sign_count=row.sign_count,
                require_user_verification=True,
            )
            new_sign_count = int(verified.new_sign_count)
            if row.sign_count and new_sign_count <= row.sign_count:
                raise ChallengeError("authenticator counter did not advance")
            row.sign_count = max(row.sign_count, new_sign_count)
            row.last_used_at = datetime.now(timezone.utc)
            db.session.commit()
        grant = create_step_up_grant_for_hash(
            current_authentication_session(),
            action,
            target_hash,
            AssuranceLevel.PHISHING_RESISTANT,
        )
    except Exception as exc:
        db.session.rollback()
        log_security_event(
            "ADMIN_STEP_UP_REJECTED",
            user=current_user.username,
            method="passkey",
            ip=client_ip,
            error=type(exc).__name__,
        )
        return _failure()
    log_security_event(
        "ADMIN_STEP_UP_GRANTED",
        user=current_user.username,
        method="passkey",
        action=action,
    )
    return jsonify({"grant": grant, "expires_in": 300})


@step_up_blueprint.post("/api/step-up/oidc/start")
@admin_required
@login_required
def oidc_step_up_start():
    try:
        data, action, target = _intent()
    except StepUpError:
        return _failure(400)
    if not config.OIDC_ENABLED or "oidc" not in authentication_methods(
        current_authentication_session()
    ):
        return _failure()
    continuation = str(data.get("continuation") or "/admin")
    from .oidc_routes import begin_oidc_step_up

    response = begin_oidc_step_up(
        action=action,
        target_hash=hash_step_up_target(target),
        continuation=continuation,
    )
    if isinstance(response, tuple):
        return response
    return jsonify({"authorization_url": response.headers["Location"]})


@step_up_blueprint.get("/api/step-up/oidc/result")
@admin_required
@login_required
def oidc_step_up_result():
    result = session.pop("_oidc_step_up_result", None)
    if (
        not isinstance(result, dict)
        or type(result.get("expires_at")) is not int
        or result["expires_at"] < int(time.time())
        or not isinstance(result.get("grant"), str)
    ):
        return _failure(404)
    return jsonify({
        "grant": result["grant"],
        "action": result.get("action"),
        "expires_in": max(0, result["expires_at"] - int(time.time())),
    })
