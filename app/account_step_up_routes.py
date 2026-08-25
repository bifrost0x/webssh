"""Account-bound reauthentication ceremonies for factor mutations."""

from datetime import datetime, timezone
import hashlib
import json
import secrets
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
    available_mfa_methods,
    current_authentication_session,
)
from .ldap_service import LDAPDirectory, LDAPLookupRejected, LDAPUnavailable
from .models import (
    LDAPIdentity,
    OIDCIdentity,
    TOTPAuthenticator,
    User,
    WebAuthnCredential,
    db,
)
from .oidc_service import OIDCStateError
from .security_features import feature_is_active
from .step_up import (
    ACCOUNT_STEP_UP_ACTIONS,
    SecurityUIUpgradeRequired,
    StepUpError,
    account_step_up_intent,
    account_step_up_status,
    approve_account_step_up_intent,
    claim_account_step_up_grant,
    create_account_step_up_intent,
    consume_account_step_up_grant,
    recent_strong_assurance,
)
from .totp_service import verify_totp
from .webauthn_service import ChallengeError, consume_challenge, create_challenge


account_step_up_blueprint = Blueprint("account_step_up", __name__)
_passkey_lock = Lock()


def _error(code, status, message="Step-up authentication failed"):
    return jsonify({"error": message, "code": code}), status


def _rate_limit_error():
    response = jsonify({
        "error": "Step-up authentication failed",
        "code": "rate_limited",
    })
    response.status_code = 429
    response.headers["Retry-After"] = "60"
    return response


def _request_data():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise StepUpError("step-up request is invalid")
    return data


def _action_target(action, data):
    if action not in ACCOUNT_STEP_UP_ACTIONS:
        raise StepUpError("step-up request is invalid")
    feature = {
        "passkey.enroll": "passkey",
        "passkey.delete": "passkey",
        "totp.enroll": "totp",
        "recovery.rotate": "recovery",
    }.get(action)
    if feature is not None and not feature_is_active(feature):
        raise StepUpError("step-up request is invalid")
    if action == "mfa.disable" and not current_user.mfa_enabled:
        raise StepUpError("step-up request is invalid")
    if action == "passkey.delete":
        target = data.get("target")
        if not isinstance(target, int) or isinstance(target, bool):
            raise StepUpError("step-up request is invalid")
        row = db.session.get(WebAuthnCredential, target)
        if row is None or row.user_id != current_user.id:
            raise StepUpError("step-up request is invalid")
        return target
    requested = data.get("target", current_user.id)
    if str(requested) != str(current_user.id):
        raise StepUpError("step-up request is invalid")
    return current_user.id


def _allowed_methods(user, auth_session, required_assurance):
    methods = authentication_methods(auth_session)
    if "recovery_code" in methods:
        return []
    if required_assurance == AssuranceLevel.MFA.value:
        available = [
            method for method in available_mfa_methods(user)
            if method in {"passkey", "totp"}
        ]
        if (
            "oidc" in methods
            and feature_is_active("oidc")
            and OIDCIdentity.query.filter_by(user_id=user.id).first() is not None
        ):
            available.insert(0, "oidc")
        return list(dict.fromkeys(available))
    if (
        "oidc" in methods
        and feature_is_active("oidc")
        and OIDCIdentity.query.filter_by(user_id=user.id).first() is not None
    ):
        return ["oidc"]
    if (
        "ldap" in methods
        and feature_is_active("ldap")
        and user.ldap_identity is not None
    ):
        return ["ldap"]
    if "password" in methods and not user.is_ldap_managed:
        return ["password"]
    if (
        "passkey" in methods
        and "passkey" in available_mfa_methods(user)
    ):
        return ["passkey"]
    return []


def _intent_context(token):
    auth_session = current_authentication_session()
    if auth_session is None:
        raise StepUpError("step-up authorization is invalid")
    intent = account_step_up_intent(token, auth_session)
    user = db.session.get(User, current_user.id, populate_existing=True)
    if user is None:
        raise StepUpError("step-up authorization is invalid")
    return intent, user, auth_session


def _reauth_limited(method):
    client_ip = request.remote_addr or "unknown"
    limited = config.RATELIMIT_ENABLED and check_reauth_rate_limit(
        current_user.id,
        client_ip,
        f"account_step_up_{method}",
        config.RATELIMIT_REAUTH,
    )
    if limited:
        log_rate_limit_exceeded(f"account_step_up_{method}", client_ip)
    return limited


def _complete_intent(token, auth_session, assurance, method):
    intent = approve_account_step_up_intent(
        token,
        auth_session,
        assurance=assurance,
        method=method,
    )
    grant = claim_account_step_up_grant(token, auth_session)
    log_security_event(
        "ACCOUNT_STEP_UP_GRANTED",
        user=current_user.username,
        action=intent.action,
        method=method,
        assurance=assurance,
    )
    return jsonify({
        "grant": grant,
        "expires_in": 300,
        "method": method,
    })


def _passkey_binding(token):
    browser_binding = session.setdefault(
        "account_step_up_webauthn_binding",
        secrets.token_urlsafe(32),
    )
    token_hash = hashlib.sha256(str(token).encode("utf-8")).hexdigest()
    return f"{browser_binding}:{token_hash}"


@account_step_up_blueprint.post("/api/account/step-up/intents")
@login_required
def create_intent():
    try:
        data = _request_data()
        action = str(data.get("action") or "").strip()
        target = _action_target(action, data)
        auth_session = current_authentication_session()
        if auth_session is None:
            return _error("authentication_session_invalid", 401)
        user = db.session.get(User, current_user.id, populate_existing=True)
        required = (
            AssuranceLevel.MFA.value
            if user.mfa_enabled else AssuranceLevel.BASIC.value
        )
        methods = _allowed_methods(user, auth_session, required)
        recent = recent_strong_assurance(auth_session)
        if not methods and recent is None:
            return _error("step_up_failed", 403)
        token, intent = create_account_step_up_intent(
            auth_session, action, target
        )
        if recent is not None:
            return _complete_intent(
                token, auth_session, recent.value, "recent"
            )
    except StepUpError:
        return _error("invalid_request", 400, "Invalid step-up request")
    log_security_event(
        "ACCOUNT_STEP_UP_CREATED",
        user=current_user.username,
        action=intent.action,
        assurance=intent.required_assurance,
    )
    return jsonify({
        "intent": token,
        "required_assurance": intent.required_assurance,
        "preferred_method": methods[0],
        "methods": methods,
        "expires_in": 300,
    })


@account_step_up_blueprint.post("/api/account/step-up/password")
@login_required
def password_step_up():
    try:
        data = _request_data()
        token = data.get("intent")
        intent, user, auth_session = _intent_context(token)
        if "password" not in _allowed_methods(
            user, auth_session, intent.required_assurance
        ):
            return _error("step_up_failed", 403)
    except StepUpError:
        return _error("step_up_failed", 403)
    if _reauth_limited("password"):
        return _rate_limit_error()
    password = data.get("password", "")
    try:
        verified = (
            isinstance(password, str)
            and not password_exceeds_bcrypt_limit(password)
            and user.check_password(password)
        )
    except (TypeError, ValueError):
        verified = False
    if not verified:
        log_security_event(
            "ACCOUNT_STEP_UP_REJECTED",
            user=current_user.username,
            action=intent.action,
            method="password",
        )
        return _error("step_up_failed", 403)
    try:
        return _complete_intent(
            token, auth_session, AssuranceLevel.BASIC.value, "password"
        )
    except StepUpError:
        return _error("step_up_failed", 403)


@account_step_up_blueprint.post("/api/account/step-up/ldap")
@login_required
def ldap_step_up():
    try:
        data = _request_data()
        token = data.get("intent")
        intent, user, auth_session = _intent_context(token)
        if "ldap" not in _allowed_methods(
            user, auth_session, intent.required_assurance
        ):
            return _error("step_up_failed", 403)
    except StepUpError:
        return _error("step_up_failed", 403)
    if _reauth_limited("ldap"):
        return _rate_limit_error()
    password = data.get("password", "")
    if (
        not isinstance(password, str)
        or not password
        or len(password.encode("utf-8")) > 4096
    ):
        return _error("step_up_failed", 403)
    mapping = db.session.get(LDAPIdentity, user.ldap_identity.id)
    try:
        directory = LDAPDirectory()
        resolved = directory.lookup(mapping.directory_username)
        identity_matches = (
            resolved.provider == mapping.provider
            and resolved.subject == mapping.subject
        )
        verified = identity_matches and directory.verify_password(
            resolved.distinguished_name,
            password,
        )
    except LDAPUnavailable:
        return _error("provider_unavailable", 503)
    except LDAPLookupRejected:
        verified = False
    finally:
        password = None
    if not verified:
        log_security_event(
            "ACCOUNT_STEP_UP_REJECTED",
            user=current_user.username,
            action=intent.action,
            method="ldap",
        )
        return _error("step_up_failed", 403)
    mapping.distinguished_name = resolved.distinguished_name
    mapping.last_verified_at = datetime.now(timezone.utc)
    try:
        return _complete_intent(
            token, auth_session, AssuranceLevel.BASIC.value, "ldap"
        )
    except StepUpError:
        db.session.rollback()
        return _error("step_up_failed", 403)


@account_step_up_blueprint.post("/api/account/step-up/totp")
@login_required
def totp_step_up():
    try:
        data = _request_data()
        token = data.get("intent")
        intent, user, auth_session = _intent_context(token)
        if "totp" not in _allowed_methods(
            user, auth_session, intent.required_assurance
        ):
            return _error("step_up_failed", 403)
    except StepUpError:
        return _error("step_up_failed", 403)
    if _reauth_limited("totp"):
        return _rate_limit_error()
    if not verify_totp(user.id, data.get("code", "")):
        log_security_event(
            "ACCOUNT_STEP_UP_REJECTED",
            user=current_user.username,
            action=intent.action,
            method="totp",
        )
        return _error("step_up_failed", 403)
    try:
        return _complete_intent(
            token, auth_session, AssuranceLevel.MFA.value, "totp"
        )
    except StepUpError:
        return _error("step_up_failed", 403)


@account_step_up_blueprint.post("/api/account/step-up/passkey/options")
@login_required
def passkey_step_up_options():
    try:
        data = _request_data()
        token = data.get("intent")
        intent, user, auth_session = _intent_context(token)
        if "passkey" not in _allowed_methods(
            user, auth_session, intent.required_assurance
        ):
            return _error("step_up_failed", 403)
    except StepUpError:
        return _error("step_up_failed", 403)
    if _reauth_limited("passkey_options"):
        return _rate_limit_error()
    rows = WebAuthnCredential.query.filter_by(user_id=user.id).all()
    if not rows:
        return _error("step_up_failed", 403)
    options = generate_authentication_options(
        rp_id=config.WEBAUTHN_RP_ID,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=bytes(row.credential_id))
            for row in rows
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    create_challenge(
        user_id=user.id,
        purpose="step_up",
        session_binding=_passkey_binding(token),
        challenge=bytes(options.challenge),
    )
    return jsonify(json.loads(options_to_json(options)))


@account_step_up_blueprint.post("/api/account/step-up/passkey/verify")
@login_required
def passkey_step_up_verify():
    try:
        data = _request_data()
        token = data.get("intent")
        intent, user, auth_session = _intent_context(token)
        if "passkey" not in _allowed_methods(
            user, auth_session, intent.required_assurance
        ):
            return _error("step_up_failed", 403)
    except StepUpError:
        return _error("step_up_failed", 403)
    if _reauth_limited("passkey_verify"):
        return _rate_limit_error()
    try:
        with _passkey_lock:
            challenge = consume_challenge(
                user_id=user.id,
                purpose="step_up",
                session_binding=_passkey_binding(token),
            )
            credential = data.get("credential") or {}
            credential_id = base64url_to_bytes(
                str(credential.get("id") or "")
            )
            row = WebAuthnCredential.query.filter_by(
                credential_id=credential_id,
                user_id=user.id,
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
        return _complete_intent(
            token,
            auth_session,
            AssuranceLevel.PHISHING_RESISTANT.value,
            "passkey",
        )
    except Exception as exc:
        db.session.rollback()
        log_security_event(
            "ACCOUNT_STEP_UP_REJECTED",
            user=current_user.username,
            action=intent.action,
            method="passkey",
            error=type(exc).__name__,
        )
        return _error("step_up_failed", 403)


@account_step_up_blueprint.post("/api/account/step-up/oidc/start")
@login_required
def oidc_step_up_start():
    try:
        data = _request_data()
        token = data.get("intent")
        intent, user, auth_session = _intent_context(token)
        if "oidc" not in _allowed_methods(
            user, auth_session, intent.required_assurance
        ):
            return _error("step_up_failed", 403)
    except StepUpError:
        return _error("step_up_failed", 403)
    if _reauth_limited("oidc_start"):
        return _rate_limit_error()
    from .oidc_routes import begin_oidc_account_step_up

    try:
        response = begin_oidc_account_step_up(
            intent=intent,
            continuation=data.get("continuation") or "/security",
        )
    except (OIDCStateError, StepUpError):
        return _error("step_up_failed", 403)
    if isinstance(response, tuple):
        return response
    return jsonify({"authorization_url": response.headers["Location"]})


@account_step_up_blueprint.post("/api/account/step-up/status")
@login_required
def oidc_step_up_status():
    try:
        data = _request_data()
        token = data.get("intent")
        auth_session = current_authentication_session()
        status = account_step_up_status(token, auth_session)
        if status == "pending":
            return jsonify({"status": "pending"})
        if status != "approved":
            return _error("step_up_expired", 410)
        grant = claim_account_step_up_grant(token, auth_session)
    except StepUpError:
        return _error("step_up_expired", 410)
    log_security_event(
        "ACCOUNT_STEP_UP_CONSUMED",
        user=current_user.username,
        method="oidc",
    )
    return jsonify({
        "status": "completed",
        "grant": grant,
        "expires_in": 300,
    })


@account_step_up_blueprint.post("/api/account/mfa/disable")
@login_required
def disable_account_mfa():
    try:
        data = _request_data()
    except StepUpError:
        return _error("invalid_request", 400, "Invalid request")
    if data.get("confirm_disable_mfa") is not True:
        return _error(
            "invalid_request",
            400,
            "MFA deactivation must be confirmed",
        )
    user = db.session.get(User, current_user.id, populate_existing=True)
    if user is None or not user.mfa_enabled:
        return _error("security_state_changed", 409)
    try:
        consume_account_step_up_grant("mfa.disable", user.id)
    except SecurityUIUpgradeRequired:
        return _error(
            "security_ui_upgrade_required",
            409,
            "Reload the Security page before continuing",
        )
    except StepUpError:
        return _error("step_up_required", 403)
    TOTPAuthenticator.query.filter_by(
        user_id=user.id,
    ).delete(synchronize_session=False)
    user.mfa_enabled = False
    db.session.commit()
    log_security_event(
        "ACCOUNT_STEP_UP_CONSUMED",
        user=user.username,
        action="mfa.disable",
    )
    log_security_event("MFA_DISABLED", user=user.username)
    return jsonify({"ok": True})
