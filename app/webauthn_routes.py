"""Feature-flagged WebAuthn registration and authentication routes."""

import json
import logging
import secrets
from datetime import datetime, timezone
from threading import Lock

from flask import Blueprint, abort, jsonify, request, session
from flask_login import current_user, login_required, login_user
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import RequestEntityTooLarge

import config

from .audit_logger import (
    log_rate_limit_exceeded,
    log_security_event,
)
from .auth import check_rate_limit, check_reauth_rate_limit
from .models import User, WebAuthnCredential, db
from .webauthn_service import ChallengeError, consume_challenge, create_challenge


webauthn_blueprint = Blueprint("webauthn", __name__)
_authentication_lock = Lock()
_registration_lock = Lock()
_AUTHENTICATION_DESCRIPTOR_COUNT = 10


def init_webauthn_request_limits(app):
    """Reject or bound WebAuthn bodies before CSRF accesses them."""

    @app.before_request
    def bound_webauthn_request_body():
        if request.blueprint != webauthn_blueprint.name:
            return None
        if (
            request.content_length is not None
            and request.content_length > config.MAX_WEBAUTHN_JSON_SIZE
        ):
            return _request_body_too_large()
        request.max_content_length = config.MAX_WEBAUTHN_JSON_SIZE + 1
        return None


def _require_enabled():
    if not config.WEBAUTHN_ENABLED:
        abort(404)


def _bounded_json():
    """Parse one WebAuthn payload with a one-byte overflow probe."""
    request.max_content_length = config.MAX_WEBAUTHN_JSON_SIZE + 1
    if (
        request.content_length is not None
        and request.content_length > config.MAX_WEBAUTHN_JSON_SIZE
    ):
        return None
    try:
        raw_data = request.get_data(cache=True)
        if len(raw_data) > config.MAX_WEBAUTHN_JSON_SIZE:
            return None
        data = request.get_json(silent=True)
    except RequestEntityTooLarge:
        return None
    return data if isinstance(data, dict) else {}


def _request_body_too_large():
    return jsonify({"error": "Request body too large"}), 413


def _binding():
    return session.setdefault(
        "webauthn_binding",
        secrets.token_urlsafe(32),
    )


def _credential_descriptor(row):
    return PublicKeyCredentialDescriptor(id=bytes(row.credential_id))


@webauthn_blueprint.get("/api/webauthn/credentials")
@login_required
def list_credentials():
    _require_enabled()
    rows = WebAuthnCredential.query.filter_by(
        user_id=current_user.id
    ).order_by(WebAuthnCredential.id.asc()).all()
    return jsonify({"credentials": [
        {
            "id": row.id,
            "name": row.name,
            "created_at": row.created_at.isoformat(),
            "last_used_at": (
                row.last_used_at.isoformat()
                if row.last_used_at
                else None
            ),
        }
        for row in rows
    ]})


@webauthn_blueprint.post("/api/webauthn/register/options")
@login_required
def registration_options():
    _require_enabled()
    client_ip = request.remote_addr or "unknown"
    if config.RATELIMIT_ENABLED and check_reauth_rate_limit(
        current_user.id,
        client_ip,
        "webauthn_register_reauth",
        config.RATELIMIT_REAUTH,
    ):
        log_rate_limit_exceeded("webauthn_register_reauth", client_ip)
        return jsonify({"error": "Too many password attempts"}), 429
    data = _bounded_json()
    if data is None:
        return _request_body_too_large()
    password = data.get("password", "")
    try:
        password_valid = current_user.check_password(password)
    except (TypeError, ValueError):
        password_valid = False
    if not password_valid:
        return jsonify({"error": "Current password is incorrect"}), 403
    existing = WebAuthnCredential.query.filter_by(
        user_id=current_user.id
    ).all()
    if len(existing) >= _AUTHENTICATION_DESCRIPTOR_COUNT:
        return jsonify({"error": "Passkey limit reached"}), 409
    legacy_upgrade = data.get("legacy_upgrade") is True
    options = generate_registration_options(
        rp_id=config.WEBAUTHN_RP_ID,
        rp_name=config.WEBAUTHN_RP_NAME,
        user_id=str(current_user.id).encode("ascii"),
        user_name=current_user.username,
        user_display_name=current_user.username,
        exclude_credentials=(
            []
            if legacy_upgrade
            else [_credential_descriptor(row) for row in existing]
        ),
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    create_challenge(
        user_id=current_user.id,
        purpose="register",
        session_binding=_binding(),
        challenge=bytes(options.challenge),
    )
    return jsonify(json.loads(options_to_json(options)))


@webauthn_blueprint.post("/api/webauthn/register/verify")
@login_required
def verify_registration():
    _require_enabled()
    data = _bounded_json()
    if data is None:
        return _request_body_too_large()
    credential = data.get("credential")
    name = str(data.get("name") or "Passkey").strip()[:80] or "Passkey"
    try:
        challenge = consume_challenge(
            user_id=current_user.id,
            purpose="register",
            session_binding=_binding(),
        )
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=config.WEBAUTHN_RP_ID,
            expected_origin=config.WEBAUTHN_ORIGIN,
            require_user_verification=True,
        )
    except Exception as exc:
        log_security_event(
            "WEBAUTHN_REGISTRATION_REJECTED",
            level=logging.WARNING,
            user=current_user.username,
            ip=request.remote_addr or "unknown",
            error=type(exc).__name__,
        )
        return jsonify({"error": "Passkey registration failed"}), 400
    transports = (
        credential.get("response", {}).get("transports", [])
        if isinstance(credential, dict)
        else []
    )
    row = WebAuthnCredential(
        user_id=current_user.id,
        credential_id=bytes(verified.credential_id),
        public_key=bytes(verified.credential_public_key),
        sign_count=int(verified.sign_count),
        transports=json.dumps(transports),
        name=name,
    )
    with _registration_lock:
        credential_count = WebAuthnCredential.query.filter_by(
            user_id=current_user.id
        ).count()
        if credential_count >= _AUTHENTICATION_DESCRIPTOR_COUNT:
            return jsonify({"error": "Passkey limit reached"}), 409
        db.session.add(row)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return jsonify({"error": "Passkey is already registered"}), 409
        except Exception as exc:
            db.session.rollback()
            log_security_event(
                "WEBAUTHN_CREDENTIAL_STORAGE_FAILED",
                level=logging.ERROR,
                user=current_user.username,
                error=type(exc).__name__,
            )
            return jsonify({
                "error": "Passkey storage is temporarily unavailable"
            }), 503
    log_security_event(
        "WEBAUTHN_CREDENTIAL_REGISTERED",
        user=current_user.username,
    )
    return jsonify({"id": row.id, "name": row.name}), 201


@webauthn_blueprint.delete("/api/webauthn/credentials/<int:credential_id>")
@login_required
def delete_credential(credential_id):
    _require_enabled()
    client_ip = request.remote_addr or "unknown"
    if config.RATELIMIT_ENABLED and check_reauth_rate_limit(
        current_user.id,
        client_ip,
        "webauthn_delete_reauth",
        config.RATELIMIT_REAUTH,
    ):
        log_rate_limit_exceeded("webauthn_delete_reauth", client_ip)
        return jsonify({"error": "Too many password attempts"}), 429
    data = _bounded_json()
    if data is None:
        return _request_body_too_large()
    try:
        password_valid = current_user.check_password(data.get("password", ""))
    except (TypeError, ValueError):
        password_valid = False
    if not password_valid:
        return jsonify({"error": "Current password is incorrect"}), 403
    row = db.session.get(WebAuthnCredential, credential_id)
    if row is None or row.user_id != current_user.id:
        return jsonify({"error": "Passkey not found"}), 404
    db.session.delete(row)
    db.session.commit()
    log_security_event(
        "WEBAUTHN_CREDENTIAL_DELETED",
        user=current_user.username,
    )
    return jsonify({"ok": True})


@webauthn_blueprint.post("/api/webauthn/auth/options")
def authentication_options():
    _require_enabled()
    client_ip = request.remote_addr or "unknown"
    if config.RATELIMIT_ENABLED and check_rate_limit(
        client_ip,
        "webauthn_auth_options",
        config.RATELIMIT_LOGIN_LIMIT,
    ):
        log_rate_limit_exceeded("webauthn_auth_options", client_ip)
        return jsonify({"error": "Too many login attempts"}), 429
    options = generate_authentication_options(
        rp_id=config.WEBAUTHN_RP_ID,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    create_challenge(
        user_id=None,
        purpose="authenticate",
        session_binding=_binding(),
        challenge=bytes(options.challenge),
    )
    return jsonify(json.loads(options_to_json(options)))


@webauthn_blueprint.post("/api/webauthn/auth/verify")
def verify_authentication():
    _require_enabled()
    client_ip = request.remote_addr or "unknown"
    if config.RATELIMIT_ENABLED and check_rate_limit(
        client_ip,
        "webauthn_auth_verify",
        config.RATELIMIT_LOGIN_LIMIT,
    ):
        return jsonify({"error": "Too many login attempts"}), 429
    data = _bounded_json()
    if data is None:
        return _request_body_too_large()
    username = None
    user = None
    try:
        with _authentication_lock:
            challenge = consume_challenge(
                user_id=None,
                purpose="authenticate",
                session_binding=_binding(),
            )
            credential_id = base64url_to_bytes(
                str((data.get("credential") or {}).get("id") or "")
            )
            row = WebAuthnCredential.query.filter_by(
                credential_id=credential_id,
            ).first()
            user = db.session.get(User, row.user_id) if row is not None else None
            if row is None or user is None or user.is_locked:
                raise ChallengeError("Credential is not available")
            username = user.username
            verified = verify_authentication_response(
                credential=data.get("credential"),
                expected_challenge=challenge,
                expected_rp_id=config.WEBAUTHN_RP_ID,
                expected_origin=config.WEBAUTHN_ORIGIN,
                credential_public_key=bytes(row.public_key),
                credential_current_sign_count=row.sign_count,
                require_user_verification=True,
            )
            new_sign_count = int(verified.new_sign_count)
            if row.sign_count and new_sign_count <= row.sign_count:
                raise ChallengeError("Authenticator counter did not advance")
            row.sign_count = max(row.sign_count, new_sign_count)
            row.last_used_at = datetime.now(timezone.utc)
            db.session.commit()
    except Exception as exc:
        db.session.rollback()
        log_security_event(
            "WEBAUTHN_AUTHENTICATION_REJECTED",
            level=logging.WARNING,
            user=username,
            ip=client_ip,
            error=type(exc).__name__,
        )
        return jsonify({"error": "Passkey authentication failed"}), 401
    session.clear()
    login_user(user)
    log_security_event(
        "WEBAUTHN_AUTHENTICATION_SUCCESS",
        user=user.username,
    )
    return jsonify({"ok": True})
