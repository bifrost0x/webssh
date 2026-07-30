"""Optional OIDC authorization-code login with PKCE and explicit linking."""

import secrets
import base64
import hashlib
import logging
from pathlib import Path

from authlib.integrations.flask_client import OAuth
from flask import Blueprint, abort, jsonify, redirect, request, session, url_for
from flask_login import current_user, login_required, login_user

import config

from .audit_logger import (
    log_rate_limit_exceeded,
    log_security_event,
    log_warning,
)
from .auth import check_rate_limit
from .decorators import admin_required
from .models import OIDCIdentity, User, db
from .oidc_service import (
    OIDCStateError,
    consume_login_state,
    create_login_state,
    discard_login_state,
    resolve_identity,
)


oidc_blueprint = Blueprint("oidc", __name__)
oauth = OAuth()


def _issuer():
    return config.OIDC_ISSUER.rstrip("/")


def _require_enabled():
    if not config.OIDC_ENABLED:
        abort(404)


def _binding():
    return session.setdefault("oidc_binding", secrets.token_urlsafe(32))


def _client():
    client = oauth.create_client("webssh_oidc")
    if client is None:
        raise RuntimeError("OIDC client is not configured")
    return client


def init_oidc(app):
    oauth.init_app(app)
    if not config.OIDC_ENABLED:
        return
    if not (
        config.OIDC_ISSUER
        and config.OIDC_CLIENT_ID
        and config.OIDC_CLIENT_SECRET_FILE
    ):
        raise RuntimeError(
            "OIDC_ENABLED requires OIDC_ISSUER, OIDC_CLIENT_ID, and "
            "OIDC_CLIENT_SECRET_FILE"
        )
    secret_path = Path(config.OIDC_CLIENT_SECRET_FILE)
    secret = secret_path.read_text(encoding="utf-8").strip()
    if not secret:
        raise RuntimeError("OIDC client secret file is empty")
    oauth.register(
        name="webssh_oidc",
        client_id=config.OIDC_CLIENT_ID,
        client_secret=secret,
        server_metadata_url=(
            f"{_issuer()}/.well-known/openid-configuration"
        ),
        client_kwargs={
            "scope": "openid profile email",
            "default_timeout": config.OIDC_HTTP_TIMEOUT,
        },
    )


@oidc_blueprint.get("/oidc/login")
def oidc_login():
    _require_enabled()
    client_ip = request.remote_addr or "unknown"
    if check_rate_limit(
        client_ip,
        "oidc_login",
        config.OIDC_LOGIN_RATE_LIMIT,
    ):
        log_rate_limit_exceeded("oidc_login", client_ip)
        return jsonify({"error": "Too many OIDC login attempts"}), 429
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    create_login_state(
        state=state,
        nonce=nonce,
        session_binding=_binding(),
        code_verifier=verifier,
    )
    callback = url_for("oidc.oidc_callback", _external=True)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).decode("ascii").rstrip("=")
    try:
        return _client().authorize_redirect(
            callback,
            state=state,
            nonce=nonce,
            code_challenge=challenge,
            code_challenge_method="S256",
        )
    except Exception as exc:
        discard_login_state(
            state=state,
            session_binding=_binding(),
        )
        log_warning("OIDC provider unavailable", error=type(exc).__name__)
        return jsonify({"error": "Identity provider unavailable"}), 503


@oidc_blueprint.get("/oidc/callback")
def oidc_callback():
    _require_enabled()
    client_ip = request.remote_addr or "unknown"
    if check_rate_limit(
        client_ip,
        "oidc_callback",
        config.OIDC_LOGIN_RATE_LIMIT,
    ):
        return jsonify({"error": "Too many OIDC login attempts"}), 429
    state = request.args.get("state", "")
    try:
        nonce, verifier = consume_login_state(
            state=state,
            session_binding=_binding(),
        )
        client = _client()
        token = client.authorize_access_token(code_verifier=verifier)
        claims = token.get("userinfo")
        if claims is None:
            claims = client.parse_id_token(token, nonce=nonce)
        issuer = str(claims.get("iss") or _issuer()).rstrip("/")
        subject = str(claims.get("sub") or "")
        if issuer != _issuer() or not subject:
            raise OIDCStateError("OIDC issuer or subject is invalid")
        if (
            config.OIDC_ALLOWED_SUBJECTS
            and subject not in config.OIDC_ALLOWED_SUBJECTS
        ):
            raise OIDCStateError("OIDC subject is not allowed")
        email = str(claims.get("email") or "")
        domain = email.rsplit("@", 1)[-1].lower() if "@" in email else ""
        if (
            config.OIDC_ALLOWED_DOMAINS
            and (
                claims.get("email_verified") is not True
                or domain not in config.OIDC_ALLOWED_DOMAINS
            )
        ):
            raise OIDCStateError("OIDC email domain is not allowed")
        user = resolve_identity(issuer, subject)
        if user is None or user.is_locked:
            log_security_event(
                "OIDC_IDENTITY_REJECTED",
                level=logging.WARNING,
                issuer=issuer,
                ip=client_ip,
                reason="unlinked_or_locked",
            )
            return jsonify({
                "error": "External identity is not linked to an active account"
            }), 403
    except OIDCStateError as exc:
        log_security_event(
            "OIDC_STATE_REJECTED",
            level=logging.WARNING,
            ip=client_ip,
            error=type(exc).__name__,
        )
        return jsonify({"error": "Invalid or expired OIDC login"}), 400
    except Exception as exc:
        log_security_event(
            "OIDC_CALLBACK_REJECTED",
            level=logging.WARNING,
            ip=client_ip,
            error=type(exc).__name__,
        )
        return jsonify({"error": "Identity provider unavailable"}), 503
    session.clear()
    login_user(user)
    log_security_event(
        "OIDC_LOGIN_SUCCESS",
        user=user.username,
        issuer=issuer,
    )
    return redirect(url_for("index"))


@oidc_blueprint.post("/admin/api/users/<int:user_id>/oidc-link")
@admin_required
@login_required
def link_oidc_identity(user_id):
    _require_enabled()
    data = request.get_json(silent=True) or {}
    try:
        password_valid = current_user.check_password(data.get("password", ""))
    except (TypeError, ValueError):
        password_valid = False
    if not password_valid:
        return jsonify({"error": "Administrator password is incorrect"}), 403
    target = db.session.get(User, user_id)
    if target is None:
        return jsonify({"error": "User not found"}), 404
    if data.get("confirm_username") != target.username:
        return jsonify({"error": "Target confirmation does not match"}), 400
    subject = str(data.get("subject") or "").strip()
    if not subject or len(subject) > 512:
        return jsonify({"error": "OIDC subject is required"}), 400
    row = OIDCIdentity(
        user_id=target.id,
        issuer=_issuer(),
        subject=subject,
    )
    db.session.add(row)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({"error": "OIDC identity is already linked"}), 409
    log_security_event(
        "OIDC_IDENTITY_LINKED",
        admin=current_user.username,
        user=target.username,
        issuer=row.issuer,
    )
    return jsonify({"id": row.id}), 201
