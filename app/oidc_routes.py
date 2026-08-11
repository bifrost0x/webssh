"""Optional OIDC authorization-code login with PKCE and explicit linking."""

import secrets
import base64
import hashlib
import logging
from pathlib import Path

from authlib.integrations.flask_client import OAuth
from flask import Blueprint, abort, jsonify, redirect, request, session, url_for
from flask_login import current_user, login_required, login_user
from sqlalchemy.exc import IntegrityError

import config

from .audit_logger import (
    log_rate_limit_exceeded,
    log_security_event,
    log_warning,
)
from .auth import check_rate_limit, check_reauth_rate_limit
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


def _password_matches(user, password):
    try:
        return user.check_password(password)
    except (TypeError, ValueError):
        return False


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
        and config.OIDC_REDIRECT_URI
    ):
        raise RuntimeError(
            "OIDC_ENABLED requires OIDC_ISSUER, OIDC_CLIENT_ID, "
            "OIDC_CLIENT_SECRET_FILE, and OIDC_REDIRECT_URI"
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
    if config.RATELIMIT_ENABLED and check_rate_limit(
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
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).decode("ascii").rstrip("=")
    try:
        return _client().authorize_redirect(
            config.OIDC_REDIRECT_URI,
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
    if config.RATELIMIT_ENABLED and check_rate_limit(
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
        token = client.authorize_access_token(
            code_verifier=verifier,
            redirect_uri=config.OIDC_REDIRECT_URI,
        )
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
    client_ip = request.remote_addr or "unknown"
    if config.RATELIMIT_ENABLED and check_reauth_rate_limit(
        current_user.id,
        client_ip,
        "oidc_link_reauth",
        config.RATELIMIT_REAUTH,
    ):
        log_rate_limit_exceeded("oidc_link_reauth", client_ip)
        return jsonify({"error": "Too many password attempts"}), 429
    data = request.get_json(silent=True) or {}
    if not _password_matches(current_user, data.get("password", "")):
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
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "OIDC identity is already linked"}), 409
    except Exception as exc:
        db.session.rollback()
        log_security_event(
            "OIDC_IDENTITY_STORAGE_FAILED",
            level=logging.ERROR,
            admin=current_user.username,
            user=target.username,
            error=type(exc).__name__,
        )
        return jsonify({
            "error": "OIDC identity storage is temporarily unavailable"
        }), 503
    log_security_event(
        "OIDC_IDENTITY_LINKED",
        admin=current_user.username,
        user=target.username,
        issuer=row.issuer,
    )
    return jsonify({"id": row.id}), 201


@oidc_blueprint.get("/admin/api/users/<int:user_id>/oidc-identities")
@admin_required
@login_required
def list_oidc_identities(user_id):
    _require_enabled()
    target = db.session.get(User, user_id)
    if target is None:
        return jsonify({"error": "User not found"}), 404
    rows = (
        OIDCIdentity.query
        .filter_by(user_id=target.id)
        .order_by(OIDCIdentity.created_at.asc(), OIDCIdentity.id.asc())
        .all()
    )
    return jsonify({
        "identities": [{
            "id": row.id,
            "issuer": row.issuer,
            "subject": row.subject,
            "created_at": row.created_at.isoformat(),
        } for row in rows]
    })


@oidc_blueprint.delete(
    "/admin/api/users/<int:user_id>/oidc-identities/<int:identity_id>"
)
@admin_required
@login_required
def unlink_oidc_identity(user_id, identity_id):
    _require_enabled()
    client_ip = request.remote_addr or "unknown"
    if config.RATELIMIT_ENABLED and check_reauth_rate_limit(
        current_user.id,
        client_ip,
        "oidc_unlink_reauth",
        config.RATELIMIT_REAUTH,
    ):
        log_rate_limit_exceeded("oidc_unlink_reauth", client_ip)
        return jsonify({"error": "Too many password attempts"}), 429
    data = request.get_json(silent=True) or {}
    if not _password_matches(current_user, data.get("password", "")):
        return jsonify({"error": "Administrator password is incorrect"}), 403
    target = db.session.get(User, user_id)
    if target is None:
        return jsonify({"error": "User not found"}), 404
    if data.get("confirm_username") != target.username:
        return jsonify({"error": "Target confirmation does not match"}), 400
    identity = db.session.get(OIDCIdentity, identity_id)
    if identity is None or identity.user_id != target.id:
        return jsonify({"error": "OIDC identity not found"}), 404
    issuer = identity.issuer
    db.session.delete(identity)
    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        log_security_event(
            "OIDC_IDENTITY_STORAGE_FAILED",
            level=logging.ERROR,
            admin=current_user.username,
            user=target.username,
            error=type(exc).__name__,
        )
        return jsonify({
            "error": "OIDC identity storage is temporarily unavailable"
        }), 503
    log_security_event(
        "OIDC_IDENTITY_UNLINKED",
        level=logging.WARNING,
        admin=current_user.username,
        user=target.username,
        issuer=issuer,
        identity_id=identity_id,
    )
    return jsonify({"ok": True})
