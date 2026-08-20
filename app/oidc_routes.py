"""Optional OIDC authorization-code login with PKCE and explicit linking."""

import secrets
import base64
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path

from authlib.integrations.flask_client import OAuth
from flask import (
    Blueprint,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    session,
)
from flask_login import current_user, login_required
from sqlalchemy.exc import IntegrityError

import config

from .audit_logger import (
    log_rate_limit_exceeded,
    log_security_event,
    log_warning,
)
from .auth import check_rate_limit
from .decorators import admin_required, step_up_required
from .models import OIDCIdentity, User, db
from .oidc_service import (
    OIDCStateError,
    consume_login_state,
    create_login_state,
    discard_login_state,
    evaluate_oidc_assurance,
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


def _authorization_redirect(
    *,
    purpose,
    continuation="/",
    requested_acr=None,
    step_up_action=None,
    step_up_target_hash=None,
):
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    create_login_state(
        state=state,
        nonce=nonce,
        session_binding=_binding(),
        code_verifier=verifier,
        purpose=purpose,
        continuation=continuation,
        requested_acr=requested_acr,
        step_up_action=step_up_action,
        step_up_target_hash=step_up_target_hash,
    )
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).decode("ascii").rstrip("=")
    authorization = {
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if purpose == "step_up":
        authorization.update({"prompt": "login", "max_age": 0})
        if requested_acr:
            authorization["acr_values"] = requested_acr
    try:
        return _client().authorize_redirect(
            config.OIDC_REDIRECT_URI,
            **authorization,
        )
    except Exception as exc:
        discard_login_state(
            state=state,
            session_binding=_binding(),
        )
        log_warning("OIDC provider unavailable", error=type(exc).__name__)
        return jsonify({"error": "Identity provider unavailable"}), 503


def begin_oidc_step_up(*, action, target_hash, continuation="/admin"):
    """Start a provider reauthentication intent for the step-up subsystem."""
    requested_acr = " ".join(sorted(config.OIDC_STEP_UP_ACR_VALUES)) or None
    return _authorization_redirect(
        purpose="step_up",
        continuation=continuation,
        requested_acr=requested_acr,
        step_up_action=action,
        step_up_target_hash=target_hash,
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
    return _authorization_redirect(
        purpose="login",
        continuation=request.args.get("next", "/"),
    )


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
        intent = consume_login_state(
            state=state,
            session_binding=_binding(),
        )
        if intent.purpose == "step_up" and (
            not current_user.is_authenticated
            or not current_user.is_admin
        ):
            return jsonify({"error": "Step-up authentication failed"}), 403
        client = _client()
        token = client.authorize_access_token(
            code_verifier=intent.code_verifier,
        )
        signed_claims = None
        if token.get("id_token"):
            signed_claims = client.parse_id_token(
                token,
                nonce=intent.nonce,
            )
        profile_claims = token.get("userinfo")
        claims = (
            signed_claims
            if signed_claims is not None
            else profile_claims
        )
        if claims is None:
            claims = client.parse_id_token(token, nonce=intent.nonce)
            signed_claims = claims
        issuer = str(claims.get("iss") or _issuer()).rstrip("/")
        subject = str(claims.get("sub") or "")
        if issuer != _issuer() or not subject:
            raise OIDCStateError("OIDC issuer or subject is invalid")
        if (
            config.OIDC_ALLOWED_SUBJECTS
            and subject not in config.OIDC_ALLOWED_SUBJECTS
        ):
            raise OIDCStateError("OIDC subject is not allowed")
        email_claims = profile_claims or claims
        email = str(email_claims.get("email") or "")
        domain = email.rsplit("@", 1)[-1].lower() if "@" in email else ""
        if (
            config.OIDC_ALLOWED_DOMAINS
            and (
                email_claims.get("email_verified") is not True
                or domain not in config.OIDC_ALLOWED_DOMAINS
            )
        ):
            raise OIDCStateError("OIDC email domain is not allowed")
        user = resolve_identity(issuer, subject)
        if user is None or user.is_locked or user.is_ldap_managed:
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
        assurance = evaluate_oidc_assurance(signed_claims or {}, config)
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
    log_security_event(
        "OIDC_ASSURANCE_EVALUATED",
        user=user.username,
        assurance=assurance.level.value,
        reason=assurance.reason,
        auth_time_present=assurance.auth_time is not None,
    )
    from .auth_assurance import (
        AssuranceLevel,
        available_mfa_methods,
        begin_authentication,
        browser_session_binding,
        consume_pending,
        current_authentication_session,
        finalize_login,
    )

    if intent.purpose == "step_up":
        from .step_up import StepUpError, create_step_up_grant_for_hash

        auth_session = current_authentication_session()
        now_timestamp = int(datetime.now(timezone.utc).timestamp())
        requested_acr = set((intent.requested_acr or "").split())
        if (
            not current_user.is_authenticated
            or not current_user.is_admin
            or auth_session is None
            or user.id != current_user.id
            or assurance.level is AssuranceLevel.BASIC
            or assurance.auth_time is None
            or not 0 <= now_timestamp - assurance.auth_time <= (
                config.STEP_UP_MAX_AGE_SECONDS
            )
            or (requested_acr and assurance.acr not in requested_acr)
        ):
            log_security_event(
                "OIDC_STEP_UP_REJECTED",
                level=logging.WARNING,
                user=getattr(current_user, "username", None),
                issuer=issuer,
                reason="insufficient_or_mismatched_assurance",
            )
            return jsonify({"error": "Step-up authentication failed"}), 403
        try:
            grant = create_step_up_grant_for_hash(
                auth_session,
                intent.step_up_action,
                intent.step_up_target_hash,
                assurance.level,
            )
        except StepUpError:
            return jsonify({"error": "Step-up authentication failed"}), 403
        session["_oidc_step_up_result"] = {
            "grant": grant,
            "action": intent.step_up_action,
            "expires_at": now_timestamp + 300,
        }
        log_security_event(
            "ADMIN_STEP_UP_GRANTED",
            user=current_user.username,
            method="oidc",
            action=intent.step_up_action,
            assurance=assurance.level.value,
        )
        return redirect(intent.continuation)

    local_mfa_methods = None
    if user.mfa_enabled and assurance.level is AssuranceLevel.BASIC:
        local_mfa_methods = tuple(
            method
            for method in available_mfa_methods(user)
            if method != "recovery"
        )
        if not local_mfa_methods:
            log_security_event(
                "OIDC_LOCAL_MFA_UNAVAILABLE",
                level=logging.WARNING,
                user=user.username,
                issuer=issuer,
            )
            return jsonify({
                "error": "No active local MFA factor is available"
            }), 403
    session.clear()
    binding = browser_session_binding()
    evidence = {
        "issuer": issuer,
        "acr": assurance.acr,
        "amr": list(assurance.amr),
        "auth_time": assurance.auth_time,
    }
    token = begin_authentication(
        user,
        "oidc",
        assurance=assurance.level,
        session_binding=binding,
        remember=False,
        continuation=intent.continuation,
        evidence=evidence,
    )
    if local_mfa_methods is not None:
        session["_pending_authentication"] = token
        return render_template(
            "login.html",
            auth_source="oidc",
            mfa_required=True,
            pending_token=token,
            mfa_methods=local_mfa_methods,
        )
    pending = consume_pending(token, binding)
    strong_authenticated_at = None
    if (
        assurance.level is not AssuranceLevel.BASIC
        and assurance.auth_time is not None
    ):
        strong_authenticated_at = datetime.fromtimestamp(
            assurance.auth_time,
            timezone.utc,
        )
    finalize_login(
        pending,
        methods=["oidc"],
        strong_authenticated_at=strong_authenticated_at,
    )
    log_security_event(
        "OIDC_LOGIN_SUCCESS",
        user=user.username,
        issuer=issuer,
        assurance=assurance.level.value,
    )
    return redirect(pending.continuation)


@oidc_blueprint.post("/admin/api/users/<int:user_id>/oidc-link")
@admin_required
@login_required
@step_up_required('oidc.link', lambda user_id: user_id)
def link_oidc_identity(user_id):
    _require_enabled()
    data = request.get_json(silent=True) or {}
    target = db.session.get(User, user_id)
    if target is None:
        return jsonify({"error": "User not found"}), 404
    if target.is_ldap_managed:
        return jsonify({
            "error": "OIDC identities cannot be linked to LDAP accounts"
        }), 400
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
@step_up_required(
    'oidc.unlink',
    lambda user_id, identity_id: f'{user_id}:{identity_id}',
)
def unlink_oidc_identity(user_id, identity_id):
    _require_enabled()
    data = request.get_json(silent=True) or {}
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
