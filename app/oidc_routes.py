"""Optional OIDC authorization-code login with PKCE and explicit linking."""

import secrets
import base64
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from authlib.integrations.flask_client import OAuth
from flask import (
    Blueprint,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import insert, literal, select
from sqlalchemy.exc import IntegrityError

import config

from .audit_logger import (
    log_rate_limit_exceeded,
    log_security_event,
    log_warning,
)
from .auth import check_rate_limit
from .decorators import admin_required, step_up_required
from .models import (
    AuthenticationSession,
    GitHubIdentity,
    OIDCIdentity,
    User,
    as_naive_utc,
    db,
)
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
    user_id=None,
    auth_generation=None,
    authentication_session_id=None,
    continuation="/",
    requested_acr=None,
    step_up_action=None,
    step_up_target_hash=None,
    step_up_intent_id=None,
    return_authorization_url=False,
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
        user_id=user_id,
        auth_generation=auth_generation,
        authentication_session_id=authentication_session_id,
        continuation=continuation,
        requested_acr=requested_acr,
        step_up_action=step_up_action,
        step_up_target_hash=step_up_target_hash,
        step_up_intent_id=step_up_intent_id,
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
    if purpose == "link":
        authorization["prompt"] = "login"
    if purpose == "step_up":
        authorization.update({"prompt": "login", "max_age": 0})
        if requested_acr:
            authorization["acr_values"] = requested_acr
    try:
        response = _client().authorize_redirect(
            config.OIDC_REDIRECT_URI,
            **authorization,
        )
        if return_authorization_url:
            location = response.headers.get("Location", "")
            parsed_location = urlsplit(location)
            returned_states = parse_qs(parsed_location.query).get("state", [])
            if (
                not 300 <= response.status_code < 400
                or parsed_location.scheme != "https"
                or not parsed_location.hostname
                or parsed_location.username is not None
                or parsed_location.password is not None
                or parsed_location.fragment
                or returned_states != [state]
            ):
                raise RuntimeError("OIDC authorization URL is unavailable")
            return jsonify({"authorization_url": location})
        return response
    except Exception as exc:
        discard_login_state(
            state=state,
            session_binding=_binding(),
        )
        log_warning("OIDC provider unavailable", error=type(exc).__name__)
        return jsonify({"error": "Identity provider unavailable"}), 503


def _current_oidc_link_target(intent):
    if (
        not current_user.is_authenticated
        or current_user.id != intent.user_id
    ):
        return None
    from .auth_assurance import current_authentication_session

    auth_session = current_authentication_session()
    target = db.session.get(User, current_user.id, populate_existing=True)
    if (
        target is None
        or target.is_locked
        or auth_session is None
        or auth_session.id != intent.authentication_session_id
        or auth_session.user_id != target.id
        or auth_session.auth_generation != intent.auth_generation
        or int(target.auth_generation or 0) != intent.auth_generation
    ):
        return None
    return target


def _complete_oidc_self_link(intent, issuer, subject):
    target = _current_oidc_link_target(intent)
    if target is None:
        log_security_event(
            "OIDC_IDENTITY_LINK_REJECTED",
            level=logging.WARNING,
            issuer=issuer,
            reason="account_session_changed",
        )
        return jsonify({"error": "OIDC identity linking failed"}), 403
    if target.is_ldap_managed or target.is_github_managed:
        return jsonify({
            "error": "OIDC cannot be linked to this account"
        }), 409
    try:
        existing = OIDCIdentity.query.filter_by(
            issuer=issuer,
            subject=subject,
        ).first()
        if existing is not None:
            if existing.user_id == target.id:
                log_security_event(
                    "OIDC_IDENTITY_LINK_CONFIRMED",
                    user=target.username,
                    issuer=issuer,
                    identity_id=existing.id,
                )
                return redirect(intent.continuation)
            log_security_event(
                "OIDC_IDENTITY_LINK_COLLISION",
                level=logging.WARNING,
                user=target.username,
                issuer=issuer,
            )
            return jsonify({
                "error": "OIDC identity is already linked"
            }), 409
        now = as_naive_utc(datetime.now(timezone.utc))
        eligible_identity = (
            select(
                User.id,
                literal(issuer),
                literal(subject),
                literal(now),
            )
            .select_from(User)
            .join(
                AuthenticationSession,
                AuthenticationSession.user_id == User.id,
            )
            .where(
                User.id == target.id,
                User.auth_generation == intent.auth_generation,
                User.is_locked.is_(False),
                ~User.ldap_identity.has(),
                ~User.github_identity.has(
                    GitHubIdentity.provisioned_by_github.is_(True)
                ),
                AuthenticationSession.id
                == intent.authentication_session_id,
                AuthenticationSession.auth_generation
                == intent.auth_generation,
                AuthenticationSession.expires_at > now,
            )
        )
        result = db.session.execute(
            insert(OIDCIdentity).from_select(
                ["user_id", "issuer", "subject", "created_at"],
                eligible_identity,
            )
        )
        if result.rowcount != 1:
            db.session.rollback()
            log_security_event(
                "OIDC_IDENTITY_LINK_REJECTED",
                level=logging.WARNING,
                user=target.username,
                issuer=issuer,
                reason="account_session_changed",
            )
            return jsonify({"error": "OIDC identity linking failed"}), 403
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "OIDC identity is already linked"}), 409
    except Exception as exc:
        db.session.rollback()
        log_security_event(
            "OIDC_IDENTITY_STORAGE_FAILED",
            level=logging.ERROR,
            user=target.username,
            issuer=issuer,
            error=type(exc).__name__,
        )
        return jsonify({
            "error": "OIDC identity storage is temporarily unavailable"
        }), 503
    log_security_event(
        "OIDC_IDENTITY_LINKED",
        user=target.username,
        issuer=issuer,
        source="self_service",
    )
    return redirect(intent.continuation)


def begin_oidc_step_up(
    *,
    action,
    target_hash,
    continuation="/admin",
    return_authorization_url=False,
):
    """Start a provider reauthentication intent for the step-up subsystem."""
    requested_acr = " ".join(sorted(config.OIDC_STEP_UP_ACR_VALUES)) or None
    return _authorization_redirect(
        purpose="step_up",
        continuation=continuation,
        requested_acr=requested_acr,
        step_up_action=action,
        step_up_target_hash=target_hash,
        return_authorization_url=return_authorization_url,
    )


def begin_oidc_account_step_up(
    *,
    intent,
    continuation="/security",
    return_authorization_url=False,
):
    """Start provider reauthentication for one persistent account intent."""
    from .auth_assurance import AssuranceLevel
    from .models import StepUpIntent

    if not isinstance(intent, StepUpIntent) or intent.id is None:
        raise OIDCStateError("account step-up intent is invalid")
    requested_acr = None
    if intent.required_assurance != AssuranceLevel.BASIC.value:
        requested_acr = (
            " ".join(sorted(config.OIDC_STEP_UP_ACR_VALUES)) or None
        )
    return _authorization_redirect(
        purpose="step_up",
        continuation=continuation,
        requested_acr=requested_acr,
        step_up_intent_id=intent.id,
        return_authorization_url=return_authorization_url,
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


@oidc_blueprint.get("/api/account/oidc")
@login_required
def oidc_account_status():
    _require_enabled()
    rows = (
        OIDCIdentity.query
        .filter_by(user_id=current_user.id)
        .order_by(OIDCIdentity.created_at.asc(), OIDCIdentity.id.asc())
        .all()
    )
    return jsonify({
        "identities": [{
            "id": row.id,
            "issuer": row.issuer,
            "created_at": row.created_at.isoformat(),
        } for row in rows]
    })


@oidc_blueprint.post("/api/account/oidc/link/start")
@login_required
@step_up_required("oidc.self_link", lambda: current_user.id)
def oidc_self_link_start():
    _require_enabled()
    target = db.session.get(User, current_user.id, populate_existing=True)
    if target is None or target.is_locked:
        return jsonify({"error": "OIDC identity linking failed"}), 403
    if target.is_ldap_managed or target.is_github_managed:
        return jsonify({
            "error": "OIDC cannot be linked to this account"
        }), 409
    from .auth_assurance import current_authentication_session

    auth_session = current_authentication_session()
    if auth_session is None:
        return jsonify({"error": "OIDC identity linking failed"}), 403
    return _authorization_redirect(
        purpose="link",
        user_id=target.id,
        auth_generation=int(target.auth_generation or 0),
        authentication_session_id=auth_session.id,
        continuation=url_for("security_center"),
        return_authorization_url=True,
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
        if (
            intent.purpose == "link"
            and _current_oidc_link_target(intent) is None
        ):
            log_security_event(
                "OIDC_IDENTITY_LINK_REJECTED",
                level=logging.WARNING,
                ip=client_ip,
                reason="account_binding_mismatch",
            )
            return jsonify({"error": "OIDC identity linking failed"}), 403
        if intent.purpose == "step_up" and (
            not current_user.is_authenticated
            or (
                intent.step_up_intent_id is None
                and not current_user.is_admin
            )
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
        if signed_claims is not None and profile_claims is not None:
            signed_subject = str(signed_claims.get("sub") or "")
            profile_subject = str(profile_claims.get("sub") or "")
            if not signed_subject or signed_subject != profile_subject:
                raise OIDCStateError("OIDC subject claims do not match")
        issuer = str(claims.get("iss") or _issuer()).rstrip("/")
        subject = str(claims.get("sub") or "")
        if (
            issuer != _issuer()
            or not subject
            or len(issuer) > 512
            or len(subject) > 512
        ):
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
        if intent.purpose != "link":
            user = resolve_identity(issuer, subject)
            rejection_reason = None
            if user is None:
                rejection_reason = "unlinked"
            elif user.is_locked:
                rejection_reason = "account_locked"
            elif user.is_ldap_managed:
                rejection_reason = "externally_managed"
            if rejection_reason is not None:
                log_security_event(
                    "OIDC_IDENTITY_REJECTED",
                    level=logging.WARNING,
                    issuer=issuer,
                    ip=client_ip,
                    reason=rejection_reason,
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
    if intent.purpose == "link":
        return _complete_oidc_self_link(intent, issuer, subject)
    log_security_event(
        "OIDC_ASSURANCE_EVALUATED",
        user=user.username,
        assurance=assurance.level.value,
        reason=assurance.reason,
        auth_time_present=assurance.auth_time is not None,
    )
    from .auth_assurance import (
        AssuranceLevel,
        authentication_methods,
        available_mfa_methods,
        begin_authentication,
        browser_session_binding,
        consume_pending,
        current_authentication_session,
        finalize_login,
    )

    if intent.purpose == "step_up":
        from .step_up import (
            StepUpError,
            approve_account_step_up_intent_by_id,
            create_step_up_grant_for_hash,
        )

        auth_session = current_authentication_session()
        now_timestamp = int(datetime.now(timezone.utc).timestamp())
        requested_acr = set((intent.requested_acr or "").split())
        invalid_step_up = (
            not current_user.is_authenticated
            or auth_session is None
            or user.id != current_user.id
            or assurance.auth_time is None
            or not 0 <= now_timestamp - assurance.auth_time <= (
                config.STEP_UP_MAX_AGE_SECONDS
            )
            or (requested_acr and assurance.acr not in requested_acr)
        )
        if invalid_step_up:
            log_security_event(
                "OIDC_STEP_UP_REJECTED",
                level=logging.WARNING,
                user=getattr(current_user, "username", None),
                issuer=issuer,
                reason="insufficient_or_mismatched_assurance",
            )
            return jsonify({"error": "Step-up authentication failed"}), 403
        if intent.step_up_intent_id is not None:
            if "oidc" not in authentication_methods(auth_session):
                return jsonify({"error": "Step-up authentication failed"}), 403
            try:
                approved = approve_account_step_up_intent_by_id(
                    intent.step_up_intent_id,
                    auth_session,
                    assurance=assurance.level,
                    method="oidc",
                )
            except StepUpError:
                return jsonify({"error": "Step-up authentication failed"}), 403
            log_security_event(
                "ACCOUNT_STEP_UP_GRANTED",
                user=current_user.username,
                method="oidc",
                action=approved.action,
                assurance=assurance.level.value,
                result="approved",
            )
            return redirect(intent.continuation)
        if (
            not current_user.is_admin
            or assurance.level is AssuranceLevel.BASIC
        ):
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
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request"}), 400
    target = db.session.get(User, user_id)
    if target is None:
        return jsonify({"error": "User not found"}), 404
    if target.is_ldap_managed or target.is_github_managed:
        return jsonify({
            "error": "OIDC identities cannot be linked to externally managed accounts"
        }), 400
    if data.get("confirm_username") != target.username:
        return jsonify({"error": "Target confirmation does not match"}), 400
    subject = data.get("subject")
    if not isinstance(subject, str):
        return jsonify({"error": "OIDC subject is required"}), 400
    subject = subject.strip()
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
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request"}), 400
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
