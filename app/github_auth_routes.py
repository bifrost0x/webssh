"""GitHub App login, account linking, and admin-managed configuration."""

import base64
from datetime import datetime, timezone
import hashlib
import logging
import re
import secrets

from flask import Blueprint, abort, jsonify, redirect, render_template, request, session
from flask_login import current_user, login_required
from sqlalchemy.exc import IntegrityError

import config

from .audit_logger import log_rate_limit_exceeded, log_security_event
from .auth import (
    check_rate_limit,
    check_reauth_rate_limit,
    user_creation_transaction,
    validate_new_user,
)
from .auth_assurance import AssuranceLevel
from .decorators import admin_required, step_up_required
from .github_auth_service import (
    GitHubConfigurationError,
    GitHubOrganizationRejected,
    GitHubProviderError,
    GitHubStateError,
    authorization_url,
    consume_oauth_state,
    create_oauth_state,
    enforce_organization_policy,
    exchange_code,
    fetch_profile,
    get_settings,
    github_auth_is_active,
    update_settings,
)
from .models import GitHubIdentity, User, db


github_auth_blueprint = Blueprint('github_auth', __name__)
_LOGIN_LIMIT = '5 per minute'
_USERNAME_PATTERN = re.compile(r'[^a-z0-9_]+')


def _require_active():
    if not github_auth_is_active():
        abort(404)


def _binding():
    return session.setdefault('github_oauth_binding', secrets.token_urlsafe(32))


def _rate_limited(bucket):
    if not config.RATELIMIT_ENABLED:
        return False
    client_ip = request.remote_addr or 'unknown'
    limited = check_rate_limit(client_ip, bucket, _LOGIN_LIMIT)
    if limited:
        log_rate_limit_exceeded(bucket, client_ip)
    return limited


def _begin_authorization(
    *, purpose, continuation='/', user_id=None, step_up_intent_id=None,
):
    settings = get_settings(include_secret=False)
    if not settings.active:
        abort(404)
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode('ascii')).digest()
    ).decode('ascii').rstrip('=')
    create_oauth_state(
        state=state,
        session_binding=_binding(),
        code_verifier=verifier,
        purpose=purpose,
        generation=settings.generation,
        user_id=user_id,
        step_up_intent_id=step_up_intent_id,
        continuation=continuation,
    )
    return authorization_url(settings, state=state, code_challenge=challenge)


@github_auth_blueprint.get('/auth/github/login')
def github_login():
    _require_active()
    if _rate_limited('github_login'):
        return jsonify({'error': 'Too many GitHub login attempts'}), 429
    return redirect(_begin_authorization(
        purpose='login', continuation=request.args.get('next', '/')
    ))


@github_auth_blueprint.post('/api/account/github/link/start')
@login_required
@step_up_required('github.link', lambda: current_user.id)
def github_link_start():
    _require_active()
    if current_user.is_ldap_managed:
        return jsonify({'error': 'GitHub cannot be linked to an LDAP-managed account'}), 409
    if current_user.github_identity is not None:
        return jsonify({'error': 'A GitHub identity is already linked'}), 409
    return jsonify({'authorization_url': _begin_authorization(
        purpose='link', user_id=current_user.id, continuation='/security'
    )})


@github_auth_blueprint.post('/api/account/step-up/github/start')
@login_required
def github_step_up_start():
    _require_active()
    from .auth_assurance import current_authentication_session
    from .step_up import account_step_up_intent, StepUpError

    data = request.get_json(silent=True) or {}
    token = data.get('intent')
    try:
        intent = account_step_up_intent(token, current_authentication_session())
    except StepUpError:
        return jsonify({'error': 'Step-up authentication failed'}), 403
    if current_user.github_identity is None:
        return jsonify({'error': 'Step-up authentication failed'}), 403
    client_ip = request.remote_addr or 'unknown'
    if config.RATELIMIT_ENABLED and check_reauth_rate_limit(
        current_user.id,
        client_ip,
        'account_step_up_github_start',
        config.RATELIMIT_REAUTH,
    ):
        log_rate_limit_exceeded('account_step_up_github_start', client_ip)
        response = jsonify({'error': 'Step-up authentication failed'})
        response.status_code = 429
        response.headers['Retry-After'] = '60'
        return response
    return jsonify({'authorization_url': _begin_authorization(
        purpose='step_up',
        step_up_intent_id=intent.id,
        continuation=data.get('continuation') or '/security',
    )})


def _provision_username(login, github_user_id):
    base = _USERNAME_PATTERN.sub('_', login.lower()).strip('_') or 'github'
    base = base[:32]
    existing_names = {
        row.username.casefold()
        for row in User.query.with_entities(User.username).all()
    }
    candidates = (
        base,
        f'{base[:20]}_gh{str(github_user_id)[-8:]}'[:32],
        f'github_{github_user_id}'[:32],
    )
    for candidate in candidates:
        if candidate.casefold() not in existing_names:
            return candidate
    for _ in range(8):
        candidate = f'gh_{str(github_user_id)[-8:]}_{secrets.token_hex(3)}'[:32]
        if candidate.casefold() not in existing_names:
            return candidate
    raise GitHubProviderError('GitHub account could not be provisioned')


def _auto_provision(profile):
    local_secret = secrets.token_urlsafe(48)
    with user_creation_transaction():
        if GitHubIdentity.query.filter_by(
            github_user_id=profile.user_id
        ).first() is not None:
            raise IntegrityError('GitHub identity exists', None, None)
        username = _provision_username(profile.login, profile.user_id)
        error = validate_new_user(username, local_secret)
        if error:
            raise GitHubProviderError('GitHub account could not be provisioned')
        # A GitHub flow must never create or retain administrator privileges.
        user = User(username=username, is_admin=False)
        user.set_password(local_secret)
        db.session.add(user)
        db.session.flush()
        identity = GitHubIdentity(
            user_id=user.id,
            github_user_id=profile.user_id,
            login=profile.login,
            display_name=profile.display_name,
            provisioned_by_github=True,
            last_verified_at=datetime.now(timezone.utc),
        )
        db.session.add(identity)
        db.session.commit()
    user.get_data_dir()
    log_security_event(
        'GITHUB_ACCOUNT_PROVISIONED', user=user.username,
        github_user_id=profile.user_id,
    )
    return user


def _complete_link(intent, profile):
    if not current_user.is_authenticated or current_user.id != intent.user_id:
        return jsonify({'error': 'GitHub account linking failed'}), 403
    if current_user.is_ldap_managed:
        return jsonify({'error': 'GitHub cannot be linked to this account'}), 409
    existing = GitHubIdentity.query.filter(
        (GitHubIdentity.user_id == current_user.id)
        | (GitHubIdentity.github_user_id == profile.user_id)
    ).first()
    if existing is not None:
        log_security_event(
            'GITHUB_IDENTITY_COLLISION', level=logging.WARNING,
            user=current_user.username, github_user_id=profile.user_id,
        )
        return jsonify({'error': 'GitHub identity is already linked'}), 409
    row = GitHubIdentity(
        user_id=current_user.id,
        github_user_id=profile.user_id,
        login=profile.login,
        display_name=profile.display_name,
        last_verified_at=datetime.now(timezone.utc),
    )
    db.session.add(row)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'GitHub identity is already linked'}), 409
    log_security_event(
        'GITHUB_IDENTITY_LINKED', user=current_user.username,
        github_user_id=profile.user_id,
    )
    return redirect(intent.continuation)


def _complete_step_up(intent, profile):
    from .auth_assurance import current_authentication_session
    from .step_up import approve_account_step_up_intent_by_id, StepUpError

    auth_session = current_authentication_session()
    identity = current_user.github_identity if current_user.is_authenticated else None
    if (
        auth_session is None
        or identity is None
        or identity.github_user_id != profile.user_id
    ):
        return jsonify({'error': 'Step-up authentication failed'}), 403
    try:
        approved = approve_account_step_up_intent_by_id(
            intent.step_up_intent_id,
            auth_session,
            assurance=AssuranceLevel.BASIC,
            method='github',
        )
    except StepUpError:
        return jsonify({'error': 'Step-up authentication failed'}), 403
    log_security_event(
        'ACCOUNT_STEP_UP_GRANTED', user=current_user.username,
        method='github', action=approved.action,
        assurance=AssuranceLevel.BASIC.value, result='approved',
    )
    return redirect(intent.continuation)


def _complete_login(intent, profile, settings):
    identity = GitHubIdentity.query.filter_by(
        github_user_id=profile.user_id
    ).first()
    if identity is None:
        if not settings.auto_provision:
            log_security_event(
                'GITHUB_IDENTITY_REJECTED', level=logging.WARNING,
                github_user_id=profile.user_id, reason='unlinked',
            )
            log_security_event(
                'GITHUB_LOGIN_FAILED', level=logging.WARNING,
                github_user_id=profile.user_id, reason='unlinked',
            )
            return jsonify({
                'error': 'GitHub identity is not linked to a WebSSH account'
            }), 403
        try:
            user = _auto_provision(profile)
        except IntegrityError:
            db.session.rollback()
            return jsonify({'error': 'GitHub account could not be provisioned'}), 409
    else:
        user = identity.user
        identity.login = profile.login
        identity.display_name = profile.display_name
        identity.last_verified_at = datetime.now(timezone.utc)
        db.session.commit()
    if user is None or user.is_locked or user.is_ldap_managed:
        log_security_event(
            'GITHUB_LOGIN_FAILED', level=logging.WARNING,
            github_user_id=profile.user_id, reason='inactive_account',
        )
        return jsonify({'error': 'GitHub identity is not linked to an active account'}), 403

    from .auth_assurance import (
        available_mfa_methods,
        begin_authentication,
        browser_session_binding,
        consume_pending,
        finalize_login,
    )
    local_mfa_methods = None
    if user.mfa_enabled:
        local_mfa_methods = tuple(
            method for method in available_mfa_methods(user)
            if method != 'recovery'
        )
        if not local_mfa_methods:
            return jsonify({'error': 'No active local MFA factor is available'}), 403
    session.clear()
    binding = browser_session_binding()
    token = begin_authentication(
        user, 'github', assurance=AssuranceLevel.BASIC,
        session_binding=binding, remember=False,
        continuation=intent.continuation,
        evidence={'github_user_id': profile.user_id},
    )
    if local_mfa_methods is not None:
        session['_pending_authentication'] = token
        return render_template(
            'login.html', auth_source='github', mfa_required=True,
            pending_token=token, mfa_methods=local_mfa_methods,
        )
    pending = consume_pending(token, binding)
    finalize_login(pending, methods=['github'])
    log_security_event(
        'GITHUB_LOGIN_SUCCESS', user=user.username,
        github_user_id=profile.user_id,
    )
    return redirect(pending.continuation)


@github_auth_blueprint.get('/auth/github/callback')
def github_callback():
    _require_active()
    if _rate_limited('github_callback'):
        return jsonify({'error': 'Too many GitHub login attempts'}), 429
    client_ip = request.remote_addr or 'unknown'
    try:
        settings = get_settings(include_secret=True)
        intent = consume_oauth_state(
            state=request.args.get('state', ''),
            session_binding=_binding(),
            generation=settings.generation,
        )
        if request.args.get('error'):
            raise GitHubStateError('GitHub authorization was rejected')
        token = exchange_code(
            settings, code=request.args.get('code', ''),
            code_verifier=intent.code_verifier,
        )
        profile = fetch_profile(token)
        enforce_organization_policy(token, settings)
    except GitHubOrganizationRejected:
        log_security_event(
            'GITHUB_ORGANIZATION_REJECTED', level=logging.WARNING, ip=client_ip
        )
        return jsonify({'error': 'GitHub organization membership is required'}), 403
    except (GitHubStateError, GitHubConfigurationError) as exc:
        log_security_event(
            'GITHUB_STATE_REJECTED', level=logging.WARNING, ip=client_ip,
            error=type(exc).__name__,
        )
        return jsonify({'error': 'Invalid or expired GitHub login'}), 400
    except GitHubProviderError as exc:
        log_security_event(
            'GITHUB_PROVIDER_UNAVAILABLE', level=logging.WARNING, ip=client_ip,
            error=type(exc).__name__,
        )
        return jsonify({'error': 'GitHub authentication is temporarily unavailable'}), 503
    if intent.purpose == 'link':
        return _complete_link(intent, profile)
    if intent.purpose == 'step_up':
        return _complete_step_up(intent, profile)
    return _complete_login(intent, profile, settings)


@github_auth_blueprint.get('/api/account/github')
@login_required
def github_account_status():
    row = current_user.github_identity
    return jsonify({'identity': None if row is None else {
        'id': row.id,
        'github_user_id': row.github_user_id,
        'login': row.login,
        'display_name': row.display_name,
        'created_at': row.created_at.isoformat(),
    }})


@github_auth_blueprint.delete('/api/account/github')
@login_required
@step_up_required('github.unlink', lambda: current_user.id)
def github_unlink():
    row = current_user.github_identity
    if row is None:
        return jsonify({'error': 'No GitHub identity is linked'}), 404
    log_security_event(
        'GITHUB_IDENTITY_UNLINK_ATTEMPTED', user=current_user.username,
        github_user_id=row.github_user_id,
    )
    # Auto-provisioned accounts have no known local password. A passkey is the
    # only currently supported independent primary fallback for safe unlinking.
    if row.provisioned_by_github and current_user.webauthn_credentials.count() == 0:
        return jsonify({
            'error': 'Add and test a passkey before disconnecting GitHub'
        }), 409
    github_user_id = row.github_user_id
    db.session.delete(row)
    db.session.commit()
    log_security_event(
        'GITHUB_IDENTITY_UNLINKED', level=logging.WARNING,
        user=current_user.username, github_user_id=github_user_id,
    )
    return jsonify({'ok': True})


@github_auth_blueprint.get('/admin/api/github-auth/config')
@admin_required
@login_required
def github_admin_config():
    return jsonify({'configuration': get_settings().public_dict()})


@github_auth_blueprint.post('/admin/api/github-auth/config')
@admin_required
@login_required
@step_up_required('github.config', 'global')
def github_admin_update_config():
    data = request.get_json(silent=True)
    try:
        settings = update_settings(data, current_user.id)
    except GitHubConfigurationError:
        db.session.rollback()
        return jsonify({'error': 'Invalid GitHub configuration'}), 400
    except Exception as exc:
        db.session.rollback()
        log_security_event(
            'GITHUB_CONFIGURATION_FAILED', level=logging.ERROR,
            admin=current_user.username, error=type(exc).__name__,
        )
        return jsonify({'error': 'GitHub configuration could not be saved'}), 503
    log_security_event(
        'GITHUB_CONFIGURATION_CHANGED', admin=current_user.username,
        enabled=settings.enabled, auto_provision=settings.auto_provision,
        allowed_org_count=len(settings.allowed_orgs),
        client_secret_configured=settings.secret_configured,
    )
    return jsonify({'configuration': settings.public_dict()})
