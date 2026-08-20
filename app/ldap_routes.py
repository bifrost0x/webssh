"""Feature-gated LDAP login and explicit administrator identity mapping."""

import logging
import secrets
import time
import unicodedata
from datetime import datetime, timezone
from urllib.parse import urlsplit

from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import RequestEntityTooLarge

import config

from . import socketio, user_lifecycle
from .audit_logger import log_rate_limit_exceeded, log_security_event
from .auth import (
    check_rate_limit,
    password_exceeds_bcrypt_limit,
    user_creation_transaction,
)
from .auth_assurance import (
    AssuranceLevel,
    available_mfa_methods,
    begin_authentication,
    browser_session_binding,
    consume_pending,
    finalize_login,
)
from .decorators import admin_required, step_up_required
from .ldap_service import LDAPDirectory, LDAPLookupRejected, LDAPUnavailable
from .models import (
    LDAPIdentity,
    OIDCIdentity,
    User,
    db,
)


ldap_blueprint = Blueprint('ldap', __name__)
_MAX_LDAP_FORM_BYTES = 4096
_MAX_LDAP_JSON_BYTES = 4096
_MAX_AUTO_PROVISIONED_USERNAME_LENGTH = 80


def _bounded_json():
    request.max_content_length = _MAX_LDAP_JSON_BYTES
    if (
        request.content_length is not None
        and request.content_length > _MAX_LDAP_JSON_BYTES
    ):
        return None
    try:
        raw_data = request.get_data(cache=True)
    except RequestEntityTooLarge:
        return None
    if len(raw_data) > _MAX_LDAP_JSON_BYTES:
        return None
    return request.get_json(silent=True) or {}


def _request_body_too_large():
    return jsonify({'error': 'Request body too large'}), 413


def get_directory():
    return LDAPDirectory()


def _rate_limited(endpoint):
    client_ip = request.remote_addr or 'unknown'
    if config.RATELIMIT_ENABLED and check_rate_limit(
        client_ip,
        endpoint,
        config.LDAP_LOGIN_RATE_LIMIT,
    ):
        log_rate_limit_exceeded(endpoint, client_ip)
        return True
    return False


def _auto_provision_ldap_identity(username, resolved, *, presented_username=None):
    """Create one non-admin LDAP account after its credentials are verified."""
    presented_username = (
        username if presented_username is None else presented_username
    )
    if (
        not username
        or len(username) > _MAX_AUTO_PROVISIONED_USERNAME_LENGTH
        or any(
            unicodedata.category(character).startswith('C')
            for character in presented_username
        )
    ):
        raise LDAPLookupRejected('Directory username cannot be provisioned safely')

    with user_creation_transaction():
        local_admin = (
            User.query
            .filter_by(is_admin=True, is_locked=False)
            .filter(~User.ldap_identity.has())
            .first()
        )
        if local_admin is None:
            raise LDAPLookupRejected(
                'A local break-glass administrator is required'
            )

        normalized_username = username.casefold()
        existing_names = User.query.with_entities(User.username).all()
        if any(
            row.username.casefold() == normalized_username
            for row in existing_names
        ):
            raise LDAPLookupRejected(
                'Directory username conflicts with a local account'
            )

        user = User(username=username, is_admin=False, is_locked=False)
        user.set_password(secrets.token_urlsafe(48))
        mapping = LDAPIdentity(
            user=user,
            provider=resolved.provider,
            subject=resolved.subject,
            directory_username=username,
            distinguished_name=resolved.distinguished_name,
            last_verified_at=datetime.now(timezone.utc),
        )
        db.session.add_all((user, mapping))
        try:
            db.session.flush()
            user.get_data_dir()
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            mapping = LDAPIdentity.query.filter_by(
                provider=resolved.provider,
                subject=resolved.subject,
            ).first()
            if (
                mapping is None
                or mapping.user.is_locked
                or mapping.user.is_admin
            ):
                raise LDAPLookupRejected(
                    'Directory identity could not be provisioned uniquely'
                )
            return mapping
        except Exception as exc:
            db.session.rollback()
            log_security_event(
                'LDAP_AUTO_PROVISION_STORAGE_FAILED',
                level=logging.ERROR,
                user=username,
                provider=resolved.provider,
                error=type(exc).__name__,
            )
            raise LDAPUnavailable(
                'LDAP account provisioning storage is unavailable'
            ) from exc

    log_security_event(
        'LDAP_USER_AUTO_PROVISIONED',
        user=user.username,
        provider=mapping.provider,
    )
    return mapping


@ldap_blueprint.post('/login/ldap')
def ldap_login():
    if request.content_length and request.content_length > _MAX_LDAP_FORM_BYTES:
        return render_template('login.html', auth_source='ldap'), 413
    if _rate_limited('ldap_login'):
        return render_template('login.html', auth_source='ldap'), 429

    presented_username = str(request.form.get('username') or '')
    username = presented_username.strip()
    password = request.form.get('password') or ''
    client_ip = request.remote_addr or 'unknown'
    try:
        directory = get_directory()
        resolved = directory.lookup(username)
        mapping = LDAPIdentity.query.filter_by(
            provider=resolved.provider,
            subject=resolved.subject,
        ).first()
        if (
            mapping is not None
            and (mapping.user.is_locked or mapping.user.is_admin)
        ):
            raise LDAPLookupRejected('Identity is not linked to an active user')
        if mapping is None and not config.LDAP_AUTO_PROVISION:
            raise LDAPLookupRejected('Identity is not linked to an active user')
        if not directory.verify_password(
            resolved.distinguished_name,
            password,
        ):
            raise LDAPLookupRejected('LDAP credentials are invalid')
        if mapping is None:
            mapping = _auto_provision_ldap_identity(
                username,
                resolved,
                presented_username=presented_username,
            )
    except LDAPLookupRejected:
        log_security_event(
            'LDAP_LOGIN_REJECTED',
            level=logging.WARNING,
            user=username or None,
            ip=client_ip,
            reason='invalid_credentials_or_mapping',
        )
        return render_template(
            'login.html',
            ldap_error='Invalid username or password',
            auth_source='ldap',
        ), 401
    except LDAPUnavailable as exc:
        log_security_event(
            'LDAP_LOGIN_UNAVAILABLE',
            level=logging.ERROR,
            user=username or None,
            ip=client_ip,
            error=type(exc).__name__,
        )
        return render_template(
            'login.html',
            ldap_error='Directory sign-in is temporarily unavailable',
            auth_source='ldap',
        ), 503

    user = mapping.user
    verified_at = int(time.time())
    mapping.directory_username = username
    mapping.distinguished_name = resolved.distinguished_name
    mapping.last_verified_at = datetime.now(timezone.utc)
    session.clear()
    binding = browser_session_binding()
    token = begin_authentication(
        user,
        'ldap',
        assurance=AssuranceLevel.BASIC,
        session_binding=binding,
        remember=False,
        continuation='/',
        evidence={
            'provider': mapping.provider,
            'verified_at': verified_at,
        },
    )
    if user.mfa_enabled:
        methods = available_mfa_methods(user)
        session['_pending_authentication'] = token
        if request.accept_mimetypes.best == 'application/json':
            return jsonify({
                'ok': True,
                'mfa_required': True,
                'methods': list(methods),
            })
        return render_template(
            'login.html',
            auth_source='ldap',
            mfa_required=True,
            pending_token=token,
            mfa_methods=methods,
        )
    pending = consume_pending(token, binding)
    finalize_login(pending, methods=['ldap'])
    return redirect(url_for('index'))


@ldap_blueprint.post('/admin/api/users/<int:user_id>/ldap-link')
@admin_required
@login_required
@step_up_required('ldap.link', lambda user_id: user_id)
def link_ldap_identity(user_id):
    data = _bounded_json()
    if data is None:
        return _request_body_too_large()
    target = db.session.get(User, user_id)
    if target is None:
        return jsonify({'error': 'User not found'}), 404
    if target.is_admin:
        return jsonify({
            'error': 'Administrator accounts must remain local break-glass accounts'
        }), 400
    if data.get('confirm_username') != target.username:
        return jsonify({'error': 'Target confirmation does not match'}), 400
    directory_username = str(data.get('directory_username') or '').strip()
    if not directory_username or len(directory_username) > 256:
        return jsonify({'error': 'Directory username is required'}), 400
    if target.ldap_identity is not None:
        return jsonify({'error': 'User already has an LDAP identity'}), 409

    try:
        resolved = get_directory().lookup(directory_username)
    except LDAPLookupRejected:
        return jsonify({'error': 'Directory identity was not found uniquely'}), 400
    except LDAPUnavailable as exc:
        log_security_event(
            'LDAP_LINK_UNAVAILABLE',
            level=logging.ERROR,
            admin=current_user.username,
            user=target.username,
            error=type(exc).__name__,
        )
        return jsonify({'error': 'Directory is temporarily unavailable'}), 503

    row = LDAPIdentity(
        user_id=target.id,
        provider=resolved.provider,
        subject=resolved.subject,
        directory_username=directory_username,
        distinguished_name=resolved.distinguished_name,
        last_verified_at=datetime.now(timezone.utc),
    )
    # Destroy the dormant local credential and incompatible OIDC mapping.
    # Unlinking requires a fresh local password, so no old password silently
    # becomes valid again after a directory outage or rollback.
    target.set_password(secrets.token_urlsafe(48))
    target.auth_generation = int(target.auth_generation or 0) + 1
    OIDCIdentity.query.filter_by(user_id=target.id).delete()
    db.session.add(row)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'LDAP identity is already linked'}), 409
    except Exception as exc:
        db.session.rollback()
        log_security_event(
            'LDAP_IDENTITY_STORAGE_FAILED',
            level=logging.ERROR,
            admin=current_user.username,
            user=target.username,
            error=type(exc).__name__,
        )
        return jsonify({
            'error': 'LDAP identity storage is temporarily unavailable'
        }), 503

    user_lifecycle.revoke_user_access(target.id, socketio)
    log_security_event(
        'LDAP_IDENTITY_LINKED',
        admin=current_user.username,
        user=target.username,
        provider=row.provider,
    )
    return jsonify({'id': row.id}), 201


@ldap_blueprint.get('/admin/api/users/<int:user_id>/ldap-identity')
@admin_required
@login_required
def get_ldap_identity(user_id):
    target = db.session.get(User, user_id)
    if target is None:
        return jsonify({'error': 'User not found'}), 404
    row = target.ldap_identity
    if row is None:
        return jsonify({'identity': None})
    return jsonify({'identity': {
        'id': row.id,
        'provider': row.provider,
        'directory_username': row.directory_username,
        'created_at': row.created_at.isoformat(),
        'last_verified_at': (
            row.last_verified_at.isoformat() if row.last_verified_at else None
        ),
    }})


@ldap_blueprint.get('/admin/api/ldap/status')
@admin_required
@login_required
def ldap_status():
    client_ip = request.remote_addr or 'unknown'
    if config.RATELIMIT_ENABLED and check_rate_limit(
        f'{current_user.id}:{client_ip}',
        'ldap_status',
        config.LDAP_LOGIN_RATE_LIMIT,
    ):
        return jsonify({'error': 'Too many LDAP diagnostic requests'}), 429
    try:
        get_directory().probe()
    except LDAPUnavailable as exc:
        log_security_event(
            'LDAP_READINESS_FAILED',
            level=logging.ERROR,
            admin=current_user.username,
            error=type(exc).__name__,
        )
        return jsonify({
            'enabled': True,
            'provider': config.LDAP_PROVIDER_ID,
            'ready': False,
            'transport': (
                'ldap+StartTLS'
                if urlsplit(config.LDAP_URL).scheme == 'ldap'
                else 'ldaps'
            ),
        }), 503
    return jsonify({
        'enabled': True,
        'provider': config.LDAP_PROVIDER_ID,
        'ready': True,
        'transport': (
            'ldap+StartTLS'
            if urlsplit(config.LDAP_URL).scheme == 'ldap'
            else 'ldaps'
        ),
    })


@ldap_blueprint.delete(
    '/admin/api/users/<int:user_id>/ldap-identities/<int:identity_id>'
)
@admin_required
@login_required
@step_up_required(
    'ldap.unlink',
    lambda user_id, identity_id: f'{user_id}:{identity_id}',
)
def unlink_ldap_identity(user_id, identity_id):
    data = _bounded_json()
    if data is None:
        return _request_body_too_large()
    target = db.session.get(User, user_id)
    if target is None:
        return jsonify({'error': 'User not found'}), 404
    if data.get('confirm_username') != target.username:
        return jsonify({'error': 'Target confirmation does not match'}), 400
    row = db.session.get(LDAPIdentity, identity_id)
    if row is None or row.user_id != target.id:
        return jsonify({'error': 'LDAP identity not found'}), 404
    new_password = data.get('new_password') or ''
    if len(new_password) < config.MIN_PASSWORD_LENGTH:
        return jsonify({
            'error': (
                f'New password must be at least {config.MIN_PASSWORD_LENGTH} '
                'characters'
            )
        }), 400
    if password_exceeds_bcrypt_limit(new_password):
        return jsonify({
            'error': (
                f'New password must not exceed {config.MAX_PASSWORD_LENGTH} '
                'bytes when encoded as UTF-8'
            )
        }), 400

    provider = row.provider
    db.session.delete(row)
    target.set_password(new_password)
    target.auth_generation = int(target.auth_generation or 0) + 1
    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        log_security_event(
            'LDAP_IDENTITY_STORAGE_FAILED',
            level=logging.ERROR,
            admin=current_user.username,
            user=target.username,
            error=type(exc).__name__,
        )
        return jsonify({
            'error': 'LDAP identity storage is temporarily unavailable'
        }), 503
    user_lifecycle.revoke_user_access(target.id, socketio)
    log_security_event(
        'LDAP_IDENTITY_UNLINKED',
        level=logging.WARNING,
        admin=current_user.username,
        user=target.username,
        provider=provider,
    )
    return jsonify({'ok': True})
