"""Owned browser-login inventory and selective access revocation."""
from datetime import datetime, timezone
import hashlib
import hmac
import re

from flask import Blueprint, current_app, jsonify, request
from flask_login import current_user, login_required

from .audit_logger import log_security_event, log_warning
from .auth_assurance import authentication_methods, current_authentication_session
from .models import AuthenticationSession, GitHubOAuthState, OIDCLoginState, SocketSession, StepUpIntent, User, db
from .login_access import serialize_login_access

account_sessions_blueprint = Blueprint('account_sessions', __name__)


def login_cancellation_check(auth):
    """Capture an exact login, then recheck it during an ongoing HTTP command."""
    auth_id, user_id, digest, generation = auth.id, auth.user_id, auth.session_hash, auth.auth_generation
    lifecycle = current_app.extensions['runtime_lifecycle']

    def cancelled():
        if not lifecycle.accepting_work():
            return True
        return db.session.query(AuthenticationSession.id).join(User).filter(
            AuthenticationSession.id == auth_id,
            AuthenticationSession.user_id == user_id,
            AuthenticationSession.session_hash == digest,
            AuthenticationSession.auth_generation == generation,
            AuthenticationSession.expires_at > datetime.now(timezone.utc).replace(tzinfo=None),
            User.auth_generation == generation,
            User.is_locked.is_(False),
        ).first() is None

    return cancelled


def _handle(row):
    # A management-only reference, domain-separated from all login credentials.
    key = str(current_app.secret_key).encode('utf-8')
    return hmac.new(key, f'login-inventory:{row.id}:{row.session_hash}'.encode(), hashlib.sha256).hexdigest()


def _live_sessions():
    return AuthenticationSession.query.filter(
        AuthenticationSession.user_id == current_user.id,
        AuthenticationSession.auth_generation == int(current_user.auth_generation or 0),
        AuthenticationSession.expires_at > datetime.now(timezone.utc).replace(tzinfo=None),
    ).order_by(AuthenticationSession.authenticated_at.desc(), AuthenticationSession.id.desc()).all()


def _response(**payload):
    response = jsonify(**payload)
    response.headers['Cache-Control'] = 'no-store'
    return response


@account_sessions_blueprint.get('/api/account/sessions')
@login_required
def list_sessions():
    current = current_authentication_session()
    if current is None:
        return _response(error='Authentication required'), 401
    return _response(sessions=[{
        'handle': _handle(row),
        'current': row.id == current.id,
        'methods': authentication_methods(row),
        'started_at': row.authenticated_at.isoformat() + 'Z',
        'expires_at': row.expires_at.isoformat() + 'Z',
    } for row in _live_sessions()])


@account_sessions_blueprint.post('/api/account/sessions/revoke')
@login_required
@serialize_login_access
def revoke_sessions():
    db.session.expire_all()
    current = current_authentication_session()
    if current is None:
        return _response(error='Authentication required'), 401
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not (
        set(body) == {'others'} and body['others'] is True
        or set(body) == {'session'} and isinstance(body['session'], str) and re.fullmatch(r'[0-9a-f]{64}', body['session'])
    ):
        return _response(error='Select a login or all other logins'), 400
    rows = _live_sessions()
    if body.get('others') is True:
        selected = [row for row in rows if row.id != current.id]
    else:
        selected = [row for row in rows if hmac.compare_digest(_handle(row), body['session'])]
        if not selected:
            return _response(error='Login is no longer available'), 404
        if selected[0].id == current.id:
            return _response(error='Use Sign out to end this login'), 409
    selected_ids = [row.id for row in selected]
    selected_identities = [(row.user_id, row.id, row.session_hash) for row in selected]
    sockets = SocketSession.query.filter(
        SocketSession.user_id == current_user.id,
        SocketSession.authentication_session_id.in_(selected_ids),
    ).all() if selected_ids else []
    socket_sids = [row.socket_sid for row in sockets]
    intents = [row.id for row in StepUpIntent.query.filter(
        StepUpIntent.authentication_session_id.in_(selected_ids),
    )] if selected_ids else []
    if selected_ids:
        for model in (GitHubOAuthState, OIDCLoginState):
            model.query.filter(db.or_(
                model.authentication_session_id.in_(selected_ids),
                model.step_up_intent_id.in_(intents),
            )).delete(synchronize_session=False)
    for row in selected:
        db.session.delete(row)
    db.session.commit()

    # Commit the authentication fence before interrupting jobs or transports.
    # Retained account-owned SSH/tmux sessions are deliberately not destroyed.
    cleanup_errors = False
    from .discovery_routes import cancel_for_authentication_sessions
    cancel_for_authentication_sessions(selected_identities)
    for session_id in selected_ids:
        for name in ('credentials', 'automation'):
            service = current_app.extensions.get(name)
            if service is not None:
                try:
                    service.revoke_session(session_id)
                except Exception as error:
                    cleanup_errors = True
                    log_warning('Login resource cleanup failed', resource=name, error_type=type(error).__name__)
    from . import socketio
    from .socket_events import disconnect_socket_transport
    from .transfer_routes import transfer_manager
    for sid in socket_sids:
        # Also cancel directly so a failing transport teardown cannot preserve
        # an already-consumed HTTP transfer token or its streaming response.
        try:
            transfer_manager.cancel_all_for_socket(current_user.id, sid)
        except Exception as error:
            cleanup_errors = True
            log_warning('Login transfer cleanup failed', error_type=type(error).__name__)
        try:
            disconnect_socket_transport(socketio.server, sid, drain=False)
        except Exception as error:
            cleanup_errors = True
            log_warning('Login socket cleanup failed', error_type=type(error).__name__)
    log_security_event('BROWSER_LOGINS_REVOKED', user=current_user.username, count=len(selected_ids))
    return _response(revoked=len(selected_ids), cleanup_incomplete=cleanup_errors)
