"""HTTP surface for terminal share links.

Owner endpoints are ordinary authenticated, CSRF-protected JSON routes.

Viewer endpoints are public and authenticated only by bearer secrets in JSON
request bodies: the link token (kept in the URL fragment, which browsers never
send to a server) and a per-viewer ticket issued on join. They never rely on
ambient cookies, so CSRF does not apply, and requiring ``application/json``
keeps cross-origin pages behind a CORS preflight the app never grants.
"""

import json
import time

from flask import Blueprint, Response, jsonify, render_template, request
from flask_login import current_user, login_required

import config
from . import ssh_manager
from .audit_logger import log_security_event
from .terminal_share import MODES, ShareError, share_hub


terminal_share_blueprint = Blueprint('terminal_share', __name__)

@terminal_share_blueprint.after_request
def no_store(response):
    response.headers['Cache-Control'] = 'no-store'
    return response


def _client_ip():
    from . import get_client_ip

    return get_client_ip()


def _error(error):
    return jsonify({'success': False, 'code': error.code}), error.status


def _json_body(allowed, required=()):
    if not request.is_json:
        raise ShareError('invalid_request', 415)
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or set(body) - set(allowed):
        raise ShareError('invalid_request')
    if any(field not in body for field in required):
        raise ShareError('invalid_request')
    return body


def _limits():
    return {
        'enabled': bool(
            config.TERMINAL_SHARE_ENABLED and config.TERMINAL_SHARE_MAX_VIEWERS
        ),
        'allow_control': config.TERMINAL_SHARE_ALLOW_CONTROL,
        'default_ttl_minutes': config.TERMINAL_SHARE_DEFAULT_TTL_MINUTES,
        'max_ttl_minutes': config.TERMINAL_SHARE_MAX_TTL_MINUTES,
        'max_viewers_per_link': min(
            config.TERMINAL_SHARE_MAX_VIEWERS_PER_LINK,
            config.TERMINAL_SHARE_MAX_VIEWERS,
        ),
        'chat': config.TERMINAL_SHARE_CHAT_ENABLED,
    }


def _session_id(value):
    if not isinstance(value, str) or not 0 < len(value) <= 128:
        raise ShareError('invalid_request')
    return value


# ----------------------------------------------------------------------
# Owner API
# ----------------------------------------------------------------------
@terminal_share_blueprint.get('/api/terminal-shares')
@login_required
def list_shares():
    session_id = request.args.get('session_id')
    if session_id is not None and not 0 < len(session_id) <= 128:
        return _error(ShareError('invalid_request'))
    shares = (
        share_hub.list_for_session(current_user.id, session_id)
        if session_id is not None
        else share_hub.list_for_owner(current_user.id)
    )
    return jsonify({'success': True, 'shares': shares, 'limits': _limits()})


@terminal_share_blueprint.post('/api/terminal-shares')
@login_required
def create_share():
    from .auth import check_socket_rate_limit

    try:
        body = _json_body(
            {
                'session_id', 'title', 'mode', 'ttl_minutes',
                'max_viewers', 'require_approval',
            },
            required=('session_id',),
        )
        session_id = body['session_id']
        title = body.get('title', '')
        if (
            not isinstance(session_id, str)
            or not 0 < len(session_id) <= 128
            or not isinstance(title, str)
            or len(title) > 256
        ):
            raise ShareError('invalid_request')
        if check_socket_rate_limit(
            current_user.id,
            'terminal_share_create',
            config.RATELIMIT_TERMINAL_SHARE_CREATE,
        ):
            raise ShareError('rate_limited', 429)
        share = share_hub.create(
            current_user.id,
            session_id,
            owner_name=current_user.username,
            title=title,
            mode=body.get('mode', 'view'),
            ttl_minutes=body.get('ttl_minutes'),
            max_viewers=body.get('max_viewers'),
            require_approval=body.get('require_approval', False),
        )
    except ShareError as error:
        return _error(error)
    log_security_event(
        'terminal_share_created',
        user=current_user.username,
        share=share['id'],
        mode=share['mode'],
        approval=share['require_approval'],
        max_viewers=share['max_viewers'],
        expires_at=share['expires_at'],
        ip=_client_ip(),
    )
    return jsonify({'success': True, 'share': share}), 201


@terminal_share_blueprint.patch('/api/terminal-shares/<share_id>')
@login_required
def update_share(share_id):
    try:
        body = _json_body({'mode'}, required=('mode',))
        if body['mode'] not in MODES:
            raise ShareError('invalid_mode')
        share = share_hub.set_mode(current_user.id, share_id, body['mode'])
    except ShareError as error:
        return _error(error)
    log_security_event(
        'terminal_share_mode_changed',
        user=current_user.username,
        share=share_id,
        mode=share['mode'],
    )
    return jsonify({'success': True, 'share': share})


@terminal_share_blueprint.delete('/api/terminal-shares/<share_id>')
@login_required
def revoke_share(share_id):
    try:
        share_hub.revoke(current_user.id, share_id)
    except ShareError as error:
        return _error(error)
    log_security_event(
        'terminal_share_revoked',
        user=current_user.username,
        share=share_id,
    )
    return jsonify({'success': True})


@terminal_share_blueprint.post(
    '/api/terminal-shares/<share_id>/viewers/<viewer_id>/approve'
)
@login_required
def approve_viewer(share_id, viewer_id):
    try:
        share_hub.approve_viewer(current_user.id, share_id, viewer_id)
    except ShareError as error:
        return _error(error)
    log_security_event(
        'terminal_share_viewer_approved',
        user=current_user.username,
        share=share_id,
        viewer=viewer_id,
    )
    return jsonify({'success': True})


@terminal_share_blueprint.delete(
    '/api/terminal-shares/<share_id>/viewers/<viewer_id>'
)
@login_required
def remove_viewer(share_id, viewer_id):
    try:
        share_hub.remove_viewer(current_user.id, share_id, viewer_id)
    except ShareError as error:
        return _error(error)
    log_security_event(
        'terminal_share_viewer_removed',
        user=current_user.username,
        share=share_id,
        viewer=viewer_id,
    )
    return jsonify({'success': True})


@terminal_share_blueprint.get('/api/terminal-shares/chat')
@login_required
def owner_chat_history():
    try:
        session_id = _session_id(request.args.get('session_id'))
    except ShareError as error:
        return _error(error)
    return jsonify({
        'success': True,
        'messages': share_hub.chat_history(current_user.id, session_id),
    })


@terminal_share_blueprint.post('/api/terminal-shares/chat')
@login_required
def owner_chat():
    try:
        body = _json_body({'session_id', 'text'}, required=('session_id', 'text'))
        message = share_hub.owner_chat(
            current_user.id,
            _session_id(body['session_id']),
            body['text'],
            name=current_user.username,
        )
    except ShareError as error:
        return _error(error)
    return jsonify({'success': True, 'message': message})


@terminal_share_blueprint.post('/api/terminal-shares/pointer')
@login_required
def owner_pointer():
    try:
        body = _json_body(
            {'session_id', 'col', 'row'},
            required=('session_id', 'col', 'row'),
        )
        pointer = share_hub.owner_pointer(
            current_user.id,
            _session_id(body['session_id']),
            body['col'],
            body['row'],
            name=current_user.username,
        )
    except ShareError as error:
        return _error(error)
    return jsonify({'success': True, 'pointer': pointer})


# ----------------------------------------------------------------------
# Public viewer surface
# ----------------------------------------------------------------------
@terminal_share_blueprint.get('/share')
def viewer_page():
    response = Response(render_template('share_view.html'))
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Robots-Tag'] = 'noindex, nofollow'
    return response


@terminal_share_blueprint.post('/api/share-view/join')
def viewer_join():
    from .auth import check_rate_limit

    try:
        body = _json_body({'token', 'name', 'ticket'}, required=('token',))
        if check_rate_limit(
            _client_ip(),
            'terminal_share_join',
            config.RATELIMIT_TERMINAL_SHARE_JOIN,
        ):
            raise ShareError('rate_limited', 429)
        token = body['token']
        ticket = body.get('ticket')
        if ticket is not None:
            # A reloading page keeps its seat instead of taking a new one.
            try:
                view = share_hub.describe(ticket)
                if share_hub.ticket_matches_link(ticket, token):
                    return jsonify({
                        'success': True,
                        'ticket': ticket,
                        'viewer': view,
                    })
            except ShareError:
                pass
        view, ticket = share_hub.join(token, body.get('name', ''))
    except ShareError as error:
        return _error(error)
    log_security_event(
        'terminal_share_joined',
        viewer=view['viewer_id'],
        status=view['status'],
        ip=_client_ip(),
    )
    return jsonify({'success': True, 'ticket': ticket, 'viewer': view})


def _sse(event):
    kind = event['type']
    payload = {key: value for key, value in event.items() if key != 'type'}
    frame = []
    if kind in ('output', 'reset'):
        frame.append(f"id: {event['seq']}")
    frame.append(f'event: {kind}')
    frame.append('data: ' + json.dumps(
        payload,
        ensure_ascii=False,
        separators=(',', ':'),
    ))
    return '\n'.join(frame) + '\n\n'


@terminal_share_blueprint.post('/api/share-view/stream')
def viewer_stream():
    try:
        body = _json_body({'ticket', 'last_event_id'}, required=('ticket',))
        last_event_id = body.get('last_event_id')
        if last_event_id is not None and (
            not isinstance(last_event_id, (str, int))
            or isinstance(last_event_id, bool)
            or len(str(last_event_id)) > 20
        ):
            raise ShareError('invalid_request')
        stream = share_hub.open_stream(body['ticket'], last_event_id)
        try:
            hello = share_hub.describe(body['ticket'])
        except ShareError:
            stream.close()
            raise
    except ShareError as error:
        return _error(error)

    heartbeat = config.TERMINAL_SHARE_HEARTBEAT_SECONDS

    def generate():
        try:
            yield _sse({
                'type': 'hello',
                'resumed': stream.resumed,
                'heartbeat': heartbeat,
                **hello,
            })
            last_write = time.monotonic()
            while True:
                events, ended = stream.poll(heartbeat)
                for event in events:
                    yield _sse(event)
                if events:
                    last_write = time.monotonic()
                elif time.monotonic() - last_write >= heartbeat:
                    # Comments keep proxies open and surface dead clients.
                    yield ': ping\n\n'
                    last_write = time.monotonic()
                if ended is not None:
                    return
        finally:
            stream.close()

    response = Response(generate(), mimetype='text/event-stream')
    response.headers['Cache-Control'] = 'no-store, no-transform'
    response.headers['X-Accel-Buffering'] = 'no'
    return response


@terminal_share_blueprint.post('/api/share-view/input')
def viewer_input():
    from .socket_events import ssh_input_budget

    try:
        body = _json_body({'ticket', 'data'}, required=('ticket', 'data'))
        data = body['data']
        if not isinstance(data, str) or not data:
            raise ShareError('invalid_request')
        try:
            input_bytes = len(data.encode('utf-8'))
        except UnicodeEncodeError as exc:
            raise ShareError('invalid_request') from exc
        if input_bytes > config.SSH_INPUT_MAX_BYTES:
            raise ShareError('input_too_large', 413)
        grant = share_hub.authorize_input(body['ticket'])
        # Guests draw from the owner's budget so sharing cannot multiply the
        # input rate one account can push through this server.
        allowed, retry_after_ms = ssh_input_budget().allow(
            grant.owner_id,
            grant.session_id,
            input_bytes,
        )
        if not allowed:
            return jsonify({
                'success': False,
                'code': 'rate_limited',
                'retry_after_ms': retry_after_ms,
            }), 429
        delivered, _error_message = ssh_manager.send_ssh_input(
            grant.session_id,
            data,
            require_complete=True,
        )
        if not delivered:
            raise ShareError('session_closed', 410)
    except ShareError as error:
        return _error(error)
    if grant.first_use:
        log_security_event(
            'terminal_share_input_used',
            share=grant.share_id,
            viewer=grant.viewer_id,
            ip=_client_ip(),
        )
    return jsonify({'success': True})


@terminal_share_blueprint.post('/api/share-view/leave')
def viewer_leave():
    try:
        body = _json_body({'ticket'}, required=('ticket',))
    except ShareError as error:
        return _error(error)
    share_hub.leave(body['ticket'])
    return jsonify({'success': True})


@terminal_share_blueprint.post('/api/share-view/chat')
def viewer_chat():
    try:
        body = _json_body({'ticket', 'text'}, required=('ticket', 'text'))
        message = share_hub.guest_chat(body['ticket'], body['text'])
    except ShareError as error:
        return _error(error)
    return jsonify({'success': True, 'message': message})


@terminal_share_blueprint.post('/api/share-view/pointer')
def viewer_pointer():
    try:
        body = _json_body({'ticket', 'col', 'row'}, required=('ticket', 'col', 'row'))
        pointer = share_hub.guest_pointer(body['ticket'], body['col'], body['row'])
    except ShareError as error:
        return _error(error)
    return jsonify({'success': True, 'pointer': pointer})


def _notify_owner(owner_id, session_id, event):
    from . import socketio

    socketio.emit('terminal_share_update', {
        'session_id': session_id,
        'event': event,
        'shares': share_hub.list_for_session(owner_id, session_id),
    }, room=f'user_{owner_id}')


def _notify_owner_activity(owner_id, session_id, kind, payload):
    from . import socketio

    socketio.emit(f'terminal_share_{kind}', {
        'session_id': session_id,
        kind: payload,
    }, room=f'user_{owner_id}')


def init_terminal_share(app, csrf):
    app.register_blueprint(terminal_share_blueprint)
    # Bearer-authenticated viewer routes; Flask-WTF matches view functions.
    for view in (
        viewer_join, viewer_stream, viewer_input, viewer_leave,
        viewer_chat, viewer_pointer,
    ):
        csrf.exempt(view)
    share_hub.set_listener(_notify_owner)
    share_hub.set_activity_listener(_notify_owner_activity)
