from flask_socketio import emit, join_room, disconnect
from flask import copy_current_request_context, request, current_app, url_for
from . import (socketio, ssh_manager, profile_manager, key_manager,
               sftp_handler, jump_host_manager, post_connect_manager,
               session_insights, runtime_inventory, smb_share_manager)
from .decorators import socket_login_required
from .auth import (
    check_socket_rate_limit,
    get_user_from_socket,
    load_user,
    register_socket_session,
)
from .models import db, SSHSession, SocketSession
from .user_settings import save_user_settings, get_user_settings
from .audit_logger import (log_info, log_warning, log_error, log_debug,
                              log_security_event,
                              log_ssh_connection, log_ssh_disconnect,
                              log_file_source_operation,
                              log_key_upload, log_key_rename, log_key_replace,
                              log_key_delete,
                              log_tailscale_ssh_usage)
from .tailscale_ssh import (
    profile_is_authorized_for_launch,
    validate_tailscale_ssh_access,
)
from .storage_errors import StorageCorruptionError
from .network_policy import canonicalize_hostname
from .ssh_errors import connection_error_payload
from . import binary_transfer, connection_pool
from .transfer_routes import prepare_transfer, transfer_manager, _terminalize
from .quota_manager import QuotaKind, quota_manager
from .socket_capacity import socket_capacity
from .remote_transfer import (
    RemoteTransferCancelled,
    RemoteTransferError,
    TransferBudget,
    copy_remote_entry,
)
from .transfer_errors import classify_transfer_failure
from .file_sources import (
    FileCapability,
    FileSourceKind,
    FileSourceUnavailable,
    file_source_audit_identity,
    file_source_resolver,
    make_source_id,
    parse_source_id,
)
from .file_service import file_service
from .smb_diagnostics import smb_diagnostic_log_fields
import posixpath
import re
import secrets
import threading
import time
import config


STORAGE_ERROR_MESSAGE = (
    'Stored data is unreadable. Please restore or remove it.'
)


_SMB_REQUEST_ID = re.compile(r'[A-Za-z0-9:._-]{1,128}')
_SMB_CONNECT_CODES = frozenset({
    'AUTHENTICATION_REQUIRED',
    'CONNECTION_FAILED',
    'CONNECT_CANCELLED',
    'DIALECT_REQUIRED',
    'ENCRYPTION_REQUIRED',
    'INVALID_REQUEST',
    'PERMISSION_DENIED',
    'QUOTA_EXCEEDED',
    'RUNTIME_SHUTTING_DOWN',
    'SHARE_UNAVAILABLE',
    'SOURCE_UNAVAILABLE',
    'TARGET_NOT_ALLOWED',
    'TIMEOUT',
})
_smb_attempts_lock = threading.RLock()
_smb_attempts = {}
_ssh_banner_prompts_lock = threading.RLock()
_ssh_banner_prompts = {}
SSH_AUTH_BANNER_DECISION_TIMEOUT = 60


def _new_smb_diagnostic_id():
    return f'SMB-{secrets.token_hex(6).upper()}'


def _cancel_ssh_banner_prompts_for_socket(socket_sid):
    with _ssh_banner_prompts_lock:
        prompts = [
            prompt
            for prompt in _ssh_banner_prompts.values()
            if prompt['socket_sid'] == socket_sid
        ]
    for prompt in prompts:
        prompt['event'].set()


def _smb_request_id(payload):
    if not isinstance(payload, dict):
        return ''
    request_id = payload.get('request_id')
    if not isinstance(request_id, str) or not _SMB_REQUEST_ID.fullmatch(
        request_id
    ):
        return ''
    return request_id


def _smb_pool():
    # Keep the optional protocol stack out of the feature-disabled path.
    from .smb_pool import smb_connection_pool

    return smb_connection_pool


def _cancel_smb_attempts_for_socket(user_id, socket_sid):
    handles = []
    with _smb_attempts_lock:
        for (owner_id, owner_sid, _request_id), attempt in tuple(
            _smb_attempts.items()
        ):
            if owner_id != str(user_id) or owner_sid != socket_sid:
                continue
            attempt['cancel_event'].set()
            if attempt.get('handle') is not None:
                handles.append(attempt['handle'])
    for handle in handles:
        handle.cancel()


def _file_request_identity(payload):
    request_id = payload.get('request_id')
    if (
        not isinstance(request_id, str)
        or not re.fullmatch(r'[A-Za-z0-9:._-]{1,128}', request_id)
    ):
        request_id = None
    return {
        'source_id': payload.get('source_id'),
        'request_id': request_id,
    }


def _file_request_source_id(payload, user_id):
    source_id = payload.get('source_id')
    if source_id:
        return source_id
    raise FileSourceUnavailable()


def _valid_file_request(identity):
    return bool(identity.get('source_id') and identity.get('request_id'))


def _public_file_source(source_id, user_id):
    return file_source_resolver.resolve(
        source_id,
        user_id,
    ).descriptor.to_public_dict()


def _file_source_unavailable_payload(**context):
    return {
        'error': 'File source unavailable',
        'code': FileSourceUnavailable.public_code,
        **context,
    }


def _audit_file_source_operation(
    user,
    source,
    *,
    operation,
    result,
    path,
    size=0,
    destination=None,
    destination_path=None,
    ip_address=None,
):
    """Record target metadata without ever accepting SMB credentials."""
    try:
        identity = file_source_audit_identity(source)
        destination_identity = (
            file_source_audit_identity(destination)
            if destination is not None else {}
        )
        log_file_source_operation(
            username=user.username,
            operation=operation,
            result=result,
            filename=posixpath.basename(str(path).rstrip('/')) or '/',
            size=size,
            ip_address=(
                request.remote_addr if ip_address is None else ip_address
            ),
            destination_target_host=destination_identity.get('target_host'),
            destination_share=destination_identity.get('share'),
            destination_filename=(
                posixpath.basename(str(destination_path).rstrip('/')) or '/'
                if destination_path is not None else None
            ),
            **identity,
        )
    except Exception as error:
        log_error(
            'File source audit failed',
            operation=operation,
            result=result,
            exception_type=type(error).__name__,
        )


class _CombinedCancellation:
    """Expose user and runtime cancellation through one Event-like interface."""

    def __init__(self, user_cancel_event, lifecycle_cancel_event):
        self._user_cancel_event = user_cancel_event
        self._lifecycle_cancel_event = lifecycle_cancel_event

    def is_set(self):
        return (
            self._user_cancel_event.is_set()
            or self._lifecycle_cancel_event.is_set()
        )

    def wait(self, timeout=None):
        if self.is_set():
            return True
        if timeout is None:
            while not self._user_cancel_event.wait(0.1):
                if self._lifecycle_cancel_event.is_set():
                    return True
            return True
        deadline = time.monotonic() + timeout
        while not self.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            self._user_cancel_event.wait(min(remaining, 0.1))
        return True


def _storage_error_payload(error, *, user_id, include_success=True, **extra):
    """Log storage metadata, never contents, and build one safe client error."""
    log_error(
        'Storage corruption detected',
        user_id=user_id,
        store=error.path.name,
        path=str(error.path),
        reason=error.reason,
    )
    payload = {
        'error': STORAGE_ERROR_MESSAGE,
        'code': 'storage_error',
        **extra,
    }
    if include_success:
        payload['success'] = False
    return payload


def _emit_storage_error(error, current_user):
    payload = _storage_error_payload(error, user_id=current_user.id)
    emit('error', payload)
    return payload


def _key_mutation_error(message):
    payload = {'success': False, 'error': message}
    emit('error', {'error': message})
    return payload


def _is_valid_host(host_str):
    """Validate host is a valid hostname or IP address."""
    try:
        canonicalize_hostname(host_str)
        return True
    except ValueError:
        return False

def _validate_ssh_params(host, port, username, allow_internal=False):
    """Validate SSH connection parameters. Returns (clean_host, clean_port, clean_username, error).

    ``allow_internal`` remains for compatibility with callers. DNS and address
    policy are enforced only at the connector, where the validated result can
    be pinned to the socket without a time-of-check/time-of-use gap.
    """
    host = (host or '').strip()
    if not host:
        return None, None, None, 'Host is required'
    if not _is_valid_host(host):
        return None, None, None, 'Invalid host format'

    try:
        port = int(port)
        if not (1 <= port <= 65535):
            return None, None, None, 'Port must be between 1 and 65535'
    except (ValueError, TypeError):
        return None, None, None, 'Invalid port number'

    username = (username or '').strip()
    if not username:
        return None, None, None, 'Username is required'
    if not re.match(r'^[a-zA-Z0-9_\-\.]{1,32}$', username):
        return None, None, None, 'Invalid username format'

    return canonicalize_hostname(host), port, username, None

@socketio.on('connect')
def handle_connect():
    """Handle client connection - authenticate and restore sessions."""
    from flask import session as flask_session

    user_id = flask_session.get('_user_id')
    if not user_id:
        log_warning("Unauthenticated connection attempt", sid=request.sid)
        emit('connected', {'status': 'unauthenticated'})
        disconnect()
        return False

    lifecycle = current_app.extensions.get('runtime_lifecycle')
    if lifecycle is None or not lifecycle.accepting_work():
        log_warning('Socket connection rejected during shutdown', sid=request.sid)
        emit('connected', {'status': 'unavailable'})
        return False

    user = load_user(user_id)
    if not user:
        log_warning("User not found during connect", user_id=user_id, sid=request.sid)
        emit('connected', {'status': 'unauthenticated'})
        disconnect()
        return False

    from .auth_assurance import (
        current_authentication_session,
        recovery_session_required,
    )
    auth_session = current_authentication_session()
    if auth_session is None or recovery_session_required(auth_session):
        log_warning(
            "Socket connection rejected by authentication assurance",
            user=user.username,
            sid=request.sid,
        )
        emit('connected', {'status': 'recovery_required'})
        disconnect()
        return False

    socket_sid = request.sid
    if not socket_capacity.reserve(
        user.id,
        socket_sid,
        config.MAX_SOCKET_CONNECTIONS,
        config.MAX_SOCKET_CONNECTIONS_PER_USER,
    ):
        log_warning(
            'Socket connection capacity reached',
            user_id=user.id,
            sid=socket_sid,
        )
        emit('connected', {'status': 'unavailable'})
        disconnect()
        return False

    user_agent = request.headers.get('User-Agent', '')
    try:
        register_socket_session(user.id, socket_sid, user_agent)
    except Exception:
        socket_capacity.release(socket_sid)
        raise

    room = f'user_{user.id}'
    join_room(room)

    log_info(f"Client connected: {user.username}", user=user.username, sid=socket_sid)

    restore_user_sessions(user.id)

    emit('connected', {
        'status': 'success',
        'username': user.username
    })

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection - cleanup socket session."""
    socket_sid = request.sid
    _cancel_ssh_banner_prompts_for_socket(socket_sid)
    owner_id = socket_capacity.release(socket_sid)
    user = get_user_from_socket(socket_sid)
    user_id = user.id if user else owner_id

    if user_id is not None:
        username = user.username if user else f'user {user_id}'
        log_info(
            f"Client disconnected: {username}",
            user=user.username if user else None,
            user_id=user_id,
            sid=socket_sid,
        )

        _cancel_smb_attempts_for_socket(user_id, socket_sid)

        try:
            transfer_manager.cancel_all_for_socket(user_id, socket_sid)
        except Exception as error:
            log_error(
                'Transfer cleanup failed on disconnect',
                user_id=user_id,
                exception_type=type(error).__name__,
            )

        SocketSession.query.filter_by(socket_sid=socket_sid).delete()
        db.session.commit()

        other_sessions = SocketSession.query.filter_by(user_id=user_id).count()

        if other_sessions == 0:
            try:
                transfer_manager.cancel_all_for_user(user_id)
            except Exception as error:
                log_error(
                    'Transfer cleanup failed on disconnect',
                    user_id=user_id,
                    exception_type=type(error).__name__,
                )
            closed = connection_pool.temp_connection_pool.close_all_user_connections(str(user_id))
            if closed > 0:
                log_info(f"Cleaned up {closed} Quick Connect connection(s) for {username}")
            from . import smb_pool

            smb_closed = smb_pool.smb_connection_pool.close_all_user_sources(
                str(user_id)
            )
            if smb_closed > 0:
                log_info(
                    f"Cleaned up {smb_closed} SMB source(s) for {username}"
                )
            log_debug(f"Last socket for {username} disconnected, SSH sessions preserved")

def restore_user_sessions(user_id):
    """Restore active SSH sessions when user reconnects."""
    # Clean up old disconnected non-persistent sessions
    SSHSession.query.filter_by(user_id=user_id, connected=False, is_persistent=False).delete()
    db.session.commit()

    db_sessions = SSHSession.query.filter_by(user_id=user_id, connected=True).all()

    room = f'user_{user_id}'

    for db_session in db_sessions:
        session_id = db_session.session_id

        session = ssh_manager.get_session(session_id)

        if session and session.get('connected'):
            buffered_output, output_sequence = (
                ssh_manager.get_output_snapshot(session_id)
            )
            emit('ssh_session_restored', {
                'session_id': session_id,
                'host': db_session.host,
                'port': db_session.port,
                'username': db_session.username,
                'auth_type': session.get('auth_type', db_session.auth_type),
                'via_jump': session.get('via_jump'),
                'use_tmux': session.get('use_tmux', False),
                'tmux_session_name': session.get('tmux_session_name'),
                'display_name': db_session.display_name,
                'buffered_output': buffered_output,
                'output_sequence': output_sequence,
                'file_source': _public_file_source(
                    make_source_id(FileSourceKind.SFTP_SESSION, session_id),
                    user_id,
                ),
            }, room=room)
            log_info(f"Restored SSH session {session_id}", user_id=user_id, room=room)
        else:
            db_session.connected = False
            db.session.commit()
            log_debug(f"SSH session {session_id} no longer active, marked disconnected")

    # Restore disconnected persistent tmux sessions as reconnect candidates
    if config.TMUX_ENABLED:
        persistent_sessions = SSHSession.query.filter_by(
            user_id=user_id, is_persistent=True, connected=False
        ).all()
        for db_session in persistent_sessions:
            emit('persistent_session_available', {
                'session_id': db_session.session_id,
                'host': db_session.host,
                'port': db_session.port,
                'username': db_session.username,
                'key_id': db_session.key_id,
                'auth_type': db_session.auth_type,
                'tmux_session_name': db_session.tmux_session_name,
                'display_name': db_session.display_name
            }, room=room)
            log_info("Persistent tmux session available for reconnect",
                     host=db_session.host, tmux_session=db_session.tmux_session_name)

@socketio.on('ssh_auth_banner_decision')
@socket_login_required
def handle_ssh_auth_banner_decision(data, current_user=None):
    """Resolve one pending SSH authentication-banner prompt."""
    if not isinstance(data, dict):
        return {'success': False}
    prompt_id = data.get('prompt_id')
    accepted = data.get('accepted')
    if (
        not isinstance(prompt_id, str)
        or not re.fullmatch(r'[A-Za-z0-9_-]{16,64}', prompt_id)
        or type(accepted) is not bool
    ):
        return {'success': False}

    with _ssh_banner_prompts_lock:
        prompt = _ssh_banner_prompts.get(prompt_id)
        if (
            prompt is None
            or prompt['socket_sid'] != request.sid
            or prompt['user_id'] != current_user.id
            or prompt['event'].is_set()
        ):
            return {'success': False}
        prompt['accepted'] = accepted
        prompt['event'].set()
    return {'success': True}


@socketio.on('ssh_connect')
@socket_login_required
def handle_ssh_connect(data, current_user=None):
    """Handle SSH connection request with input validation."""
    password = None
    key_content = None
    bastion_password = None
    bastion_key_content = None
    client_request_id = None
    socket_sid = request.sid
    try:
        client_request_id = data.get('client_request_id')
        if not current_app.extensions[
            'runtime_lifecycle'
        ].accepting_work():
            emit('ssh_error', {
                'error': 'Server is shutting down',
                'client_request_id': client_request_id,
            })
            return

        password = data.get('password')
        key_id = data.get('key_id')
        auth_type = data.get('auth_type') or ('key' if key_id else 'password')

        def emit_error(message):
            emit('ssh_error', connection_error_payload(
                message,
                client_request_id=client_request_id,
            ))

        def request_auth_banner_decision(banner, context):
            prompt_id = secrets.token_urlsafe(24)
            decision_event = threading.Event()
            prompt = {
                'event': decision_event,
                'accepted': False,
                'socket_sid': socket_sid,
                'user_id': current_user.id,
            }
            with _ssh_banner_prompts_lock:
                _ssh_banner_prompts[prompt_id] = prompt
            emit('ssh_auth_banner', {
                'prompt_id': prompt_id,
                'banner': banner,
                'context': context,
                'host': bastion_host if context == 'jump_host' else host,
                'port': bastion_port if context == 'jump_host' else port,
                'client_request_id': client_request_id,
            })
            answered = decision_event.wait(SSH_AUTH_BANNER_DECISION_TIMEOUT)
            with _ssh_banner_prompts_lock:
                _ssh_banner_prompts.pop(prompt_id, None)
            accepted = answered and prompt['accepted'] is True
            log_security_event(
                'SSH_AUTH_BANNER_DECISION',
                user=current_user.username,
                host=bastion_host if context == 'jump_host' else host,
                port=bastion_port if context == 'jump_host' else port,
                context=context,
                result='ACCEPTED' if accepted else (
                    'DECLINED' if answered else 'TIMED_OUT'
                ),
                ip_address=request.remote_addr,
            )
            return accepted

        startup_commands, startup_commands_error = (
            post_connect_manager.resolve_configuration(
                current_user.id, data
            )
        )
        if startup_commands_error:
            emit_error(startup_commands_error)
            return

        proxy_jump = data.get('proxy_jump')
        if not isinstance(proxy_jump, dict):
            proxy_jump = None
        saved_jump_host_id = (
            proxy_jump.get('jump_host_id') if proxy_jump else None
        )
        if saved_jump_host_id:
            live_jump_host = jump_host_manager.get_jump_host(
                current_user.id, saved_jump_host_id
            )
            if live_jump_host is None:
                emit_error('Jump host reference not found')
                return
            runtime_password = proxy_jump.get('password')
            proxy_jump = {
                'host': live_jump_host.get('host'),
                'port': live_jump_host.get('port', 22),
                'username': live_jump_host.get('username'),
                'auth_type': live_jump_host.get('auth_type'),
                'key_id': live_jump_host.get('key_id'),
            }
            if live_jump_host.get('auth_type') == 'password':
                proxy_jump['password'] = runtime_password

        if auth_type == 'key' and key_id:
            key_content, key_error = key_manager.read_key_content(
                current_user.id, key_id
            )
            if key_error:
                emit_error(f'SSH key error: {key_error}')
                return
        if proxy_jump:
            bastion_password = proxy_jump.get('password')
            bastion_key_id = proxy_jump.get('key_id')
            if not bastion_password and not bastion_key_id:
                emit_error('Jump host password or SSH key required')
                return
            if bastion_key_id:
                bastion_key_content, bastion_key_error = (
                    key_manager.read_key_content(
                        current_user.id, bastion_key_id
                    )
                )
                if bastion_key_error:
                    emit_error(
                        f'Jump host SSH key error: {bastion_key_error}'
                    )
                    return

        if check_socket_rate_limit(current_user.id, 'ssh_connect', config.RATELIMIT_SSH_CONNECT):
            log_warning("SSH connect rate limit hit", user=current_user.username)
            emit_error('Too many connection attempts. Please wait a moment.')
            return

        # The target may be internal when reached via a bastion (legitimate).
        host, port, username, error = _validate_ssh_params(
            data.get('host'), data.get('port', 22), data.get('username'),
            allow_internal=bool(proxy_jump)
        )
        if error:
            emit_error(error)
            return

        if auth_type not in {'password', 'key', 'tailscale'}:
            emit_error('Invalid authentication method')
            return

        if auth_type == 'tailscale':
            access_error = validate_tailscale_ssh_access(current_user, host, username)
            log_tailscale_ssh_usage(
                current_user.username, host, port, username, request.remote_addr,
                allowed=access_error is None, error=access_error
            )
            if access_error:
                emit_error(access_error)
                return

        if auth_type == 'password' and not password:
            emit_error('Password required')
            return

        if auth_type == 'key' and not key_id:
            emit_error('Password or SSH key required')
            return

        if key_id and key_content is None:
            key_content, key_error = key_manager.read_key_content(
                current_user.id, key_id
            )
            if key_error:
                emit_error(f'SSH key error: {key_error}')
                return

        # Resolve optional ProxyJump / bastion parameters. The bastion is reached
        # directly by the server, so it is validated WITHOUT allow_internal.
        bastion_host = bastion_port = bastion_username = None
        if proxy_jump:
            bastion_host, bastion_port, bastion_username, bastion_error = _validate_ssh_params(
                proxy_jump.get('host'), proxy_jump.get('port', 22), proxy_jump.get('username')
            )
            if bastion_error:
                emit_error(f'Jump host: {bastion_error}')
                return

        use_tmux = bool(data.get('use_tmux')) and config.TMUX_ENABLED
        reconnect_tmux_name = None
        if use_tmux:
            raw_name = data.get('reconnect_tmux_name')
            if raw_name:
                import re as _re
                # Whitelist: alphanumeric, underscores, max 190 chars
                if not _re.match(r'^[A-Za-z0-9_]{1,190}$', raw_name):
                    emit_error('Invalid tmux session name')
                    return
                # Verify the name maps to an SSHSession owned by this user
                existing = SSHSession.query.filter_by(
                    user_id=current_user.id,
                    tmux_session_name=raw_name,
                    is_persistent=True
                ).first()
                if existing:
                    reconnect_tmux_name = raw_name

        app = current_app._get_current_object()
        lifecycle = app.extensions['runtime_lifecycle']
        credential_box = {
            'password': password,
            'key_content': key_content,
            'bastion_password': bastion_password,
            'bastion_key_content': bastion_key_content,
        }

        @copy_current_request_context
        def connect_ssh(cancel_event, credentials=credential_box):
            """Run blocking SSH setup outside the synchronous socket reader."""
            local_password = credentials.pop('password', None)
            local_key_content = credentials.pop('key_content', None)
            local_bastion_password = credentials.pop(
                'bastion_password', None
            )
            local_bastion_key_content = credentials.pop(
                'bastion_key_content', None
            )
            try:
                if cancel_event.is_set():
                    return
                session_id, error = ssh_manager.create_ssh_connection(
                    host=host,
                    port=int(port),
                    username=username,
                    password=local_password,
                    key_content=local_key_content,
                    socketio_instance=socketio,
                    app=app,
                    user_id=current_user.id,
                    proxy_jump_host=bastion_host,
                    proxy_jump_port=bastion_port,
                    proxy_jump_username=bastion_username,
                    proxy_jump_password=local_bastion_password,
                    proxy_jump_key_content=local_bastion_key_content,
                    use_tmux=use_tmux,
                    reconnect_tmux_name=reconnect_tmux_name,
                    auth_type=auth_type,
                    startup_commands=(
                        '' if reconnect_tmux_name else startup_commands
                    ),
                    auth_banner_decision=request_auth_banner_decision,
                )

                if error:
                    emit_error(error)
                    return

                socket_is_live = SocketSession.query.filter_by(
                    socket_sid=socket_sid,
                    user_id=current_user.id,
                ).first() is not None
                if cancel_event.is_set() or not socket_is_live:
                    ssh_manager.close_session(
                        session_id,
                        kill_tmux=use_tmux,
                    )
                    return

                created_session = ssh_manager.get_session(session_id)
                if not created_session:
                    log_error(
                        "SSH session disappeared after creation",
                        session_id=session_id,
                    )
                    emit_error("Connection failed")
                    return
                created_tmux_name = (
                    created_session.get('tmux_session_name')
                    if use_tmux else None
                )

                display_name = data.get('display_name') if use_tmux else None
                if display_name:
                    display_name = display_name.strip()[:128] or None
                try:
                    # Clean up the specific old disconnected persistent session
                    # when reconnecting to avoid ghost tabs on refresh.
                    if use_tmux and reconnect_tmux_name:
                        old_session = SSHSession.query.filter_by(
                            user_id=current_user.id,
                            host=host,
                            port=port,
                            is_persistent=True,
                            connected=False,
                            tmux_session_name=reconnect_tmux_name,
                        ).first()
                        if old_session:
                            db.session.delete(old_session)
                            log_info(
                                "Cleaned up old persistent session",
                                user=current_user.username,
                                host=host,
                                tmux_session=reconnect_tmux_name,
                            )

                    ssh_session = SSHSession(
                        session_id=session_id,
                        user_id=current_user.id,
                        host=host,
                        port=port,
                        username=username,
                        is_persistent=use_tmux,
                        key_id=key_id if use_tmux else None,
                        auth_type=auth_type,
                        tmux_session_name=created_tmux_name,
                        display_name=display_name if use_tmux else None,
                    )
                    db.session.add(ssh_session)
                    db.session.commit()
                except Exception as db_err:
                    db.session.rollback()
                    log_error(
                        "Failed to record SSH session in database",
                        error=str(db_err),
                        session_id=session_id,
                    )

                emit('ssh_connected', {
                    'session_id': session_id,
                    'host': host,
                    'port': port,
                    'username': username,
                    'client_request_id': client_request_id,
                    'via_jump': bastion_host,
                    'use_tmux': use_tmux,
                    'key_id': key_id if use_tmux else None,
                    'auth_type': auth_type,
                    'tmux_session_name': created_tmux_name,
                    'display_name': display_name,
                    'file_source': _public_file_source(
                        make_source_id(
                            FileSourceKind.SFTP_SESSION,
                            session_id,
                        ),
                        current_user.id,
                    ),
                })
                log_ssh_connection(
                    current_user.username,
                    host,
                    port,
                    True,
                    request.remote_addr,
                )
            except StorageCorruptionError as error:
                emit('ssh_error', _storage_error_payload(
                    error,
                    user_id=current_user.id,
                    include_success=False,
                    client_request_id=client_request_id,
                ))
            except Exception as error:
                log_error(
                    "SSH connection failed",
                    error=str(error),
                    user=current_user.username,
                )
                emit('ssh_error', {'error': 'Connection failed'})
            finally:
                credentials.clear()
                local_password = None
                local_key_content = None
                local_bastion_password = None
                local_bastion_key_content = None

        try:
            lifecycle.start_job(
                'ssh_connect',
                connect_ssh,
                owner_id=current_user.id,
            )
        except Exception as error:
            credential_box.clear()
            log_warning(
                'SSH connection job rejected',
                user=current_user.username,
                error_type=type(error).__name__,
            )
            emit_error('Server is shutting down')

    except StorageCorruptionError as error:
        emit('ssh_error', _storage_error_payload(
            error,
            user_id=current_user.id,
            include_success=False,
            client_request_id=client_request_id,
        ))
    except Exception as e:
        log_error("SSH connection failed", error=str(e), user=current_user.username)
        emit('ssh_error', {'error': 'Connection failed'})
    finally:
        password = None
        key_content = None
        bastion_password = None
        bastion_key_content = None

@socketio.on('ssh_input')
@socket_login_required
def handle_ssh_input(data, current_user=None):
    """Handle user input to SSH session."""
    try:
        session_id = data.get('session_id')
        input_data = data.get('data')

        if not session_id or input_data is None:
            return

        if not verify_session_ownership(session_id, current_user.id):
            emit('ssh_error', {'error': 'Unauthorized access to session', 'session_id': session_id})
            return

        if not isinstance(input_data, str):
            return

        success, error = ssh_manager.send_ssh_input(session_id, input_data)
        if error:
            emit('ssh_error', {'error': error, 'session_id': session_id})

    except Exception as e:
        log_error("SSH input error", error=str(e))
        emit('ssh_error', {'error': 'Input error'})

@socketio.on('keep_alive')
@socket_login_required
def handle_keep_alive(data=None, current_user=None):
    """Keep sessions alive by updating last_activity timestamp."""
    try:
        import time
        with ssh_manager.sessions_lock:
            for sid, session in ssh_manager.sessions.items():
                if session.get('user_id') == current_user.id:
                    session['last_activity'] = time.time()
    except Exception as e:
        log_debug(f"Keep-alive error: {e}")

@socketio.on('ssh_resize')
@socket_login_required
def handle_ssh_resize(data, current_user=None):
    """Handle terminal resize."""
    session_id = None
    try:
        session_id = data.get('session_id')
        rows = data.get('rows')
        cols = data.get('cols')

        if not all([session_id, rows, cols]):
            return

        if not verify_session_ownership(session_id, current_user.id):
            return

        rows = max(1, min(int(rows), 500))
        cols = max(1, min(int(cols), 1000))

        success, error = ssh_manager.resize_terminal(session_id, rows, cols)
        if error:
            log_debug(f"Resize error: {error}", session_id=session_id)

    except Exception as e:
        log_debug(f"Resize exception: {e}", session_id=session_id)

@socketio.on('ssh_disconnect')
@socket_login_required
def handle_ssh_disconnect(data, current_user=None):
    """Handle SSH disconnection request."""
    try:
        session_id = data.get('session_id')
        if not session_id:
            return

        if not verify_session_ownership(session_id, current_user.id):
            emit('ssh_error', {'error': 'Unauthorized access to session'})
            return

        ssh_session = SSHSession.query.filter_by(session_id=session_id).first()
        host = ssh_session.host if ssh_session else 'unknown'
        port = ssh_session.port if ssh_session else 0
        if ssh_session:
            try:
                if ssh_session.is_persistent:
                    db.session.delete(ssh_session)
                else:
                    ssh_session.connected = False
                db.session.commit()
            except Exception as db_err:
                db.session.rollback()
                log_error("Failed to update SSH session in database",
                          error=str(db_err), session_id=session_id)

        success = ssh_manager.close_session(session_id, kill_tmux=True)
        if success:
            room = f'user_{current_user.id}'
            socketio.emit('ssh_disconnected', {
                'session_id': session_id,
                'reason': 'User requested disconnect'
            }, room=room)
            log_ssh_disconnect(current_user.username, host, port, request.remote_addr, reason='User requested')

    except Exception:
        emit('ssh_error', {'error': 'Disconnect failed'})

@socketio.on('list_profiles')
@socket_login_required
def handle_list_profiles(current_user=None):
    """Return list of saved connection profiles for this user."""
    try:
        profiles = []
        for stored_profile in profile_manager.load_profiles(current_user.id):
            profile = dict(stored_profile)
            if profile.get('auth_type') == 'tailscale':
                profile['tailscale_authorized'] = (
                    profile_is_authorized_for_launch(current_user, profile)
                )
            profiles.append(profile)
        emit('profiles_list', {'profiles': profiles})
    except StorageCorruptionError as error:
        return _emit_storage_error(error, current_user)
    except Exception as e:
        log_error("Failed to load profiles", error=str(e))
        emit('error', {'error': 'Failed to load profiles'})

@socketio.on('save_profile')
@socket_login_required
def handle_save_profile(data, current_user=None):
    """Create or update a connection profile without starting SSH."""
    try:
        data = data if isinstance(data, dict) else {}
        auth_type = data.get('auth_type')
        host = data.get('host')
        username = data.get('username')

        if auth_type == 'tailscale':
            access_error = validate_tailscale_ssh_access(current_user, host, username)
            if access_error:
                emit('error', {'error': access_error})
                return {'success': False, 'error': access_error}

        profile, error = profile_manager.upsert_profile(current_user.id, data)

        if error:
            emit('error', {'error': error})
            return {'success': False, 'error': error}
        else:
            payload = {'success': True, 'profile': profile}
            emit('profile_saved', payload)
            handle_list_profiles(current_user=current_user)
            return payload

    except StorageCorruptionError as error:
        return _emit_storage_error(error, current_user)
    except Exception as e:
        log_error("Failed to save profile", error=str(e))
        emit('error', {'error': 'Failed to save profile'})
        return {'success': False, 'error': 'Failed to save profile'}

@socketio.on('delete_profile')
@socket_login_required
def handle_delete_profile(data, current_user=None):
    """Delete a connection profile for this user."""
    try:
        profile_id = data.get('profile_id')
        if not profile_id:
            emit('error', {'error': 'Profile ID required'})
            return

        success, error = profile_manager.delete_profile(current_user.id, profile_id)
        if error:
            return _command_set_error(error)
        payload = {'success': True, 'profile_id': profile_id}
        emit('profile_deleted', payload)
        handle_list_profiles(current_user=current_user)
        return payload

    except StorageCorruptionError as storage_error:
        return _emit_storage_error(storage_error, current_user)
    except Exception as e:
        log_error("Failed to delete profile", error=str(e))
        return _command_set_error('Failed to delete profile')


@socketio.on('update_profile_organization')
@socket_login_required
def handle_update_profile_organization(data, current_user=None):
    """Update grouping metadata without resubmitting connection secrets."""
    try:
        data = data if isinstance(data, dict) else {}
        profile_id = data.get('profile_id')
        if not isinstance(profile_id, str) or not profile_id:
            return {'success': False, 'error': 'Profile ID required'}
        patch = {
            key: data[key]
            for key in ('group', 'favorite')
            if key in data
        }
        profile, error = profile_manager.update_profile_organization(
            current_user.id,
            profile_id,
            patch,
        )
        if error:
            return {'success': False, 'error': error}
        payload = {'success': True, 'profile': profile}
        emit('profile_organization_updated', payload)
        handle_list_profiles(current_user=current_user)
        return payload
    except StorageCorruptionError as error:
        return _emit_storage_error(error, current_user)
    except Exception as exc:
        log_error('Failed to update profile organization', error=str(exc))
        return {
            'success': False,
            'error': 'Failed to update profile organization',
        }


@socketio.on('move_profile')
@socket_login_required
def handle_move_profile(data, current_user=None):
    """Move one profile atomically within the user's flat group structure."""
    try:
        data = data if isinstance(data, dict) else {}
        profile_id = data.get('profile_id')
        if not isinstance(profile_id, str) or not profile_id:
            return {'success': False, 'error': 'Profile ID required'}

        source_group = data.get('expected_source_group')
        if not isinstance(source_group, str):
            return {'success': False, 'error': 'Invalid source group'}
        target_group = data.get('target_group')
        if not isinstance(target_group, str):
            return {'success': False, 'error': 'Invalid target group'}
        if len(source_group.strip()) > 64 or len(target_group.strip()) > 64:
            return {
                'success': False,
                'error': 'Group must not exceed 64 characters',
            }

        target_index = data.get('target_index')
        if type(target_index) is not int or target_index < 0:
            return {'success': False, 'error': 'Invalid target index'}
        confirmed = data.get('confirm_source_group_removal', False)
        if type(confirmed) is not bool:
            return {'success': False, 'error': 'Invalid confirmation value'}

        result, error = profile_manager.move_profile(
            current_user.id,
            profile_id,
            source_group,
            target_group,
            target_index,
            confirm_source_group_removal=confirmed,
        )
        if error:
            return {
                'success': False,
                'error': error,
                **(result or {}),
            }
        if result.get('requires_confirmation'):
            return {'success': False, **result}

        payload = {'success': True, **result}
        emit('profile_organization_updated', payload)
        handle_list_profiles(current_user=current_user)
        return payload
    except StorageCorruptionError as error:
        return _emit_storage_error(error, current_user)
    except Exception as exc:
        log_error('Failed to move profile', error=str(exc))
        return {'success': False, 'error': 'Failed to move profile'}

@socketio.on('list_jump_hosts')
@socket_login_required
def handle_list_jump_hosts(current_user=None):
    """Return list of saved jump hosts for this user."""
    try:
        emit('jump_hosts_list', {'jump_hosts': jump_host_manager.load_jump_hosts(current_user.id)})
    except StorageCorruptionError as error:
        return _emit_storage_error(error, current_user)
    except Exception as e:
        log_error("Failed to load jump hosts", error=str(e))
        emit('error', {'error': 'Failed to load jump hosts'})

@socketio.on('save_jump_host')
@socket_login_required
def handle_save_jump_host(data, current_user=None):
    """Save a new jump host (bastion) for this user. Never stores a password."""
    try:
        jump_host, error = jump_host_manager.add_jump_host(
            user_id=current_user.id,
            name=data.get('name'),
            host=data.get('host'),
            port=data.get('port', 22),
            username=data.get('username'),
            auth_type=data.get('auth_type'),
            key_id=data.get('key_id')
        )
        if error:
            emit('error', {'error': error})
        else:
            emit('jump_host_saved', {'jump_host': jump_host})
            handle_list_jump_hosts(current_user=current_user)
    except StorageCorruptionError as error:
        return _emit_storage_error(error, current_user)
    except Exception as e:
        log_error("Failed to save jump host", error=str(e))
        emit('error', {'error': 'Failed to save jump host'})

@socketio.on('delete_jump_host')
@socket_login_required
def handle_delete_jump_host(data, current_user=None):
    """Delete a jump host for this user."""
    try:
        jump_host_id = data.get('jump_host_id')
        if not jump_host_id:
            emit('error', {'error': 'Jump host ID required'})
            return
        success, error, usages = jump_host_manager.delete_jump_host(
            current_user.id, jump_host_id
        )
        if success:
            emit('jump_host_deleted', {'jump_host_id': jump_host_id})
            handle_list_jump_hosts(current_user=current_user)
            return {'success': True, 'jump_host_id': jump_host_id}
        else:
            return _command_set_error(error, usages)
    except StorageCorruptionError as error:
        return _emit_storage_error(error, current_user)
    except Exception as e:
        log_error("Failed to delete jump host", error=str(e))
        emit('error', {'error': 'Failed to delete jump host'})

@socketio.on('list_keys')
@socket_login_required
def handle_list_keys(current_user=None):
    """Return list of stored SSH keys for this user."""
    try:
        keys = key_manager.load_key_summaries(current_user.id)
        emit('keys_list', {'keys': keys})
    except StorageCorruptionError as error:
        return _emit_storage_error(error, current_user)
    except Exception as e:
        log_error("Failed to load keys", error=str(e))
        emit('error', {'error': 'Failed to load keys'})

@socketio.on('upload_key')
@socket_login_required
def handle_upload_key(data, current_user=None):
    """Store a new SSH private key for this user."""
    try:
        data = data if isinstance(data, dict) else {}
        name = data.get('name')
        key_content = data.get('key_content')

        if (not isinstance(name, str) or not name
                or not isinstance(key_content, str) or not key_content):
            return _key_mutation_error('Name and key content required')

        # SSH private keys are a few KB at most; reject oversized input outright
        # so a client cannot force large writes to disk.
        if len(name) > 128:
            return _key_mutation_error(
                'Key name too long (max 128 characters)'
            )
        if len(key_content) > 64 * 1024:
            return _key_mutation_error(
                'Key content too large (max 64KB)'
            )

        key_meta, error = key_manager.save_key(current_user.id, name, key_content)
        if error:
            log_key_upload(current_user.username, name, False, request.remote_addr)
            return _key_mutation_error(error)
        log_key_upload(current_user.username, name, True, request.remote_addr)
        emit('key_uploaded', {'key': key_meta})
        handle_list_keys(current_user=current_user)
        return {'success': True, 'key': key_meta}

    except StorageCorruptionError as error:
        return _emit_storage_error(error, current_user)
    except Exception:
        return _key_mutation_error('Failed to upload key')


@socketio.on('rename_key')
@socket_login_required
def handle_rename_key(data, current_user=None):
    """Rename one owned SSH key without exposing its encrypted contents."""
    try:
        data = data if isinstance(data, dict) else {}
        result, error = key_manager.rename_key(
            current_user.id,
            data.get('key_id'),
            data.get('name'),
        )
        if error:
            return _key_mutation_error(error)

        log_key_rename(
            current_user.username,
            result['before']['name'],
            result['key']['name'],
            request.remote_addr,
        )
        payload = {'success': True, 'key': result['key']}
        emit('key_renamed', payload)
        handle_list_keys(current_user=current_user)
        return payload
    except StorageCorruptionError as error:
        return _emit_storage_error(error, current_user)
    except Exception:
        return _key_mutation_error('Failed to rename key')


@socketio.on('replace_key')
@socket_login_required
def handle_replace_key(data, current_user=None):
    """Replace one owned SSH key without changing its stable identity."""
    try:
        data = data if isinstance(data, dict) else {}
        key_id = data.get('key_id')
        key_content = data.get('key_content')
        if (
            not isinstance(key_id, str)
            or not key_id
            or not isinstance(key_content, str)
            or not key_content
        ):
            return _key_mutation_error('Key ID and key content required')
        if len(key_content) > 64 * 1024:
            return _key_mutation_error(
                'Key content too large (max 64KB)'
            )

        key, error = key_manager.replace_key(
            current_user.id,
            key_id,
            key_content,
        )
        if error:
            log_key_replace(
                current_user.username,
                key_id,
                False,
                request.remote_addr,
            )
            return _key_mutation_error(error)

        log_key_replace(
            current_user.username,
            key['name'],
            True,
            request.remote_addr,
        )
        payload = {'success': True, 'key': key}
        emit('key_replaced', payload)
        handle_list_keys(current_user=current_user)
        return payload
    except StorageCorruptionError as error:
        return _emit_storage_error(error, current_user)
    except Exception:
        return _key_mutation_error('Failed to replace key')

@socketio.on('delete_key')
@socket_login_required
def handle_delete_key(data, current_user=None):
    """Delete an SSH key for this user."""
    try:
        key_id = data.get('key_id')
        if not key_id:
            emit('error', {'error': 'Key ID required'})
            return

        success = key_manager.delete_key(current_user.id, key_id)
        if success:
            log_key_delete(current_user.username, key_id, request.remote_addr)
            emit('key_deleted', {'key_id': key_id})
            handle_list_keys(current_user=current_user)
        else:
            emit('error', {'error': 'Failed to delete key'})

    except StorageCorruptionError as error:
        return _emit_storage_error(error, current_user)
    except Exception:
        emit('error', {'error': 'Failed to delete key'})

@socketio.on('probe_session_sftp')
@socket_login_required
def handle_probe_session_sftp(data, current_user=None):
    """Check whether an owned SSH session supports browsable SFTP."""
    session_id = data.get('session_id') if isinstance(data, dict) else None
    request_id = data.get('request_id') if isinstance(data, dict) else None
    valid_identifiers = (
        isinstance(session_id, str)
        and 0 < len(session_id) <= 128
        and isinstance(request_id, str)
        and 0 < len(request_id) <= 128
    )
    safe_session_id = session_id if valid_identifiers else ''
    safe_request_id = request_id if valid_identifiers else ''

    def emit_result(*, success, available=False):
        emit('session_sftp_capability', {
            'success': success,
            'session_id': safe_session_id,
            'request_id': safe_request_id,
            'available': available,
        })

    if not valid_identifiers:
        emit_result(success=False)
        return
    if check_socket_rate_limit(
            current_user.id,
            'session_sftp_capability',
            sftp_handler.CAPABILITY_RATE_LIMIT):
        emit_result(success=False)
        return
    if not verify_session_ownership(session_id, current_user.id):
        log_warning(
            'Unauthorized SFTP capability request',
            user_id=current_user.id,
            session_id=session_id,
        )
        emit_result(success=False)
        return

    try:
        available = sftp_handler.probe_sftp_capability(session_id)
    except Exception as exc:
        log_warning(
            'SFTP capability probe failed',
            session_id=session_id,
            error_type=type(exc).__name__,
        )
        emit_result(success=False)
        return

    if available is None:
        emit_result(success=False)
        return
    emit_result(success=True, available=available is True)


@socketio.on('list_directory')
@socket_login_required
def handle_list_directory(data, current_user=None):
    """List files in remote directory."""
    import time as _time
    _t0 = _time.time()
    try:
        payload = data if isinstance(data, dict) else {}
        identity = _file_request_identity(payload)
        source_id = identity.get('source_id')
        remote_path = payload.get('remote_path', '.')
        request_context = {
            'operation': 'list_directory',
            **identity,
            'path': remote_path,
        }

        if not _valid_file_request(identity):
            emit('error', {
                'error': 'Source ID and request ID required',
                **request_context,
            })
            return

        try:
            _t1 = _time.time()
            files, error = file_service.list_directory(
                source_id,
                user_id=current_user.id,
                path=remote_path,
            )
        except FileSourceUnavailable:
            log_warning(
                'File source unavailable for directory listing',
                user_id=current_user.id,
            )
            emit('error', _file_source_unavailable_payload(**request_context))
            return
        _t2 = _time.time()

        if error:
            log_warning("list_directory failed", path=remote_path, error=error,
                       auth_ms=int((_t1-_t0)*1000), sftp_ms=int((_t2-_t1)*1000))
            emit('error', {'error': f'Failed to list directory: {error}', **request_context})
        else:
            log_info("list_directory OK", path=remote_path, files=len(files),
                    auth_ms=int((_t1-_t0)*1000), sftp_ms=int((_t2-_t1)*1000))
            emit('directory_listing', {
                **identity,
                'path': remote_path,
                'files': files,
            })

    except Exception as e:
        log_error("list_directory exception", error=str(e), elapsed_ms=int((_time.time()-_t0)*1000))
        emit('error', {
            'error': 'Failed to list directory',
            'operation': 'list_directory',
            **_file_request_identity(payload),
            'path': payload.get('remote_path', '.'),
        })

@socketio.on('set_theme')
@socket_login_required
def handle_set_theme(data, current_user=None):
    """Persist theme selection for the current user."""
    try:
        theme = data.get('theme')
        valid_themes = [
            'glass', 'retro', 'solar', 'paper', 'noir',
            'arctic-ice', 'rose-gold', 'cyberpunk-neon', 'emerald-matrix', 'obsidian'
        ]
        if theme not in valid_themes:
            emit('error', {'error': 'Invalid theme'})
            return

        success = save_user_settings(current_user.id, {'theme': theme})
        if success:
            emit('theme_updated', {'theme': theme})
        else:
            emit('error', {'error': 'Failed to save theme'})
    except StorageCorruptionError as error:
        return _emit_storage_error(error, current_user)
    except Exception as e:
        log_error("Failed to save theme", error=str(e))
        emit('error', {'error': 'Failed to save theme'})


@socketio.on('set_confirm_session_close')
@socket_login_required
def handle_set_confirm_session_close(data, current_user=None):
    """Persist the explicit session-close confirmation preference."""
    try:
        enabled = data.get('enabled') if isinstance(data, dict) else None
        if not isinstance(enabled, bool):
            payload = {
                'success': False,
                'error': 'Invalid close confirmation setting',
            }
            emit('error', payload)
            return payload

        if not save_user_settings(
            current_user.id,
            {'confirm_session_close': enabled},
        ):
            payload = {
                'success': False,
                'error': 'Failed to save close confirmation setting',
            }
            emit('error', payload)
            return payload

        return {
            'success': True,
            'confirm_session_close': enabled,
        }
    except StorageCorruptionError as error:
        return _emit_storage_error(error, current_user)
    except Exception as error:
        log_error(
            "Failed to save close confirmation setting",
            error=str(error),
        )
        payload = {
            'success': False,
            'error': 'Failed to save close confirmation setting',
        }
        emit('error', payload)
        return payload


@socketio.on('set_disconnect_session_action')
@socket_login_required
def handle_set_disconnect_session_action(data, current_user=None):
    """Persist how the workspace handles a completed SSH connection."""
    try:
        action = data.get('action') if isinstance(data, dict) else None
        if action not in {'retry', 'close'}:
            payload = {
                'success': False,
                'error': 'Invalid disconnect session action',
            }
            emit('error', payload)
            return payload

        if not save_user_settings(
            current_user.id,
            {'disconnect_session_action': action},
        ):
            payload = {
                'success': False,
                'error': 'Failed to save disconnect session action',
            }
            emit('error', payload)
            return payload

        return {
            'success': True,
            'disconnect_session_action': action,
        }
    except StorageCorruptionError as error:
        return _emit_storage_error(error, current_user)
    except Exception as error:
        log_error(
            "Failed to save disconnect session action",
            error=str(error),
        )
        payload = {
            'success': False,
            'error': 'Failed to save disconnect session action',
        }
        emit('error', payload)
        return payload

@socketio.on('get_notepad')
@socket_login_required
def handle_get_notepad(current_user=None):
    """Return the persisted notepad for the current user."""
    try:
        settings = get_user_settings(current_user.id)
        emit('notepad_data', {'notepad': settings.get('notepad', '')})
    except StorageCorruptionError as error:
        return _emit_storage_error(error, current_user)
    except Exception as e:
        log_error("Failed to load notepad", error=str(e))
        emit('error', {'error': 'Failed to load notepad'})

@socketio.on('save_notepad')
@socket_login_required
def handle_save_notepad(data, current_user=None):
    """Persist the notepad text for the current user."""
    try:
        text = data.get('text', '')
        if not isinstance(text, str):
            payload = {
                'success': False,
                'error': 'Invalid notepad content',
            }
            emit('error', payload)
            return payload
        if len(text) > 100000:
            emit('error', {'error': 'Notepad content too large (max 100KB)'})
            return
        success = save_user_settings(current_user.id, {'notepad': text})
        if not success:
            emit('error', {'error': 'Failed to save notepad'})
    except StorageCorruptionError as error:
        return _emit_storage_error(error, current_user)
    except Exception as e:
        log_error("Failed to save notepad", error=str(e))
        emit('error', {'error': 'Failed to save notepad'})

@socketio.on('list_commands')
@socket_login_required
def handle_list_commands(data, current_user=None):
    """Return list of commands (system + user) filtered by OS."""
    try:
        from . import command_manager

        os_filter = data.get('os_filter')

        commands = command_manager.get_all_commands(current_user.id, os_filter)
        emit('commands_list', {'commands': commands})
    except StorageCorruptionError as error:
        return _emit_storage_error(error, current_user)
    except Exception as e:
        log_error("Failed to load commands", error=str(e))
        emit('error', {'error': 'Failed to load commands'})

@socketio.on('add_command')
@socket_login_required
def handle_add_command(data, current_user=None):
    """Add a new user command."""
    try:
        from . import command_manager

        name = data.get('name')
        command = data.get('command')
        parameters = data.get('parameters', '')
        description = data.get('description')
        os_list = data.get('os', ['all'])
        category = data.get('category', 'custom')

        if not all([name, command, description]):
            emit('error', {'error': 'Name, command, and description are required'})
            return

        if not command_manager.valid_user_command_input(
            name, command, parameters, description, os_list, category
        ):
            return _command_set_error('Invalid command data')

        new_cmd = command_manager.add_user_command(
            current_user.id, name, command, parameters, description, os_list, category
        )
        if not new_cmd:
            emit('error', {'error': 'Failed to add command'})
            return {'success': False, 'error': 'Failed to add command'}

        emit('command_added', {'command': new_cmd})
        handle_list_commands({}, current_user=current_user)
        return {'success': True, 'command': new_cmd}

    except StorageCorruptionError as error:
        return _emit_storage_error(error, current_user)
    except Exception as e:
        log_error("Failed to add command", error=str(e))
        emit('error', {'error': 'Failed to add command'})
        return {'success': False, 'error': 'Failed to add command'}

@socketio.on('update_command')
@socket_login_required
def handle_update_command(data, current_user=None):
    """Update an existing user command."""
    try:
        from . import command_manager

        command_id = data.get('command_id')
        name = data.get('name')
        command = data.get('command')
        parameters = data.get('parameters', '')
        description = data.get('description')
        os_list = data.get('os', ['all'])
        category = data.get('category', 'custom')

        if not all([command_id, name, command, description]):
            emit('error', {'error': 'Command ID, name, command, and description are required'})
            return

        if not command_manager.valid_user_command_input(
            name, command, parameters, description, os_list, category
        ):
            return _command_set_error('Invalid command data')

        updated, error = command_manager.update_user_command(
            current_user.id, command_id, name, command, parameters, description, os_list, category
        )

        if error:
            return _command_set_error(error)
        payload = {'success': True, 'command': updated}
        emit('command_updated', payload)
        handle_list_commands({}, current_user=current_user)
        return payload

    except StorageCorruptionError as storage_error:
        return _emit_storage_error(storage_error, current_user)
    except Exception as e:
        log_error("Failed to update command", error=str(e))
        return _command_set_error('Failed to update command')

@socketio.on('delete_command')
@socket_login_required
def handle_delete_command(data, current_user=None):
    """Delete a user command."""
    try:
        from . import command_manager

        command_id = data.get('command_id')
        if not command_id:
            emit('error', {'error': 'Command ID required'})
            return

        success, error, usages = command_manager.delete_user_command(current_user.id, command_id)
        if success:
            emit('command_deleted', {'command_id': command_id})
            handle_list_commands({}, current_user=current_user)
            return {'success': True, 'command_id': command_id}
        else:
            payload = {
                'success': False,
                'error': error or 'Failed to delete command',
                'code': (
                    'in_use' if usages
                    else 'not_found'
                    if error == 'Command not found'
                    else 'delete_failed'
                ),
            }
            if usages:
                payload['usages'] = usages
            emit('error', payload)
            return payload

    except StorageCorruptionError as storage_error:
        return _emit_storage_error(storage_error, current_user)
    except Exception as e:
        log_error("Failed to delete command", error=str(e))
        emit('error', {'error': 'Failed to delete command'})


def _command_set_error(error, usages=None):
    if usages:
        code = 'in_use'
    elif error in (
        'Command not found',
        'Command set not found',
        'Profile not found',
        'Jump host not found',
    ):
        code = 'not_found'
    elif error and 'unreadable' in error:
        code = 'storage_error'
    else:
        code = 'validation_error'
    payload = {'success': False, 'error': error, 'code': code}
    if usages:
        payload['usages'] = usages
    emit('error', payload)
    return payload


@socketio.on('list_command_sets')
@socket_login_required
def handle_list_command_sets(data=None, current_user=None):
    """Return all named command sets owned by the current user."""
    from . import command_set_manager

    try:
        command_sets, error = command_set_manager.load_command_sets_with_resolution(
            current_user.id
        )
    except StorageCorruptionError as storage_error:
        return _emit_storage_error(storage_error, current_user)
    if error:
        return _command_set_error(error)
    payload = {'success': True, 'command_sets': command_sets}
    emit('command_sets_list', payload)
    return payload


@socketio.on('save_command_set')
@socket_login_required
def handle_save_command_set(data, current_user=None):
    """Create or update a named command set."""
    from . import command_set_manager

    try:
        command_set, error = command_set_manager.upsert_command_set(
            current_user.id, data
        )
    except StorageCorruptionError as storage_error:
        return _emit_storage_error(storage_error, current_user)
    if error:
        return _command_set_error(error)
    payload = {'success': True, 'command_set': command_set}
    emit('command_set_saved', payload)
    handle_list_command_sets(current_user=current_user)
    return payload


@socketio.on('duplicate_command_set')
@socket_login_required
def handle_duplicate_command_set(data, current_user=None):
    """Duplicate one of the current user's command sets."""
    from . import command_set_manager

    data = data if isinstance(data, dict) else {}
    try:
        command_set, error = command_set_manager.duplicate_command_set(
            current_user.id, data.get('command_set_id')
        )
    except StorageCorruptionError as storage_error:
        return _emit_storage_error(storage_error, current_user)
    if error:
        return _command_set_error(error)
    payload = {'success': True, 'command_set': command_set}
    emit('command_set_saved', payload)
    handle_list_command_sets(current_user=current_user)
    return payload


@socketio.on('delete_command_set')
@socket_login_required
def handle_delete_command_set(data, current_user=None):
    """Delete an unused command set."""
    from . import command_set_manager

    data = data if isinstance(data, dict) else {}
    command_set_id = data.get('command_set_id')
    try:
        success, error, usages = command_set_manager.delete_command_set(
            current_user.id, command_set_id
        )
    except StorageCorruptionError as storage_error:
        return _emit_storage_error(storage_error, current_user)
    if not success:
        return _command_set_error(error, usages)
    payload = {'success': True, 'command_set_id': command_set_id}
    emit('command_set_deleted', payload)
    handle_list_command_sets(current_user=current_user)
    return payload


@socketio.on('convert_legacy_command_set')
@socket_login_required
def handle_convert_legacy_command_set(data, current_user=None):
    """Convert one profile's legacy startup text into a named command set."""
    from . import command_set_manager

    data = data if isinstance(data, dict) else {}
    try:
        profile = profile_manager.get_profile(
            current_user.id, data.get('profile_id')
        )
    except StorageCorruptionError as storage_error:
        return _emit_storage_error(storage_error, current_user)
    if not profile:
        return _command_set_error('Profile not found')
    if profile.get('command_set_id'):
        return _command_set_error('Profile already uses a command set')
    legacy_commands = profile.get('startup_commands')
    if not isinstance(legacy_commands, str) or not legacy_commands.strip():
        return _command_set_error('Profile has no legacy startup commands')

    try:
        command_set, error = command_set_manager.upsert_command_set(
            current_user.id,
            {
                'name': data.get('name'),
                'description': data.get('description', ''),
                'use_sudo': False,
                'steps': [{'type': 'inline', 'command': legacy_commands}],
            },
        )
    except StorageCorruptionError as storage_error:
        return _emit_storage_error(storage_error, current_user)
    if error:
        return _command_set_error(error)

    try:
        updated_profile, error = profile_manager.assign_command_set(
            current_user.id, profile['id'], command_set['id']
        )
    except StorageCorruptionError as storage_error:
        return _emit_storage_error(storage_error, current_user)
    if error:
        return _command_set_error(error)
    payload = {
        'success': True,
        'command_set': command_set,
        'profile': updated_profile,
    }
    emit('command_set_converted', payload)
    handle_list_command_sets(current_user=current_user)
    handle_list_profiles(current_user=current_user)
    return payload

@socketio.on('save_session_name')
@socket_login_required
def handle_save_session_name(data, current_user=None):
    """Save session display name to database."""
    try:
        session_id = data.get('session_id')
        display_name = data.get('display_name')
        if display_name:
            display_name = display_name.strip()[:128] or None
        if not session_id:
            return
        ssh_session = SSHSession.query.filter_by(
            session_id=session_id, user_id=current_user.id
        ).first()
        if ssh_session:
            ssh_session.display_name = display_name if display_name else None
            db.session.commit()
    except Exception as e:
        db.session.rollback()
        log_error("Failed to save session name", error=str(e))

def verify_session_ownership(session_id, user_id):
    """
    Verify that a session belongs to a user.

    Checks in-memory sessions first (fast path), then falls back to database.
    The DB query is done outside the lock to avoid blocking the SSH output reader.
    """
    try:
        source_id = make_source_id(FileSourceKind.SFTP_SESSION, session_id)
    except FileSourceUnavailable:
        return False
    return file_source_resolver.owns(source_id, user_id)


@socketio.on('request_session_insights')
@socket_login_required
def handle_request_session_insights(data, current_user=None):
    """Return one bounded Linux sample for an owned active SSH session."""
    session_id = data.get('session_id') if isinstance(data, dict) else None
    request_id = data.get('request_id') if isinstance(data, dict) else None

    valid_identifiers = (
        isinstance(session_id, str)
        and 0 < len(session_id) <= 128
        and isinstance(request_id, str)
        and 0 < len(request_id) <= 128
    )
    safe_session_id = session_id if valid_identifiers else ''
    safe_request_id = request_id if valid_identifiers else ''

    def emit_unavailable(reason=None):
        payload = {
            'success': False,
            'session_id': safe_session_id,
            'request_id': safe_request_id,
            'error': 'Session insights unavailable',
        }
        if reason in {'busy', 'transient', 'unsupported'}:
            payload['reason'] = reason
        emit('session_insights', payload)

    if not valid_identifiers:
        emit_unavailable()
        return

    if check_socket_rate_limit(
            current_user.id,
            'session_insights',
            session_insights.REQUEST_RATE_LIMIT):
        emit_unavailable()
        return

    if not verify_session_ownership(session_id, current_user.id):
        log_warning(
            'Unauthorized session insights request',
            user_id=current_user.id,
            session_id=session_id,
        )
        emit_unavailable()
        return

    try:
        include_diagnostics = data.get('include_diagnostics') is True
        stats, error = session_insights.collect_linux_stats(
            session_id,
            include_diagnostics=include_diagnostics,
        )
    except Exception as exc:
        log_warning(
            'Session insights collection failed',
            session_id=session_id,
            error_type=type(exc).__name__,
        )
        emit_unavailable('transient')
        return

    if error or stats is None:
        emit_unavailable(error)
        return

    emit('session_insights', {
        'success': True,
        'session_id': session_id,
        'request_id': request_id,
        'stats': stats,
    })


@socketio.on('request_session_runtime_inventory')
@socket_login_required
def handle_request_session_runtime_inventory(data, current_user=None):
    """Return one bounded runtime inventory for an owned SSH session."""
    session_id = data.get('session_id') if isinstance(data, dict) else None
    request_id = data.get('request_id') if isinstance(data, dict) else None
    valid_identifiers = (
        isinstance(session_id, str)
        and 0 < len(session_id) <= 128
        and isinstance(request_id, str)
        and 0 < len(request_id) <= 128
    )
    safe_session_id = session_id if valid_identifiers else ''
    safe_request_id = request_id if valid_identifiers else ''

    def emit_unavailable():
        emit('session_runtime_inventory', {
            'success': False,
            'session_id': safe_session_id,
            'request_id': safe_request_id,
            'error': 'Runtime inventory unavailable',
        })

    if not valid_identifiers:
        emit_unavailable()
        return
    if check_socket_rate_limit(
            current_user.id,
            'session_runtime_inventory',
            runtime_inventory.REQUEST_RATE_LIMIT):
        emit_unavailable()
        return
    if not verify_session_ownership(session_id, current_user.id):
        log_warning(
            'Unauthorized runtime inventory request',
            user_id=current_user.id,
            session_id=session_id,
        )
        emit_unavailable()
        return
    try:
        inventory, error = runtime_inventory.collect_runtime_inventory(session_id)
    except Exception as exc:
        log_warning(
            'Runtime inventory collection failed',
            session_id=session_id,
            error_type=type(exc).__name__,
        )
        emit_unavailable()
        return
    if error or inventory is None:
        emit_unavailable()
        return
    emit('session_runtime_inventory', {
        'success': True,
        'session_id': session_id,
        'request_id': request_id,
        'sampled_at': int(time.time()),
        **inventory,
    })


@socketio.on('prepare_transfer')
@socket_login_required
def handle_prepare_transfer(data, current_user=None):
    """Issue only metadata for a later bounded HTTP transfer."""
    payload = data if isinstance(data, dict) else {}
    identity = _file_request_identity(payload)
    try:
        if not _valid_file_request(identity):
            return {
                'success': False,
                'error': 'Transfer unavailable',
                **identity,
            }
        direction = payload.get('direction')
        remote_path = payload.get('remote_path')
        archive = bool(payload.get('archive'))
        conflict_policy = payload.get('conflict_policy', 'error')
        source_id = _file_request_source_id(payload, current_user.id)
        record = prepare_transfer(
            current_user.id, direction, source_id, remote_path,
            owner_sid=getattr(request, 'sid', None),
            archive=archive,
            conflict_policy=conflict_policy,
        )
        if record is None:
            return {
                'success': False,
                'error': 'Transfer unavailable',
                **identity,
            }
        if direction == 'upload':
            endpoint = 'transfers.upload_transfer'
        elif archive:
            endpoint = 'transfers.download_folder_transfer'
        else:
            endpoint = 'transfers.download_transfer'
        transfer_url = url_for(endpoint, token=record.token)
        application_root = getattr(config, 'APPLICATION_ROOT', '').rstrip('/')
        if application_root and not transfer_url.startswith(f'{application_root}/'):
            transfer_url = f'{application_root}{transfer_url}'
        return {
            'success': True,
            'transfer_id': record.transfer_id,
            'url': transfer_url,
            'expires_at': record.expires_at,
            'direction': direction,
            **identity,
        }
    except Exception as error:
        log_error('Transfer preparation failed', user_id=current_user.id,
                  exception_type=type(error).__name__)
        return {
            'success': False,
            'error': 'Transfer unavailable',
            **identity,
        }


@socketio.on('cancel_transfer')
@socket_login_required
def handle_cancel_transfer(data, current_user=None):
    """Cancel a prepared or streaming transfer owned by this user only."""
    transfer_id = data.get('transfer_id') if isinstance(data, dict) else None
    try:
        result = transfer_manager.cancel_with_result(
            transfer_id, current_user.id
        )
    except Exception as error:
        log_error('Transfer cancellation failed', user_id=current_user.id,
                  exception_type=type(error).__name__)
        return {'success': False, 'state': 'unavailable'}
    if result.accepted:
        socketio.emit('transfer_finished', {
            'transfer_id': transfer_id,
            'status': 'cancelled',
        }, room=f'user_{current_user.id}')
    return {
        'success': result.state != 'unavailable',
        'state': result.state,
    }

@socketio.on('download_file_binary')
@socket_login_required
def handle_download_file_binary(data, current_user=None):
    """Handle binary file download (no base64 encoding)."""
    try:
        payload = data if isinstance(data, dict) else {}
        identity = _file_request_identity(payload)
        remote_path = payload.get('remote_path')
        for_preview = payload.get('for_preview', False)
        context = {
            'operation': 'download_file_binary',
            **identity,
            'path': remote_path,
        }

        if (
            not _valid_file_request(identity)
            or not remote_path
            or not for_preview
        ):
            emit('error', {
                'error': 'Missing required fields for binary download',
                **context,
            })
            return

        try:
            source_id = _file_request_source_id(payload, current_user.id)
            source = file_service.resolve(
                source_id, current_user.id, FileCapability.PREVIEW
            )
            binary_data, error = file_service.read_binary_preview(
                source_id,
                user_id=current_user.id,
                path=remote_path,
                max_size=config.MAX_EDITOR_FILE_SIZE,
            )
        except FileSourceUnavailable:
            emit('error', _file_source_unavailable_payload(**context))
            return

        if error:
            _audit_file_source_operation(
                current_user,
                source,
                operation='binary_preview',
                result='FAILED',
                path=remote_path,
            )
            emit('error', {'error': f'Download failed: {error}', **context})
        else:
            import os
            import base64
            filename = os.path.basename(remote_path)

            encoded_data = base64.b64encode(binary_data).decode('ascii')
            emit('file_download_ready_binary', {
                **identity,
                'filename': filename,
                'file_data': encoded_data,
                'size': len(binary_data),
                'for_preview': True,
                'encoding': 'base64'
            })
            _audit_file_source_operation(
                current_user,
                source,
                operation='binary_preview',
                result='COMPLETED',
                path=remote_path,
                size=len(binary_data),
            )

    except Exception:
        emit('error', {
            'error': 'Download failed',
            'operation': 'download_file_binary',
            **_file_request_identity(payload),
            'path': payload.get('remote_path'),
        })

def _smb_share_error(action, error, request_id='', code=None):
    payload = {
        'action': action,
        'error': error,
        'request_id': request_id,
    }
    if code:
        payload['code'] = code
    emit('smb_share_error', payload)
    return {
        'success': False,
        'error': error,
        'request_id': request_id,
    }


def _emit_smb_shares_list(current_user):
    shares = smb_share_manager.load_smb_shares(current_user.id)
    payload = {'smb_shares': shares}
    emit('smb_shares_list', payload)
    return payload


@socketio.on('list_smb_shares')
@socket_login_required
def handle_list_smb_shares(_data=None, current_user=None):
    """Return saved SMB definitions without credentials."""
    if not config.SMB_ENABLED:
        return _smb_share_error(
            'list', 'SMB is disabled', code='SMB_DISABLED'
        )
    if check_socket_rate_limit(
        current_user.id,
        'smb_share_list',
        config.SMB_SHARE_LIST_RATELIMIT,
    ):
        return _smb_share_error(
            'list',
            'Too many saved SMB share requests',
            code='RATE_LIMITED',
        )
    try:
        return _emit_smb_shares_list(current_user)
    except StorageCorruptionError as error:
        return _emit_storage_error(error, current_user)
    except Exception as error:
        log_error(
            'Failed to load SMB shares',
            user_id=current_user.id,
            exception_type=type(error).__name__,
        )
        return _smb_share_error('list', 'Failed to load SMB shares')


@socketio.on('save_smb_share')
@socket_login_required
def handle_save_smb_share(data, current_user=None):
    """Create or update one non-secret SMB connection definition."""
    request_id = _smb_request_id(data)
    if not config.SMB_ENABLED:
        return _smb_share_error(
            'save',
            'SMB is disabled',
            request_id,
            code='SMB_DISABLED',
        )
    if not request_id:
        return _smb_share_error(
            'save', 'Valid request ID required', code='INVALID_REQUEST'
        )
    if check_socket_rate_limit(
        current_user.id,
        'smb_share_mutation',
        config.SMB_SHARE_MUTATION_RATELIMIT,
    ):
        return _smb_share_error(
            'save',
            'Too many saved SMB share changes',
            request_id,
            code='RATE_LIMITED',
        )
    try:
        share, error = smb_share_manager.upsert_smb_share(
            current_user.id,
            data if isinstance(data, dict) else {},
        )
        if error:
            return _smb_share_error('save', error, request_id)
        payload = {
            'success': True,
            'request_id': request_id,
            'share': share,
        }
        emit('smb_share_saved', payload)
        _emit_smb_shares_list(current_user)
        log_info(
            'SMB share definition saved',
            user_id=current_user.id,
            share_id=share['id'],
        )
        return payload
    except StorageCorruptionError as error:
        storage_error = _storage_error_payload(
            error, user_id=current_user.id
        )
        return _smb_share_error(
            'save', storage_error['error'], request_id, code='storage_error'
        )
    except Exception as error:
        log_error(
            'Failed to save SMB share',
            user_id=current_user.id,
            exception_type=type(error).__name__,
        )
        return _smb_share_error(
            'save', 'Failed to save SMB share', request_id
        )


@socketio.on('delete_smb_share')
@socket_login_required
def handle_delete_smb_share(data, current_user=None):
    """Delete one saved SMB definition owned by the current user."""
    payload = data if isinstance(data, dict) else {}
    request_id = _smb_request_id(payload)
    if not config.SMB_ENABLED:
        return _smb_share_error(
            'delete',
            'SMB is disabled',
            request_id,
            code='SMB_DISABLED',
        )
    if not request_id:
        return _smb_share_error(
            'delete', 'Valid request ID required', code='INVALID_REQUEST'
        )
    if check_socket_rate_limit(
        current_user.id,
        'smb_share_mutation',
        config.SMB_SHARE_MUTATION_RATELIMIT,
    ):
        return _smb_share_error(
            'delete',
            'Too many saved SMB share changes',
            request_id,
            code='RATE_LIMITED',
        )
    share_id = payload.get('share_id')
    if not isinstance(share_id, str) or not share_id:
        return _smb_share_error(
            'delete', 'SMB share ID required', request_id
        )
    try:
        success, error = smb_share_manager.delete_smb_share(
            current_user.id,
            share_id,
        )
        if error:
            return _smb_share_error('delete', error, request_id)
        result = {
            'success': success,
            'request_id': request_id,
            'share_id': share_id,
        }
        emit('smb_share_deleted', result)
        _emit_smb_shares_list(current_user)
        log_info(
            'SMB share definition deleted',
            user_id=current_user.id,
            share_id=share_id,
        )
        return result
    except StorageCorruptionError as error:
        storage_error = _storage_error_payload(
            error, user_id=current_user.id
        )
        return _smb_share_error(
            'delete', storage_error['error'], request_id, code='storage_error'
        )
    except Exception as error:
        log_error(
            'Failed to delete SMB share',
            user_id=current_user.id,
            exception_type=type(error).__name__,
        )
        return _smb_share_error(
            'delete', 'Failed to delete SMB share', request_id
        )


@socketio.on('smb_quick_connect')
@socket_login_required
def handle_smb_quick_connect(data, current_user=None):
    """Open one encrypted SMB 3.1.1 source for the current browser socket."""
    request_id = _smb_request_id(data)
    if not config.SMB_ENABLED:
        emit(
            'smb_quick_connect_error',
            {'request_id': request_id, 'code': 'SMB_DISABLED'},
        )
        return

    payload = data if isinstance(data, dict) else {}
    if not request_id:
        emit(
            'smb_quick_connect_error',
            {'request_id': '', 'code': 'INVALID_REQUEST'},
        )
        return
    if check_socket_rate_limit(
        current_user.id,
        'smb_connect',
        config.SMB_CONNECT_RATELIMIT,
    ):
        emit(
            'smb_quick_connect_error',
            {'request_id': request_id, 'code': 'RATE_LIMITED'},
        )
        return

    try:
        from .smb_paths import SMBShareName

        host = canonicalize_hostname(payload.get('host'))
        share = str(SMBShareName.parse(payload.get('share')))
        username = payload.get('username')
        password = payload.get('password')
        domain = payload.get('domain', '')
        if (
            not isinstance(username, str)
            or not username
            or len(username) > 256
            or any(ord(character) < 32 for character in username)
            or not isinstance(password, str)
            or not password
            or len(password) > 4096
            or any(ord(character) < 32 for character in password)
            or not isinstance(domain, str)
            or len(domain) > 255
            or any(ord(character) < 32 for character in domain)
        ):
            raise ValueError('Invalid SMB connection input')
    except (TypeError, ValueError):
        emit(
            'smb_quick_connect_error',
            {'request_id': request_id, 'code': 'INVALID_REQUEST'},
        )
        return

    lifecycle = current_app.extensions.get('runtime_lifecycle')
    if lifecycle is None or not lifecycle.accepting_work():
        password = None
        emit(
            'smb_quick_connect_error',
            {'request_id': request_id, 'code': 'RUNTIME_SHUTTING_DOWN'},
        )
        return

    database_user_id = current_user.id
    user_id = str(database_user_id)
    socket_sid = request.sid
    attempt_key = (user_id, socket_sid, request_id)
    attempt = {
        'cancel_event': threading.Event(),
        'handle': None,
    }
    with _smb_attempts_lock:
        if attempt_key in _smb_attempts:
            password = None
            emit(
                'smb_quick_connect_error',
                {'request_id': request_id, 'code': 'REQUEST_IN_PROGRESS'},
            )
            return
        _smb_attempts[attempt_key] = attempt

    app = current_app._get_current_object()
    pool = _smb_pool()
    credential_box = {'password': password}

    def connect_smb(lifecycle_cancel_event):
        local_password = credential_box.pop('password', None)
        cancellation = _CombinedCancellation(
            attempt['cancel_event'],
            lifecycle_cancel_event,
        )
        descriptor = None
        try:
            descriptor = pool.create_source(
                host=host,
                share=share,
                domain=domain,
                username=username,
                password=local_password,
                user_id=user_id,
                cancel_event=cancellation,
            )
            with app.app_context():
                socket_is_live = SocketSession.query.filter_by(
                    socket_sid=socket_sid,
                    user_id=database_user_id,
                ).first() is not None
            with _smb_attempts_lock:
                attempt_is_live = _smb_attempts.get(attempt_key) is attempt
            if (
                cancellation.is_set()
                or not attempt_is_live
                or not socket_is_live
            ):
                pool.request_close(descriptor.source_id, user_id)
                return
            socketio.emit(
                'smb_quick_connect_success',
                {
                    'request_id': request_id,
                    'file_source': descriptor.to_public_dict(),
                },
                room=socket_sid,
            )
            log_info(
                'SMB source connected',
                user_id=user_id,
                host=host,
                share=share,
            )
        except Exception as error:
            code = getattr(error, 'public_code', 'CONNECTION_FAILED')
            if code not in _SMB_CONNECT_CODES:
                code = 'CONNECTION_FAILED'
            diagnostic_id = _new_smb_diagnostic_id()
            diagnostic_fields = smb_diagnostic_log_fields(error)
            if not cancellation.is_set():
                socketio.emit(
                    'smb_quick_connect_error',
                    {
                        'request_id': request_id,
                        'code': code,
                        'diagnostic_id': diagnostic_id,
                    },
                    room=socket_sid,
                )
            log_warning(
                'SMB source connection failed',
                user_id=user_id,
                host=host,
                share=share,
                result_code=code,
                diagnostic_id=diagnostic_id,
                **diagnostic_fields,
                exception_type=type(error).__name__,
            )
        finally:
            local_password = None
            with _smb_attempts_lock:
                if _smb_attempts.get(attempt_key) is attempt:
                    _smb_attempts.pop(attempt_key, None)

    try:
        handle = lifecycle.start_job(
            'smb_quick_connect',
            connect_smb,
            owner_id=user_id,
        )
        attempt['handle'] = handle
        if attempt['cancel_event'].is_set():
            handle.cancel()
    except Exception as error:
        credential_box.clear()
        with _smb_attempts_lock:
            if _smb_attempts.get(attempt_key) is attempt:
                _smb_attempts.pop(attempt_key, None)
        emit(
            'smb_quick_connect_error',
            {'request_id': request_id, 'code': 'RUNTIME_SHUTTING_DOWN'},
        )
        log_warning(
            'SMB source job rejected',
            user_id=user_id,
            exception_type=type(error).__name__,
        )
    finally:
        password = None


@socketio.on('smb_quick_connect_cancel')
@socket_login_required
def handle_smb_quick_connect_cancel(data, current_user=None):
    """Cancel only the matching user's SMB attempt on this socket."""
    request_id = _smb_request_id(data)
    if not request_id:
        return
    attempt_key = (str(current_user.id), request.sid, request_id)
    with _smb_attempts_lock:
        attempt = _smb_attempts.get(attempt_key)
        if attempt is None:
            return
        attempt['cancel_event'].set()
        handle = attempt.get('handle')
    if handle is not None:
        handle.cancel()


@socketio.on('quick_connect')
@socket_login_required
def handle_quick_connect(data, current_user=None):
    """Create temporary SSH connection for file transfers without active session."""
    try:
        if not current_app.extensions[
            'runtime_lifecycle'
        ].accepting_work():
            emit(
                'quick_connect_error',
                {'error': 'Server is shutting down'},
            )
            return

        if check_socket_rate_limit(current_user.id, 'ssh_connect', config.RATELIMIT_SSH_CONNECT):
            log_warning("Quick connect rate limit hit", user=current_user.username)
            emit('quick_connect_error', {'error': 'Too many connection attempts. Please wait a moment.'})
            return

        password = data.get('password')
        key_id = data.get('key_id')

        host, port, username, error = _validate_ssh_params(
            data.get('host'), data.get('port', 22), data.get('username')
        )
        if error:
            emit('quick_connect_error', connection_error_payload(error))
            return

        if not password and not key_id:
            emit('quick_connect_error', {'error': 'Password or SSH key required'})
            return

        key_content = None
        if key_id:
            key_content, key_error = key_manager.read_key_content(current_user.id, key_id)
            if key_error:
                emit('quick_connect_error', {'error': f'SSH key error: {key_error}'})
                return

        connection_id, error = connection_pool.temp_connection_pool.create_connection(
            host=host,
            port=port,
            username=username,
            password=password,
            key_content=key_content,
            user_id=str(current_user.id)
        )

        if password:
            password = None
        if key_content:
            key_content = None

        if error:
            emit('quick_connect_error', connection_error_payload(error))
        else:
            emit('quick_connect_success', {
                'connection_id': connection_id,
                'host': host,
                'port': port,
                'username': username,
                'file_source': _public_file_source(
                    make_source_id(FileSourceKind.SFTP_QUICK, connection_id),
                    current_user.id,
                ),
            })
            log_info(f"Quick connection created: {connection_id}", user=current_user.username, host=host)

    except Exception as e:
        log_error("Quick connect failed", error=str(e))
        emit('quick_connect_error', {'error': 'Connection failed'})
    finally:
        password = None
        key_content = None

@socketio.on('quick_disconnect')
@socket_login_required
def handle_quick_disconnect(data, current_user=None):
    """Close a temporary connection."""
    try:
        connection_id = data.get('connection_id')

        if not connection_id:
            emit('error', {'error': 'Connection ID required'})
            return

        result = connection_pool.temp_connection_pool.request_close(
            connection_id,
            current_user.id,
        )
        if result == 'unavailable':
            emit('error', {'error': 'Unauthorized access to connection'})
            return

        if result in {'closed', 'deferred'}:
            emit('quick_disconnect_success', {'connection_id': connection_id})
        else:
            emit('error', {'error': 'Connection not found'})

    except Exception as e:
        log_error("Quick disconnect failed", error=str(e))
        emit('error', {'error': 'Disconnect failed'})


@socketio.on('file_source_disconnect')
@socket_login_required
def handle_file_source_disconnect(data, current_user=None):
    """Close an owned ephemeral source without revealing foreign sources."""
    payload = data if isinstance(data, dict) else {}
    source_id = payload.get('source_id')
    try:
        kind, handle_id = parse_source_id(source_id)
    except Exception:
        emit('error', _file_source_unavailable_payload(source_id=source_id))
        return

    if kind is FileSourceKind.SFTP_QUICK:
        result = connection_pool.temp_connection_pool.request_close(
            handle_id,
            current_user.id,
        )
    elif kind is FileSourceKind.SMB_QUICK:
        result = _smb_pool().request_close(source_id, current_user.id)
    else:
        result = 'unavailable'

    if result in {'closed', 'deferred'}:
        emit(
            'file_source_disconnect_success',
            {'source_id': source_id},
        )
        return
    emit('error', _file_source_unavailable_payload(source_id=source_id))

@socketio.on('create_directory')
@socket_login_required
def handle_create_directory(data, current_user=None):
    """Create a directory on remote server."""
    try:
        payload = data if isinstance(data, dict) else {}
        identity = _file_request_identity(payload)
        remote_path = payload.get('remote_path')
        context = {
            'operation': 'create_directory',
            **identity,
            'path': remote_path,
        }

        if not _valid_file_request(identity) or not remote_path:
            emit('error', {'error': 'Missing required fields', **context})
            return

        try:
            source_id = _file_request_source_id(payload, current_user.id)
            source = file_service.resolve(
                source_id, current_user.id, FileCapability.MKDIR
            )
            success, error = file_service.create_directory(
                source_id,
                user_id=current_user.id,
                path=remote_path,
            )
        except FileSourceUnavailable:
            emit('error', _file_source_unavailable_payload(**context))
            return

        if error:
            _audit_file_source_operation(
                current_user,
                source,
                operation='mkdir',
                result='FAILED',
                path=remote_path,
            )
            emit('error', {
                'error': f'Failed to create directory: {error}',
                **context,
            })
        else:
            _audit_file_source_operation(
                current_user,
                source,
                operation='mkdir',
                result='COMPLETED',
                path=remote_path,
            )
            emit('directory_created', {'path': remote_path, **identity})

    except Exception as e:
        log_error("Create directory failed", error=str(e))
        emit('error', {
            'error': 'Failed to create directory',
            'operation': 'create_directory',
            **_file_request_identity(payload),
            'path': payload.get('remote_path'),
        })

@socketio.on('rename_file')
@socket_login_required
def handle_rename_file(data, current_user=None):
    """Rename a file or directory on remote server."""
    payload = data if isinstance(data, dict) else {}
    identity = _file_request_identity(payload)
    old_path = payload.get('old_path')
    new_path = payload.get('new_path')
    response_context = {
        'operation': 'rename_file',
        **identity,
        'old_path': old_path,
        'new_path': new_path,
    }

    def reject(code, message):
        result = {
            'success': False,
            'code': code,
            'error': message,
            **response_context,
        }
        emit('error', {**result, 'path': old_path})
        return result

    try:
        if (
            not _valid_file_request(identity)
            or not old_path
            or not new_path
        ):
            return reject('INVALID_REQUEST', 'The move request is invalid.')

        try:
            source_id = _file_request_source_id(payload, current_user.id)
            source = file_service.resolve(
                source_id, current_user.id, FileCapability.RENAME
            )
            success, error = file_service.rename(
                source_id,
                user_id=current_user.id,
                old_path=old_path,
                new_path=new_path,
            )
        except FileSourceUnavailable:
            return reject(
                'SOURCE_UNAVAILABLE',
                'File source unavailable',
            )

        if error:
            _audit_file_source_operation(
                current_user,
                source,
                operation='rename',
                result='FAILED',
                path=old_path,
                destination=source,
                destination_path=new_path,
            )
            normalized = str(error or '').lower()
            if error == 'Invalid move request':
                code = 'INVALID_REQUEST'
                message = 'The move request is invalid.'
            elif error == 'Destination already exists' or any(
                marker in normalized for marker in ('conflict', 'already exists')
            ):
                code = 'CONFLICT'
                message = 'A file or folder already exists at the destination.'
            elif any(
                marker in normalized for marker in ('permission', 'access denied')
            ):
                code = 'PERMISSION_DENIED'
                message = 'Permission denied for this file operation.'
            elif 'not found' in normalized:
                code = 'NOT_FOUND'
                message = 'The requested file or folder was not found.'
            else:
                code = 'OPERATION_FAILED'
                message = 'The item could not be moved or renamed.'
            return reject(code, message)
        else:
            _audit_file_source_operation(
                current_user,
                source,
                operation='rename',
                result='COMPLETED',
                path=old_path,
                destination=source,
                destination_path=new_path,
            )
            emit('file_renamed', {
                'old_path': old_path,
                'new_path': new_path,
                **identity,
            })
            log_info('File source item renamed', user=current_user.username)
            return {
                'success': True,
                **identity,
                'old_path': old_path,
                'new_path': new_path,
            }

    except Exception as e:
        log_error('Rename failed', exception_type=type(e).__name__)
        return reject('OPERATION_FAILED', 'The item could not be moved or renamed.')

@socketio.on('delete_item')
@socket_login_required
def handle_delete_item(data, current_user=None):
    """Delete a file or directory (recursive) on remote server."""
    try:
        payload = data if isinstance(data, dict) else {}
        identity = _file_request_identity(payload)
        path = payload.get('path')
        context = {
            'operation': 'delete_item',
            **identity,
            'path': path,
        }

        if not _valid_file_request(identity) or not path:
            emit('error', {'error': 'Missing required fields', **context})
            return

        try:
            source_id = _file_request_source_id(payload, current_user.id)
            source = file_service.resolve(
                source_id, current_user.id, FileCapability.DELETE
            )
            success, error = file_service.delete(
                source_id,
                user_id=current_user.id,
                path=path,
            )
        except FileSourceUnavailable:
            emit('error', _file_source_unavailable_payload(**context))
            return

        if error:
            _audit_file_source_operation(
                current_user,
                source,
                operation='delete',
                result='FAILED',
                path=path,
            )
            emit('error', {'error': f'Failed to delete: {error}', **context})
        else:
            _audit_file_source_operation(
                current_user,
                source,
                operation='delete',
                result='COMPLETED',
                path=path,
            )
            emit('item_deleted', {'path': path, **identity})
            log_info(f"Deleted: {path}", user=current_user.username)

    except Exception as e:
        log_error("Delete failed", error=str(e))
        emit('error', {
            'error': 'Failed to delete',
            'operation': 'delete_item',
            **_file_request_identity(payload),
            'path': payload.get('path'),
        })

@socketio.on('get_home_directory')
@socket_login_required
def handle_get_home_directory(data, current_user=None):
    """Get the home directory of the SFTP session."""
    import time as _time
    _t0 = _time.time()
    try:
        payload = data if isinstance(data, dict) else {}
        identity = _file_request_identity(payload)
        request_context = {
            'operation': 'get_home_directory',
            **identity,
        }

        if not _valid_file_request(identity):
            emit('error', {
                'error': 'Source ID and request ID required',
                **request_context,
            })
            return

        try:
            source_id = _file_request_source_id(payload, current_user.id)
            _t1 = _time.time()
            home_path, error = file_service.get_home_directory(
                source_id,
                user_id=current_user.id,
            )
        except FileSourceUnavailable:
            emit('error', _file_source_unavailable_payload(**request_context))
            return
        _t2 = _time.time()

        if error:
            log_warning("get_home_directory failed", error=error,
                       auth_ms=int((_t1-_t0)*1000), sftp_ms=int((_t2-_t1)*1000))
            emit('error', {'error': f'Failed to get home directory: {error}', **request_context})
        else:
            log_info("get_home_directory OK", path=home_path,
                    auth_ms=int((_t1-_t0)*1000), sftp_ms=int((_t2-_t1)*1000))
            emit('home_directory', {
                **identity,
                'path': home_path,
            })

    except Exception as e:
        log_error("get_home_directory exception", error=str(e),
                 elapsed_ms=int((_time.time()-_t0)*1000))
        emit('error', {
            'error': 'Failed to get home directory',
            'operation': 'get_home_directory',
            **_file_request_identity(payload),
        })

@socketio.on('check_exists')
@socket_login_required
def handle_check_exists(data, current_user=None):
    """Check if a file or directory exists on remote server."""
    try:
        payload = data if isinstance(data, dict) else {}
        identity = _file_request_identity(payload)
        path = payload.get('path')
        context = {
            'operation': 'check_exists',
            **identity,
            'path': path,
        }

        if not _valid_file_request(identity) or not path:
            emit('error', {'error': 'Missing required fields', **context})
            return

        try:
            source_id = _file_request_source_id(payload, current_user.id)
            result, error = file_service.check_exists(
                source_id,
                user_id=current_user.id,
                path=path,
            )
        except FileSourceUnavailable:
            emit('error', _file_source_unavailable_payload(**context))
            return

        if error:
            emit('error', {'error': f'Failed to check: {error}', **context})
        else:
            emit('file_exists_result', {'path': path, **result, **identity})

    except Exception as e:
        log_error("Check exists failed", error=str(e))
        emit('error', {
            'error': 'Failed to check file',
            'operation': 'check_exists',
            **_file_request_identity(payload),
            'path': payload.get('path'),
        })

@socketio.on('get_file_stat')
@socket_login_required
def handle_get_file_stat(data, current_user=None):
    """Get detailed file statistics."""
    try:
        payload = data if isinstance(data, dict) else {}
        identity = _file_request_identity(payload)
        path = payload.get('path')
        context = {
            'operation': 'get_file_stat',
            **identity,
            'path': path,
        }

        if not _valid_file_request(identity) or not path:
            emit('error', {'error': 'Missing required fields', **context})
            return

        try:
            source_id = _file_request_source_id(payload, current_user.id)
            result, error = file_service.get_file_stat(
                source_id,
                user_id=current_user.id,
                path=path,
            )
        except FileSourceUnavailable:
            emit('error', _file_source_unavailable_payload(**context))
            return

        if error:
            emit('error', {
                'error': f'Failed to get file info: {error}',
                **context,
            })
        else:
            emit('file_stat_result', {**result, **identity})

    except Exception as e:
        log_error("Get file stat failed", error=str(e))
        emit('error', {
            'error': 'Failed to get file info',
            'operation': 'get_file_stat',
            **_file_request_identity(payload),
            'path': payload.get('path'),
        })

@socketio.on('preview_file')
@socket_login_required
def handle_preview_file(data, current_user=None):
    """
    Read file content for preview purposes.
    Supports text files, code files, and log files with tail mode.
    """
    try:
        payload = data if isinstance(data, dict) else {}
        identity = _file_request_identity(payload)
        path = payload.get('path')
        max_bytes = payload.get('max_bytes', 512000)
        offset = payload.get('offset', 0)
        tail_lines = payload.get('tail_lines')
        context = {
            'operation': 'preview_file',
            **identity,
            'path': path,
        }

        if not _valid_file_request(identity) or not path:
            emit('preview_error', {
                'error': 'Missing required fields',
                **context,
            })
            return

        try:
            max_bytes, offset, tail_lines = (
                file_service.normalize_preview_options(
                    max_bytes=max_bytes,
                    offset=offset,
                    tail_lines=tail_lines,
                )
            )
        except ValueError as exc:
            emit('preview_error', {
                'error': f'Invalid preview options: {exc}',
                **context,
            })
            return

        try:
            source_id = _file_request_source_id(payload, current_user.id)
            result, error = file_service.read_file_preview(
                source_id,
                user_id=current_user.id,
                path=path,
                max_bytes=max_bytes,
                offset=offset,
                tail_lines=tail_lines,
            )
        except FileSourceUnavailable:
            emit('preview_error', _file_source_unavailable_payload(
                **context,
            ))
            return

        if error:
            emit('preview_error', {
                'error': f'Failed to read file: {error}',
                **context,
            })
        else:
            import os
            result['filename'] = os.path.basename(path)
            result['path'] = path
            result.update(identity)
            emit('preview_data', result)

    except Exception as e:
        log_error("Preview failed", error=str(e))
        emit('preview_error', {
            'error': 'Preview failed',
            'operation': 'preview_file',
            **_file_request_identity(payload),
            'path': payload.get('path', ''),
        })

@socketio.on('open_file_for_edit')
@socket_login_required
def handle_open_file_for_edit(data, current_user=None):
    """Load a full text file for inline editing (no truncation, text only)."""
    try:
        payload = data if isinstance(data, dict) else {}
        identity = _file_request_identity(payload)
        path = payload.get('path')
        context = {
            'operation': 'open_file_for_edit',
            **identity,
            'path': path or '',
        }

        if not _valid_file_request(identity) or not path:
            emit('edit_error', {
                'error': 'Missing required fields',
                **context,
            })
            return

        try:
            source_id = _file_request_source_id(payload, current_user.id)
            result, error = file_service.read_file_for_edit(
                source_id,
                user_id=current_user.id,
                path=path,
            )
        except FileSourceUnavailable:
            emit('edit_error', _file_source_unavailable_payload(
                **context,
            ))
            return

        if error:
            emit('edit_error', {
                'error': f'Failed to open file: {error}',
                **context,
            })
        else:
            import os
            result['filename'] = os.path.basename(path)
            result['path'] = path
            result.update(identity)
            emit('edit_data', result)

    except Exception as e:
        log_error("Open for edit failed", error=str(e))
        emit('edit_error', {
            'error': 'Failed to open file for editing',
            'operation': 'open_file_for_edit',
            **_file_request_identity(payload),
            'path': payload.get('path', ''),
        })

@socketio.on('save_file')
@socket_login_required
def handle_save_file(data, current_user=None):
    """Save revision-bound editor content through its file source backend."""
    try:
        payload = data if isinstance(data, dict) else {}
        identity = _file_request_identity(payload)
        path = payload.get('path')
        content = payload.get('content')
        encoding = payload.get('encoding', 'utf-8')
        newline = payload.get('newline', 'lf')
        expected_revision = payload.get('expected_revision')
        replace_strategy = payload.get('replace_strategy', 'atomic')
        context = {
            'operation': 'save_file',
            **identity,
            'path': path,
        }

        if (
            not _valid_file_request(identity)
            or path is None
            or content is None
        ):
            emit('error', {
                'error': 'Missing required fields for save',
                **context,
            })
            return

        if replace_strategy not in {'atomic', 'recoverable_swap'}:
            emit('error', {
                'error': 'Invalid replacement strategy',
                'code': 'INVALID_REQUEST',
                **context,
            })
            return

        content_bytes = content.encode('utf-8', errors='ignore')
        max_size = config.MAX_EDITOR_FILE_SIZE
        if len(content_bytes) > max_size:
            max_mb = max_size // (1024 * 1024)
            emit('error', {
                'error': f'File too large to save. Maximum size: {max_mb}MB',
                **context,
            })
            return

        try:
            source_id = _file_request_source_id(payload, current_user.id)
            source = file_service.resolve(
                source_id, current_user.id, FileCapability.EDIT
            )
            outcome = file_service.write_file_text(
                source_id,
                user_id=current_user.id,
                path=path,
                content=content,
                encoding=encoding,
                newline=newline,
                expected_revision=expected_revision,
                replace_strategy=replace_strategy,
            )
        except FileSourceUnavailable:
            emit('error', _file_source_unavailable_payload(**context))
            return

        if not outcome.success:
            audit_result = {
                'SMB_RECOVERABLE_REPLACE_REQUIRED': (
                    'RECOVERABLE_REPLACE_REQUIRED'
                ),
                'SMB_RECOVERABLE_REPLACE_FAILED': (
                    'RECOVERABLE_REPLACE_FAILED_ROLLED_BACK'
                ),
                'SMB_RECOVERY_REQUIRED': 'RECOVERY_REQUIRED',
                'EDIT_CONFLICT': 'EDIT_CONFLICT',
            }.get(outcome.code, 'FAILED')
            _audit_file_source_operation(
                current_user,
                source,
                operation='edit_save',
                result=audit_result,
                path=path,
                size=len(content_bytes),
            )
            failure = {'error': outcome.error or 'Save failed', **context}
            if outcome.code:
                failure['code'] = outcome.code
            if outcome.revision:
                failure['revision'] = outcome.revision
            if outcome.recovery_leaves:
                failure['recovery_leaves'] = list(outcome.recovery_leaves)
            emit('error', failure)
            return

        audit_result = 'COMPLETED'
        if replace_strategy == 'recoverable_swap':
            audit_result = 'RECOVERABLE_REPLACE_COMPLETED'
        if outcome.warning_code:
            audit_result = 'COMPLETED_WITH_RECOVERY_BACKUP'
        _audit_file_source_operation(
            current_user,
            source,
            operation='edit_save',
            result=audit_result,
            path=path,
            size=len(content_bytes),
        )
        saved = {'path': path, **identity}
        if outcome.revision:
            saved['revision'] = outcome.revision
        if outcome.warning_code:
            saved['warning_code'] = outcome.warning_code
        if outcome.recovery_leaves:
            saved['recovery_leaves'] = list(outcome.recovery_leaves)
        emit('file_saved', saved)

    except Exception as e:
        log_error("Save failed", error=str(e))
        emit('error', {
            'error': 'Save failed',
            'operation': 'save_file',
            **_file_request_identity(payload),
            'path': payload.get('path'),
        })

@socketio.on('transfer_server_to_server')
@socket_login_required
def handle_transfer_server_to_server(data, current_user=None):
    """
    Handle server-to-server file transfer.
    Streams files directly between two SSH servers without local buffering.
    """
    try:
        payload = data if isinstance(data, dict) else {}
        identity = _file_request_identity(payload)
        source_id = identity.get('source_id')
        requested_source_path = payload.get('source_path')
        destination_source_id = payload.get('destination_source_id')
        requested_dest_path = payload.get('dest_path')
        is_dir = payload.get('is_dir', False)
        conflict_policy = payload.get('conflict_policy', 'error')
        transfer_id = None
        response_context = {
            **identity,
            'destination_source_id': destination_source_id,
        }

        if (
            not _valid_file_request(identity)
            or conflict_policy not in {'error', 'replace'}
            or not all([
                requested_source_path,
                destination_source_id,
                requested_dest_path,
            ])
        ):
            emit('s2s_transfer_error', {
                **response_context,
                'transfer_id': None,
                'error': 'Missing required fields'
            })
            return {
                'success': False,
                'error': 'Missing required fields',
                **response_context,
            }

        legacy_source_path = sftp_handler.sanitize_path(requested_source_path)
        legacy_dest_path = sftp_handler.sanitize_path(requested_dest_path)
        if legacy_source_path is None or legacy_dest_path is None:
            emit('s2s_transfer_error', {
                **response_context,
                'transfer_id': transfer_id,
                'error': 'Invalid path'
            })
            return {
                'success': False,
                'error': 'Invalid path',
                **response_context,
            }

        try:
            source = file_service.resolve(
                source_id,
                current_user.id,
                FileCapability.READ,
            )
            file_service.resolve(
                source_id,
                current_user.id,
                FileCapability.REMOTE_TRANSFER,
            )
        except FileSourceUnavailable:
            failure = classify_transfer_failure(
                FileSourceUnavailable(), operation='remote_transfer'
            )
            emit('s2s_transfer_error', {
                **response_context,
                'transfer_id': transfer_id,
                **failure.to_public_dict(),
            })
            return {
                'success': False,
                **failure.to_public_dict(),
                **response_context,
            }

        try:
            destination = file_service.resolve(
                destination_source_id,
                current_user.id,
                FileCapability.WRITE,
            )
            file_service.resolve(
                destination_source_id,
                current_user.id,
                FileCapability.REMOTE_TRANSFER,
            )
        except FileSourceUnavailable:
            failure = classify_transfer_failure(
                FileSourceUnavailable(), operation='remote_transfer'
            )
            emit('s2s_transfer_error', {
                **response_context,
                'transfer_id': transfer_id,
                **failure.to_public_dict(),
            })
            return {
                'success': False,
                **failure.to_public_dict(),
                **response_context,
            }

        try:
            source_audit_identity = file_source_audit_identity(source)
            destination_audit_identity = file_source_audit_identity(destination)
        except Exception as error:
            source_audit_identity = None
            destination_audit_identity = None
            log_error(
                'S2S audit identity unavailable',
                exception_type=type(error).__name__,
            )
        audit_username = current_user.username
        audit_ip = request.remote_addr

        def audit_s2s(result, size=0):
            if source_audit_identity is None:
                return
            try:
                log_file_source_operation(
                    username=audit_username,
                    operation='server_to_server_copy',
                    result=result,
                    filename=(
                        posixpath.basename(
                            str(requested_source_path).rstrip('/')
                        ) or '/'
                    ),
                    size=size,
                    ip_address=audit_ip,
                    destination_target_host=(
                        destination_audit_identity['target_host']
                    ),
                    destination_share=destination_audit_identity['share'],
                    destination_filename=(
                        posixpath.basename(
                            str(requested_dest_path).rstrip('/')
                        ) or '/'
                    ),
                    **source_audit_identity,
                )
            except Exception as error:
                log_error(
                    'S2S transfer audit failed',
                    result=result,
                    exception_type=type(error).__name__,
                )

        if hasattr(source, 'backend') and hasattr(destination, 'backend'):
            source_path = source.backend.normalize_path(requested_source_path)
            dest_path = destination.backend.normalize_path(requested_dest_path)
        else:
            source_path = legacy_source_path
            dest_path = legacy_dest_path
        if source_path is None or dest_path is None:
            emit('s2s_transfer_error', {
                **response_context,
                'transfer_id': transfer_id,
                'error': 'Invalid path',
            })
            return {
                'success': False,
                'error': 'Invalid path',
                **response_context,
            }

        user_id = current_user.id
        user_room = f'user_{user_id}'
        source_holds = file_source_resolver.acquire_transfer_holds(
            user_id,
            (source_id, destination_source_id),
        )
        try:
            background_reservation = quota_manager.reserve(
                QuotaKind.BACKGROUND_JOB, user_id
            )
        except Exception:
            source_holds.release()
            raise
        try:
            record = transfer_manager.create(
                user_id=user_id,
                source_id=source_id,
                source_ids=(source_id, destination_source_id),
                source_holds=source_holds,
                direction='server_to_server',
                owner_sid=getattr(request, 'sid', None),
                metadata={
                    'source_path': source_path,
                    'destination_source_id': destination_source_id,
                    'destination_path': dest_path,
                    'is_dir': bool(is_dir),
                    'conflict_policy': conflict_policy,
                },
            )
            transfer_manager.consume_token(record.token, user_id)
        except Exception:
            background_reservation.release()
            raise
        transfer_id = record.transfer_id

        lifecycle = current_app.extensions['runtime_lifecycle']

        def run_transfer(lifecycle_cancel_event):
            cancel_event = _CombinedCancellation(
                record.cancel_event, lifecycle_cancel_event
            )
            transferred = 0
            try:
                active_source = file_service.resolve(
                    source_id,
                    user_id,
                    FileCapability.READ,
                )
                file_service.resolve(
                    source_id,
                    user_id,
                    FileCapability.REMOTE_TRANSFER,
                )
                active_destination = file_service.resolve(
                    destination_source_id,
                    user_id,
                    FileCapability.WRITE,
                )
                file_service.resolve(
                    destination_source_id,
                    user_id,
                    FileCapability.REMOTE_TRANSFER,
                )
                if (
                    hasattr(active_source, 'backend')
                    and hasattr(active_destination, 'backend')
                ):
                    def report_progress(progress):
                        nonlocal transferred
                        transferred = progress['transferred']
                        total = max(
                            transferred,
                            progress.get('file_size', 0),
                        )
                        socketio.emit('s2s_transfer_progress', {
                            **response_context,
                            'transfer_id': transfer_id,
                            'filename': posixpath.basename(
                                progress['path'].rstrip('/')
                            ),
                            'transferred': transferred,
                            'total': total,
                            'percent': (
                                min(100, int(transferred * 100 / total))
                                if total else 0
                            ),
                            'status': 'transferring',
                        }, room=user_room)

                    transfer_result = copy_remote_entry(
                        active_source,
                        source_path,
                        active_destination,
                        dest_path,
                        conflict_policy=conflict_policy,
                        budget=TransferBudget(
                            max_bytes=config.MAX_ZIP_DOWNLOAD_SIZE,
                            max_members=config.MAX_TRANSFER_MEMBERS,
                        ),
                        cancel_event=cancel_event,
                        progress=report_progress,
                        chunk_size=config.CHUNK_SIZE,
                    )
                    transferred = transfer_result.bytes_transferred
                    success, error = True, None
                else:
                    success, error = sftp_handler.transfer_server_to_server(
                        source_session_id=active_source.handle_id,
                        source_path=source_path,
                        dest_session_id=active_destination.handle_id,
                        dest_path=dest_path,
                        transfer_id=transfer_id,
                        socketio_instance=socketio,
                        is_dir=is_dir,
                        user_room=user_room,
                        cancel_event=cancel_event,
                        max_bytes=config.MAX_ZIP_DOWNLOAD_SIZE,
                        chunk_size=config.CHUNK_SIZE,
                        event_context=response_context,
                        conflict_policy=conflict_policy,
                    )

                if success and _terminalize(
                    record, user_id, 'completed', manager=transfer_manager
                ):
                    audit_s2s('COMPLETED', transferred)
                    socketio.emit('s2s_transfer_complete', {
                        **response_context,
                        'transfer_id': transfer_id,
                        'filename': posixpath.basename(
                            source_path.rstrip('/')
                        ),
                        'source_path': source_path,
                        'dest_path': dest_path,
                    }, room=user_room)
                elif error:
                    internal_error = (
                        error
                        if isinstance(error, BaseException)
                        else RemoteTransferError('Transfer unavailable')
                    )
                    failure = classify_transfer_failure(
                        internal_error, operation='remote_transfer'
                    )
                    if not _terminalize(
                        record,
                        user_id,
                        'failed',
                        manager=transfer_manager,
                        failure=failure,
                    ):
                        return
                    audit_s2s(failure.code, transferred)
                    log_error(
                        'S2S transfer failed',
                        user_id=user_id,
                        transfer_id=transfer_id,
                        result_code=failure.code,
                        operation='remote_transfer',
                        exception_type=type(internal_error).__name__,
                    )
                    socketio.emit('s2s_transfer_error', {
                        **response_context,
                        'transfer_id': transfer_id,
                        **failure.to_public_dict(),
                    }, room=user_room)
            except RemoteTransferCancelled as error:
                failure = classify_transfer_failure(
                    error, operation='remote_transfer'
                )
                if _terminalize(
                    record,
                    user_id,
                    'cancelled',
                    manager=transfer_manager,
                    failure=failure,
                ):
                    audit_s2s(failure.code, transferred)
                    socketio.emit('s2s_transfer_error', {
                        **response_context,
                        'transfer_id': transfer_id,
                        **failure.to_public_dict(),
                    }, room=user_room)
            except Exception as error:
                failure = classify_transfer_failure(
                    error, operation='remote_transfer'
                )
                if _terminalize(
                    record,
                    user_id,
                    'failed',
                    manager=transfer_manager,
                    failure=failure,
                ):
                    audit_s2s(failure.code, transferred)
                    log_error(
                        'S2S transfer crashed',
                        user_id=user_id,
                        transfer_id=transfer_id,
                        result_code=failure.code,
                        operation='remote_transfer',
                        exception_type=type(error).__name__,
                    )
                    socketio.emit('s2s_transfer_error', {
                        **response_context,
                        'transfer_id': transfer_id,
                        **failure.to_public_dict(),
                    }, room=user_room)
            finally:
                try:
                    record.release_source_holds()
                finally:
                    background_reservation.release()

        try:
            lifecycle.start_job(
                'server_to_server_transfer', run_transfer, owner_id=user_id
            )
        except Exception as error:
            failure = classify_transfer_failure(
                error, operation='remote_transfer'
            )
            try:
                _terminalize(
                    record,
                    user_id,
                    'failed',
                    manager=transfer_manager,
                    failure=failure,
                )
            finally:
                try:
                    record.release_source_holds()
                finally:
                    background_reservation.release()
            raise

        log_info(
            'S2S transfer started',
            user_id=current_user.id,
            transfer_id=transfer_id,
        )
        return {
            'success': True,
            'transfer_id': transfer_id,
            **response_context,
        }

    except Exception as error:
        failure = classify_transfer_failure(
            error, operation='remote_transfer'
        )
        log_error(
            'S2S transfer setup failed',
            user_id=getattr(current_user, 'id', None),
            result_code=failure.code,
            operation='remote_transfer',
            exception_type=type(error).__name__,
        )
        emit('s2s_transfer_error', {
            **(
                response_context
                if 'response_context' in locals()
                else _file_request_identity(payload)
            ),
            'transfer_id': payload.get('transfer_id'),
            **failure.to_public_dict(),
        })
        return {
            'success': False,
            **failure.to_public_dict(),
            **(
                response_context
                if 'response_context' in locals()
                else _file_request_identity(payload)
            ),
        }
