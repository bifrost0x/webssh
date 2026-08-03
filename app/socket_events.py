from flask_socketio import emit, join_room, disconnect
from flask import request, current_app, url_for
from . import (socketio, ssh_manager, profile_manager, key_manager,
               sftp_handler, jump_host_manager, post_connect_manager)
from .decorators import socket_login_required
from .auth import register_socket_session, get_user_from_socket, check_socket_rate_limit
from .models import db, SSHSession, SocketSession
from .user_settings import save_user_settings, get_user_settings
from .audit_logger import (log_info, log_warning, log_error, log_debug,
                              log_ssh_connection, log_ssh_disconnect,
                              log_file_upload, log_file_download,
                              log_key_upload, log_key_rename, log_key_delete,
                              log_tailscale_ssh_usage)
from .tailscale_ssh import (
    profile_is_authorized_for_launch,
    validate_tailscale_ssh_access,
)
from .storage_errors import StorageCorruptionError
from .network_policy import canonicalize_hostname
from . import binary_transfer, connection_pool
from .transfer_routes import prepare_transfer, transfer_manager, _terminalize
from .quota_manager import QuotaKind, quota_manager
from .socket_capacity import socket_capacity
import posixpath
import re
import time
import config


STORAGE_ERROR_MESSAGE = (
    'Stored data is unreadable. Please restore or remove it.'
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
        log_warning(f"Unauthenticated connection attempt", sid=request.sid)
        emit('connected', {'status': 'unauthenticated'})
        disconnect()
        return False

    lifecycle = current_app.extensions.get('runtime_lifecycle')
    if lifecycle is None or not lifecycle.accepting_work():
        log_warning('Socket connection rejected during shutdown', sid=request.sid)
        emit('connected', {'status': 'unavailable'})
        return False

    from .models import User
    user = db.session.get(User, int(user_id))
    if not user or user.is_locked:
        log_warning(f"User not found during connect", user_id=user_id, sid=request.sid)
        emit('connected', {'status': 'unauthenticated'})
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
            buffered_output = ssh_manager.get_output_buffer(session_id)
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
                'buffered_output': buffered_output
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
            log_info(f"Persistent tmux session available for reconnect",
                     host=db_session.host, tmux_session=db_session.tmux_session_name)

@socketio.on('ssh_connect')
@socket_login_required
def handle_ssh_connect(data, current_user=None):
    """Handle SSH connection request with input validation."""
    password = None
    key_content = None
    bastion_password = None
    bastion_key_content = None
    client_request_id = None
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
            emit('ssh_error', {'error': message, 'client_request_id': client_request_id})

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

        session_id, error = ssh_manager.create_ssh_connection(
            host=host,
            port=int(port),
            username=username,
            password=password,
            key_content=key_content,
            socketio_instance=socketio,
            app=current_app._get_current_object(),
            user_id=current_user.id,
            proxy_jump_host=bastion_host,
            proxy_jump_port=bastion_port,
            proxy_jump_username=bastion_username,
            proxy_jump_password=bastion_password,
            proxy_jump_key_content=bastion_key_content,
            use_tmux=use_tmux,
            reconnect_tmux_name=reconnect_tmux_name,
            auth_type=auth_type,
            startup_commands='' if reconnect_tmux_name else startup_commands,
        )

        if password:
            password = None
        if key_content:
            key_content = None

        if error:
            emit_error(error)
        else:
            created_session = ssh_manager.get_session(session_id)
            if not created_session:
                log_error("SSH session disappeared after creation", session_id=session_id)
                emit_error("Connection failed")
                return
            created_tmux_name = created_session.get('tmux_session_name') if use_tmux else None

            display_name = data.get('display_name') if use_tmux else None
            if display_name:
                display_name = display_name.strip()[:128] or None
            try:
                # Clean up the specific old disconnected persistent session when
                # reconnecting to avoid ghost tabs on refresh.
                if use_tmux and reconnect_tmux_name:
                    old_session = SSHSession.query.filter_by(
                        user_id=current_user.id, host=host, port=port,
                        is_persistent=True, connected=False,
                        tmux_session_name=reconnect_tmux_name
                    ).first()
                    if old_session:
                        db.session.delete(old_session)
                        log_info(f"Cleaned up old persistent session",
                                user=current_user.username, host=host,
                                tmux_session=reconnect_tmux_name)

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
                    display_name=display_name if use_tmux else None
                )
                db.session.add(ssh_session)
                db.session.commit()
            except Exception as db_err:
                db.session.rollback()
                log_error(f"Failed to record SSH session in database",
                          error=str(db_err), session_id=session_id)

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
                'display_name': display_name
            })
            log_ssh_connection(current_user.username, host, port, True, request.remote_addr)

    except StorageCorruptionError as error:
        emit('ssh_error', _storage_error_payload(
            error,
            user_id=current_user.id,
            include_success=False,
            client_request_id=client_request_id,
        ))
    except Exception as e:
        log_error(f"SSH connection failed", error=str(e), user=current_user.username)
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
        log_error(f"SSH input error", error=str(e))
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
                log_error(f"Failed to update SSH session in database",
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
        existing = key_manager.get_key(current_user.id, data.get('key_id'))
        updated, error = key_manager.rename_key(
            current_user.id,
            data.get('key_id'),
            data.get('name'),
        )
        if error:
            return _key_mutation_error(error)
        if existing is None:
            return _key_mutation_error('Key not found')

        log_key_rename(
            current_user.username,
            existing['name'],
            updated['name'],
            request.remote_addr,
        )
        payload = {'success': True, 'key': updated}
        emit('key_renamed', payload)
        handle_list_keys(current_user=current_user)
        return payload
    except StorageCorruptionError as error:
        return _emit_storage_error(error, current_user)
    except Exception:
        return _key_mutation_error('Failed to rename key')

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

@socketio.on('list_directory')
@socket_login_required
def handle_list_directory(data, current_user=None):
    """List files in remote directory."""
    import time as _time
    _t0 = _time.time()
    try:
        session_id = data.get('session_id')
        remote_path = data.get('remote_path', '.')

        if not session_id:
            emit('error', {'error': 'Session ID required'})
            return

        authorized = False
        if verify_session_ownership(session_id, current_user.id):
            authorized = True
        else:
            conn_info = connection_pool.temp_connection_pool.get_connection_info(session_id)
            if conn_info and conn_info['user_id'] == str(current_user.id):
                authorized = True

        _t1 = _time.time()
        if not authorized:
            log_warning(f"list_directory unauthorized", session_id=session_id, user=current_user.username)
            emit('error', {'error': 'Unauthorized access to session'})
            return

        files, error = sftp_handler.list_directory(session_id, remote_path)
        _t2 = _time.time()

        if error:
            log_warning(f"list_directory failed", path=remote_path, error=error,
                       auth_ms=int((_t1-_t0)*1000), sftp_ms=int((_t2-_t1)*1000))
            emit('error', {'error': f'Failed to list directory: {error}'})
        else:
            log_info(f"list_directory OK", path=remote_path, files=len(files),
                    auth_ms=int((_t1-_t0)*1000), sftp_ms=int((_t2-_t1)*1000))
            emit('directory_listing', {
                'session_id': session_id,
                'path': remote_path,
                'files': files
            })

    except Exception as e:
        log_error(f"list_directory exception", error=str(e), elapsed_ms=int((_time.time()-_t0)*1000))
        emit('error', {'error': 'Failed to list directory'})

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
    if not session_id or not user_id:
        return False

    user_id_str = str(user_id)

    with ssh_manager.sessions_lock:
        session = ssh_manager.sessions.get(session_id)
        if session and session.get('user_id') is not None:
            return str(session.get('user_id')) == user_id_str

    ssh_session = SSHSession.query.filter_by(session_id=session_id).first()
    if ssh_session is not None:
        return str(ssh_session.user_id) == user_id_str

    return False


@socketio.on('prepare_transfer')
@socket_login_required
def handle_prepare_transfer(data, current_user=None):
    """Issue only metadata for a later bounded HTTP transfer."""
    try:
        direction = data.get('direction') if isinstance(data, dict) else None
        session_id = data.get('session_id') if isinstance(data, dict) else None
        remote_path = data.get('remote_path') if isinstance(data, dict) else None
        archive = bool(data.get('archive')) if isinstance(data, dict) else False
        record = prepare_transfer(
            current_user.id, direction, session_id, remote_path,
            owner_sid=getattr(request, 'sid', None),
            archive=archive,
        )
        if record is None:
            return {'success': False, 'error': 'Transfer unavailable'}
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
        }
    except Exception as error:
        log_error('Transfer preparation failed', user_id=current_user.id,
                  exception_type=type(error).__name__)
        return {'success': False, 'error': 'Transfer unavailable'}


@socketio.on('cancel_transfer')
@socket_login_required
def handle_cancel_transfer(data, current_user=None):
    """Cancel a prepared or streaming transfer owned by this user only."""
    transfer_id = data.get('transfer_id') if isinstance(data, dict) else None
    try:
        cancelled = transfer_manager.cancel(transfer_id, current_user.id)
    except Exception as error:
        log_error('Transfer cancellation failed', user_id=current_user.id,
                  exception_type=type(error).__name__)
        cancelled = False
    if cancelled:
        socketio.emit('transfer_finished', {
            'transfer_id': transfer_id,
            'status': 'cancelled',
        }, room=f'user_{current_user.id}')
    return {'success': bool(cancelled)}

@socketio.on('download_file_binary')
@socket_login_required
def handle_download_file_binary(data, current_user=None):
    """Handle binary file download (no base64 encoding)."""
    try:
        session_id = data.get('session_id')
        remote_path = data.get('remote_path')
        for_preview = data.get('for_preview', False)

        if not all([session_id, remote_path]) or not for_preview:
            emit('error', {'error': 'Missing required fields for binary download'})
            return

        if not verify_session_ownership(session_id, current_user.id):
            conn_info = connection_pool.temp_connection_pool.get_connection_info(session_id)
            if not conn_info or conn_info['user_id'] != str(current_user.id):
                emit('error', {'error': 'Unauthorized access to session/connection'})
                return

        binary_data, error = binary_transfer.handle_binary_download(
            session_id=session_id,
            remote_path=remote_path,
            socketio_instance=None,
            max_size=config.MAX_EDITOR_FILE_SIZE,
        )

        if error:
            emit('error', {'error': f'Download failed: {error}'})
        else:
            import os
            import base64
            filename = os.path.basename(remote_path)

            encoded_data = base64.b64encode(binary_data).decode('ascii')
            emit('file_download_ready_binary', {
                'session_id': session_id,
                'filename': filename,
                'file_data': encoded_data,
                'size': len(binary_data),
                'for_preview': True,
                'encoding': 'base64'
            })
            log_file_download(current_user.username, target_host='via-sftp', filename=filename,
                            size=len(binary_data), success=True, ip_address=request.remote_addr)

    except Exception:
        emit('error', {'error': 'Download failed'})

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
            emit('quick_connect_error', {'error': error})
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
            emit('quick_connect_error', {'error': error})
        else:
            emit('quick_connect_success', {
                'connection_id': connection_id,
                'host': host,
                'port': port,
                'username': username
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

        conn_info = connection_pool.temp_connection_pool.get_connection_info(connection_id)
        if not conn_info or conn_info['user_id'] != str(current_user.id):
            emit('error', {'error': 'Unauthorized access to connection'})
            return

        success = connection_pool.temp_connection_pool.close_connection(connection_id)

        if success:
            emit('quick_disconnect_success', {'connection_id': connection_id})
        else:
            emit('error', {'error': 'Connection not found'})

    except Exception as e:
        log_error("Quick disconnect failed", error=str(e))
        emit('error', {'error': 'Disconnect failed'})

@socketio.on('create_directory')
@socket_login_required
def handle_create_directory(data, current_user=None):
    """Create a directory on remote server."""
    try:
        session_id = data.get('session_id')
        remote_path = data.get('remote_path')

        if not all([session_id, remote_path]):
            emit('error', {'error': 'Missing required fields'})
            return

        if not verify_session_ownership(session_id, current_user.id):
            conn_info = connection_pool.temp_connection_pool.get_connection_info(session_id)
            if not conn_info or conn_info['user_id'] != str(current_user.id):
                emit('error', {'error': 'Unauthorized access'})
                return

        success, error = sftp_handler.create_directory(session_id, remote_path)

        if error:
            emit('error', {'error': f'Failed to create directory: {error}'})
        else:
            emit('directory_created', {'path': remote_path})

    except Exception as e:
        log_error("Create directory failed", error=str(e))
        emit('error', {'error': 'Failed to create directory'})

@socketio.on('rename_file')
@socket_login_required
def handle_rename_file(data, current_user=None):
    """Rename a file or directory on remote server."""
    try:
        session_id = data.get('session_id')
        old_path = data.get('old_path')
        new_path = data.get('new_path')

        if not all([session_id, old_path, new_path]):
            emit('error', {'error': 'Missing required fields'})
            return

        if not verify_session_ownership(session_id, current_user.id):
            conn_info = connection_pool.temp_connection_pool.get_connection_info(session_id)
            if not conn_info or conn_info['user_id'] != str(current_user.id):
                emit('error', {'error': 'Unauthorized access'})
                return

        success, error = sftp_handler.rename_item(session_id, old_path, new_path)

        if error:
            emit('error', {'error': f'Failed to rename: {error}'})
        else:
            emit('file_renamed', {'old_path': old_path, 'new_path': new_path})
            log_info(f"Renamed: {old_path} -> {new_path}", user=current_user.username)

    except Exception as e:
        log_error("Rename failed", error=str(e))
        emit('error', {'error': 'Failed to rename'})

@socketio.on('delete_item')
@socket_login_required
def handle_delete_item(data, current_user=None):
    """Delete a file or directory (recursive) on remote server."""
    try:
        session_id = data.get('session_id')
        path = data.get('path')

        if not all([session_id, path]):
            emit('error', {'error': 'Missing required fields'})
            return

        if not verify_session_ownership(session_id, current_user.id):
            conn_info = connection_pool.temp_connection_pool.get_connection_info(session_id)
            if not conn_info or conn_info['user_id'] != str(current_user.id):
                emit('error', {'error': 'Unauthorized access'})
                return

        success, error = sftp_handler.delete_directory_recursive(session_id, path)

        if error:
            emit('error', {'error': f'Failed to delete: {error}'})
        else:
            emit('item_deleted', {'path': path})
            log_info(f"Deleted: {path}", user=current_user.username)

    except Exception as e:
        log_error("Delete failed", error=str(e))
        emit('error', {'error': 'Failed to delete'})

@socketio.on('get_home_directory')
@socket_login_required
def handle_get_home_directory(data, current_user=None):
    """Get the home directory of the SFTP session."""
    import time as _time
    _t0 = _time.time()
    try:
        session_id = data.get('session_id')

        if not session_id:
            emit('error', {'error': 'Session ID required'})
            return

        if not verify_session_ownership(session_id, current_user.id):
            conn_info = connection_pool.temp_connection_pool.get_connection_info(session_id)
            if not conn_info or conn_info['user_id'] != str(current_user.id):
                emit('error', {'error': 'Unauthorized access'})
                return

        _t1 = _time.time()
        home_path, error = sftp_handler.get_home_directory(session_id)
        _t2 = _time.time()

        if error:
            log_warning(f"get_home_directory failed", error=error,
                       auth_ms=int((_t1-_t0)*1000), sftp_ms=int((_t2-_t1)*1000))
            emit('error', {'error': f'Failed to get home directory: {error}'})
        else:
            log_info(f"get_home_directory OK", path=home_path,
                    auth_ms=int((_t1-_t0)*1000), sftp_ms=int((_t2-_t1)*1000))
            emit('home_directory', {'session_id': session_id, 'path': home_path})

    except Exception as e:
        log_error(f"get_home_directory exception", error=str(e),
                 elapsed_ms=int((_time.time()-_t0)*1000))
        emit('error', {'error': 'Failed to get home directory'})

@socketio.on('check_exists')
@socket_login_required
def handle_check_exists(data, current_user=None):
    """Check if a file or directory exists on remote server."""
    try:
        session_id = data.get('session_id')
        path = data.get('path')

        if not all([session_id, path]):
            emit('error', {'error': 'Missing required fields'})
            return

        if not verify_session_ownership(session_id, current_user.id):
            conn_info = connection_pool.temp_connection_pool.get_connection_info(session_id)
            if not conn_info or conn_info['user_id'] != str(current_user.id):
                emit('error', {'error': 'Unauthorized access'})
                return

        result, error = sftp_handler.check_exists(session_id, path)

        if error:
            emit('error', {'error': f'Failed to check: {error}'})
        else:
            emit('file_exists_result', {'path': path, **result})

    except Exception as e:
        log_error("Check exists failed", error=str(e))
        emit('error', {'error': 'Failed to check file'})

@socketio.on('get_file_stat')
@socket_login_required
def handle_get_file_stat(data, current_user=None):
    """Get detailed file statistics."""
    try:
        session_id = data.get('session_id')
        path = data.get('path')

        if not all([session_id, path]):
            emit('error', {'error': 'Missing required fields'})
            return

        if not verify_session_ownership(session_id, current_user.id):
            conn_info = connection_pool.temp_connection_pool.get_connection_info(session_id)
            if not conn_info or conn_info['user_id'] != str(current_user.id):
                emit('error', {'error': 'Unauthorized access'})
                return

        result, error = sftp_handler.get_file_stat(session_id, path)

        if error:
            emit('error', {'error': f'Failed to get file info: {error}'})
        else:
            emit('file_stat_result', result)

    except Exception as e:
        log_error("Get file stat failed", error=str(e))
        emit('error', {'error': 'Failed to get file info'})

@socketio.on('preview_file')
@socket_login_required
def handle_preview_file(data, current_user=None):
    """
    Read file content for preview purposes.
    Supports text files, code files, and log files with tail mode.
    """
    try:
        session_id = data.get('session_id')
        path = data.get('path')
        max_bytes = data.get('max_bytes', 512000)
        offset = data.get('offset', 0)
        tail_lines = data.get('tail_lines')

        if not all([session_id, path]):
            emit('error', {'error': 'Missing required fields'})
            return

        try:
            max_bytes, offset, tail_lines = (
                sftp_handler.normalize_file_preview_options(
                    max_bytes=max_bytes,
                    offset=offset,
                    tail_lines=tail_lines,
                )
            )
        except ValueError as exc:
            emit('preview_error', {
                'error': f'Invalid preview options: {exc}',
                'path': path,
            })
            return

        if not verify_session_ownership(session_id, current_user.id):
            conn_info = connection_pool.temp_connection_pool.get_connection_info(session_id)
            if not conn_info or conn_info['user_id'] != str(current_user.id):
                emit('error', {'error': 'Unauthorized access'})
                return

        result, error = sftp_handler.read_file_preview(
            session_id=session_id,
            path=path,
            max_bytes=max_bytes,
            offset=offset,
            tail_lines=tail_lines
        )

        if error:
            emit('preview_error', {'error': f'Failed to read file: {error}', 'path': path})
        else:
            import os
            result['filename'] = os.path.basename(path)
            result['path'] = path
            emit('preview_data', result)

    except Exception as e:
        log_error("Preview failed", error=str(e))
        emit('preview_error', {'error': 'Preview failed', 'path': data.get('path', '')})

@socketio.on('open_file_for_edit')
@socket_login_required
def handle_open_file_for_edit(data, current_user=None):
    """Load a full text file for inline editing (no truncation, text only)."""
    try:
        session_id = data.get('session_id')
        path = data.get('path')

        if not all([session_id, path]):
            emit('edit_error', {'error': 'Missing required fields', 'path': path or ''})
            return

        if not verify_session_ownership(session_id, current_user.id):
            conn_info = connection_pool.temp_connection_pool.get_connection_info(session_id)
            if not conn_info or conn_info['user_id'] != str(current_user.id):
                emit('edit_error', {'error': 'Unauthorized access', 'path': path})
                return

        result, error = sftp_handler.read_file_for_edit(session_id=session_id, path=path)

        if error:
            emit('edit_error', {'error': f'Failed to open file: {error}', 'path': path})
        else:
            import os
            result['filename'] = os.path.basename(path)
            result['path'] = path
            emit('edit_data', result)

    except Exception as e:
        log_error("Open for edit failed", error=str(e))
        emit('edit_error', {'error': 'Failed to open file for editing', 'path': data.get('path', '')})

@socketio.on('save_file')
@socket_login_required
def handle_save_file(data, current_user=None):
    """Save edited text content back to a remote file via SFTP."""
    try:
        session_id = data.get('session_id')
        path = data.get('path')
        content = data.get('content')
        encoding = data.get('encoding', 'utf-8')
        newline = data.get('newline', 'lf')

        if session_id is None or path is None or content is None:
            emit('error', {'error': 'Missing required fields for save'})
            return

        content_bytes = content.encode('utf-8', errors='ignore')
        max_size = config.MAX_EDITOR_FILE_SIZE
        if len(content_bytes) > max_size:
            max_mb = max_size // (1024 * 1024)
            emit('error', {'error': f'File too large to save. Maximum size: {max_mb}MB'})
            return

        if not verify_session_ownership(session_id, current_user.id):
            conn_info = connection_pool.temp_connection_pool.get_connection_info(session_id)
            if not conn_info or conn_info['user_id'] != str(current_user.id):
                emit('error', {'error': 'Unauthorized access to session'})
                return

        success, error = sftp_handler.write_file_text(
            session_id=session_id,
            path=path,
            content_str=content,
            encoding=encoding,
            newline=newline
        )

        if error:
            emit('error', {'error': f'Save failed: {error}'})
        else:
            import os
            log_file_upload(current_user.username, target_host='via-sftp-edit',
                            filename=os.path.basename(path), size=len(content_bytes),
                            success=True, ip_address=request.remote_addr)
            emit('file_saved', {'path': path})

    except Exception as e:
        log_error("Save failed", error=str(e))
        emit('error', {'error': 'Save failed'})

@socketio.on('transfer_server_to_server')
@socket_login_required
def handle_transfer_server_to_server(data, current_user=None):
    """
    Handle server-to-server file transfer.
    Streams files directly between two SSH servers without local buffering.
    """
    try:
        source_session_id = data.get('source_session_id')
        source_path = data.get('source_path')
        dest_session_id = data.get('dest_session_id')
        dest_path = data.get('dest_path')
        is_dir = data.get('is_dir', False)
        transfer_id = None

        if not all([source_session_id, source_path, dest_session_id, dest_path]):
            emit('s2s_transfer_error', {
                'transfer_id': None,
                'error': 'Missing required fields'
            })
            return {'success': False, 'error': 'Transfer unavailable'}

        source_path = sftp_handler.sanitize_path(source_path)
        dest_path = sftp_handler.sanitize_path(dest_path)
        if source_path is None or dest_path is None:
            emit('s2s_transfer_error', {
                'transfer_id': transfer_id,
                'error': 'Invalid path'
            })
            return {'success': False, 'error': 'Transfer unavailable'}

        source_authorized = False
        if verify_session_ownership(source_session_id, current_user.id):
            source_authorized = True
        else:
            conn_info = connection_pool.temp_connection_pool.get_connection_info(source_session_id)
            if conn_info and conn_info['user_id'] == str(current_user.id):
                source_authorized = True

        if not source_authorized:
            emit('s2s_transfer_error', {
                'transfer_id': transfer_id,
                'error': 'Unauthorized access to source server'
            })
            return {'success': False, 'error': 'Transfer unavailable'}

        dest_authorized = False
        if verify_session_ownership(dest_session_id, current_user.id):
            dest_authorized = True
        else:
            conn_info = connection_pool.temp_connection_pool.get_connection_info(dest_session_id)
            if conn_info and conn_info['user_id'] == str(current_user.id):
                dest_authorized = True

        if not dest_authorized:
            emit('s2s_transfer_error', {
                'transfer_id': transfer_id,
                'error': 'Unauthorized access to destination server'
            })
            return {'success': False, 'error': 'Transfer unavailable'}

        user_id = current_user.id
        user_room = f'user_{user_id}'
        background_reservation = quota_manager.reserve(
            QuotaKind.BACKGROUND_JOB, user_id
        )
        try:
            record = transfer_manager.create(
                user_id=user_id,
                session_id=source_session_id,
                direction='server_to_server',
                owner_sid=getattr(request, 'sid', None),
                metadata={
                    'source_path': source_path,
                    'destination_session_id': dest_session_id,
                    'destination_path': dest_path,
                    'is_dir': bool(is_dir),
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
            try:
                success, error = sftp_handler.transfer_server_to_server(
                    source_session_id=source_session_id,
                    source_path=source_path,
                    dest_session_id=dest_session_id,
                    dest_path=dest_path,
                    transfer_id=transfer_id,
                    socketio_instance=socketio,
                    is_dir=is_dir,
                    user_room=user_room,
                    cancel_event=cancel_event,
                    max_bytes=config.MAX_ZIP_DOWNLOAD_SIZE,
                    chunk_size=config.CHUNK_SIZE,
                )

                if success and _terminalize(
                    record, user_id, 'completed', manager=transfer_manager
                ):
                    socketio.emit('s2s_transfer_complete', {
                        'transfer_id': transfer_id,
                        'filename': posixpath.basename(
                            source_path.rstrip('/')
                        ),
                        'source_path': source_path,
                        'dest_path': dest_path,
                    }, room=user_room)
                elif error and _terminalize(
                    record, user_id, 'failed', manager=transfer_manager
                ):
                    log_error(
                        'S2S transfer failed',
                        user_id=user_id,
                        transfer_id=transfer_id,
                        detail=str(error),
                    )
                    socketio.emit('s2s_transfer_error', {
                        'transfer_id': transfer_id,
                        'error': 'Transfer unavailable'
                    }, room=user_room)
            except Exception as error:
                if _terminalize(
                    record, user_id, 'failed', manager=transfer_manager
                ):
                    log_error(
                        'S2S transfer crashed',
                        user_id=user_id,
                        transfer_id=transfer_id,
                        exception_type=type(error).__name__,
                    )
                    socketio.emit('s2s_transfer_error', {
                        'transfer_id': transfer_id,
                        'error': 'Transfer unavailable'
                    }, room=user_room)
            finally:
                background_reservation.release()

        try:
            lifecycle.start_job(
                'server_to_server_transfer', run_transfer, owner_id=user_id
            )
        except Exception:
            try:
                _terminalize(
                    record, user_id, 'failed', manager=transfer_manager
                )
            finally:
                background_reservation.release()
            raise

        log_info(f"S2S transfer started: {source_path} -> {dest_path}", user=current_user.username)
        return {'success': True, 'transfer_id': transfer_id}

    except Exception as e:
        log_error("S2S transfer setup failed", error=str(e), user=current_user.username)
        emit('s2s_transfer_error', {
            'transfer_id': data.get('transfer_id') if isinstance(data, dict) else None,
            'error': 'Failed to start transfer'
        })
        return {'success': False, 'error': 'Transfer unavailable'}
