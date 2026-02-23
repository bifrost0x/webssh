from flask_socketio import emit, join_room, disconnect
from flask import request, current_app
from flask_login import current_user
from . import socketio, ssh_manager, profile_manager, key_manager, sftp_handler
from .decorators import socket_login_required
from .auth import register_socket_session, get_user_from_socket
from .models import db, SSHSession, SocketSession
from .user_settings import save_user_settings, get_user_settings
from .audit_logger import (log_info, log_warning, log_error, log_debug,
                              log_ssh_connection, log_ssh_disconnect,
                              log_file_upload, log_file_download,
                              log_key_upload, log_key_delete)
from . import binary_transfer, connection_pool
import base64
import os
import re
import ipaddress
import config

def _is_valid_host(host_str):
    """Validate host is a valid hostname or IP address."""
    try:
        ipaddress.ip_address(host_str)
        return True
    except ValueError:
        pass
    hostname_pattern = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    )
    return bool(hostname_pattern.match(host_str))

def _is_internal_address(host_str):
    """Check if host is a loopback or link-local address (SSRF protection).

    When BLOCK_INTERNAL_SSH is enabled, prevents SSH connections to
    loopback and link-local addresses to mitigate SSRF attacks.
    """
    try:
        addr = ipaddress.ip_address(host_str)
        return addr.is_loopback or addr.is_link_local
    except ValueError:
        return host_str.lower() in ('localhost', 'localhost.localdomain')

def _validate_ssh_params(host, port, username):
    """Validate SSH connection parameters. Returns (clean_host, clean_port, clean_username, error)."""
    host = (host or '').strip()
    if not host:
        return None, None, None, 'Host is required'
    if not _is_valid_host(host):
        return None, None, None, 'Invalid host format'

    if config.BLOCK_INTERNAL_SSH and _is_internal_address(host):
        log_warning(f"SECURITY: SSH to internal address blocked", host=host)
        return None, None, None, 'Connections to internal addresses are not allowed'

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

    return host, port, username, None

@socketio.on('connect')
def handle_connect():
    """Handle client connection - authenticate and restore sessions."""
    from flask import session as flask_session

    user_id = flask_session.get('_user_id')
    if not user_id:
        log_warning(f"Unauthenticated connection attempt", sid=request.sid)
        emit('connected', {'status': 'unauthenticated'})
        disconnect()
        return

    from .models import User
    user = User.query.get(int(user_id))
    if not user:
        log_warning(f"User not found during connect", user_id=user_id, sid=request.sid)
        emit('connected', {'status': 'unauthenticated'})
        disconnect()
        return

    socket_sid = request.sid
    user_agent = request.headers.get('User-Agent', '')
    register_socket_session(user.id, socket_sid, user_agent)

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
    user = get_user_from_socket(socket_sid)

    if user:
        log_info(f"Client disconnected: {user.username}", user=user.username, sid=socket_sid)

        SocketSession.query.filter_by(socket_sid=socket_sid).delete()
        db.session.commit()

        other_sessions = SocketSession.query.filter_by(user_id=user.id).count()

        if other_sessions == 0:
            closed = connection_pool.temp_connection_pool.close_all_user_connections(str(user.id))
            if closed > 0:
                log_info(f"Cleaned up {closed} Quick Connect connection(s) for {user.username}")
            log_debug(f"Last socket for {user.username} disconnected, SSH sessions preserved")

def restore_user_sessions(user_id):
    """Restore active SSH sessions when user reconnects."""
    db_sessions = SSHSession.query.filter_by(user_id=user_id, connected=True).all()

    room = f'user_{user_id}'

    for db_session in db_sessions:
        session_id = db_session.session_id

        session = ssh_manager.get_session(session_id)

        if session and session.get('connected'):
            emit('ssh_session_restored', {
                'session_id': session_id,
                'host': db_session.host,
                'port': db_session.port,
                'username': db_session.username
            }, room=room)
            log_info(f"Restored SSH session {session_id}", user_id=user_id, room=room)
        else:
            db_session.connected = False
            db.session.commit()
            log_debug(f"SSH session {session_id} no longer active, marked disconnected")

@socketio.on('ssh_connect')
@socket_login_required
def handle_ssh_connect(data, current_user=None):
    """Handle SSH connection request with input validation."""
    try:
        password = data.get('password')
        key_id = data.get('key_id')
        client_request_id = data.get('client_request_id')

        def emit_error(message):
            emit('ssh_error', {'error': message, 'client_request_id': client_request_id})

        host, port, username, error = _validate_ssh_params(
            data.get('host'), data.get('port', 22), data.get('username')
        )
        if error:
            emit_error(error)
            return

        if not password and not key_id:
            emit_error('Password or SSH key required')
            return

        key_content = None
        if key_id:
            key_content, key_error = key_manager.read_key_content(current_user.id, key_id)
            if key_error:
                emit_error(f'SSH key error: {key_error}')
                return

        session_id, error = ssh_manager.create_ssh_connection(
            host=host,
            port=int(port),
            username=username,
            password=password,
            key_content=key_content,
            socketio_instance=socketio,
            app=current_app._get_current_object(),
            user_id=current_user.id
        )

        if password:
            password = None
        if key_content:
            key_content = None

        if error:
            emit_error(error)
        else:
            try:
                ssh_session = SSHSession(
                    session_id=session_id,
                    user_id=current_user.id,
                    host=host,
                    port=port,
                    username=username
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
                'client_request_id': client_request_id
            })
            log_ssh_connection(current_user.username, host, port, True, request.remote_addr)

    except Exception as e:
        log_error(f"SSH connection failed", error=str(e), user=current_user.username)
        emit('ssh_error', {'error': 'Connection failed'})
    finally:
        password = None
        key_content = None

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
def handle_keep_alive(current_user=None):
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
                ssh_session.connected = False
                db.session.commit()
            except Exception as db_err:
                db.session.rollback()
                log_error(f"Failed to update SSH session in database",
                          error=str(db_err), session_id=session_id)

        success = ssh_manager.close_session(session_id)
        if success:
            room = f'user_{current_user.id}'
            socketio.emit('ssh_disconnected', {
                'session_id': session_id,
                'reason': 'User requested disconnect'
            }, room=room)
            log_ssh_disconnect(current_user.username, host, port, request.remote_addr, reason='User requested')

    except Exception as e:
        emit('ssh_error', {'error': 'Disconnect failed'})

@socketio.on('list_profiles')
@socket_login_required
def handle_list_profiles(current_user=None):
    """Return list of saved connection profiles for this user."""
    try:
        profiles = profile_manager.load_profiles(current_user.id)
        emit('profiles_list', {'profiles': profiles})
    except Exception as e:
        log_error("Failed to load profiles", error=str(e))
        emit('error', {'error': 'Failed to load profiles'})

@socketio.on('save_profile')
@socket_login_required
def handle_save_profile(data, current_user=None):
    """Save a new connection profile for this user."""
    try:
        name = data.get('name')
        host = data.get('host')
        port = data.get('port', 22)
        username = data.get('username')
        auth_type = data.get('auth_type')
        key_id = data.get('key_id')

        profile, error = profile_manager.add_profile(
            user_id=current_user.id,
            name=name,
            host=host,
            port=port,
            username=username,
            auth_type=auth_type,
            key_id=key_id
        )

        if error:
            emit('error', {'error': error})
        else:
            emit('profile_saved', {'profile': profile})
            handle_list_profiles(current_user=current_user)

    except Exception as e:
        log_error("Failed to save profile", error=str(e))
        emit('error', {'error': 'Failed to save profile'})

@socketio.on('delete_profile')
@socket_login_required
def handle_delete_profile(data, current_user=None):
    """Delete a connection profile for this user."""
    try:
        profile_id = data.get('profile_id')
        if not profile_id:
            emit('error', {'error': 'Profile ID required'})
            return

        success = profile_manager.delete_profile(current_user.id, profile_id)
        if success:
            emit('profile_deleted', {'profile_id': profile_id})
            handle_list_profiles(current_user=current_user)
        else:
            emit('error', {'error': 'Failed to delete profile'})

    except Exception as e:
        log_error("Failed to delete profile", error=str(e))
        emit('error', {'error': 'Failed to delete profile'})

@socketio.on('list_keys')
@socket_login_required
def handle_list_keys(current_user=None):
    """Return list of stored SSH keys for this user."""
    try:
        keys = key_manager.load_keys(current_user.id)
        emit('keys_list', {'keys': keys})
    except Exception as e:
        log_error("Failed to load keys", error=str(e))
        emit('error', {'error': 'Failed to load keys'})

@socketio.on('upload_key')
@socket_login_required
def handle_upload_key(data, current_user=None):
    """Store a new SSH private key for this user."""
    try:
        name = data.get('name')
        key_content = data.get('key_content')

        if not all([name, key_content]):
            emit('error', {'error': 'Name and key content required'})
            return

        key_meta, error = key_manager.save_key(current_user.id, name, key_content)
        if error:
            log_key_upload(current_user.username, name, False, request.remote_addr)
            emit('error', {'error': error})
        else:
            log_key_upload(current_user.username, name, True, request.remote_addr)
            emit('key_uploaded', {'key': key_meta})
            handle_list_keys(current_user=current_user)

    except Exception as e:
        emit('error', {'error': 'Failed to upload key'})

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

    except Exception as e:
        emit('error', {'error': 'Failed to delete key'})

@socketio.on('upload_file')
@socket_login_required
def handle_upload_file(data, current_user=None):
    """Handle file upload via SFTP."""
    try:
        session_id = data.get('session_id')
        filename = data.get('filename')
        file_data = data.get('file_data')
        remote_path = data.get('remote_path')

        if not all([session_id, filename, file_data, remote_path]):
            emit('error', {'error': 'Missing required fields for file upload'})
            return

        max_size = config.MAX_UPLOAD_SIZE
        estimated_size = len(file_data) * 0.75 if file_data else 0
        if estimated_size > max_size:
            max_mb = max_size // (1024 * 1024)
            emit('error', {'error': f'File too large. Maximum size: {max_mb}MB'})
            return

        if not verify_session_ownership(session_id, current_user.id):
            conn_info = connection_pool.temp_connection_pool.get_connection_info(session_id)
            if not conn_info or conn_info['user_id'] != str(current_user.id):
                emit('error', {'error': 'Unauthorized access to session'})
                return

        file_bytes = base64.b64decode(file_data)

        chunk_size = 65536
        chunks = [file_bytes[i:i+chunk_size] for i in range(0, len(file_bytes), chunk_size)]

        success, error = sftp_handler.upload_file_chunked(
            session_id=session_id,
            filename=filename,
            chunks=chunks,
            remote_path=remote_path,
            socketio_instance=socketio
        )

        if error:
            emit('error', {'error': f'Upload failed: {error}'})
        else:
            log_file_upload(current_user.username, target_host='via-sftp', filename=filename,
                          size=len(file_bytes), success=True, ip_address=request.remote_addr)

    except Exception as e:
        emit('error', {'error': 'Upload failed'})

@socketio.on('download_file')
@socket_login_required
def handle_download_file(data, current_user=None):
    """Handle file download via SFTP."""
    try:
        session_id = data.get('session_id')
        remote_path = data.get('remote_path')

        if not all([session_id, remote_path]):
            emit('error', {'error': 'Missing required fields for file download'})
            return

        if not verify_session_ownership(session_id, current_user.id):
            conn_info = connection_pool.temp_connection_pool.get_connection_info(session_id)
            if not conn_info or conn_info['user_id'] != str(current_user.id):
                emit('error', {'error': 'Unauthorized access to session'})
                return

        result, error = sftp_handler.download_file_chunked(
            session_id=session_id,
            remote_path=remote_path,
            socketio_instance=socketio
        )

        if error:
            emit('error', {'error': f'Download failed: {error}'})
        else:
            file_bytes = b''.join(result['chunks'])
            file_data = base64.b64encode(file_bytes).decode('utf-8')

            emit('file_download_ready', {
                'filename': result['filename'],
                'file_data': file_data,
                'size': result['size']
            })
            log_file_download(current_user.username, target_host='via-sftp', filename=result['filename'],
                            size=result['size'], success=True, ip_address=request.remote_addr)

    except Exception as e:
        emit('error', {'error': 'Download failed'})

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

@socketio.on('get_sessions')
@socket_login_required
def handle_get_sessions(current_user=None):
    """Get list of active SSH sessions for this user."""
    try:
        db_sessions = SSHSession.query.filter_by(user_id=current_user.id, connected=True).all()

        sessions = []
        for db_session in db_sessions:
            session = ssh_manager.get_session(db_session.session_id)
            if session and session.get('connected'):
                sessions.append({
                    'session_id': db_session.session_id,
                    'host': db_session.host,
                    'port': db_session.port,
                    'username': db_session.username
                })

        emit('sessions_list', {'sessions': sessions})
    except Exception as e:
        log_error("Failed to get sessions", error=str(e))
        emit('error', {'error': 'Failed to get sessions'})

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
    except Exception as e:
        log_error("Failed to load notepad", error=str(e))
        emit('error', {'error': 'Failed to load notepad'})

@socketio.on('save_notepad')
@socket_login_required
def handle_save_notepad(data, current_user=None):
    """Persist the notepad text for the current user."""
    try:
        text = data.get('text', '')
        if len(text) > 100000:
            emit('error', {'error': 'Notepad content too large (max 100KB)'})
            return
        success = save_user_settings(current_user.id, {'notepad': text})
        if not success:
            emit('error', {'error': 'Failed to save notepad'})
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

        new_cmd = command_manager.add_user_command(
            current_user.id, name, command, parameters, description, os_list, category
        )

        emit('command_added', {'command': new_cmd})
        handle_list_commands({}, current_user=current_user)

    except Exception as e:
        log_error("Failed to add command", error=str(e))
        emit('error', {'error': 'Failed to add command'})

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

        success = command_manager.update_user_command(
            current_user.id, command_id, name, command, parameters, description, os_list, category
        )

        if success:
            emit('command_updated', {'command_id': command_id})
            handle_list_commands({}, current_user=current_user)
        else:
            emit('error', {'error': 'Failed to update command'})

    except Exception as e:
        log_error("Failed to update command", error=str(e))
        emit('error', {'error': 'Failed to update command'})

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

        success = command_manager.delete_user_command(current_user.id, command_id)
        if success:
            emit('command_deleted', {'command_id': command_id})
            handle_list_commands({}, current_user=current_user)
        else:
            emit('error', {'error': 'Failed to delete command'})

    except Exception as e:
        log_error("Failed to delete command", error=str(e))
        emit('error', {'error': 'Failed to delete command'})

@socketio.on('detect_os')
@socket_login_required
def handle_detect_os(data, current_user=None):
    """OS detection disabled to avoid terminal noise."""
    emit('error', {'error': 'OS detection is disabled'})

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

@socketio.on('upload_file_binary')
@socket_login_required
def handle_upload_file_binary(data, current_user=None):
    """Handle binary file upload (no base64 encoding)."""
    try:
        session_id = data.get('session_id')
        filename = data.get('filename')
        file_data = data.get('file_data')
        remote_path = data.get('remote_path')

        if not all([session_id, filename, file_data, remote_path]):
            emit('error', {'error': 'Missing required fields for binary upload'})
            return

        if not verify_session_ownership(session_id, current_user.id):
            conn_info = connection_pool.temp_connection_pool.get_connection_info(session_id)
            if not conn_info or conn_info['user_id'] != str(current_user.id):
                emit('error', {'error': 'Unauthorized access to session/connection'})
                return

        success, error = binary_transfer.handle_binary_upload(
            session_id=session_id,
            filename=filename,
            binary_data=file_data,
            remote_path=remote_path,
            socketio_instance=socketio
        )

        if error:
            emit('error', {'error': f'Upload failed: {error}'})
        else:
            log_file_upload(current_user.username, target_host='via-sftp', filename=filename,
                          size=len(file_data), success=True, ip_address=request.remote_addr)

    except Exception as e:
        emit('error', {'error': 'Upload failed'})

@socketio.on('download_file_binary')
@socket_login_required
def handle_download_file_binary(data, current_user=None):
    """Handle binary file download (no base64 encoding)."""
    try:
        session_id = data.get('session_id')
        remote_path = data.get('remote_path')
        for_preview = data.get('for_preview', False)

        if not all([session_id, remote_path]):
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
            socketio_instance=socketio
        )

        if error:
            emit('error', {'error': f'Download failed: {error}'})
        else:
            import os
            import base64
            filename = os.path.basename(remote_path)

            if for_preview:
                encoded_data = base64.b64encode(binary_data).decode('ascii')
                emit('file_download_ready_binary', {
                    'session_id': session_id,
                    'filename': filename,
                    'file_data': encoded_data,
                    'size': len(binary_data),
                    'for_preview': True,
                    'encoding': 'base64'
                })
            else:
                emit('file_download_ready_binary', {
                    'session_id': session_id,
                    'filename': filename,
                    'file_data': binary_data,
                    'size': len(binary_data),
                    'for_preview': False
                })
            log_file_download(current_user.username, target_host='via-sftp', filename=filename,
                            size=len(binary_data), success=True, ip_address=request.remote_addr)

    except Exception as e:
        emit('error', {'error': 'Download failed'})

@socketio.on('download_folder_binary')
@socket_login_required
def handle_download_folder_binary(data, current_user=None):
    """Handle folder download as ZIP archive."""
    try:
        import zipfile
        import tempfile
        import os

        session_id = data.get('session_id')
        remote_path = data.get('remote_path')

        if not all([session_id, remote_path]):
            emit('error', {'error': 'Missing required fields for folder download'})
            return

        if not verify_session_ownership(session_id, current_user.id):
            conn_info = connection_pool.temp_connection_pool.get_connection_info(session_id)
            if not conn_info or conn_info['user_id'] != str(current_user.id):
                emit('error', {'error': 'Unauthorized access to session/connection'})
                return

        _sftp_lock = sftp_handler._get_sftp_lock(session_id)
        _sftp_lock.acquire()
        try:
            sftp, error, source_type = sftp_handler.get_any_sftp_client(session_id)
        except Exception as e:
            _sftp_lock.release()
            log_error("SFTP client error", error=str(e))
            emit('error', {'error': 'SFTP operation failed'})
            return
        if error:
            _sftp_lock.release()
            emit('error', {'error': error})
            return

        safe_path = sftp_handler.sanitize_path(remote_path)
        if safe_path is None:
            _sftp_lock.release()
            emit('error', {'error': 'Invalid remote path'})
            return

        try:
            file_stat = sftp.stat(safe_path)
            import stat
            if not stat.S_ISDIR(file_stat.st_mode):
                _sftp_lock.release()
                emit('error', {'error': 'Path is not a directory'})
                return
        except FileNotFoundError:
            _sftp_lock.release()
            emit('error', {'error': 'Remote directory not found'})
            return

        folder_name = os.path.basename(safe_path.rstrip('/'))

        def is_safe_for_shell(path):
            """Validate path is safe for shell command use (defense in depth)."""
            if not path:
                return False
            dangerous_chars = ['\n', '\r', '\x00', '`', '$', '|', ';', '&']
            return not any(c in path for c in dangerous_chars)

        remote_zip_path = f"/tmp/{folder_name}_{os.urandom(8).hex()}.zip"

        try:
            ssh_client = sftp._client if hasattr(sftp, '_client') else None
            if ssh_client and is_safe_for_shell(safe_path):
                import shlex
                parent_dir = os.path.dirname(safe_path)
                base_name = os.path.basename(safe_path)

                if not (is_safe_for_shell(parent_dir) and is_safe_for_shell(base_name)):
                    raise ValueError("Path contains unsafe characters")

                zip_command = f"cd {shlex.quote(parent_dir)} && zip -r -q {shlex.quote(remote_zip_path)} {shlex.quote(base_name)}"

                stdin, stdout, stderr = ssh_client.exec_command(zip_command)
                stdout.channel.settimeout(300)
                exit_code = stdout.channel.recv_exit_status()

                if exit_code == 0:
                    log_debug(f"Remote ZIP created: {remote_zip_path}")

                    zip_path = None
                    try:
                        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False, mode='wb') as tmp_zip:
                            zip_path = tmp_zip.name
                            os.chmod(zip_path, 0o600)
                            with sftp.file(remote_zip_path, 'rb') as remote_file:
                                while True:
                                    chunk = remote_file.read(65536)
                                    if not chunk:
                                        break
                                    tmp_zip.write(chunk)

                        with open(zip_path, 'rb') as f:
                            zip_data = f.read()

                        emit('file_download_ready_binary', {
                            'session_id': session_id,
                            'filename': f"{folder_name}.zip",
                            'file_data': zip_data,
                            'size': len(zip_data),
                            'for_preview': False
                        })

                        log_info(f"Folder download (remote): {folder_name}.zip", user=current_user.username)
                    finally:
                        if zip_path and os.path.exists(zip_path):
                            try:
                                os.unlink(zip_path)
                            except Exception as cleanup_err:
                                log_warning(f"Failed to cleanup temp file", path=zip_path, error=str(cleanup_err))

                        try:
                            sftp.remove(remote_zip_path)
                        except Exception as remote_cleanup_err:
                            log_warning(f"Failed to cleanup remote ZIP", path=remote_zip_path, error=str(remote_cleanup_err))

                        if source_type == 'pool':
                            sftp.close()

                    _sftp_lock.release()
                    return
                else:
                    log_debug(f"Remote zip command failed, falling back to SFTP method")

        except Exception as e:
            log_debug(f"Remote ZIP creation failed, falling back to SFTP method", error=str(e))

        zip_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False, mode='wb') as tmp_zip:
                zip_path = tmp_zip.name
            os.chmod(zip_path, 0o600)

            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as zipf:
                file_count = 0
                error_count = 0

                cumulative_size = 0
                max_zip_size = config.MAX_ZIP_DOWNLOAD_SIZE

                def add_folder_to_zip(sftp_client, remote_folder, zip_prefix='', depth=0):
                    """Recursively add folder contents to ZIP."""
                    nonlocal file_count, error_count, cumulative_size

                    if depth > 50:
                        log_warning(f"Maximum recursion depth exceeded in folder download: {remote_folder}")
                        error_count += 1
                        return

                    try:
                        items = sftp_client.listdir_attr(remote_folder)

                        if not items and zip_prefix:
                            zipf.writestr(zip_prefix + '/', '')

                        for item in items:
                            item_path = f"{remote_folder}/{item.filename}"
                            zip_item_path = f"{zip_prefix}/{item.filename}" if zip_prefix else item.filename

                            try:
                                try:
                                    item_lstat = sftp_client.lstat(item_path)
                                except Exception:
                                    item_lstat = item

                                if stat.S_ISLNK(item_lstat.st_mode):
                                    log_debug(f"Skipping symlink in ZIP download: {item_path}")
                                    continue

                                if stat.S_ISDIR(item_lstat.st_mode):
                                    zipf.writestr(zip_item_path + '/', '')
                                    add_folder_to_zip(sftp_client, item_path, zip_item_path, depth + 1)
                                else:
                                    with sftp_client.file(item_path, 'rb') as remote_file:
                                        file_data = remote_file.read()
                                        cumulative_size += len(file_data)
                                        if cumulative_size > max_zip_size:
                                            max_mb = max_zip_size // (1024 * 1024)
                                            raise ValueError(f"Folder exceeds maximum download size ({max_mb}MB)")
                                        zipf.writestr(zip_item_path, file_data)
                                    file_count += 1
                            except ValueError:
                                raise
                            except Exception as item_error:
                                error_count += 1
                                log_debug(f"Error adding {item_path}", error=str(item_error))

                    except ValueError:
                        raise
                    except Exception as e:
                        log_error(f"Error reading directory {remote_folder}", error=str(e))
                        raise

                log_debug(f"Starting folder download: {folder_name} from {safe_path}")
                add_folder_to_zip(sftp, safe_path, folder_name)
                log_debug(f"Added {file_count} files to ZIP ({error_count} errors)")

            with open(zip_path, 'rb') as f:
                zip_data = f.read()

            emit('file_download_ready_binary', {
                'session_id': session_id,
                'filename': f"{folder_name}.zip",
                'file_data': zip_data,
                'size': len(zip_data),
                'for_preview': False
            })

            log_info(f"Folder download: {folder_name}.zip", user=current_user.username)

        finally:
            if zip_path and os.path.exists(zip_path):
                try:
                    os.unlink(zip_path)
                except Exception as cleanup_err:
                    log_warning(f"Failed to cleanup temp file", path=zip_path, error=str(cleanup_err))

            if source_type == 'pool':
                sftp.close()

            _sftp_lock.release()

    except Exception as e:
        log_error("Folder download failed", error=str(e))
        emit('error', {'error': 'Folder download failed'})

@socketio.on('quick_connect')
@socket_login_required
def handle_quick_connect(data, current_user=None):
    """Create temporary SSH connection for file transfers without active session."""
    try:
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

@socketio.on('transfer_server_to_server')
@socket_login_required
def handle_transfer_server_to_server(data, current_user=None):
    """
    Handle server-to-server file transfer.
    Streams files directly between two SSH servers without local buffering.
    """
    import threading

    try:
        source_session_id = data.get('source_session_id')
        source_path = data.get('source_path')
        dest_session_id = data.get('dest_session_id')
        dest_path = data.get('dest_path')
        transfer_id = data.get('transfer_id')
        is_dir = data.get('is_dir', False)

        if not all([source_session_id, source_path, dest_session_id, dest_path, transfer_id]):
            emit('s2s_transfer_error', {
                'transfer_id': transfer_id,
                'error': 'Missing required fields'
            })
            return

        source_path = sftp_handler.sanitize_path(source_path)
        dest_path = sftp_handler.sanitize_path(dest_path)
        if source_path is None or dest_path is None:
            emit('s2s_transfer_error', {
                'transfer_id': transfer_id,
                'error': 'Invalid path'
            })
            return

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
            return

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
            return

        user_room = f'user_{current_user.id}'

        def run_transfer():
            success, error = sftp_handler.transfer_server_to_server(
                source_session_id=source_session_id,
                source_path=source_path,
                dest_session_id=dest_session_id,
                dest_path=dest_path,
                transfer_id=transfer_id,
                socketio_instance=socketio,
                is_dir=is_dir,
                user_room=user_room
            )

            if not success and error:
                socketio.emit('s2s_transfer_error', {
                    'transfer_id': transfer_id,
                    'error': error
                }, room=user_room)

        transfer_thread = threading.Thread(target=run_transfer, daemon=True)
        transfer_thread.start()

        log_info(f"S2S transfer started: {source_path} -> {dest_path}", user=current_user.username)

    except Exception as e:
        log_error("S2S transfer setup failed", error=str(e), user=current_user.username)
        emit('s2s_transfer_error', {
            'transfer_id': data.get('transfer_id'),
            'error': 'Failed to start transfer'
        })
