from flask_socketio import emit, join_room, disconnect
from flask import request, current_app
from flask_login import current_user
from . import socketio, ssh_manager, profile_manager, key_manager, sftp_handler
from .decorators import socket_login_required
from .auth import register_socket_session, get_user_from_socket
from .models import db, SSHSession, SocketSession
from .user_settings import save_user_settings, get_user_settings
from .audit_logger import log_info, log_warning, log_error, log_debug
from . import binary_transfer, connection_pool
import base64
import os


@socketio.on('connect')
def handle_connect():
    """Handle client connection - authenticate and restore sessions."""
    from flask import session as flask_session

    user_id = flask_session.get('_user_id')
    if not user_id:
        log_warning(f"Unauthenticated connection attempt", sid=request.sid)
        emit('connected', {'status': 'unauthenticated'})
        # SECURITY: Disconnect unauthenticated clients immediately
        disconnect()
        return

    from .models import User
    user = User.query.get(int(user_id))
    if not user:
        log_warning(f"User not found during connect", user_id=user_id, sid=request.sid)
        emit('connected', {'status': 'unauthenticated'})
        # SECURITY: Disconnect if user not found
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
        import re

        host = data.get('host', '').strip()
        port = data.get('port', 22)
        username = data.get('username', '').strip()
        password = data.get('password')
        key_id = data.get('key_id')
        client_request_id = data.get('client_request_id')

        def emit_error(message):
            emit('ssh_error', {'error': message, 'client_request_id': client_request_id})

        # Validate host format (hostname or IP)
        if not host:
            emit_error('Host is required')
            return

        # SECURITY: Proper hostname/IP validation
        import ipaddress

        def is_valid_host(host_str):
            """Validate host is a valid hostname or IP address."""
            # Try as IP address first (proper validation, not just regex)
            try:
                ipaddress.ip_address(host_str)
                return True
            except ValueError:
                pass

            # Validate as hostname
            hostname_pattern = re.compile(
                r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
                r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
            )
            return bool(hostname_pattern.match(host_str))

        if not is_valid_host(host):
            emit_error('Invalid host format')
            return

        # Validate port range
        try:
            port = int(port)
            if not (1 <= port <= 65535):
                emit_error('Port must be between 1 and 65535')
                return
        except (ValueError, TypeError):
            emit_error('Invalid port number')
            return

        # Validate username (alphanumeric, underscore, dash, max 32 chars)
        if not username:
            emit_error('Username is required')
            return

        if not re.match(r'^[a-zA-Z0-9_\-]{1,32}$', username):
            emit_error('Invalid username format')
            return

        # Validate authentication method
        if not password and not key_id:
            emit_error('Password or SSH key required')
            return

        key_content = None
        if key_id:
            # Read and decrypt key content (keys are encrypted at rest)
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

        # SECURITY: Clear credentials from memory after use
        if password:
            password = None
        if key_content:
            key_content = None

        if error:
            emit_error(error)
        else:
            ssh_session = SSHSession(
                session_id=session_id,
                user_id=current_user.id,
                host=host,
                port=port,
                username=username
            )
            db.session.add(ssh_session)
            db.session.commit()

            emit('ssh_connected', {
                'session_id': session_id,
                'host': host,
                'port': port,
                'username': username,
                'client_request_id': client_request_id
            })
            log_info(f"SSH connection established: {session_id}", user=current_user.username, host=host)

    except Exception as e:
        emit('ssh_error', {'error': f'Connection failed: {str(e)}'})
    finally:
        # SECURITY: Ensure credentials are cleared even on exception
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

        success, error = ssh_manager.send_ssh_input(session_id, input_data)
        if error:
            emit('ssh_error', {'error': error, 'session_id': session_id})

    except Exception as e:
        emit('ssh_error', {'error': str(e)})


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

        success, error = ssh_manager.resize_terminal(session_id, int(rows), int(cols))
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
        if ssh_session:
            ssh_session.connected = False
            db.session.commit()

        success = ssh_manager.close_session(session_id)
        if success:
            room = f'user_{current_user.id}'
            socketio.emit('ssh_disconnected', {
                'session_id': session_id,
                'reason': 'User requested disconnect'
            }, room=room)
            log_info(f"SSH session closed: {session_id}", user=current_user.username)

    except Exception as e:
        emit('ssh_error', {'error': str(e)})


@socketio.on('list_profiles')
@socket_login_required
def handle_list_profiles(current_user=None):
    """Return list of saved connection profiles for this user."""
    try:
        profiles = profile_manager.load_profiles(current_user.id)
        emit('profiles_list', {'profiles': profiles})
    except Exception as e:
        emit('error', {'error': f'Failed to load profiles: {str(e)}'})


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
        emit('error', {'error': f'Failed to save profile: {str(e)}'})


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
        emit('error', {'error': f'Failed to delete profile: {str(e)}'})


@socketio.on('list_keys')
@socket_login_required
def handle_list_keys(current_user=None):
    """Return list of stored SSH keys for this user."""
    try:
        keys = key_manager.load_keys(current_user.id)
        emit('keys_list', {'keys': keys})
    except Exception as e:
        emit('error', {'error': f'Failed to load keys: {str(e)}'})


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
            emit('error', {'error': error})
        else:
            emit('key_uploaded', {'key': key_meta})
            handle_list_keys(current_user=current_user)

    except Exception as e:
        emit('error', {'error': f'Failed to upload key: {str(e)}'})


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
            emit('key_deleted', {'key_id': key_id})
            handle_list_keys(current_user=current_user)
        else:
            emit('error', {'error': 'Failed to delete key'})

    except Exception as e:
        emit('error', {'error': f'Failed to delete key: {str(e)}'})


@socketio.on('upload_file')
@socket_login_required
def handle_upload_file(data, current_user=None):
    """Handle file upload via SFTP."""
    try:
        session_id = data.get('session_id')
        filename = data.get('filename')
        file_data = data.get('file_data')  # Base64 encoded
        remote_path = data.get('remote_path')

        if not all([session_id, filename, file_data, remote_path]):
            emit('error', {'error': 'Missing required fields for file upload'})
            return

        # SECURITY: Validate upload size (Base64 overhead ~33%, so check encoded size * 0.75)
        max_size = config.MAX_UPLOAD_SIZE
        estimated_size = len(file_data) * 0.75 if file_data else 0
        if estimated_size > max_size:
            max_mb = max_size // (1024 * 1024)
            emit('error', {'error': f'File too large. Maximum size: {max_mb}MB'})
            return

        # Verify ownership - check SSH session first, then connection pool
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
            log_info(f"File uploaded: {filename}", user=current_user.username, path=remote_path)

    except Exception as e:
        emit('error', {'error': f'Upload failed: {str(e)}'})


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

        # Verify ownership - check SSH session first, then connection pool
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
            log_info(f"File downloaded: {result['filename']}", user=current_user.username)

    except Exception as e:
        emit('error', {'error': f'Download failed: {str(e)}'})


@socketio.on('list_directory')
@socket_login_required
def handle_list_directory(data, current_user=None):
    """List files in remote directory."""
    try:
        session_id = data.get('session_id')
        remote_path = data.get('remote_path', '.')

        if not session_id:
            emit('error', {'error': 'Session ID required'})
            return

        # Verify ownership - check SSH session first, then connection pool
        authorized = False
        if verify_session_ownership(session_id, current_user.id):
            authorized = True
        else:
            # Check if it's a Quick Connect connection from the pool
            conn_info = connection_pool.temp_connection_pool.get_connection_info(session_id)
            if conn_info and conn_info['user_id'] == str(current_user.id):
                authorized = True

        if not authorized:
            emit('error', {'error': 'Unauthorized access to session'})
            return

        files, error = sftp_handler.list_directory(session_id, remote_path)
        if error:
            emit('error', {'error': f'Failed to list directory: {error}'})
        else:
            emit('directory_listing', {
                'session_id': session_id,
                'path': remote_path,
                'files': files
            })

    except Exception as e:
        emit('error', {'error': f'Failed to list directory: {str(e)}'})


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
        emit('error', {'error': f'Failed to get sessions: {str(e)}'})


@socketio.on('set_theme')
@socket_login_required
def handle_set_theme(data, current_user=None):
    """Persist theme selection for the current user."""
    try:
        theme = data.get('theme')
        valid_themes = [
            # Original themes
            'glass', 'nordic', 'retro', 'ember', 'forest', 'solar', 'paper', 'noir',
            # New themes
            'midnight-azure', 'arctic-ice', 'sunset-blaze', 'rose-gold',
            'cherry-blossom', 'lavender-dreams', 'cyberpunk-neon', 'emerald-matrix',
            'forest-canopy', 'ocean-depth', 'desert-mirage', 'amber-alert',
            'monochrome-elite', 'obsidian', 'ivory'
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
        emit('error', {'error': f'Failed to save theme: {str(e)}'})


@socketio.on('get_notepad')
@socket_login_required
def handle_get_notepad(current_user=None):
    """Return the persisted notepad for the current user."""
    try:
        settings = get_user_settings(current_user.id)
        emit('notepad_data', {'notepad': settings.get('notepad', '')})
    except Exception as e:
        emit('error', {'error': f'Failed to load notepad: {str(e)}'})


@socketio.on('save_notepad')
@socket_login_required
def handle_save_notepad(data, current_user=None):
    """Persist the notepad text for the current user."""
    try:
        text = data.get('text', '')
        success = save_user_settings(current_user.id, {'notepad': text})
        if not success:
            emit('error', {'error': 'Failed to save notepad'})
    except Exception as e:
        emit('error', {'error': f'Failed to save notepad: {str(e)}'})


# ==================== COMMAND LIBRARY EVENTS ====================

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
        emit('error', {'error': f'Failed to load commands: {str(e)}'})


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
        emit('error', {'error': f'Failed to add command: {str(e)}'})


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
        emit('error', {'error': f'Failed to update command: {str(e)}'})


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
        emit('error', {'error': f'Failed to delete command: {str(e)}'})


@socketio.on('detect_os')
@socket_login_required
def handle_detect_os(data, current_user=None):
    """OS detection disabled to avoid terminal noise."""
    emit('error', {'error': 'OS detection is disabled'})


# Helper functions

def verify_session_ownership(session_id, user_id):
    """
    Verify that a session belongs to a user.

    SECURITY: This function checks both in-memory sessions and database records
    atomically within the lock to prevent race conditions during session state
    transitions.
    """
    if not session_id or not user_id:
        return False

    user_id_str = str(user_id)

    with ssh_manager.sessions_lock:
        # Check in-memory session first (active sessions)
        session = ssh_manager.sessions.get(session_id)
        if session and session.get('user_id') is not None:
            return str(session.get('user_id')) == user_id_str

        # If not in memory, check database (for session recovery scenarios)
        # This is done within the lock to prevent TOCTOU race conditions
        ssh_session = SSHSession.query.filter_by(session_id=session_id).first()
        if ssh_session is not None:
            return str(ssh_session.user_id) == user_id_str

    return False


# ============================================
# BINARY FILE TRANSFER EVENTS
# ============================================

@socketio.on('upload_file_binary')
@socket_login_required
def handle_upload_file_binary(data, current_user=None):
    """Handle binary file upload (no base64 encoding)."""
    try:
        session_id = data.get('session_id')
        filename = data.get('filename')
        file_data = data.get('file_data')  # Binary ArrayBuffer
        remote_path = data.get('remote_path')

        if not all([session_id, filename, file_data, remote_path]):
            emit('error', {'error': 'Missing required fields for binary upload'})
            return

        # Verify session ownership
        if not verify_session_ownership(session_id, current_user.id):
            # Check if it's a temporary connection
            conn_info = connection_pool.temp_connection_pool.get_connection_info(session_id)
            if not conn_info or conn_info['user_id'] != str(current_user.id):
                emit('error', {'error': 'Unauthorized access to session/connection'})
                return

        # Upload using binary transfer
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
            log_info(f"Binary upload: {filename}", user=current_user.username, path=remote_path)

    except Exception as e:
        emit('error', {'error': f'Upload failed: {str(e)}'})


@socketio.on('download_file_binary')
@socket_login_required
def handle_download_file_binary(data, current_user=None):
    """Handle binary file download (no base64 encoding)."""
    try:
        session_id = data.get('session_id')
        remote_path = data.get('remote_path')
        for_preview = data.get('for_preview', False)  # Flag to distinguish preview from download

        if not all([session_id, remote_path]):
            emit('error', {'error': 'Missing required fields for binary download'})
            return

        # Verify session ownership
        if not verify_session_ownership(session_id, current_user.id):
            # Check if it's a temporary connection
            conn_info = connection_pool.temp_connection_pool.get_connection_info(session_id)
            if not conn_info or conn_info['user_id'] != str(current_user.id):
                emit('error', {'error': 'Unauthorized access to session/connection'})
                return

        # Download using binary transfer
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
                # For preview, use base64 encoding for reliable transfer
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
                # For actual downloads, send binary data directly
                emit('file_download_ready_binary', {
                    'session_id': session_id,
                    'filename': filename,
                    'file_data': binary_data,
                    'size': len(binary_data),
                    'for_preview': False
                })
            log_info(f"Binary download: {filename}", user=current_user.username)

    except Exception as e:
        emit('error', {'error': f'Download failed: {str(e)}'})


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

        # Verify session ownership
        if not verify_session_ownership(session_id, current_user.id):
            # Check if it's a temporary connection
            conn_info = connection_pool.temp_connection_pool.get_connection_info(session_id)
            if not conn_info or conn_info['user_id'] != str(current_user.id):
                emit('error', {'error': 'Unauthorized access to session/connection'})
                return

        # Get SFTP client
        sftp, error, source_type = sftp_handler.get_any_sftp_client(session_id)
        if error:
            emit('error', {'error': error})
            return

        # Sanitize remote path
        safe_path = sftp_handler.sanitize_path(remote_path)
        if safe_path is None:
            emit('error', {'error': 'Invalid remote path'})
            return

        # Verify it's a directory
        try:
            file_stat = sftp.stat(safe_path)
            import stat
            if not stat.S_ISDIR(file_stat.st_mode):
                emit('error', {'error': 'Path is not a directory'})
                return
        except FileNotFoundError:
            emit('error', {'error': 'Remote directory not found'})
            return

        folder_name = os.path.basename(safe_path.rstrip('/'))

        # SECURITY: Validate path doesn't contain shell-dangerous characters
        # Even with shlex.quote, we add defense-in-depth by rejecting suspicious paths
        def is_safe_for_shell(path):
            """Validate path is safe for shell command use (defense in depth)."""
            if not path:
                return False
            # Reject paths with newlines, null bytes, or backticks
            dangerous_chars = ['\n', '\r', '\x00', '`', '$', '|', ';', '&']
            return not any(c in path for c in dangerous_chars)

        # Try to create ZIP on remote server first (much faster for large folders)
        # If that fails, fall back to SFTP-based approach
        remote_zip_path = f"/tmp/{folder_name}_{os.urandom(8).hex()}.zip"

        try:
            # Attempt to create ZIP on remote server using shell command
            ssh_client = sftp._client if hasattr(sftp, '_client') else None
            if ssh_client and is_safe_for_shell(safe_path):
                # Use zip command on remote server (faster)
                import shlex
                parent_dir = os.path.dirname(safe_path)
                base_name = os.path.basename(safe_path)

                # SECURITY: Additional validation before exec_command
                if not (is_safe_for_shell(parent_dir) and is_safe_for_shell(base_name)):
                    raise ValueError("Path contains unsafe characters")

                # Escape shell arguments for security
                zip_command = f"cd {shlex.quote(parent_dir)} && zip -r -q {shlex.quote(remote_zip_path)} {shlex.quote(base_name)}"

                stdin, stdout, stderr = ssh_client.exec_command(zip_command)
                # SECURITY: Set timeout to prevent indefinite hanging
                stdout.channel.settimeout(300)  # 5 minutes max for ZIP creation
                exit_code = stdout.channel.recv_exit_status()

                if exit_code == 0:
                    # Remote ZIP creation successful - download it
                    log_debug(f"Remote ZIP created: {remote_zip_path}")

                    # SECURITY: Use context manager for guaranteed cleanup
                    zip_path = None
                    try:
                        # Download the remote ZIP file
                        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False, mode='wb') as tmp_zip:
                            zip_path = tmp_zip.name
                            # SECURITY: Set restrictive permissions on temp file
                            os.chmod(zip_path, 0o600)
                            with sftp.file(remote_zip_path, 'rb') as remote_file:
                                while True:
                                    chunk = remote_file.read(65536)
                                    if not chunk:
                                        break
                                    tmp_zip.write(chunk)

                        # Read local ZIP and send to client
                        with open(zip_path, 'rb') as f:
                            zip_data = f.read()

                        # Send to client
                        emit('file_download_ready_binary', {
                            'session_id': session_id,
                            'filename': f"{folder_name}.zip",
                            'file_data': zip_data,
                            'size': len(zip_data),
                            'for_preview': False
                        })

                        log_info(f"Folder download (remote): {folder_name}.zip", user=current_user.username)
                    finally:
                        # SECURITY: Guaranteed cleanup of local temp file
                        if zip_path and os.path.exists(zip_path):
                            try:
                                os.unlink(zip_path)
                            except Exception as cleanup_err:
                                log_warning(f"Failed to cleanup temp file", path=zip_path, error=str(cleanup_err))

                        # Clean up remote ZIP
                        try:
                            sftp.remove(remote_zip_path)
                        except Exception as remote_cleanup_err:
                            log_warning(f"Failed to cleanup remote ZIP", path=remote_zip_path, error=str(remote_cleanup_err))

                        sftp.close()

                    return
                else:
                    log_debug(f"Remote zip command failed, falling back to SFTP method")

        except Exception as e:
            log_debug(f"Remote ZIP creation failed, falling back to SFTP method", error=str(e))

        # Fallback: Create ZIP locally using SFTP
        # SECURITY: Initialize zip_path before try block for guaranteed cleanup
        zip_path = None
        try:
            # Create temporary ZIP file
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False, mode='wb') as tmp_zip:
                zip_path = tmp_zip.name
            # SECURITY: Set restrictive permissions on temp file
            os.chmod(zip_path, 0o600)

            # Create ZIP archive with minimal compression for speed
            # ZIP_STORED = no compression (faster), ZIP_DEFLATED = compression (slower)
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_STORED) as zipf:
                file_count = 0
                error_count = 0

                def add_folder_to_zip(sftp_client, remote_folder, zip_prefix=''):
                    """Recursively add folder contents to ZIP."""
                    nonlocal file_count, error_count
                    try:
                        items = sftp_client.listdir_attr(remote_folder)

                        # If folder is empty, create directory entry in ZIP
                        if not items and zip_prefix:
                            zipf.writestr(zip_prefix + '/', '')

                        for item in items:
                            item_path = f"{remote_folder}/{item.filename}"
                            zip_item_path = f"{zip_prefix}/{item.filename}" if zip_prefix else item.filename

                            try:
                                if stat.S_ISDIR(item.st_mode):
                                    # Create directory entry in ZIP
                                    zipf.writestr(zip_item_path + '/', '')
                                    # Recursively add subdirectory contents
                                    add_folder_to_zip(sftp_client, item_path, zip_item_path)
                                else:
                                    # Add file to ZIP - read in one go for speed
                                    with sftp_client.file(item_path, 'rb') as remote_file:
                                        file_data = remote_file.read()
                                        zipf.writestr(zip_item_path, file_data)
                                    file_count += 1
                            except Exception as item_error:
                                error_count += 1
                                log_debug(f"Error adding {item_path}", error=str(item_error))
                                # Continue with next item instead of stopping

                    except Exception as e:
                        log_error(f"Error reading directory {remote_folder}", error=str(e))
                        raise

                # Add folder contents to ZIP
                log_debug(f"Starting folder download: {folder_name} from {safe_path}")
                add_folder_to_zip(sftp, safe_path, folder_name)
                log_debug(f"Added {file_count} files to ZIP ({error_count} errors)")

            # Read ZIP file as binary
            with open(zip_path, 'rb') as f:
                zip_data = f.read()

            # Send ZIP file to client
            emit('file_download_ready_binary', {
                'session_id': session_id,
                'filename': f"{folder_name}.zip",
                'file_data': zip_data,
                'size': len(zip_data),
                'for_preview': False
            })

            log_info(f"Folder download: {folder_name}.zip", user=current_user.username)

        finally:
            # SECURITY: Guaranteed cleanup of local temp file
            if zip_path and os.path.exists(zip_path):
                try:
                    os.unlink(zip_path)
                except Exception as cleanup_err:
                    log_warning(f"Failed to cleanup temp file", path=zip_path, error=str(cleanup_err))

            # Close SFTP
            sftp.close()

    except Exception as e:
        emit('error', {'error': f'Folder download failed: {str(e)}'})


# ============================================
# QUICK CONNECTION (TEMPORARY CONNECTIONS)
# ============================================

@socketio.on('quick_connect')
@socket_login_required
def handle_quick_connect(data, current_user=None):
    """Create temporary SSH connection for file transfers without active session."""
    try:
        host = data.get('host')
        port = data.get('port', 22)
        username = data.get('username')
        password = data.get('password')
        key_id = data.get('key_id')

        if not host or not username:
            emit('quick_connect_error', {'error': 'Host and username are required'})
            return

        # Need either password or key
        if not password and not key_id:
            emit('quick_connect_error', {'error': 'Password or SSH key required'})
            return

        # Get key content if using key authentication (keys are encrypted at rest)
        key_content = None
        if key_id:
            key_content, key_error = key_manager.read_key_content(current_user.id, key_id)
            if key_error:
                emit('quick_connect_error', {'error': f'SSH key error: {key_error}'})
                return

        # Create temporary connection
        connection_id, error = connection_pool.temp_connection_pool.create_connection(
            host=host,
            port=port,
            username=username,
            password=password,
            key_content=key_content,
            user_id=str(current_user.id)
        )

        # SECURITY: Clear password from memory after use
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
        emit('quick_connect_error', {'error': str(e)})
    finally:
        # SECURITY: Ensure credentials are cleared even on exception
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

        # Verify ownership
        conn_info = connection_pool.temp_connection_pool.get_connection_info(connection_id)
        if not conn_info or conn_info['user_id'] != str(current_user.id):
            emit('error', {'error': 'Unauthorized access to connection'})
            return

        # Close connection
        success = connection_pool.temp_connection_pool.close_connection(connection_id)

        if success:
            emit('quick_disconnect_success', {'connection_id': connection_id})
        else:
            emit('error', {'error': 'Connection not found'})

    except Exception as e:
        emit('error', {'error': str(e)})


# ============================================
# FILE OPERATIONS
# ============================================

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

        # Verify ownership
        if not verify_session_ownership(session_id, current_user.id):
            conn_info = connection_pool.temp_connection_pool.get_connection_info(session_id)
            if not conn_info or conn_info['user_id'] != str(current_user.id):
                emit('error', {'error': 'Unauthorized access'})
                return

        # Create directory
        success, error = sftp_handler.create_directory(session_id, remote_path)

        if error:
            emit('error', {'error': f'Failed to create directory: {error}'})
        else:
            emit('directory_created', {'path': remote_path})

    except Exception as e:
        emit('error', {'error': str(e)})


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

        # Verify ownership
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
        emit('error', {'error': str(e)})


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

        # Verify ownership
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
        emit('error', {'error': str(e)})


@socketio.on('get_home_directory')
@socket_login_required
def handle_get_home_directory(data, current_user=None):
    """Get the home directory of the SFTP session."""
    try:
        session_id = data.get('session_id')

        if not session_id:
            emit('error', {'error': 'Session ID required'})
            return

        # Verify ownership
        if not verify_session_ownership(session_id, current_user.id):
            conn_info = connection_pool.temp_connection_pool.get_connection_info(session_id)
            if not conn_info or conn_info['user_id'] != str(current_user.id):
                emit('error', {'error': 'Unauthorized access'})
                return

        home_path, error = sftp_handler.get_home_directory(session_id)

        if error:
            emit('error', {'error': f'Failed to get home directory: {error}'})
        else:
            emit('home_directory', {'session_id': session_id, 'path': home_path})

    except Exception as e:
        emit('error', {'error': str(e)})


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

        # Verify ownership
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
        emit('error', {'error': str(e)})


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

        # Verify ownership
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
        emit('error', {'error': str(e)})


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
        max_bytes = data.get('max_bytes', 512000)  # 500KB default
        offset = data.get('offset', 0)
        tail_lines = data.get('tail_lines')  # For log file tail mode

        if not all([session_id, path]):
            emit('error', {'error': 'Missing required fields'})
            return

        # Verify ownership
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
        emit('preview_error', {'error': str(e), 'path': data.get('path', '')})


# ============================================
# SERVER-TO-SERVER TRANSFER
# ============================================

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

        # Verify ownership of source (session or connection)
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

        # Verify ownership of destination (session or connection)
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

        # Get user room for emitting progress
        user_room = f'user_{current_user.id}'

        # Run transfer in background thread to not block
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

        # Start transfer thread
        transfer_thread = threading.Thread(target=run_transfer, daemon=True)
        transfer_thread.start()

        log_info(f"S2S transfer started: {source_path} -> {dest_path}", user=current_user.username)

    except Exception as e:
        emit('s2s_transfer_error', {
            'transfer_id': data.get('transfer_id'),
            'error': str(e)
        })

