import paramiko
import time
import uuid
import socket
from threading import Lock, Thread
import config
from pathlib import Path
from .audit_logger import log_info, log_warning, log_error, log_debug

sessions = {}
sessions_lock = Lock()


class PersistentHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Secure host key policy with logging and audit trail."""
    def __init__(self, known_hosts_path):
        self.known_hosts_path = Path(known_hosts_path)

    def missing_host_key(self, client, hostname, key):
        import binascii

        # Log the new host key for security audit
        key_type = key.get_name()
        key_fingerprint = binascii.hexlify(key.get_fingerprint()).decode('utf-8')
        key_fingerprint_formatted = ':'.join([key_fingerprint[i:i+2] for i in range(0, len(key_fingerprint), 2)])

        log_warning(f"SECURITY: New SSH host key detected",
                    host=hostname, key_type=key_type, fingerprint=key_fingerprint_formatted)

        # Store the host key
        host_keys = client.get_host_keys()
        host_keys.add(hostname, key.get_name(), key)
        self.known_hosts_path.parent.mkdir(parents=True, exist_ok=True)

        # Set restrictive permissions on known_hosts file
        host_keys.save(str(self.known_hosts_path))
        import os
        os.chmod(str(self.known_hosts_path), 0o600)

        log_info(f"Host key stored", path=str(self.known_hosts_path))

def create_ssh_connection(host, port, username, password=None, key_path=None, key_content=None, socketio_instance=None, app=None, user_id=None):
    """
    Create a new SSH connection and return session ID.

    Args:
        host: SSH server hostname
        port: SSH server port
        username: SSH username
        password: Password for authentication (optional)
        key_path: Path to SSH key file - DEPRECATED, use key_content instead
        key_content: Decrypted SSH private key content (preferred)
        socketio_instance: SocketIO instance for output streaming
        app: Flask app instance
        user_id: User ID for session tracking
    """
    try:
        with sessions_lock:
            if len(sessions) >= config.MAX_SESSIONS:
                return None, "Maximum number of sessions reached"

        client = paramiko.SSHClient()
        if config.KNOWN_HOSTS_FILE.exists():
            client.load_host_keys(str(config.KNOWN_HOSTS_FILE))
        client.set_missing_host_key_policy(PersistentHostKeyPolicy(config.KNOWN_HOSTS_FILE))

        auth_kwargs = {
            'hostname': host,
            'port': port,
            'username': username,
            'timeout': config.SSH_CONNECT_TIMEOUT,
            'look_for_keys': False,
            'allow_agent': False
        }

        if key_content:
            # Load key from decrypted content (preferred - keys encrypted at rest)
            import io
            key_file = io.StringIO(key_content)
            try:
                # Try to load as RSA first, then other key types
                pkey = paramiko.RSAKey.from_private_key(key_file)
            except paramiko.ssh_exception.SSHException:
                key_file.seek(0)
                try:
                    pkey = paramiko.Ed25519Key.from_private_key(key_file)
                except paramiko.ssh_exception.SSHException:
                    key_file.seek(0)
                    try:
                        pkey = paramiko.ECDSAKey.from_private_key(key_file)
                    except paramiko.ssh_exception.SSHException:
                        key_file.seek(0)
                        pkey = paramiko.DSSKey.from_private_key(key_file)
            auth_kwargs['pkey'] = pkey
        elif key_path:
            # Legacy: Load from file path (for backwards compatibility)
            auth_kwargs['key_filename'] = key_path
        elif password:
            auth_kwargs['password'] = password
        else:
            return None, "No authentication method provided"

        client.connect(**auth_kwargs)

        # Enable SSH-level keepalive to prevent remote server from closing idle connections
        transport = client.get_transport()
        if transport:
            transport.set_keepalive(30)  # Send keepalive every 30 seconds

        channel = client.invoke_shell(
            term='xterm-256color',
            width=80,
            height=24
        )
        # Don't set timeout to 0 - it causes issues with select()
        channel.settimeout(0.1)

        session_id = str(uuid.uuid4())

        # Brief pause for shell initialization (reduced from 1.0s)
        time.sleep(0.1)

        with sessions_lock:
            sessions[session_id] = {
                'client': client,
                'channel': channel,
                'host': host,
                'port': port,
                'username': username,
                'user_id': user_id,
                'connected': True,
                'last_activity': time.time()
            }

        if socketio_instance and app:
            thread = Thread(
                target=read_ssh_output,
                args=(session_id, socketio_instance, app),
                daemon=True
            )
            thread.start()

        return session_id, None

    except paramiko.AuthenticationException:
        return None, "Authentication failed - invalid credentials"
    except paramiko.SSHException as e:
        return None, f"SSH error: {str(e)}"
    except socket.timeout:
        return None, "Connection timeout - host unreachable"
    except socket.error as e:
        return None, f"Network error: {str(e)}"
    except Exception as e:
        return None, f"Unexpected error: {str(e)}"

def read_ssh_output(session_id, socketio_instance, app):
    """Background greenthread to continuously read SSH output and emit to client.

    IMPORTANT: Do NOT use select.select() on the paramiko channel here.
    Under eventlet, select.select() watches the transport socket FD, which
    conflicts with paramiko's own transport reader greenthread and any
    concurrent SFTP operations on the same transport. This causes SFTP
    operations to hang intermittently.

    Instead, use channel.recv() directly with a timeout. Paramiko's channel
    internally uses green-compatible Events (monkey-patched threading.Event)
    that properly yield to other greenthreads.
    """
    from datetime import datetime, timezone

    # Cache room/user_id once at startup to avoid DB query per chunk
    cached_room = None
    last_db_update = 0

    try:
        with app.app_context():
            from .models import SSHSession, db

            # Wait for DB record (created by socket_events after create_ssh_connection returns)
            db_session = None
            for _attempt in range(30):  # Wait up to 3 seconds
                db_session = SSHSession.query.filter_by(session_id=session_id).first()
                if db_session:
                    break
                time.sleep(0.1)

            if db_session:
                cached_room = f'user_{db_session.user_id}'

            if not cached_room:
                log_error(f"No DB session found for output reader", session_id=session_id)
                return

            while True:
                with sessions_lock:
                    if session_id not in sessions:
                        break
                    session = sessions[session_id]
                    if not session['connected']:
                        break
                    channel = session['channel']

                try:
                    # channel.recv() uses paramiko's internal buffer + green Event.
                    # With channel.settimeout(0.1), this yields for up to 100ms
                    # if no data, allowing other greenthreads (SFTP ops) to run.
                    data = channel.recv(32768)
                    if data:
                        decoded_data = data.decode('utf-8', errors='replace')
                        socketio_instance.emit('ssh_output', {
                            'session_id': session_id,
                            'data': decoded_data
                        }, room=cached_room)

                        now = time.time()
                        with sessions_lock:
                            if session_id in sessions:
                                sessions[session_id]['last_activity'] = now

                        # Debounce DB updates to reduce SQLite contention
                        if now - last_db_update >= 10.0:
                            last_db_update = now
                            try:
                                db_session = SSHSession.query.filter_by(session_id=session_id).first()
                                if db_session:
                                    db_session.last_activity = datetime.now(timezone.utc)
                                    db.session.commit()
                            except Exception:
                                db.session.rollback()
                    else:
                        break  # Connection closed
                except socket.timeout:
                    # No data within channel timeout (0.1s) -- normal, loop back
                    pass
                except EOFError:
                    # Channel closed by remote
                    break
                except Exception as e:
                    log_error(f"Error reading from channel", error=str(e), exc_info=True)
                    break

                if channel.closed or channel.exit_status_ready():
                    break

    except Exception as e:
        log_error(f"Error in output reader thread", error=str(e), exc_info=True)
    finally:
        with app.app_context():
            from .models import SSHSession, db
            db_session = SSHSession.query.filter_by(session_id=session_id).first()
            if db_session:
                db_session.connected = False
                db.session.commit()

                socketio_instance.emit('ssh_disconnected', {
                    'session_id': session_id,
                    'reason': 'Connection closed'
                }, room=cached_room or f'user_{db_session.user_id}')

        close_session(session_id)

def send_ssh_input(session_id, data):
    """Send user input to SSH channel."""
    try:
        with sessions_lock:
            if session_id not in sessions:
                return False, "Session not found"

            session = sessions[session_id]
            if not session['connected']:
                return False, "Session not connected"

            channel = session['channel']

        channel.send(data)

        with sessions_lock:
            if session_id in sessions:
                sessions[session_id]['last_activity'] = time.time()

        return True, None
    except Exception as e:
        return False, str(e)

def resize_terminal(session_id, rows, cols):
    """Resize terminal PTY."""
    try:
        with sessions_lock:
            if session_id not in sessions:
                return False, "Session not found"

            session = sessions[session_id]
            channel = session['channel']

        channel.resize_pty(width=cols, height=rows)
        return True, None
    except Exception as e:
        return False, str(e)

def close_session(session_id):
    """Close SSH session and clean up resources."""
    try:
        # Close cached SFTP client first
        from .sftp_handler import close_sftp_cache
        close_sftp_cache(session_id)

        with sessions_lock:
            if session_id not in sessions:
                return False

            session = sessions[session_id]
            session['connected'] = False

            if session['channel']:
                try:
                    session['channel'].close()
                except Exception as e:
                    log_debug(f"Error closing channel", session_id=session_id, error=str(e))

            if session['client']:
                try:
                    session['client'].close()
                except Exception as e:
                    log_debug(f"Error closing SSH client", session_id=session_id, error=str(e))

            del sessions[session_id]

        return True
    except Exception as e:
        log_error(f"Error closing session", session_id=session_id, error=str(e))
        return False

def get_session(session_id):
    """Get session info by ID."""
    with sessions_lock:
        if session_id in sessions:
            session = sessions[session_id]
            return {
                'id': session_id,
                'host': session['host'],
                'port': session['port'],
                'username': session['username'],
                'connected': session['connected']
            }
    return None

def cleanup_idle_sessions():
    """Clean up sessions that have been idle too long."""
    try:
        from . import socketio
        current_time = time.time()
        to_close = []
        to_warn = []

        with sessions_lock:
            for session_id, session in sessions.items():
                idle_time = current_time - session['last_activity']

                # Close session if timeout exceeded
                if idle_time > config.SESSION_TIMEOUT:
                    to_close.append(session_id)
                # Warn 2 minutes before timeout if not already warned
                elif idle_time > (config.SESSION_TIMEOUT - 120) and not session.get('_warned'):
                    to_warn.append((session_id, session.get('user_id')))
                    session['_warned'] = True
                # Clear warning flag if session becomes active again
                elif idle_time <= (config.SESSION_TIMEOUT - 120) and session.get('_warned'):
                    session['_warned'] = False

        # Send warnings
        for session_id, user_id in to_warn:
            if user_id:
                room = f'user_{user_id}'
                socketio.emit('session_timeout_warning', {
                    'session_id': session_id
                }, room=room)
                log_debug(f"Sent timeout warning for session: {session_id}")

        # Close timed-out sessions
        for session_id in to_close:
            close_session(session_id)
            log_info(f"Closed idle session: {session_id}")

    except Exception as e:
        log_error(f"Error cleaning up idle sessions", error=str(e))

import atexit

def cleanup_all_sessions():
    """Close all sessions on application exit."""
    with sessions_lock:
        session_ids = list(sessions.keys())

    for session_id in session_ids:
        close_session(session_id)

atexit.register(cleanup_all_sessions)
