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

        key_type = key.get_name()
        key_fingerprint = binascii.hexlify(key.get_fingerprint()).decode('utf-8')
        key_fingerprint_formatted = ':'.join([key_fingerprint[i:i+2] for i in range(0, len(key_fingerprint), 2)])

        log_warning(f"SECURITY: New SSH host key detected",
                    host=hostname, key_type=key_type, fingerprint=key_fingerprint_formatted)

        host_keys = client.get_host_keys()
        host_keys.add(hostname, key.get_name(), key)
        self.known_hosts_path.parent.mkdir(parents=True, exist_ok=True)

        host_keys.save(str(self.known_hosts_path))
        import os
        os.chmod(str(self.known_hosts_path), 0o600)

        log_info(f"Host key stored", path=str(self.known_hosts_path))

def _load_private_key(key_content):
    """Parse a decrypted PEM private key into a paramiko PKey (RSA/Ed25519/ECDSA/DSS)."""
    import io
    key_file = io.StringIO(key_content)
    for key_cls in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.DSSKey):
        try:
            return key_cls.from_private_key(key_file)
        except paramiko.ssh_exception.SSHException:
            key_file.seek(0)
    raise paramiko.ssh_exception.SSHException("Unsupported or invalid private key format")


def create_ssh_connection(host, port, username, password=None, key_path=None, key_content=None,
                          socketio_instance=None, app=None, user_id=None,
                          proxy_jump_host=None, proxy_jump_port=None, proxy_jump_username=None,
                          proxy_jump_password=None, proxy_jump_key_content=None):
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
        proxy_jump_*: Optional jump host (bastion) connection parameters
    """
    bastion_client = None
    connection_stored = False
    try:
        with sessions_lock:
            if len(sessions) >= config.MAX_SESSIONS:
                return None, "Maximum number of sessions reached"

        # Optional ProxyJump: connect to the bastion first, then tunnel to the target.
        sock = None
        if proxy_jump_host:
            try:
                bastion_client = paramiko.SSHClient()
                if config.KNOWN_HOSTS_FILE.exists():
                    bastion_client.load_host_keys(str(config.KNOWN_HOSTS_FILE))
                bastion_client.set_missing_host_key_policy(PersistentHostKeyPolicy(config.KNOWN_HOSTS_FILE))

                bastion_auth = {
                    'hostname': proxy_jump_host,
                    'port': proxy_jump_port or 22,
                    'username': proxy_jump_username,
                    'timeout': config.SSH_CONNECT_TIMEOUT,
                    'look_for_keys': False,
                    'allow_agent': False,
                }
                if proxy_jump_key_content:
                    bastion_auth['pkey'] = _load_private_key(proxy_jump_key_content)
                elif proxy_jump_password:
                    bastion_auth['password'] = proxy_jump_password
                else:
                    return None, "Jump host authentication method not provided"

                bastion_client.connect(**bastion_auth)
                bastion_transport = bastion_client.get_transport()
                if bastion_transport:
                    bastion_transport.set_keepalive(30)
                sock = bastion_transport.open_channel(
                    'direct-tcpip', (host, port), ('127.0.0.1', 0)
                )
                log_info("Jump host connection established", bastion=proxy_jump_host)
            except paramiko.AuthenticationException:
                return None, "Jump host authentication failed - invalid credentials"
            except Exception as e:
                return None, f"Jump host connection failed: {str(e)}"

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
        if sock:
            auth_kwargs['sock'] = sock

        if key_content:
            auth_kwargs['pkey'] = _load_private_key(key_content)
        elif key_path:
            auth_kwargs['key_filename'] = key_path
        elif password:
            auth_kwargs['password'] = password
        else:
            return None, "No authentication method provided"

        client.connect(**auth_kwargs)

        transport = client.get_transport()
        if transport:
            transport.set_keepalive(30)

        channel = client.invoke_shell(
            term='xterm-256color',
            width=80,
            height=24
        )
        channel.settimeout(0.1)

        session_id = str(uuid.uuid4())

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
                'last_activity': time.time(),
                'bastion_client': bastion_client,
                'proxy_jump_host': proxy_jump_host
            }
            connection_stored = True

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
        # Detail to the server log only; the client gets a generic message so
        # low-level errors cannot be used to probe remote hosts/ports.
        log_warning("SSH connection failed", host=f"{host}:{port}", error=str(e))
        return None, "SSH connection failed"
    except socket.timeout:
        return None, "Connection timeout - host unreachable"
    except socket.error as e:
        log_warning("SSH network error", host=f"{host}:{port}", error=str(e))
        return None, "Network error - could not reach host"
    except Exception as e:
        log_error("SSH connection unexpected error", host=f"{host}:{port}", error=str(e))
        return None, "Connection failed"
    finally:
        # Avoid leaking the bastion connection if the target connect failed.
        if bastion_client is not None and not connection_stored:
            try:
                bastion_client.close()
            except Exception:
                pass

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

    cached_room = None
    last_db_update = 0

    try:
        with app.app_context():
            from .models import SSHSession, db

            db_session = None
            for _attempt in range(30):
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
                        break
                except socket.timeout:
                    pass
                except EOFError:
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

            if session.get('bastion_client'):
                try:
                    session['bastion_client'].close()
                except Exception as e:
                    log_debug(f"Error closing jump host client", session_id=session_id, error=str(e))

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
                'connected': session['connected'],
                'via_jump': session.get('proxy_jump_host')
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

                if idle_time > config.SESSION_TIMEOUT:
                    to_close.append(session_id)
                elif idle_time > (config.SESSION_TIMEOUT - 120) and not session.get('_warned'):
                    to_warn.append((session_id, session.get('user_id')))
                    session['_warned'] = True
                elif idle_time <= (config.SESSION_TIMEOUT - 120) and session.get('_warned'):
                    session['_warned'] = False

        for session_id, user_id in to_warn:
            if user_id:
                room = f'user_{user_id}'
                socketio.emit('session_timeout_warning', {
                    'session_id': session_id
                }, room=room)
                log_debug(f"Sent timeout warning for session: {session_id}")

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
