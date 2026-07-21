import paramiko
from paramiko.auth_strategy import AuthStrategy, NoneAuth
import time
import uuid
import socket
from threading import Lock, Thread
import config
from pathlib import Path
from .audit_logger import log_info, log_warning, log_error, log_debug
from .ssh_key_loader import load_private_key as _load_private_key
from .startup_commands import to_terminal_input

sessions = {}
sessions_lock = Lock()


class TailscaleSSHAuthStrategy(AuthStrategy):
    """Authenticate through Tailscale SSH without user-managed credentials."""

    def __init__(self, username):
        super().__init__(ssh_config=None)
        self.username = username

    def get_sources(self):
        yield NoneAuth(self.username)


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

def create_ssh_connection(host, port, username, password=None, key_path=None, key_content=None,
                          socketio_instance=None, app=None, user_id=None,
                          proxy_jump_host=None, proxy_jump_port=None, proxy_jump_username=None,
                          proxy_jump_password=None, proxy_jump_key_content=None,
                          use_tmux=False, reconnect_tmux_name=None,
                          auth_type='password', startup_commands=''):
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
        auth_type: Target authentication method (password, key, or tailscale)
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
            'timeout': config.SSH_CONNECT_TIMEOUT
        }
        if sock:
            auth_kwargs['sock'] = sock

        if auth_type == 'tailscale':
            auth_kwargs['auth_strategy'] = TailscaleSSHAuthStrategy(username)
        else:
            auth_kwargs['look_for_keys'] = False
            auth_kwargs['allow_agent'] = False
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

        tmux_session_name = None
        if use_tmux:
            # Tailscale SSH does not populate locale variables. Force UTF-8 on
            # the tmux client so existing servers do not replace multibyte
            # characters with underscores.
            tmux_command = (
                'env LANG=C.UTF-8 LC_ALL=C.UTF-8 tmux -u'
                if auth_type == 'tailscale'
                else 'tmux'
            )

            # Each new connection gets a unique tmux session name.
            # For reconnections, use reconnect_tmux_name to attach to existing.
            # Sanitize host and username for tmux session name: replace dots,
            # colons (IPv6), and hyphens with underscores (tmux rejects them).
            safe_host = host.replace('.', '_').replace(':', '_').replace('-', '_')
            safe_user = username.replace('.', '_').replace('-', '_')
            if reconnect_tmux_name:
                tmux_session_name = reconnect_tmux_name
                tmux_cmd = f'{tmux_command} new-session -A -s {tmux_session_name}'
            else:
                unique_suffix = uuid.uuid4().hex[:8]
                tmux_session_name = f"{config.TMUX_SESSION_PREFIX}_{safe_user}_{safe_host}_{port}_{unique_suffix}"
                tmux_cmd = f'{tmux_command} new-session -s {tmux_session_name}'

            log_info(f"Using tmux persistent session", tmux_session=tmux_session_name, host=f"{host}:{port}")

            # Probe for tmux on a separate exec channel before opening the
            # real session. This avoids locale-dependent error string matching
            # and avoids swallowing tmux's initial screen draw.
            probe_channel = transport.open_session()
            probe_channel.exec_command('command -v tmux')
            probe_channel.settimeout(3.0)
            try:
                probe_channel.recv(1)
            except Exception:
                pass
            tmux_available = probe_channel.recv_exit_status() == 0
            probe_channel.close()

            if not tmux_available:
                log_warning(f"tmux not found on target host, falling back to regular shell",
                           host=f"{host}:{port}")
                tmux_session_name = None
                use_tmux = False
                channel = client.invoke_shell(
                    term='xterm-256color',
                    width=80,
                    height=24
                )
                channel.settimeout(0.1)
            else:
                # Use exec_command with PTY to run tmux directly.
                # This replaces the shell with tmux, attaching to existing or creating new.
                channel = transport.open_session()
                channel.get_pty('xterm-256color', 80, 24)
                channel.exec_command(tmux_cmd)
                channel.settimeout(0.1)
        else:
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
                'proxy_jump_host': proxy_jump_host,
                'auth_type': auth_type,
                'use_tmux': use_tmux,
                'tmux_session_name': tmux_session_name,
                'output_buffer': [],
                'output_buffer_size': 0,
                'output_buffer_max': 512000  # 512KB max buffer
            }
            connection_stored = True

        if socketio_instance and app:
            thread = Thread(
                target=read_ssh_output,
                args=(session_id, socketio_instance, app),
                daemon=True
            )
            thread.start()

        if startup_commands and not reconnect_tmux_name:
            terminal_input = to_terminal_input(startup_commands).rstrip('\r') + '\r'
            delivered, _delivery_error = send_ssh_input(
                session_id, terminal_input, require_complete=True
            )
            if not delivered:
                close_session(session_id)
                return None, "Connection failed"

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
                        import re as _re
                        decoded_data = data.decode('utf-8', errors='replace')
                        # Filter Device Attributes responses (ESC[c sequences only).
                        # Bare-pattern regexes were removed because they corrupt
                        # legitimate output like "padding:0;color:red".
                        decoded_data = _re.sub(r'\x1b\[[?>]?[0-9;]*c', '', decoded_data)
                        if not decoded_data:
                            # Nothing to emit; skip
                            continue
                        socketio_instance.emit('ssh_output', {
                            'session_id': session_id,
                            'data': decoded_data
                        }, room=cached_room)

                        now = time.time()
                        with sessions_lock:
                            if session_id in sessions:
                                sessions[session_id]['last_activity'] = now
                                buf = sessions[session_id].get('output_buffer')
                                if buf is not None:
                                    buf.append(decoded_data)
                                    sessions[session_id]['output_buffer_size'] += len(decoded_data)
                                    # Trim buffer if over max
                                    while sessions[session_id]['output_buffer_size'] > sessions[session_id].get('output_buffer_max', 512000) and len(buf) > 1:
                                        removed = buf.pop(0)
                                        sessions[session_id]['output_buffer_size'] -= len(removed)

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

def send_ssh_input(session_id, data, require_complete=False):
    """Send user input to SSH channel."""
    try:
        import re as _re
        # Filter Device Attributes responses (ESC[c sequences only) that
        # xterm.js may echo back as input. Bare-pattern regexes were removed
        # because they corrupt legitimate input like "100c" or "cat file".
        if isinstance(data, str):
            data = _re.sub(r'\x1b\[[?>]?[0-9;]*c', '', data)
        if not data:
            return True, None

        with sessions_lock:
            if session_id not in sessions:
                return False, "Session not found"

            session = sessions[session_id]
            if not session['connected']:
                return False, "Session not connected"

            channel = session['channel']

        if require_complete:
            remaining = data.encode('utf-8') if isinstance(data, str) else data
            while remaining:
                sent = channel.send(remaining)
                if not isinstance(sent, int) or sent <= 0:
                    return False, "Failed to send SSH input"
                remaining = remaining[sent:]
        else:
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

def close_session(session_id, kill_tmux=False):
    """Close SSH session and clean up resources.

    kill_tmux: If True and the session uses tmux, kill the remote tmux session.
               Default False — idle timeout and server restart detach only,
               leaving tmux running so the session shows up as a reconnect
               candidate. Pass True only from explicit user disconnect.
    """
    try:
        from .sftp_handler import close_sftp_cache
        close_sftp_cache(session_id)

        with sessions_lock:
            if session_id not in sessions:
                return False

            session = sessions[session_id]
            session['connected'] = False

            # Kill tmux session on remote host only on explicit disconnect.
            # Idle timeout and server restart leave tmux running so the
            # session survives and appears as a reconnect candidate.
            if kill_tmux and session.get('use_tmux') and session.get('tmux_session_name') and session['client']:
                try:
                    transport = session['client'].get_transport()
                    if transport and transport.is_active():
                        kill_channel = transport.open_session()
                        kill_channel.exec_command(f'tmux kill-session -t {session["tmux_session_name"]}')
                        kill_channel.settimeout(2.0)
                        try:
                            kill_channel.recv(1)
                        except Exception:
                            pass
                        kill_channel.close()
                except Exception as e:
                    log_debug(f"Error killing tmux session", session_id=session_id, error=str(e))

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
                'via_jump': session.get('proxy_jump_host'),
                'use_tmux': session.get('use_tmux', False),
                'tmux_session_name': session.get('tmux_session_name')
            }
    return None

def get_output_buffer(session_id):
    """Get buffered output for a session (for replay on reconnect)."""
    import re as _re
    with sessions_lock:
        if session_id in sessions:
            buf = sessions[session_id].get('output_buffer')
            if buf:
                output = ''.join(buf)
                # Filter Device Attributes responses (ESC[c sequences only)
                output = _re.sub(r'\x1b\[[?>]?[0-9;]*c', '', output)
                return output
    return ''

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
