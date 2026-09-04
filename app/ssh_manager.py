import paramiko
from paramiko.auth_strategy import AuthStrategy, NoneAuth
import shlex
import time
import uuid
import socket
from threading import Lock, Timer
import config
from .audit_logger import log_info, log_warning, log_error, log_debug
from .host_key_store import HostKeyStore
from .network_policy import (
    canonicalize_hostname,
    open_validated_socket,
    proxy_jump_remote_dns_allowed,
    resolve_allowed_target,
)
from .ssh_key_loader import load_private_key as _load_private_key
from .ssh_errors import SSHConnectionError
from .startup_commands import to_terminal_input
from .tailscale_ssh import TailscaleSSHAuthorization
from . import paramiko_channels
from .quota_manager import (
    QuotaExceeded,
    QuotaKind,
    quota_manager,
    release_reservation,
)
from .ssh_output_flow import emit_ssh_output

sessions = {}
sessions_lock = Lock()
TMUX_KILL_TIMEOUT = 2.0
TMUX_PROBE_TIMEOUT = 2.0
SSH_AUTH_BANNER_MAX_CHARS = 16 * 1024


class TailscaleSSHAuthStrategy(AuthStrategy):
    """Authenticate through Tailscale SSH without user-managed credentials."""

    def __init__(self, username):
        super().__init__(ssh_config=None)
        self.username = username

    def get_sources(self):
        yield NoneAuth(self.username)


def _configure_host_key_trust(client, store):
    store.load_into(client)
    client.set_missing_host_key_policy(store.missing_key_policy())


def _authentication_banner(transport):
    """Return a bounded, display-safe SSH authentication banner."""
    get_banner = getattr(transport, 'get_banner', None)
    if not callable(get_banner):
        return ''
    banner = get_banner()
    if banner is None:
        return ''
    if isinstance(banner, bytes):
        banner = banner.decode('utf-8', errors='replace')
    else:
        banner = str(banner)
    banner = banner.replace('\r\n', '\n').replace('\r', '\n')
    banner = ''.join(
        character
        for character in banner
        if character in {'\n', '\t'} or character.isprintable()
    )
    return banner[:SSH_AUTH_BANNER_MAX_CHARS].strip()


def _authentication_banner_accepted(transport, decision_callback, context):
    banner = _authentication_banner(transport)
    if not banner or decision_callback is None:
        return True
    try:
        return decision_callback(banner, context) is True
    except Exception as error:
        log_warning(
            "SSH authentication banner decision failed",
            context=context,
            error_type=type(error).__name__,
        )
        return False


def _open_exec_channel(transport, command, *, timeout, pty=None):
    """Open a bounded exec channel for a reviewed, fully quoted command."""
    channel = transport.open_session(timeout=timeout)
    channel.settimeout(timeout)
    timeout_guard = Timer(timeout, channel.close)
    timeout_guard.daemon = True
    timeout_guard.start()
    try:
        if pty is not None:
            channel.get_pty(*pty)
        # Intentional SSH command boundary; callers provide reviewed quoting.
        channel.exec_command(command)  # nosec B601
    except Exception:
        channel.close()
        raise
    finally:
        timeout_guard.cancel()
    return channel


def _probe_tmux_session(session):
    """Return True/False only when the remote tmux state can be confirmed."""
    client = session.get('client')
    tmux_session_name = session.get('tmux_session_name')
    if not client or not tmux_session_name:
        return None

    probe_channel = None
    try:
        transport = client.get_transport()
        if not transport or not transport.is_active():
            return None
        probe_channel = _open_exec_channel(
            transport,
            'tmux has-session -t ' + shlex.quote(tmux_session_name),
            timeout=TMUX_PROBE_TIMEOUT,
        )
        probe_channel.recv(1)
        if not probe_channel.exit_status_ready():
            return None
        return probe_channel.recv_exit_status() == 0
    except Exception as error:
        log_debug(
            "Unable to confirm remote tmux session",
            error_type=type(error).__name__,
        )
        return None
    finally:
        if probe_channel is not None:
            try:
                probe_channel.close()
            except Exception:
                pass

def create_ssh_connection(host, port, username, password=None, key_path=None, key_content=None,
                          socketio_instance=None, app=None, user_id=None,
                          proxy_jump_host=None, proxy_jump_port=None, proxy_jump_username=None,
                          proxy_jump_password=None, proxy_jump_key_content=None,
                          use_tmux=False, reconnect_tmux_name=None,
                          auth_type='password', startup_commands='',
                          auth_banner_decision=None,
                          tailscale_authorization=None):
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
        auth_banner_decision: Callback that must accept a server banner before
            any forwarding channel, shell, tmux probe, or startup command opens
    """
    try:
        host_key_store = HostKeyStore(
            user_id, config.KNOWN_HOSTS_FILE, config.USERS_DIR
        )
    except (TypeError, ValueError):
        return None, "User identity is required"
    user_id = host_key_store.user_id

    tailscale_target_authorized = False
    if auth_type == 'tailscale':
        if (
            not isinstance(
                tailscale_authorization,
                TailscaleSSHAuthorization,
            )
            or not tailscale_authorization.matches(
                user_id,
                host,
                username,
            )
        ):
            return None, 'Tailscale SSH authorization is invalid'
        tailscale_target_authorized = True

    try:
        reservation = quota_manager.reserve(
            QuotaKind.SSH_SESSION, user_id
        )
    except QuotaExceeded:
        return None, "Maximum number of sessions reached"

    bastion_client = None
    client = None
    validated_socket = None
    connection_stored = False
    try:
        # Optional ProxyJump: connect to the bastion first, then tunnel to the target.
        sock = None
        if proxy_jump_host:
            try:
                host = canonicalize_hostname(host)
                proxy_jump_host = canonicalize_hostname(proxy_jump_host)
                try:
                    target = resolve_allowed_target(
                        host,
                        port,
                        allow_internal=(
                            not config.BLOCK_INTERNAL_SSH
                            or tailscale_target_authorized
                        ),
                    )
                    channel_destination = (target.ip, target.port)
                    host = target.hostname
                    port = target.port
                except ValueError:
                    remote_dns_allowed = (
                        not config.BLOCK_INTERNAL_SSH
                        or proxy_jump_remote_dns_allowed(
                            host,
                            config.PROXY_JUMP_REMOTE_DNS_ALLOWLIST,
                        )
                    )
                    if not remote_dns_allowed:
                        return (
                            None,
                            'Connections to this address are not allowed',
                        )
                    host = canonicalize_hostname(host)
                    port = int(port)
                    channel_destination = (host, port)

                bastion_target = resolve_allowed_target(
                    proxy_jump_host,
                    proxy_jump_port or 22,
                    allow_internal=not config.BLOCK_INTERNAL_SSH,
                )
                validated_socket = open_validated_socket(
                    bastion_target, config.SSH_CONNECT_TIMEOUT
                )
                bastion_client = paramiko.SSHClient()
                _configure_host_key_trust(bastion_client, host_key_store)

                bastion_auth = {
                    'hostname': bastion_target.hostname,
                    'port': bastion_target.port,
                    'username': proxy_jump_username,
                    'timeout': config.SSH_CONNECT_TIMEOUT,
                    'sock': validated_socket,
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

                if not _authentication_banner_accepted(
                    bastion_transport, auth_banner_decision, 'jump_host'
                ):
                    return None, SSHConnectionError(
                        "SSH authentication banner was not accepted",
                        code="auth_banner_declined",
                        context="jump_host",
                    )

                sock = bastion_transport.open_channel(
                    'direct-tcpip',
                    channel_destination,
                    ('127.0.0.1', 0),
                    timeout=config.SSH_CONNECT_TIMEOUT,
                )
                log_info("Jump host connection established", bastion=proxy_jump_host)
            except paramiko.BadHostKeyException:
                log_warning(
                    "SSH host key changed",
                    host=f"{proxy_jump_host}:{proxy_jump_port or 22}",
                    context="jump_host",
                )
                return None, SSHConnectionError(
                    "SSH host key changed",
                    code="host_key_changed",
                    context="jump_host",
                )
            except paramiko.AuthenticationException:
                return None, "Jump host authentication failed - invalid credentials"
            except Exception as e:
                log_warning(
                    "Jump host connection failed",
                    bastion=proxy_jump_host,
                    error_type=type(e).__name__,
                )
                return None, "Jump host connection failed"
        else:
            target = resolve_allowed_target(
                host,
                port,
                allow_internal=(
                    not config.BLOCK_INTERNAL_SSH
                    or tailscale_target_authorized
                ),
            )
            host = target.hostname
            port = target.port
            validated_socket = open_validated_socket(
                target, config.SSH_CONNECT_TIMEOUT
            )
            sock = validated_socket

        client = paramiko.SSHClient()
        _configure_host_key_trust(client, host_key_store)

        auth_kwargs = {
            'hostname': host,
            'port': port,
            'username': username,
            'timeout': config.SSH_CONNECT_TIMEOUT,
            'sock': sock,
        }

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

        if not _authentication_banner_accepted(
            transport, auth_banner_decision, 'target'
        ):
            return None, SSHConnectionError(
                "SSH authentication banner was not accepted",
                code="auth_banner_declined",
                context="target",
            )

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
                tmux_cmd = (
                    f'{tmux_command} new-session -A -s '
                    f'{shlex.quote(tmux_session_name)}'
                )
            else:
                unique_suffix = uuid.uuid4().hex[:8]
                tmux_session_name = f"{config.TMUX_SESSION_PREFIX}_{safe_user}_{safe_host}_{port}_{unique_suffix}"
                tmux_cmd = (
                    f'{tmux_command} new-session -s '
                    f'{shlex.quote(tmux_session_name)}'
                )

            log_info("Using tmux persistent session", tmux_session=tmux_session_name, host=f"{host}:{port}")

            # Probe for tmux on a separate exec channel before opening the
            # real session. This avoids locale-dependent error string matching
            # and avoids swallowing tmux's initial screen draw.
            probe_channel = _open_exec_channel(
                transport,
                'command -v tmux',
                timeout=3.0,
            )
            try:
                probe_channel.recv(1)
            except Exception:
                pass
            try:
                tmux_available = paramiko_channels.wait_for_exit_status(
                    probe_channel,
                    timeout=3.0,
                ) == 0
            except socket.timeout:
                tmux_available = False
            finally:
                probe_channel.close()

            if not tmux_available:
                log_warning("tmux not found on target host, falling back to regular shell",
                           host=f"{host}:{port}")
                tmux_session_name = None
                use_tmux = False
                channel = paramiko_channels.open_shell_channel(
                    transport,
                    timeout=config.SSH_CONNECT_TIMEOUT,
                    term='xterm-256color',
                    width=80,
                    height=24
                )
                channel.settimeout(0.1)
            else:
                # Use exec_command with PTY to run tmux directly.
                # This replaces the shell with tmux, attaching to existing or creating new.
                channel = _open_exec_channel(
                    transport,
                    tmux_cmd,
                    timeout=config.SSH_CONNECT_TIMEOUT,
                    pty=('xterm-256color', 80, 24),
                )
                channel.settimeout(0.1)
        else:
            channel = paramiko_channels.open_shell_channel(
                transport,
                timeout=config.SSH_CONNECT_TIMEOUT,
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
                'output_buffer_max': 512000,  # 512KB max buffer
                'output_sequence': 0,
                'quota_reservation': reservation,
                'reader_handle': None,
            }
            connection_stored = True

        if socketio_instance and app:
            lifecycle = getattr(app, 'extensions', {}).get('runtime_lifecycle')
            if lifecycle is None:
                close_session(session_id, kill_tmux=use_tmux)
                return None, "Connection failed"
            try:
                reader_handle = lifecycle.start_job(
                    'ssh_output_reader',
                    lambda cancel_event: read_ssh_output(
                        session_id, socketio_instance, app, cancel_event
                    ),
                    owner_id=user_id,
                )
            except Exception as exc:
                log_error(
                    'Unable to start SSH output reader',
                    session_id=session_id,
                    error_type=type(exc).__name__,
                )
                close_session(session_id, kill_tmux=use_tmux)
                return None, "Connection failed"
            with sessions_lock:
                active_session = sessions.get(session_id)
                if active_session is None:
                    reader_handle.cancel()
                else:
                    active_session['reader_handle'] = reader_handle

        if startup_commands and not reconnect_tmux_name:
            terminal_input = to_terminal_input(startup_commands).rstrip('\r') + '\r'
            delivered, _delivery_error = send_ssh_input(
                session_id, terminal_input, require_complete=True
            )
            if not delivered:
                close_session(session_id, kill_tmux=use_tmux)
                return None, "Connection failed"

        return session_id, None

    except paramiko.BadHostKeyException:
        log_warning(
            "SSH host key changed",
            host=f"{host}:{port}",
            context="target",
        )
        return None, SSHConnectionError(
            "SSH host key changed",
            code="host_key_changed",
            context="target",
        )
    except paramiko.AuthenticationException:
        return None, "Authentication failed - invalid credentials"
    except ValueError as e:
        return None, str(e)
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
        if not connection_stored:
            release_reservation(reservation)

        # Avoid leaking the bastion connection if the target connect failed.
        if bastion_client is not None and not connection_stored:
            try:
                bastion_client.close()
            except Exception:
                pass
        if client is not None and not connection_stored:
            try:
                client.close()
            except Exception:
                pass
        if validated_socket is not None and not connection_stored:
            try:
                validated_socket.close()
            except Exception:
                pass

def record_output(session_id, decoded_data, *, now=None):
    """Append one output chunk and return its monotone session sequence."""
    activity_time = time.time() if now is None else now
    with sessions_lock:
        session = sessions.get(session_id)
        if not session or not session.get('connected'):
            return None
        sequence = session.get('output_sequence', 0) + 1
        session['output_sequence'] = sequence
        session['last_activity'] = activity_time
        buf = session.get('output_buffer')
        if buf is not None:
            buf.append(decoded_data)
            session['output_buffer_size'] += len(decoded_data)
            while (
                session['output_buffer_size']
                > session.get('output_buffer_max', 512000)
                and len(buf) > 1
            ):
                removed = buf.pop(0)
                session['output_buffer_size'] -= len(removed)
        return sequence


def read_ssh_output(session_id, socketio_instance, app, cancel_event=None):
    """Continuously read SSH output and emit it until cancelled or disconnected.

    IMPORTANT: Do NOT use select.select() on the Paramiko channel here.
    Let Paramiko own transport readiness and use channel.recv() with a finite
    timeout, so the reader observes cancellation and concurrent SFTP activity
    continues to make progress on the shared transport.
    """
    from datetime import datetime, timezone

    cached_room = None
    cached_user_id = None
    last_db_update = 0
    persistent_tmux_available = None

    try:
        with app.app_context():
            from .models import SSHSession, db

            db_session = None
            for _attempt in range(30):
                if cancel_event is not None and cancel_event.is_set():
                    return
                db_session = SSHSession.query.filter_by(session_id=session_id).first()
                if db_session:
                    break
                if cancel_event is not None:
                    if cancel_event.wait(0.1):
                        return
                else:
                    time.sleep(0.1)

            if db_session:
                cached_user_id = db_session.user_id
                cached_room = f'user_{db_session.user_id}'

            if not cached_room:
                log_error("No DB session found for output reader", session_id=session_id)
                return

            while cancel_event is None or not cancel_event.is_set():
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
                        now = time.time()
                        sequence = record_output(
                            session_id, decoded_data, now=now
                        )
                        if sequence is None:
                            break
                        emit_ssh_output(socketio_instance, cached_room, cached_user_id, session_id, {
                            'session_id': session_id,
                            'data': decoded_data,
                            'sequence': sequence,
                        }, cancel_event=cancel_event)

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
                    log_error("Error reading from channel", error=str(e), exc_info=True)
                    break

                if channel.closed or channel.exit_status_ready():
                    break

    except Exception as e:
        log_error("Error in output reader thread", error=str(e), exc_info=True)
    finally:
        reader_cancelled = cancel_event is not None and cancel_event.is_set()
        with sessions_lock:
            closing_session = sessions.get(session_id)
        if (
            not reader_cancelled
            and closing_session
            and closing_session.get('use_tmux')
        ):
            persistent_tmux_available = _probe_tmux_session(closing_session)

        with app.app_context():
            from .models import SSHSession, db
            db_session = SSHSession.query.filter_by(session_id=session_id).first()
            if db_session:
                room = cached_room or f'user_{db_session.user_id}'
                if db_session.is_persistent and persistent_tmux_available is False:
                    db.session.delete(db_session)
                else:
                    db_session.connected = False
                db.session.commit()

                socketio_instance.emit('ssh_disconnected', {
                    'session_id': session_id,
                    'reason': 'Connection closed'
                }, room=room)

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
    reservation = None
    reader_handle = None
    try:
        with sessions_lock:
            session = sessions.pop(session_id, None)
            if session is None:
                return False
            session['connected'] = False
        reservation = session.get('quota_reservation')
        reader_handle = session.get('reader_handle')
        if reader_handle is not None:
            reader_handle.cancel()

        # All network I/O happens after removing the session from the shared
        # registry, so a slow or half-open SSH transport cannot block unrelated
        # session operations behind sessions_lock.
        try:
            from .sftp_handler import close_sftp_cache
            close_sftp_cache(session_id)
        except Exception as e:
            log_debug("Error closing SFTP cache", session_id=session_id, error=str(e))

        if kill_tmux and session.get('use_tmux') and session.get('tmux_session_name') and session['client']:
            kill_channel = None
            try:
                transport = session['client'].get_transport()
                if transport and transport.is_active():
                    command = 'tmux kill-session -t ' + shlex.quote(session['tmux_session_name'])
                    kill_channel = _open_exec_channel(
                        transport,
                        command,
                        timeout=TMUX_KILL_TIMEOUT,
                    )
                    try:
                        kill_channel.recv(1)
                    except Exception:
                        pass
            except Exception as e:
                log_debug("Error killing tmux session", session_id=session_id, error=str(e))
            finally:
                if kill_channel is not None:
                    try:
                        kill_channel.close()
                    except Exception:
                        pass

        if session['channel']:
            try:
                session['channel'].close()
            except Exception as e:
                log_debug("Error closing channel", session_id=session_id, error=str(e))

        if session['client']:
            try:
                session['client'].close()
            except Exception as e:
                log_debug("Error closing SSH client", session_id=session_id, error=str(e))

        if session.get('bastion_client'):
            try:
                session['bastion_client'].close()
            except Exception as e:
                log_debug("Error closing jump host client", session_id=session_id, error=str(e))

        if reader_handle is not None:
            reader_handle.join(1.0)

        return True
    except Exception as e:
        log_error("Error closing session", session_id=session_id, error=str(e))
        return False
    finally:
        release_reservation(reservation)

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
    return get_output_snapshot(session_id)[0]


def get_output_snapshot(session_id):
    """Return buffered output and its atomic monotone sequence watermark."""
    import re as _re
    with sessions_lock:
        if session_id in sessions:
            buf = sessions[session_id].get('output_buffer')
            if buf:
                output = ''.join(buf)
                # Filter Device Attributes responses (ESC[c sequences only)
                output = _re.sub(r'\x1b\[[?>]?[0-9;]*c', '', output)
                return output, sessions[session_id].get('output_sequence', 0)
            return '', sessions[session_id].get('output_sequence', 0)
    return '', 0

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
        log_error("Error cleaning up idle sessions", error=str(e))

import atexit

def cleanup_all_sessions():
    """Close all sessions on application exit."""
    with sessions_lock:
        session_ids = list(sessions.keys())

    for session_id in session_ids:
        close_session(session_id)

atexit.register(cleanup_all_sessions)
