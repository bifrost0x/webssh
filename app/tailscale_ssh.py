"""Authorization policy for the optional shared-identity Tailscale SSH mode."""

from dataclasses import dataclass
import ipaddress
import socket
import struct

import config

from .network_policy import (
    ResolvedTarget,
    canonicalize_hostname,
    resolve_allowed_target,
)


@dataclass(frozen=True)
class TailscaleSSHAuthorization:
    """Attempt-scoped authority for one exact shared-identity connection."""

    user_id: int
    host: str
    port: int
    remote_username: str
    resolved_target: ResolvedTarget

    def matches(self, user_id, host, port, remote_username):
        try:
            canonical_host = canonicalize_hostname(host)
            clean_user_id = int(user_id)
            clean_port = int(port)
        except (TypeError, ValueError):
            return False
        return (
            clean_user_id == self.user_id
            and canonical_host == self.host
            and clean_port == self.port
            and str(remote_username or '').strip() == self.remote_username
            and self.resolved_target.hostname == self.host
            and self.resolved_target.port == self.port
        )


def _allowed_target_pairs():
    allowed = set()
    for target in config.TAILSCALE_SSH_ALLOWED_TARGETS:
        try:
            allowed.add(config.parse_tailscale_ssh_target(target))
        except (TypeError, ValueError):
            # Homelab keeps legacy startup compatibility, but an invalid entry
            # never grants authority and cannot disable a valid sibling.
            continue
    return allowed


_NLMSG_HEADER = struct.Struct('=IHHII')
_RTMSG = struct.Struct('=BBBBBBBBI')
_RTATTR_HEADER = struct.Struct('=HH')
_RTM_NEWROUTE = 24
_RTM_GETROUTE = 26
_NLMSG_ERROR = 2
_NLMSG_DONE = 3
_NLM_F_REQUEST = 1
_RTA_DST = 1
_RTA_OIF = 4


def _align_netlink(length):
    return (length + 3) & ~3


def _netlink_attribute(kind, payload):
    length = _RTATTR_HEADER.size + len(payload)
    return (
        _RTATTR_HEADER.pack(length, kind)
        + payload
        + (b'\x00' * (_align_netlink(length) - length))
    )


def _route_interface_for_ip(address, *, socket_factory=socket.socket):
    """Ask the kernel FIB which interface an exact address will use.

    RTM_GETROUTE follows Linux policy-routing rules, including Tailscale's
    table 52. The proc route files expose only the main table and therefore
    cannot validate normal Tailscale routes.
    """
    try:
        target = ipaddress.ip_address(address)
        family = socket.AF_INET if target.version == 4 else socket.AF_INET6
        sequence = 1
        route_request = _RTMSG.pack(
            family,
            target.max_prefixlen,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ) + _netlink_attribute(_RTA_DST, target.packed)
        message = _NLMSG_HEADER.pack(
            _NLMSG_HEADER.size + len(route_request),
            _RTM_GETROUTE,
            _NLM_F_REQUEST,
            sequence,
            0,
        ) + route_request
        route_socket = socket_factory(
            socket.AF_NETLINK,
            socket.SOCK_RAW,
            socket.NETLINK_ROUTE,
        )
        try:
            route_socket.settimeout(1.0)
            route_socket.bind((0, 0))
            route_socket.sendto(message, (0, 0))
            while True:
                response = route_socket.recv(65535)
                offset = 0
                while offset + _NLMSG_HEADER.size <= len(response):
                    length, kind, _flags, reply_sequence, _pid = (
                        _NLMSG_HEADER.unpack_from(response, offset)
                    )
                    if (
                        length < _NLMSG_HEADER.size
                        or offset + length > len(response)
                    ):
                        return None
                    payload = response[
                        offset + _NLMSG_HEADER.size:offset + length
                    ]
                    if reply_sequence == sequence:
                        if kind == _NLMSG_ERROR:
                            return None
                        if kind == _NLMSG_DONE:
                            return None
                        if kind == _RTM_NEWROUTE and len(payload) >= _RTMSG.size:
                            attributes = payload[_RTMSG.size:]
                            attr_offset = 0
                            while attr_offset + _RTATTR_HEADER.size <= len(attributes):
                                attr_length, attr_kind = _RTATTR_HEADER.unpack_from(
                                    attributes, attr_offset
                                )
                                if (
                                    attr_length < _RTATTR_HEADER.size
                                    or attr_offset + attr_length > len(attributes)
                                ):
                                    return None
                                attr_payload = attributes[
                                    attr_offset + _RTATTR_HEADER.size:
                                    attr_offset + attr_length
                                ]
                                if attr_kind == _RTA_OIF and len(attr_payload) >= 4:
                                    interface_index = struct.unpack_from(
                                        '=I', attr_payload
                                    )[0]
                                    return socket.if_indextoname(interface_index)
                                attr_offset += _align_netlink(attr_length)
                    offset += _align_netlink(length)
        finally:
            route_socket.close()
    except (AttributeError, OSError, TypeError, ValueError):
        return None


def _interface_present(name):
    try:
        socket.if_nametoindex(name)
    except (OSError, ValueError):
        return False
    return True


def log_tailnet_route_restriction(event):
    """Record the effective restriction while Tailscale SSH is enabled.

    With the restriction lifted, any WebSSH user can reach tailssh nodes
    under the shared node identity, so that state is logged as a warning.
    Returns the effective value, or None while Tailscale SSH is disabled.
    """
    if not config.TAILSCALE_SSH_ENABLED:
        # The block only applies while the feature is enabled. A Tailscale
        # interface on the host suggests the node may still be logged in.
        interface = str(config.TAILSCALE_SSH_INTERFACE or '').strip() or 'tailscale0'
        if _interface_present(interface):
            from .audit_logger import log_warning
            log_warning(
                'Tailscale SSH is disabled but the Tailscale interface exists; '
                'ordinary SSH to tailnet nodes is not blocked, see '
                'docs/tailscale-ssh.md',
                event=event, interface=interface,
            )
        return None
    from .app_settings import is_tailnet_route_restricted
    from .audit_logger import log_info, log_warning
    try:
        restricted = is_tailnet_route_restricted()
    except Exception as error:
        log_warning('Tailnet route restriction could not be read',
                    event=event, error_type=type(error).__name__)
        return None
    if restricted:
        log_info('Ordinary SSH to Tailscale node addresses is blocked',
                 event=event, tailscale_ssh_restrict_tailnet_routes=True)
    else:
        log_warning(
            'Ordinary SSH to Tailscale node addresses is allowed; any WebSSH '
            'user can reach Tailscale SSH nodes under the shared node identity',
            event=event, tailscale_ssh_restrict_tailnet_routes=False,
        )
    return restricted


def close_restricted_tailnet_connections(socketio_instance=None):
    """Close open ordinary connections that the tailnet block now refuses.

    Called when an administrator turns the block on. Terminal sessions are
    detached the way an administrator disconnect detaches them: tmux keeps
    running and the owner is told why. Tailscale SSH sessions stay open.
    """
    from .network_policy import _active_tailnet_restriction, open_route_restricted
    result = {'ssh_sessions': 0, 'pool_connections': 0, 'errors': 0}
    if _active_tailnet_restriction() is None:
        return result
    from . import connection_pool, ssh_manager
    from .audit_logger import log_security_event, log_warning
    from .models import SSHSession, db

    if socketio_instance is None:
        from . import socketio as socketio_instance

    with ssh_manager.sessions_lock:
        candidates = [
            (session_id, session.get('user_id'), session.get('peer_ip'),
             session.get('relay_destination'))
            for session_id, session in ssh_manager.sessions.items()
            if session.get('auth_type') != 'tailscale'
        ]
    closed = []
    for session_id, user_id, peer_ip, relay_destination in candidates:
        if not open_route_restricted(peer_ip, relay_destination):
            continue

        def notify_owner(session_id=session_id, user_id=user_id):
            socketio_instance.emit('ssh_disconnected', {
                'session_id': session_id,
                'reason': 'This host is on the tailnet and requires Tailscale SSH',
            }, room=f'user_{user_id}')

        try:
            if ssh_manager.close_session(session_id, kill_tmux=False,
                                         on_disconnect=notify_owner):
                closed.append(session_id)
        except Exception as error:
            result['errors'] += 1
            log_warning('Tailnet-restricted SSH session could not be closed',
                        session_id=session_id, error_type=type(error).__name__)
    result['ssh_sessions'] = len(closed)
    if closed:
        try:
            SSHSession.query.filter(SSHSession.session_id.in_(closed)).update(
                {'connected': False}, synchronize_session=False,
            )
            db.session.commit()
        except Exception as error:
            db.session.rollback()
            result['errors'] += 1
            log_warning('Closed tailnet-restricted sessions could not be marked',
                        error_type=type(error).__name__)

    try:
        result['pool_connections'] = (
            connection_pool.temp_connection_pool.close_connections_where(
                open_route_restricted
            )
        )
    except Exception as error:
        result['errors'] += 1
        log_warning('Tailnet-restricted file connections could not be closed',
                    error_type=type(error).__name__)

    log_security_event('TAILNET_RESTRICTED_CONNECTIONS_CLOSED', **result)
    return result


def target_uses_tailscale_route(address):
    """Require the pinned target to leave through the configured tailnet."""
    return _route_interface_for_ip(address) == config.TAILSCALE_SSH_INTERFACE


def user_can_use_tailscale_ssh(user):
    """Return whether a WebSSH user may use the node's Tailscale identity."""
    if not config.TAILSCALE_SSH_ENABLED or not user:
        return False
    return bool(
        getattr(user, 'is_admin', False)
        or getattr(user, 'username', None) in config.TAILSCALE_SSH_ALLOWED_WEBSSH_USERS
    )


def validate_tailscale_ssh_access(user, host, remote_username, port=22):
    """Return an error message when the shared Tailscale identity is denied."""
    if not user_can_use_tailscale_ssh(user):
        return 'Tailscale SSH is not enabled for this account'
    if not str(config.TAILSCALE_SSH_INTERFACE or '').strip():
        return 'Tailscale SSH target is not allowed'

    try:
        canonical_host = canonicalize_hostname(host)
        clean_port = int(port)
        if not 1 <= clean_port <= 65535:
            raise ValueError
    except (TypeError, ValueError):
        return 'Tailscale SSH target is not allowed'

    allowed_targets = _allowed_target_pairs()
    if not allowed_targets or (canonical_host, clean_port) not in allowed_targets:
        return 'Tailscale SSH target is not allowed'

    clean_remote_username = str(remote_username or '').strip()
    allowed_remote_users = config.TAILSCALE_SSH_ALLOWED_REMOTE_USERS
    if allowed_remote_users and clean_remote_username not in allowed_remote_users:
        return 'Tailscale SSH remote username is not allowed'

    return None


def authorize_tailscale_ssh_access(user, host, remote_username, port=22):
    """Return an exact internal authorization object or a safe error."""
    error = validate_tailscale_ssh_access(
        user, host, remote_username, port=port
    )
    if error:
        return None, error
    try:
        user_id = int(getattr(user, 'id'))
        canonical_host = canonicalize_hostname(host)
        clean_port = int(port)
        resolved_target = resolve_allowed_target(
            canonical_host,
            clean_port,
            allow_internal=True,
            target_validator=lambda target: target_uses_tailscale_route(
                target.ip
            ),
            tailscale_ssh=True,
        )
    except (TypeError, ValueError):
        return None, 'Tailscale SSH target is not allowed'
    return TailscaleSSHAuthorization(
        user_id=user_id,
        host=canonical_host,
        port=clean_port,
        remote_username=str(remote_username or '').strip(),
        resolved_target=resolved_target,
    ), None


def profile_is_authorized_for_launch(user, profile):
    """Return whether a saved profile is still allowed by current policy."""
    if not isinstance(profile, dict) or profile.get('auth_type') != 'tailscale':
        return True
    return validate_tailscale_ssh_access(
        user,
        profile.get('host'),
        profile.get('username'),
        port=profile.get('port', 22),
    ) is None
