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


def _target_policy_entry(value):
    raw = str(value or '').strip()
    if not raw:
        raise ValueError('empty target')
    host = raw
    port = 22
    if raw.startswith('['):
        end = raw.find(']')
        if end < 0:
            raise ValueError('invalid bracketed target')
        host = raw[1:end]
        suffix = raw[end + 1:]
        if suffix:
            if not suffix.startswith(':') or not suffix[1:].isdigit():
                raise ValueError('invalid target port')
            port = int(suffix[1:])
    elif raw.count(':') == 1:
        possible_host, possible_port = raw.rsplit(':', 1)
        if possible_port.isdigit():
            host = possible_host
            port = int(possible_port)
    if not 1 <= port <= 65535:
        raise ValueError('invalid target port')
    return canonicalize_hostname(host), port


def _allowed_target_pairs():
    return {
        _target_policy_entry(target)
        for target in config.TAILSCALE_SSH_ALLOWED_TARGETS
    }


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

    try:
        canonical_host = canonicalize_hostname(host)
        clean_port = int(port)
        if not 1 <= clean_port <= 65535:
            raise ValueError
    except (TypeError, ValueError):
        return 'Tailscale SSH target is not allowed'

    try:
        allowed_targets = _allowed_target_pairs()
    except (TypeError, ValueError):
        return 'Tailscale SSH target is not allowed'
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
        allowed_targets = _allowed_target_pairs()
        resolved_target = resolve_allowed_target(
            canonical_host,
            clean_port,
            allow_internal=True,
            target_validator=lambda target: target_uses_tailscale_route(
                target.ip
            ),
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
