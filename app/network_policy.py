"""Resolve SSH targets once and connect only to the validated address."""

from dataclasses import dataclass, field
import ipaddress
import socket


@dataclass(frozen=True)
class ResolvedTarget:
    hostname: str
    port: int
    ip: str
    family: int
    sockaddr: tuple | None = None
    # True when only an internal-network allowlist entry permitted the address.
    via_internal_allowlist: bool = field(default=False, compare=False)

    def __post_init__(self):
        if self.sockaddr is not None:
            object.__setattr__(self, 'sockaddr', tuple(self.sockaddr))
            return
        if self.family == socket.AF_INET6:
            sockaddr = (self.ip, self.port, 0, 0)
        elif self.family == socket.AF_INET:
            sockaddr = (self.ip, self.port)
        else:
            raise ValueError('Unsupported address family')
        object.__setattr__(self, 'sockaddr', sockaddr)


class TailnetRouteRestricted(ValueError):
    """A pinned address leaves through the Tailscale SSH interface."""

    code = 'tailscale_route_restricted'

    def __init__(self, message='This target is on the tailnet and requires Tailscale SSH'):
        super().__init__(message)


_TAILSCALE_NODE_NETWORKS = (
    ipaddress.ip_network('100.64.0.0/10'),
    ipaddress.ip_network('fd7a:115c:a1e0::/48'),
)
# Tailscale's 4via6 subnet routes embed a site ID and an IPv4 address in this
# prefix; the destinations behind them are subnet hosts with their own sshd.
_TAILSCALE_4VIA6_NETWORK = ipaddress.ip_network('fd7a:115c:a1e0:b1a::/64')


def _tailscale_node_address(address):
    """Return the address in its routed form if it is a tailnet node address.

    An IPv4-mapped IPv6 address is returned as IPv4: a dual-stack socket sends
    it over IPv4, so only the IPv4 route table describes where it leaves.
    """
    address = ipaddress.ip_address(address)
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.version == 6 and address in _TAILSCALE_4VIA6_NETWORK:
        return None
    if any(
        address.version == network.version and address in network
        for network in _TAILSCALE_NODE_NETWORKS
    ):
        return address
    return None


def _tailnet_route_restricted(address):
    """Return whether an ordinary connection must not use this address.

    tailssh listens on tailnet node addresses and authorizes the WebSSH node,
    not the credential it is offered, so a password or key connection to such
    an address would run under the shared node identity outside every
    Tailscale SSH allowlist. Subnet-route and exit-node destinations run their
    own sshd and stay unaffected. A node address whose route cannot be
    determined is restricted, and so is this node's own tailnet address,
    which the kernel routes through the loopback device. One routed through
    another interface, such as carrier-grade NAT on the local network, is not.
    """
    node_address = _tailscale_node_address(address)
    if node_address is None:
        return False
    interface = _active_tailnet_restriction()
    if interface is None:
        return False
    from . import tailscale_ssh
    route_interface = tailscale_ssh._route_interface_for_ip(node_address.compressed)
    return route_interface in (None, 'lo', interface)


def _active_tailnet_restriction():
    """Return the Tailscale interface while the restriction applies, else None."""
    import config
    interface = str(config.TAILSCALE_SSH_INTERFACE or '').strip()
    if not (config.TAILSCALE_SSH_ENABLED and interface):
        return None
    from .app_settings import is_tailnet_route_restricted
    if not is_tailnet_route_restricted():
        return None
    return interface


_RELAY_MESSAGE = (
    'A proxy or jump host on the WebSSH host itself would use the Tailscale '
    'node identity'
)
_REMOTE_NAME_MESSAGE = (
    'This name resolves to the tailnet and requires Tailscale SSH'
)


def check_relay_endpoint(target):
    """Refuse a SOCKS5 proxy or jump host that would egress as this node.

    A relay on loopback or on one of this host's own addresses shares the
    WebSSH network namespace, for example tailscaled's SOCKS5 server, so its
    onward connections leave with the shared node identity. Tailnet node
    addresses are already refused when the relay address is resolved. A relay
    whose route cannot be determined may be one of those addresses and is
    refused as well.
    """
    if _active_tailnet_restriction() is None:
        return
    if _relay_address_restricted(target.ip):
        raise TailnetRouteRestricted(_RELAY_MESSAGE)


def _relay_address_restricted(ip):
    address = ipaddress.ip_address(ip)
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.is_loopback or address.is_unspecified:
        return True
    from . import tailscale_ssh
    # The kernel routes this host's own addresses through the local table,
    # whose output interface is the loopback device.
    return tailscale_ssh._route_interface_for_ip(address.compressed) in (None, 'lo')


def check_remote_name(hostname):
    """Refuse a name a proxy or bastion would resolve onto the tailnet.

    MagicDNS names are refused outright. Any other name is resolved locally
    once; if a candidate is a restricted tailnet node address, a resolver in
    this network namespace would return the same address. A name that does
    not resolve here stays allowed for the remote side.
    """
    if _active_tailnet_restriction() is None:
        return
    canonical = canonicalize_hostname(hostname)
    if canonical == 'ts.net' or canonical.endswith('.ts.net'):
        raise TailnetRouteRestricted(_REMOTE_NAME_MESSAGE)
    try:
        candidates = socket.getaddrinfo(canonical, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError, UnicodeError):
        return
    for _family, _type, _proto, _canonname, sockaddr in candidates:
        try:
            restricted = _tailnet_route_restricted(sockaddr[0])
        except (ValueError, TypeError, IndexError):
            continue
        if restricted:
            raise TailnetRouteRestricted(_REMOTE_NAME_MESSAGE)


def open_route_restricted(peer_ip, relay_destination=None):
    """Return whether an open ordinary connection uses a now refused route.

    ``peer_ip`` is the address the connection was pinned to: the target, or
    the jump host or SOCKS5 proxy when ``relay_destination`` names what the
    relay connects to. Applies the checks a new connection would pass; an
    unknown or unparsable address is treated as restricted.
    """
    if _active_tailnet_restriction() is None:
        return False
    try:
        if peer_ip is None or _tailnet_route_restricted(peer_ip):
            return True
        if relay_destination is None:
            return False
        if _relay_address_restricted(peer_ip):
            return True
        check_remote_name(relay_destination)
    except ValueError:
        return True
    return False


def canonicalize_hostname(hostname):
    """Return the canonical hostname used for policy and host-key identity."""
    value = str(hostname or '').strip()
    if value.startswith('[') and value.endswith(']'):
        value = value[1:-1]
    value = value.rstrip('.')
    if not value:
        raise ValueError('Host is required')

    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        pass

    try:
        canonical = value.encode('idna').decode('ascii').lower()
    except UnicodeError as error:
        raise ValueError('Invalid host format') from error
    if (
        len(canonical) > 253
        or '*' in canonical
        or any(
            not label
            or len(label) > 63
            or label.startswith('-')
            or label.endswith('-')
            or not all(char.isalnum() or char == '-' for char in label)
            for label in canonical.split('.')
        )
    ):
        raise ValueError('Invalid host format')
    return canonical


def _ip_is_internal(address):
    return (
        not address.is_global
        or address.is_loopback
        or address.is_link_local
        or address.is_private
        or address.is_reserved
        or getattr(address, 'is_site_local', False)
        or address.is_multicast
        or address.is_unspecified
    )


def _ip_is_never_allowlistable(address):
    return (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
        or getattr(address, 'is_site_local', False)
        or (address.version == 6 and address.ipv4_mapped is not None)
    )


def _ip_in_internal_allowlist(address, allowed_networks):
    if _ip_is_never_allowlistable(address):
        return False
    return any(
        address.version == network.version and address in network
        for network in allowed_networks or ()
    )


def _address_decision(address, allow_internal, allowed_networks):
    """Return ``(allowed, via_internal_allowlist)`` for one address."""
    if allow_internal or not _ip_is_internal(address):
        return True, False
    if _ip_in_internal_allowlist(address, allowed_networks):
        return True, True
    return False, False


def resolve_allowed_target(
    hostname,
    port,
    allow_internal=False,
    *,
    target_validator=None,
    allowed_internal_networks=(),
    tailscale_ssh=False,
):
    """Resolve once and select the first policy-allowed TCP address.

    ``allowed_internal_networks`` re-admits internal addresses inside the
    given networks while ``allow_internal`` is false. Loopback, link-local,
    multicast, unspecified, reserved and IPv4-mapped addresses stay blocked.

    While Tailscale SSH is enabled, addresses routed through its interface
    are reserved for the Tailscale SSH strategy, which alone passes
    ``tailscale_ssh=True``. Raises ``TailnetRouteRestricted`` when such an
    address was the only candidate left.
    """
    canonical = canonicalize_hostname(hostname)
    try:
        clean_port = int(port)
    except (TypeError, ValueError) as error:
        raise ValueError('Invalid port number') from error
    if not 1 <= clean_port <= 65535:
        raise ValueError('Port must be between 1 and 65535')

    try:
        literal = ipaddress.ip_address(canonical)
    except ValueError:
        literal = None

    if literal is not None:
        allowed, via_allowlist = _address_decision(
            literal, allow_internal, allowed_internal_networks
        )
        if not allowed:
            raise ValueError('Connections to this address are not allowed')
        if not tailscale_ssh and _tailnet_route_restricted(literal.compressed):
            raise TailnetRouteRestricted()
        target = ResolvedTarget(
            canonical,
            clean_port,
            literal.compressed,
            socket.AF_INET6 if literal.version == 6 else socket.AF_INET,
            via_internal_allowlist=via_allowlist,
        )
        if target_validator is not None and not target_validator(target):
            raise ValueError('Connections to this address are not allowed')
        return target

    try:
        candidates = socket.getaddrinfo(
            canonical,
            clean_port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except (socket.gaierror, OSError) as error:
        raise ValueError('Host could not be resolved') from error

    seen = set()
    tailnet_restricted = False
    for family, socktype, _protocol, _canonname, sockaddr in candidates:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        if socktype not in (0, socket.SOCK_STREAM):
            continue
        sockaddr = tuple(sockaddr)
        candidate_key = (family, sockaddr)
        if candidate_key in seen:
            continue
        seen.add(candidate_key)
        try:
            address = ipaddress.ip_address(sockaddr[0])
        except (ValueError, TypeError, IndexError):
            continue
        if address.version == 4 and family != socket.AF_INET:
            continue
        if address.version == 6 and family != socket.AF_INET6:
            continue
        allowed, via_allowlist = _address_decision(
            address, allow_internal, allowed_internal_networks
        )
        if allowed and not tailscale_ssh and _tailnet_route_restricted(
            address.compressed
        ):
            tailnet_restricted = True
            continue
        if allowed:
            target = ResolvedTarget(
                canonical,
                clean_port,
                address.compressed,
                family,
                sockaddr,
                via_internal_allowlist=via_allowlist,
            )
            if target_validator is None or target_validator(target):
                return target

    if tailnet_restricted:
        raise TailnetRouteRestricted()
    raise ValueError('Connections to this address are not allowed')


def audit_internal_allowlist_use(target, role):
    """Record that SSH_ALLOWED_INTERNAL_NETWORKS admitted a resolved target."""
    if not getattr(target, 'via_internal_allowlist', False):
        return
    from .audit_logger import log_info
    log_info(
        'SSH target admitted by internal network allowlist',
        role=role,
        host=target.hostname,
        ip=target.ip,
        port=target.port,
    )


_LINUX_IP_UNICAST_IF = 50
_LINUX_IPV6_UNICAST_IF = 76


def _bind_unicast_interface(connected, family, interface):
    """Bind one Linux unicast socket to an interface by index."""
    interface_index = socket.htonl(socket.if_nametoindex(interface))
    if family == socket.AF_INET:
        connected.setsockopt(
            socket.IPPROTO_IP,
            _LINUX_IP_UNICAST_IF,
            interface_index,
        )
        return
    if family == socket.AF_INET6:
        connected.setsockopt(
            socket.IPPROTO_IPV6,
            _LINUX_IPV6_UNICAST_IF,
            interface_index,
        )
        return
    raise ValueError('Connections through this interface are not supported')


def open_validated_socket(target, timeout, *, required_interface=None):
    """Connect the pinned address, optionally through one exact interface."""
    connected = socket.socket(target.family, socket.SOCK_STREAM)
    try:
        connected.settimeout(timeout)
        if required_interface is not None:
            _bind_unicast_interface(
                connected,
                target.family,
                required_interface,
            )
        connected.connect(target.sockaddr)
        return connected
    except Exception:
        connected.close()
        raise


def remote_dns_allowed(hostname, allowlist):
    """Match a remote-DNS target against an exact hostname-only allowlist."""
    try:
        candidate = canonicalize_hostname(hostname)
    except ValueError:
        return False
    try:
        ipaddress.ip_address(candidate)
        return False
    except ValueError:
        pass

    for raw_entry in allowlist or ():
        try:
            entry = canonicalize_hostname(raw_entry)
        except ValueError:
            continue
        try:
            ipaddress.ip_address(entry)
            continue
        except ValueError:
            if entry == candidate:
                return True
    return False


proxy_jump_remote_dns_allowed = remote_dns_allowed


def socks_destination(
    host, port, remote_dns, *, allow_internal=False,
    allowed_internal_networks=(), remote_dns_allowlist=(),
):
    """Select a pinned address or an explicitly permitted remote-DNS name."""
    from .socks5_client import RemoteName

    if type(remote_dns) is not bool:
        raise ValueError('Invalid remote DNS setting')
    canonical = canonicalize_hostname(host)
    if '%' in canonical:
        raise ValueError('Scoped addresses cannot be used through a SOCKS5 proxy')
    if isinstance(port, bool) or not isinstance(port, (int, str)):
        raise ValueError('Invalid port number')
    try:
        port = int(port)
    except (TypeError, ValueError) as error:
        raise ValueError('Invalid port number') from error
    if not 1 <= port <= 65535:
        raise ValueError('Port must be between 1 and 65535')
    try:
        ipaddress.ip_address(canonical)
        literal = True
    except ValueError:
        literal = False

    if not literal and remote_dns and (
        allow_internal or remote_dns_allowed(canonical, remote_dns_allowlist)
    ):
        check_remote_name(canonical)
        if not allow_internal:
            from .audit_logger import log_info
            log_info(
                'SOCKS target admitted by remote DNS allowlist',
                role='socks_target', host=canonical, port=port,
            )
        return RemoteName(canonical, port)

    try:
        target = resolve_allowed_target(
            canonical, port, allow_internal=allow_internal,
            allowed_internal_networks=allowed_internal_networks,
        )
    except TailnetRouteRestricted:
        raise
    except ValueError:
        if remote_dns and not allow_internal:
            raise ValueError('Connections to this address are not allowed') from None
        raise
    audit_internal_allowlist_use(target, 'socks_target')
    return target
