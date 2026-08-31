"""Resolve SSH targets once and connect only to the validated address."""

from dataclasses import dataclass
import ipaddress
import socket


@dataclass(frozen=True)
class ResolvedTarget:
    hostname: str
    port: int
    ip: str
    family: int
    sockaddr: tuple | None = None

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


def resolve_allowed_target(hostname, port, allow_internal=False):
    """Resolve once and select the first policy-allowed TCP address."""
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
        if not allow_internal and _ip_is_internal(literal):
            raise ValueError('Connections to this address are not allowed')
        return ResolvedTarget(
            canonical,
            clean_port,
            literal.compressed,
            socket.AF_INET6 if literal.version == 6 else socket.AF_INET,
        )

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
        if allow_internal or not _ip_is_internal(address):
            return ResolvedTarget(
                canonical,
                clean_port,
                address.compressed,
                family,
                sockaddr,
            )

    raise ValueError('Connections to this address are not allowed')


def open_validated_socket(target, timeout):
    """Connect a TCP socket to the already resolved address without DNS."""
    connected = socket.socket(target.family, socket.SOCK_STREAM)
    try:
        connected.settimeout(timeout)
        connected.connect(target.sockaddr)
        return connected
    except Exception:
        connected.close()
        raise


def proxy_jump_remote_dns_allowed(hostname, allowlist):
    """Match a remote-only ProxyJump target against an exact hostname list."""
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
