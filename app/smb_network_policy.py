"""Exact-target network policy for outbound SMB client connections."""

from __future__ import annotations

import ipaddress
import socket

from .network_policy import ResolvedTarget, canonicalize_hostname


_RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')
)
_ULA_NETWORK = ipaddress.ip_network('fc00::/7')


def parse_smb_allowed_targets(value) -> tuple[str, ...]:
    """Parse a comma-separated list containing only exact hosts or IPs."""

    if value is None:
        return ()
    if isinstance(value, str):
        entries = value.split(',')
    else:
        try:
            entries = tuple(value)
        except TypeError as exc:
            raise ValueError('Invalid SMB target allowlist') from exc

    targets = []
    for raw_entry in entries:
        if not isinstance(raw_entry, str):
            raise ValueError('Invalid SMB target allowlist')
        entry = raw_entry.strip()
        if not entry:
            continue
        if any(character in entry for character in ('/', '\\', '@', '*', '?', '#')):
            raise ValueError('SMB target allowlist accepts exact hosts only')
        try:
            canonical = canonicalize_hostname(entry)
        except ValueError as exc:
            raise ValueError('Invalid SMB target allowlist entry') from exc
        try:
            ipaddress.ip_address(canonical)
        except ValueError:
            if ':' in entry or '[' in entry or ']' in entry:
                raise ValueError('SMB target allowlist does not accept ports')
        if canonical not in targets:
            targets.append(canonical)
    return tuple(targets)


def _address_class_allowed(address) -> bool:
    if (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    ):
        return False
    if address.is_global:
        return True
    if address.version == 4:
        return any(address in network for network in _RFC1918_NETWORKS)
    return address in _ULA_NETWORK


def _resolved_candidate(family, sockaddr):
    if family not in (socket.AF_INET, socket.AF_INET6):
        return None
    try:
        address = ipaddress.ip_address(sockaddr[0])
    except (ValueError, TypeError, IndexError):
        return None
    if address.version == 4 and family != socket.AF_INET:
        return None
    if address.version == 6 and family != socket.AF_INET6:
        return None
    if not _address_class_allowed(address):
        raise ValueError('SMB target is not allowed')
    clean_sockaddr = (
        (address.compressed, 445, 0, 0)
        if family == socket.AF_INET6
        else (address.compressed, 445)
    )
    return address.compressed, family, clean_sockaddr


def resolve_allowed_smb_target(host, allowed_targets) -> ResolvedTarget:
    """Resolve an exact allowlisted SMB host once and validate every answer."""

    canonical = canonicalize_hostname(host)
    allowlist = parse_smb_allowed_targets(allowed_targets)
    if canonical not in allowlist:
        raise ValueError('SMB target is not allowed')

    try:
        literal = ipaddress.ip_address(canonical)
    except ValueError:
        literal = None

    if literal is not None:
        family = socket.AF_INET6 if literal.version == 6 else socket.AF_INET
        candidate = _resolved_candidate(
            family,
            (literal.compressed, 445, 0, 0)
            if family == socket.AF_INET6
            else (literal.compressed, 445),
        )
        ip, family, sockaddr = candidate
        return ResolvedTarget(canonical, 445, ip, family, sockaddr)

    try:
        answers = socket.getaddrinfo(
            canonical,
            445,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except (socket.gaierror, OSError) as exc:
        raise ValueError('SMB target could not be resolved') from exc

    candidates = []
    seen = set()
    for family, socktype, _protocol, _canonname, sockaddr in answers:
        if socktype not in (0, socket.SOCK_STREAM):
            continue
        candidate = _resolved_candidate(family, sockaddr)
        if candidate is None or candidate[:2] in seen:
            continue
        seen.add(candidate[:2])
        candidates.append(candidate)
    if not candidates:
        raise ValueError('SMB target is not allowed')

    ip, family, sockaddr = candidates[0]
    return ResolvedTarget(canonical, 445, ip, family, sockaddr)
