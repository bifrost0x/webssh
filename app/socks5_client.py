"""Negotiate bounded SOCKS5 CONNECT tunnels over validated TCP sockets."""

from dataclasses import dataclass
import ipaddress
import math
import socket
import time

from .network_policy import ResolvedTarget, canonicalize_hostname


@dataclass(frozen=True)
class RemoteName:
    hostname: str
    port: int


_MESSAGES = {
    'socks_proxy_failure': 'The SOCKS5 proxy reported a general failure.',
    'socks_not_allowed': 'The SOCKS5 proxy does not allow this connection.',
    'socks_network_unreachable': 'The SOCKS5 proxy cannot reach the target network.',
    'socks_host_unreachable': 'The SOCKS5 proxy cannot reach the target host.',
    'socks_connection_refused': 'The target refused the connection through the SOCKS5 proxy.',
    'socks_ttl_expired': 'The connection through the SOCKS5 proxy timed out.',
    'socks_unsupported': 'The SOCKS5 proxy does not support this request.',
    'socks_protocol_error': 'The SOCKS5 proxy sent an invalid response.',
    'socks_proxy_unreachable': 'The SOCKS5 proxy could not be reached.',
    'socks_timeout': 'The SOCKS5 proxy did not respond in time.',
    'socks_auth_required': 'The SOCKS5 proxy requires a username and password.',
    'socks_auth_rejected': 'The SOCKS5 proxy does not accept username and password login.',
    'socks_auth_failed': 'SOCKS5 proxy login failed. Check the username and password.',
    'connection_cancelled': 'Connection cancelled',
}
_REPLY_CODES = {
    1: 'socks_proxy_failure',
    2: 'socks_not_allowed',
    3: 'socks_network_unreachable',
    4: 'socks_host_unreachable',
    5: 'socks_connection_refused',
    6: 'socks_ttl_expired',
    7: 'socks_unsupported',
    8: 'socks_unsupported',
}


class Socks5Error(Exception):
    """A stable failure code and public message without proxy-supplied details."""

    def __init__(self, code):
        self.code = code if isinstance(code, str) and code in _MESSAGES else 'socks_protocol_error'
        super().__init__(_MESSAGES[self.code])


def _remaining(deadline, cancelled):
    if cancelled is not None:
        try:
            stopped = bool(cancelled())
        except Exception:
            stopped = True
        if stopped:
            raise Socks5Error('connection_cancelled')
    if not isinstance(deadline, (int, float)) or not math.isfinite(deadline):
        raise Socks5Error('socks_protocol_error')
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise Socks5Error('socks_timeout')
    return remaining


def _send_packet(sock, packet, deadline, cancelled):
    sock.settimeout(_remaining(deadline, cancelled))
    sock.sendall(packet)
    _remaining(deadline, cancelled)


def _recv_exact(sock, size, deadline, cancelled):
    data = bytearray()
    while len(data) < size:
        sock.settimeout(_remaining(deadline, cancelled))
        chunk = sock.recv(size - len(data))
        _remaining(deadline, cancelled)
        if not chunk:
            raise Socks5Error('socks_protocol_error')
        data.extend(chunk)
    return bytes(data)


def _authentication_packet(username, password):
    if username is None and password is None:
        return None
    if not all(isinstance(value, str) and 1 <= len(value) <= 255
               for value in (username, password)):
        raise Socks5Error('socks_auth_failed')
    encoded = None
    try:
        encoded = (username.encode('utf-8'), password.encode('utf-8'))
    except UnicodeError:
        pass
    if encoded is None or any(len(value) > 255 for value in encoded):
        raise Socks5Error('socks_auth_failed')
    encoded_user, encoded_password = encoded
    return bytearray(
        b'\x01' + bytes([len(encoded_user)]) + encoded_user
        + bytes([len(encoded_password)]) + encoded_password
    )


def _connect_packet(destination):
    if not isinstance(destination, (ResolvedTarget, RemoteName)):
        raise Socks5Error('socks_protocol_error')
    if type(destination.port) is not int or not 1 <= destination.port <= 65535:
        raise Socks5Error('socks_protocol_error')
    if isinstance(destination, RemoteName):
        hostname = canonicalize_hostname(destination.hostname).encode('ascii')
        if not 1 <= len(hostname) <= 255:
            raise Socks5Error('socks_protocol_error')
        address = b'\x03' + bytes([len(hostname)]) + hostname
    else:
        address_ip = ipaddress.ip_address(destination.ip)
        if address_ip.version == 4 and destination.family == socket.AF_INET:
            address = b'\x01' + address_ip.packed
        elif address_ip.version == 6 and destination.family == socket.AF_INET6:
            # SOCKS5 has no field for an IPv6 interface scope.
            if address_ip.scope_id is not None or (
                len(destination.sockaddr) > 3 and destination.sockaddr[3]
            ):
                raise Socks5Error('socks_protocol_error')
            address = b'\x04' + address_ip.packed
        else:
            raise Socks5Error('socks_protocol_error')
    return b'\x05\x01\x00' + address + destination.port.to_bytes(2, 'big')


def _erase(packet):
    if packet is not None:
        packet[:] = b'\x00' * len(packet)
        packet.clear()


def open_socks5_tunnel(sock, destination, *, username=None, password=None,
                       deadline, cancelled=None):
    """Negotiate CONNECT over an already connected socket and return it."""
    authentication = None
    succeeded = False
    error_code = 'socks_protocol_error'
    try:
        _remaining(deadline, cancelled)
        authentication = _authentication_packet(username, password)
        username = password = None
        request = _connect_packet(destination)
        method = 0 if authentication is None else 2
        _send_packet(sock, bytes([5, 1, method]), deadline, cancelled)
        version, selected = _recv_exact(sock, 2, deadline, cancelled)
        if version != 5:
            raise Socks5Error('socks_protocol_error')
        if selected == 255:
            raise Socks5Error('socks_auth_required' if method == 0 else 'socks_auth_rejected')
        if selected != method:
            raise Socks5Error('socks_protocol_error')

        if method == 2:
            try:
                _send_packet(sock, authentication, deadline, cancelled)
            finally:
                _erase(authentication)
                authentication = None
            version, status = _recv_exact(sock, 2, deadline, cancelled)
            if version not in (1, 5):
                raise Socks5Error('socks_protocol_error')
            if status != 0:
                raise Socks5Error('socks_auth_failed')

        _send_packet(sock, request, deadline, cancelled)
        version, reply, reserved, address_type = _recv_exact(sock, 4, deadline, cancelled)
        if version != 5 or reserved != 0:
            raise Socks5Error('socks_protocol_error')
        # The socket is closed on failure, so a failed reply needs no bound
        # address; proxies that truncate it still report the real reason.
        if reply != 0:
            raise Socks5Error(_REPLY_CODES.get(reply, 'socks_protocol_error'))
        if address_type == 1:
            address_length = 4
        elif address_type == 4:
            address_length = 16
        elif address_type == 3:
            address_length = _recv_exact(sock, 1, deadline, cancelled)[0]
            if not address_length:
                raise Socks5Error('socks_protocol_error')
        else:
            raise Socks5Error('socks_protocol_error')
        _recv_exact(sock, address_length, deadline, cancelled)
        _recv_exact(sock, 2, deadline, cancelled)
        _remaining(deadline, cancelled)
        succeeded = True
    except Socks5Error as error:
        error_code = error.code
    except TimeoutError:
        error_code = 'socks_timeout'
    except Exception:
        error_code = 'socks_protocol_error'
    finally:
        username = password = None
        _erase(authentication)
        authentication = None
        if not succeeded:
            try:
                sock.close()
            except OSError:
                pass

    if not succeeded:
        # Raising outside the handler discards raw exceptions and their locals.
        raise Socks5Error(error_code)
    return sock
