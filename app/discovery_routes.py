"""Manual discovery of SSH endpoints in a network range the user names.

A scan is started only by an explicit request. It probes at most 256
addresses, one TCP connection per address and port, under the same network
policy as SSH connections. It never sends data: it reads the greeting that an
SSH server sends on its own and closes the socket. New connection attempts
are paced (a few per second, few in flight) so a scan does not flood the
network; it is not hidden from monitoring, and an IDS may still notice it.
"""
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import ipaddress
import re
import secrets
import socket
import threading
import time

from flask import Blueprint, current_app, jsonify, request
from flask_login import current_user, login_required

import config
from .audit_logger import log_security_event
from .auth import check_user_rate_limit
from .login_access import login_access
from .auth_assurance import current_authentication_session

discovery_blueprint = Blueprint('discovery', __name__)

MAX_ADDRESSES = 256
MAX_PORTS = 3
START_INTERVAL_SECONDS = 0.3   # at most ~3 new connection attempts per second
IN_FLIGHT = 3                  # concurrent attempts per scan
CONNECT_TIMEOUT_SECONDS = 1.5
BANNER_TIMEOUT_SECONDS = 2.0
REVERSE_DNS_TIMEOUT_SECONDS = 1.0
MAX_RUNNING_SCANS = 2          # in the whole process
RESULT_RETENTION_SECONDS = 15 * 60
RATE_LIMIT = '10 per hour'
_BANNER = re.compile(r'^SSH-(?P<protocol>[0-9.]+)-(?P<software>[!-~]{1,100})(?: (?P<comment>[ -~]{0,120}))?$')
_PLATFORM_HINTS = (
    ('raspberrypi', re.compile(r'raspbian|raspberry', re.I)),
    ('ubuntu', re.compile(r'ubuntu', re.I)),
    ('debian', re.compile(r'debian', re.I)),
    ('freebsd', re.compile(r'freebsd', re.I)),
    ('fedora', re.compile(r'fedora|\.fc\d+', re.I)),
    ('alpinelinux', re.compile(r'alpine', re.I)),
)

_LOCK = threading.Lock()
_SCANS = {}
# Scans run on their own small pool so they never take a worker that SSH
# sessions or other background jobs are sized for.
_RUNNERS = ThreadPoolExecutor(max_workers=MAX_RUNNING_SCANS, thread_name_prefix='discovery-scan')
# Reverse lookups can block without a timeout of their own; they run here.
_RESOLVER = ThreadPoolExecutor(max_workers=2, thread_name_prefix='discovery-dns')


def discovery_available():
    """HOST_DISCOVERY_ENABLED; off by default in production, where the server could scan third parties."""
    return config.HOST_DISCOVERY_ENABLED


class ScanRequestError(ValueError):
    """Invalid scan input; ``code`` selects a fixed message, never the exception text."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


_INPUT_MESSAGES = {
    'network': 'Enter a network such as 192.168.1.0/24.',
    'network_size': 'Choose a range of at most 256 addresses (for example a /24).',
    'ports': 'Choose up to three ports between 1 and 65535.',
}


def parse_network(value):
    """Return the addresses to probe, or raise ScanRequestError."""
    if not isinstance(value, str) or not value.strip() or len(value) > 64:
        raise ScanRequestError('network')
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        raise ScanRequestError('network') from None
    if network.num_addresses > MAX_ADDRESSES:
        raise ScanRequestError('network_size')
    if network.version == 4 and network.prefixlen < 31:
        return [str(address) for address in network.hosts()]
    return [str(address) for address in network]


def parse_ports(value):
    if value is None:
        return [22]
    if (not isinstance(value, list) or not 1 <= len(value) <= MAX_PORTS
            or not all(type(port) is int and 1 <= port <= 65535 for port in value)):
        raise ScanRequestError('ports')
    return sorted(set(value))


def describe_banner(raw):
    """Parse an SSH greeting into printable software and platform hints."""
    line = raw.split(b'\n', 1)[0].rstrip(b'\r').decode('ascii', 'replace')
    match = _BANNER.match(line)
    if not match:
        return None
    software = match.group('software').replace('_', ' ', 1)
    comment = match.group('comment') or ''
    platform = next((name for name, pattern in _PLATFORM_HINTS if pattern.search(f'{software} {comment}')), None)
    return dict(software=software[:80], comment=comment[:80], platform=platform)


def _reverse_name(address):
    future = _RESOLVER.submit(socket.gethostbyaddr, address)
    try:
        name = future.result(timeout=REVERSE_DNS_TIMEOUT_SECONDS)[0]
    except Exception:
        return None
    name = name.rstrip('.')
    return name if re.fullmatch(r'[A-Za-z0-9.-]{1,253}', name) else None


def _probe(address, port):
    """Connect under the network policy, read the greeting, close. Never sends."""
    from .network_policy import open_validated_socket, resolve_allowed_target
    try:
        target = resolve_allowed_target(address, port, allow_internal=not config.BLOCK_INTERNAL_SSH,
                                        allowed_internal_networks=config.SSH_ALLOWED_INTERNAL_NETWORKS)
    except ValueError:
        return dict(state='blocked')
    try:
        connection = open_validated_socket(target, CONNECT_TIMEOUT_SECONDS)
    except OSError:
        return dict(state='closed')
    try:
        connection.settimeout(BANNER_TIMEOUT_SECONDS)
        raw = b''
        deadline = time.monotonic() + BANNER_TIMEOUT_SECONDS
        while b'\n' not in raw and len(raw) < 255 and time.monotonic() < deadline:
            chunk = connection.recv(255 - len(raw))
            if not chunk:
                break
            raw += chunk
    except OSError:
        raw = b''
    finally:
        connection.close()
    banner = describe_banner(raw)
    # Only SSH servers are results; other listeners are not reported.
    return dict(state='ssh', **banner) if banner else dict(state='closed')


def _known_endpoints(user_id):
    from .data_access import user_data_access
    from .jump_host_manager import load_jump_hosts
    from .profile_manager import load_profiles
    with user_data_access(user_id):
        records = [*load_profiles(user_id), *load_jump_hosts(user_id)]
    return {(str(item.get('host') or '').lower(), int(item.get('port') or 22)) for item in records}


class Scan:
    def __init__(self, user_id, network, addresses, ports, known, authentication_session_id=None, authentication_session_hash=None):
        self.id = secrets.token_urlsafe(12)
        self.user_id = user_id
        self.authentication_session_id = authentication_session_id
        self.authentication_session_hash = authentication_session_hash
        self.network = network
        self.targets = [(address, port) for address in addresses for port in ports]
        self.known = known
        self.checked = 0
        self.blocked = 0
        self.found = []
        self.state = 'running'
        self.started = time.time()
        self.finished_at = None
        self.revoked = False
        self.cancel_event = threading.Event()

    def view(self):
        with _LOCK:
            return dict(id=self.id, network=self.network, state=self.state, total=len(self.targets),
                        checked=self.checked, blocked=self.blocked, found=list(self.found),
                        started_at=self.started, finished_at=self.finished_at)

    def run(self):
        cancel_event = self.cancel_event
        try:
            with ThreadPoolExecutor(max_workers=IN_FLIGHT, thread_name_prefix='discovery-probe') as pool:
                pending = set()
                for address, port in self.targets:
                    if cancel_event.is_set() or self.state == 'cancelled':
                        break
                    while len(pending) >= IN_FLIGHT:
                        done, pending = wait(pending, return_when=FIRST_COMPLETED)
                    future = pool.submit(_probe, address, port)
                    future.add_done_callback(lambda done, address=address, port=port: self._record(address, port, done))
                    pending.add(future)
                    # Pacing: never start more than one attempt per interval.
                    if cancel_event.wait(START_INTERVAL_SECONDS):
                        break
                wait(pending)
        finally:
            with _LOCK:
                if self.state == 'running':
                    self.state = 'cancelled' if cancel_event.is_set() else 'done'
                self.finished_at = time.time()
            log_security_event('host_discovery_finished', user_id=self.user_id, network=self.network, state=self.state,
                               checked=self.checked, found=len(self.found), blocked=self.blocked)

    def _record(self, address, port, future):
        try:
            outcome = future.result()
        except Exception:
            outcome = dict(state='closed')
        entry = None
        if outcome['state'] == 'ssh':
            entry = dict(address=address, port=port, software=outcome['software'], comment=outcome['comment'],
                         platform=outcome['platform'], name=_reverse_name(address),
                         known=(address.lower(), port) in self.known)
        with _LOCK:
            self.checked += 1
            if outcome['state'] == 'blocked':
                self.blocked += 1
            if entry and not self.revoked:
                self.found.append(entry)
                self.found.sort(key=lambda item: (ipaddress.ip_address(item['address']), item['port']))


def _prune():
    cutoff = time.time() - RESULT_RETENTION_SECONDS
    for scan_id in [key for key, scan in _SCANS.items() if scan.finished_at and scan.finished_at < cutoff]:
        _SCANS.pop(scan_id, None)


def _own_scan(scan_id):
    with _LOCK:
        scan = _SCANS.get(scan_id)
    # A scan belongs to the user who started it; others get the same answer as for no scan.
    return scan if scan and scan.user_id == current_user.id and not scan.revoked else None


@discovery_blueprint.post('/api/discovery/scans')
@login_required
def start_scan():
    auth = current_authentication_session()
    if auth is None:
        return jsonify(error='Authentication required'), 401
    if not discovery_available():
        return jsonify(error='Host discovery is not available on this instance.', code='unavailable'), 404
    lifecycle = current_app.extensions['runtime_lifecycle']
    if not lifecycle.accepting_work():
        return jsonify(error='WebSSH is not accepting new work.', code='unavailable'), 503
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) - {'network', 'ports'}:
        return jsonify(error='Invalid request.', code='invalid_request'), 400
    try:
        addresses = parse_network(data.get('network'))
        ports = parse_ports(data.get('ports'))
    except ScanRequestError as error:
        return jsonify(error=_INPUT_MESSAGES.get(error.code, _INPUT_MESSAGES['network']), code='invalid_network'), 400
    user_id = current_user.id
    network = str(ipaddress.ip_network(data['network'].strip(), strict=False))
    known = _known_endpoints(user_id)
    if check_user_rate_limit(user_id, 'host_discovery', RATE_LIMIT):
        return jsonify(error='Too many scans. Try again later.', code='busy'), 429
    scan = Scan(user_id, network, addresses, ports, known, auth.id, auth.session_hash)
    # Only final admission is serialized with revocation. Validation and scan
    # construction may proceed concurrently, without delaying login cleanup.
    with login_access():
        if current_authentication_session() is None:
            return jsonify(error='Authentication required'), 401
        with _LOCK:
            _prune()
            # A cancelled scan counts until its in-flight probes have ended.
            if any(item.user_id == user_id and item.finished_at is None for item in _SCANS.values()):
                return jsonify(error='A scan is already running. Wait for it or cancel it.', code='running'), 409
            if sum(item.finished_at is None for item in _SCANS.values()) >= MAX_RUNNING_SCANS:
                return jsonify(error='Another discovery is running. Try again shortly.', code='busy'), 429
            _SCANS[scan.id] = scan
    _RUNNERS.submit(scan.run)
    log_security_event('host_discovery_started', user_id=user_id, network=network, addresses=len(addresses), ports=ports)
    return jsonify(scan.view()), 202


@discovery_blueprint.get('/api/discovery/scans/<scan_id>')
@login_required
def scan_status(scan_id):
    scan = _own_scan(scan_id)
    if not scan:
        return jsonify(error='Scan not found.', code='not_found'), 404
    response = jsonify(scan.view())
    response.headers['Cache-Control'] = 'no-store'
    return response


@discovery_blueprint.delete('/api/discovery/scans/<scan_id>')
@login_required
def cancel_scan(scan_id):
    scan = _own_scan(scan_id)
    if not scan:
        return jsonify(error='Scan not found.', code='not_found'), 404
    scan.cancel_event.set()
    with _LOCK:
        if scan.state == 'running':
            scan.state = 'cancelled'
    return jsonify(scan.view())


def cancel_for_user(user_id):
    """Stop the account's scans and forget their results (logout, lock, deletion)."""
    with _LOCK:
        owned = [scan for scan in _SCANS.values() if scan.user_id == user_id and not scan.revoked]
        for scan in owned:
            scan.cancel_event.set()
            scan.revoked = True
            scan.found = []
            if scan.state == 'running':
                scan.state = 'cancelled'
    # Revoked scans stay counted until their probes ended; _prune removes them later.
    return len(owned)


def cancel_for_authentication_sessions(identities):
    """Cancel only discovery launched by the revoked browser logins."""
    with _LOCK:
        owned = [scan for scan in _SCANS.values() if (
            scan.user_id, scan.authentication_session_id, scan.authentication_session_hash,
        ) in identities]
        for scan in owned:
            scan.cancel_event.set()
            scan.revoked = True
            scan.found = []
            if scan.state == 'running':
                scan.state = 'cancelled'
    return len(owned)


def cancel_all(_deadline=None):
    """Shutdown hook: stop every running scan; in-flight probes end within their timeouts."""
    with _LOCK:
        scans = list(_SCANS.values())
    for scan in scans:
        scan.cancel_event.set()
