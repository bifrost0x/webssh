"""Dedicated SSH automation connections; no terminal or local shell execution."""
from contextlib import contextmanager, nullcontext
import codecs
import hashlib
import re
import unicodedata
import shlex
import threading
import time

import paramiko
from paramiko.auth_strategy import AuthStrategy, AuthFailure, Password, InMemoryPrivateKey
import config

from . import paramiko_channels
from .automation_store import AutomationError
from .host_key_store import HostKeyStore, HostKeyNotAccepted, RevokedHostKeyError
from .key_manager import read_key_content
from .network_policy import (audit_internal_allowlist_use, canonicalize_hostname, open_validated_socket,
                             proxy_jump_remote_dns_allowed, resolve_allowed_target)
from .quota_manager import quota_manager, QuotaKind
from .ssh_key_loader import load_private_key

class _StrictPassword(Password):
    def __init__(self, username, password_getter, cancelled):
        super().__init__(username, password_getter)
        self.cancelled = cancelled

    def authenticate(self, transport):
        # Paramiko reaches this source only after the handshake and host-key
        # verification, which may outlive the original credential admission.
        if self.cancelled():
            raise AutomationError('cancelled')
        return transport.auth_password(self.username, self.password_getter(), fallback=False)


class _StrictPrivateKey(InMemoryPrivateKey):
    def __init__(self, username, pkey, cancelled):
        super().__init__(username, pkey)
        self.cancelled = cancelled

    def authenticate(self, transport):
        if self.cancelled():
            raise AutomationError('cancelled')
        return super().authenticate(transport)

class _Authentication(AuthStrategy):
    def __init__(self, source):
        super().__init__(ssh_config=None)
        self.source = source
    def get_sources(self):
        yield self.source

CONNECTION_REASONS = frozenset({'host_key_required','host_key_changed','host_key_revoked',
    'authentication_failed','connect_timeout','connection_failed','preview_changed','key_unavailable',
    'credential_missing','vault_locked','run_interrupted'})

def connection_reason(error):
    if isinstance(error, HostKeyNotAccepted):
        return 'host_key_required'
    if isinstance(error, RevokedHostKeyError):
        return 'host_key_revoked'
    if isinstance(error, paramiko.BadHostKeyException):
        return 'host_key_changed'
    if isinstance(error, (paramiko.AuthenticationException, AuthFailure)):
        return 'authentication_failed'
    if isinstance(error, TimeoutError):
        return 'connect_timeout'
    if isinstance(error, AutomationError) and error.code in CONNECTION_REASONS:
        return error.code
    return 'connection_failed'

def command_for(step):
    return 'sudo -n -- sh -c ' + shlex.quote(step['command']) if step['sudo'] else step['command']

def _allowed_target(host, port):
    return resolve_allowed_target(host, port, allow_internal=not config.BLOCK_INTERNAL_SSH,
                                  allowed_internal_networks=config.SSH_ALLOWED_INTERNAL_NETWORKS)


def _destination_behind_jump(profile):
    """Apply the interactive ProxyJump rules to the target behind a jump host.

    A locally resolvable target must pass the network policy and is reached by
    its validated address. A name that only the jump host can resolve is
    allowed when internal SSH is open or the name is on the remote DNS allowlist.
    """
    host = canonicalize_hostname(profile['host'])
    port = int(profile.get('port', 22))
    try:
        target = _allowed_target(host, port)
    except ValueError:
        if config.BLOCK_INTERNAL_SSH and not proxy_jump_remote_dns_allowed(
                host, config.PROXY_JUMP_REMOTE_DNS_ALLOWLIST):
            raise
        return host, port, (host, port)
    audit_internal_allowlist_use(target, 'automation_target')
    return target.hostname, target.port, (target.ip, target.port)


def _connect_client(user_id, profile, password, sock, hostname, port, hold, access,
                    expected_key_digest, authentication_cancelled):
    client = hold(paramiko.SSHClient())
    with access():
        store = HostKeyStore(user_id, config.KNOWN_HOSTS_FILE, config.USERS_DIR)
        store.load_into(client)
        client.set_missing_host_key_policy(store.missing_key_policy())
        if profile.get('auth_type') == 'key':
            content, error = read_key_content(user_id, profile.get('key_id'))
            if error or not content:
                raise AutomationError('key_unavailable')
            if expected_key_digest is not None and hashlib.sha256(content.encode()).hexdigest() != expected_key_digest:
                raise AutomationError('preview_changed')
            source = _StrictPrivateKey(profile['username'], load_private_key(content),
                                       lambda: authentication_cancelled())
            content = None
        else:
            source = _StrictPassword(profile['username'], lambda: password,
                                     lambda: authentication_cancelled())
    guard = threading.Timer(15, client.close)
    guard.daemon = True
    guard.start()
    try:
        client.connect(hostname=hostname, port=port, username=profile['username'],
            sock=sock, timeout=10, banner_timeout=10, auth_timeout=10,
            channel_timeout=10, allow_agent=False, look_for_keys=False,
            auth_strategy=_Authentication(source))
    finally:
        guard.cancel()
        password = None
        source = None
    return client


@contextmanager
def connect_profile(user_id, profile, password, cancelled, own=lambda _resource: None, *,
                    access=nullcontext, expected_key_digest=None, validate_auth=None,
                    route=None, route_password=None, route_key_digest=None):
    """Open an authenticated SSH transport, optionally through one jump host.

    Both hops use the account's verified host keys, the SSH network policy
    and their own credentials; nothing is accepted on first use.
    """
    opened = []

    def hold(resource):
        opened.append(resource)
        own(resource)
        return resource

    def authentication_cancelled():
        if cancelled():
            return True
        if validate_auth is not None:
            with access():
                validate_auth()
        return False

    timeout = min(config.SSH_CONNECT_TIMEOUT, 10)
    with quota_manager.reserve(QuotaKind.SSH_SESSION, user_id):
        try:
            if cancelled():
                raise AutomationError('cancelled')
            if route is None:
                target = _allowed_target(profile['host'], profile.get('port', 22))
                audit_internal_allowlist_use(target, 'automation_target')
                hostname, port = target.hostname, target.port
                sock = hold(open_validated_socket(target, timeout))
            else:
                hostname, port, destination = _destination_behind_jump(profile)
                bastion = _allowed_target(route['host'], route.get('port', 22))
                audit_internal_allowlist_use(bastion, 'automation_jump_host')
                bastion_socket = hold(open_validated_socket(bastion, timeout))
                if cancelled():
                    raise AutomationError('cancelled')
                bastion_client = _connect_client(user_id, route, route_password, bastion_socket,
                                                 bastion.hostname, bastion.port, hold, access,
                                                 route_key_digest, authentication_cancelled)
                route_password = None
                if cancelled():
                    raise AutomationError('cancelled')
                sock = hold(bastion_client.get_transport().open_channel(
                    'direct-tcpip', destination, ('127.0.0.1', 0), timeout=timeout))
            if cancelled():
                raise AutomationError('cancelled')
            client = _connect_client(user_id, profile, password, sock, hostname, port, hold, access,
                                     expected_key_digest, authentication_cancelled)
            password = None
            if cancelled():
                raise AutomationError('cancelled')
            yield client.get_transport()
        finally:
            for resource in reversed(opened):
                try:
                    resource.close()
                except Exception:
                    pass

STEP_OUTPUT_BYTES = 8 * 1024
RUN_OUTPUT_BYTES = 64 * 1024
# Bound captured bytes, not bytes drained from the SSH channel. Large finite
# inventories must still reach their exit status; deadlines bound noisy commands.
EXECUTION_OUTPUT_BYTES = 256 * 1024
STREAM_OUTPUT_BYTES = EXECUTION_OUTPUT_BYTES // 2
STEP_REASONS = frozenset({'nonzero_exit', 'timeout', 'cancelled', 'output_limit',
    'channel_lost', 'acknowledgement_lost', 'dispatch_failed', 'run_interrupted'})


def _plain_output(value):
    # Remove complete and interrupted terminal escape sequences, including OSC/DCS.
    value = re.sub(r'(?:\x1b\]|\x9d).*?(?:\x07|\x1b\\|$)', '', value, flags=re.S)
    value = re.sub(r'\x1b[P_X^].*?(?:\x1b\\|$)', '', value, flags=re.S)
    value = re.sub(r'(?:\x1b\[|\x9b)[0-?]*[ -/]*(?:[@-~]|$)', '', value)
    value = re.sub(r'\x1b(?:[ -/]*[@-~]|.*$)', '', value, flags=re.S)
    return ''.join(c for c in value.replace('\r\n', '\n').replace('\r', '\n')
                   if c in '\n\t' or unicodedata.category(c) not in {'Cc', 'Cf', 'Cs'})


def _redact_output(value, secrets, interrupted=False):
    for secret in sorted(set(s for s in secrets if s), key=len, reverse=True):
        value = value.replace(secret, '[redacted]')
        # An interrupted stream can end in a partial authentication secret.
        for size in range(min(len(secret)-1, len(value)) if interrupted else 0, 0, -1):
            if value.endswith(secret[:size]):
                value = value[:-size] + '[redacted]'
                break
    return value


def execute_step(transport, step, cancelled, output_secrets=(), output_budget=STEP_OUTPUT_BYTES):
    sent = False
    channel = None
    started = time.monotonic()
    deadline = started + step['timeout']
    captured = [bytearray(), bytearray()]
    capture_truncated = [False, False]
    def result(status, reason=None, exit_code=None):
        remaining = max(0, min(STEP_OUTPUT_BYTES, output_budget))
        encoded_output, truncated = [], any(capture_truncated)
        for index, raw in enumerate(captured):
            incomplete = status == 'unknown' or capture_truncated[index]
            decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
            # An interrupted multibyte character must not append a replacement
            # character that hides the preceding credential prefix from redaction.
            # Invalid bytes within the stream still receive normal replacement.
            decoded = decoder.decode(raw, final=not incomplete)
            truncated = truncated or bool(decoder.getstate()[0])
            value = _redact_output(decoded, output_secrets, incomplete)
            value = _redact_output(_plain_output(value), tuple(_plain_output(s) for s in output_secrets), incomplete)
            encoded_output.append(value.encode('utf-8'))
        # Reserve half for stderr, then let either stream use the other's spare capacity.
        stderr_budget = min(len(encoded_output[1]), remaining // 2)
        stdout_budget = min(len(encoded_output[0]), remaining - stderr_budget)
        stderr_budget = remaining - stdout_budget
        output = [value[:budget].decode('utf-8', errors='ignore')
                  for value, budget in zip(encoded_output, (stdout_budget, stderr_budget))]
        truncated = truncated or any(len(value) > len(kept.encode('utf-8'))
                                     for value, kept in zip(encoded_output, output))
        return dict(status=status, reason=reason, exit_code=exit_code,
                    duration=round(time.monotonic()-started, 2), stdout=output[0],
                    stderr=output[1], output_truncated=truncated)
    def before_exec():
        nonlocal sent
        if cancelled():
            raise AutomationError('cancelled')
        sent = True
    try:
        if cancelled():
            return result('cancelled', 'cancelled')
        channel = paramiko_channels.open_exec_channel(transport, command_for(step),
                                        timeout=step['timeout'], before_exec=before_exec)
        channel.shutdown_write()
        while True:
            if cancelled():
                return result('unknown', 'cancelled')
            if time.monotonic() >= deadline:
                return result('unknown', 'timeout')
            for index, (ready, recv) in enumerate(((channel.recv_ready, channel.recv), (channel.recv_stderr_ready, channel.recv_stderr))):
                if ready():
                    chunk = recv(32768)
                    # Reserve space for stderr even after a large stdout stream.
                    available = max(0, STREAM_OUTPUT_BYTES-len(captured[index]))
                    captured[index].extend(chunk[:available])
                    capture_truncated[index] |= len(chunk) > available
            # Exit status can arrive before the reader has seen EOF (and before
            # the final stderr packet). Wait for the stream end as well.
            if (channel.closed or channel.eof_received) and channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                status = channel.recv_exit_status()
                return result('succeeded' if status == 0 else 'failed' if status > 0 else 'unknown',
                              None if status == 0 else 'nonzero_exit' if status > 0 else 'channel_lost',
                              status if status >= 0 else None)
            # Paramiko can receive CLOSE and the exit status before our reader
            # has consumed buffered stdout/stderr. Drain both before deciding.
            if not channel.recv_ready() and not channel.recv_stderr_ready():
                if channel.closed:
                    return result('unknown', 'channel_lost')
                time.sleep(0.03)
    except Exception:
        return result('unknown' if sent else 'cancelled' if cancelled() else 'failed',
                      'cancelled' if cancelled() else 'acknowledgement_lost' if sent and channel is None
                      else 'channel_lost' if sent else 'dispatch_failed')
    finally:
        if channel is not None:
            channel.close()
