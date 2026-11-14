"""Resolve saved connection passwords only within the authenticated TLS session."""
import time

from flask import current_app, request

from .automation_store import AutomationError
from .transport_security import request_reached_over_https
from paramiko.auth_strategy import AuthStrategy


def _saved_route(data, kind='jump'):
    field, reference = ('socks_proxy', 'socks_proxy_id') if kind == 'socks' else ('proxy_jump', 'jump_host_id')
    route = data.get(field)
    if route is not None and (not isinstance(route, dict) or not isinstance(route.get(reference), str)
                              or not route[reference]):
        raise AutomationError('credential_target_changed')
    return route.get(reference) if isinstance(route, dict) else None


def _connection_target(kind, data):
    """Keep the proxy endpoint distinct from a host's nested route."""
    from .credential_service import CredentialService
    connection = dict(data)
    if kind in {'ssh', 'jump', 'socks'}:
        connection['kind'] = kind
        connection.setdefault('auth_type', 'password')
        connection.setdefault('port', 1080 if kind == 'socks' else 22)
        if kind == 'jump':
            connection['jump_host_id'] = _saved_route(data)
        connection = CredentialService._normalize_target(connection)
        if kind == 'ssh':
            # Only nested routes are consumed by the SSH transport. A claimed
            # profile reference alone must not authorize a direct connection.
            connection['jump_host_id'] = _saved_route(data)
            socks_id = _saved_route(data, 'socks')
            if socks_id:
                connection['socks_proxy_id'] = socks_id
            else:
                connection.pop('socks_proxy_id', None)
    return connection


class SavedPasswordAuth(AuthStrategy):
    """Check the lease after SSH host verification, just before authentication."""
    def __init__(self, username, password, guard):
        super().__init__(ssh_config=None)
        self.username, self.password, self.guard = username, password, guard

    def authenticate(self, transport):
        try:
            self.guard.check()
            return transport.auth_password(self.username, self.password, fallback=False)
        finally:
            self.password = None


class CredentialGuard:
    """A pending authentication becomes cancelled when its binding changes."""
    def __init__(self, user_id, kind, data):
        from .auth_assurance import current_authentication_session
        from copy import deepcopy
        auth = current_authentication_session()
        if not request_reached_over_https() or auth is None or auth.user_id != user_id:
            raise AutomationError('authentication_required')
        self.app = current_app._get_current_object()
        self.service = self.app.extensions['credentials']
        connection = _connection_target(kind, data)
        connection = deepcopy({key: value for key, value in connection.items() if key in {
            'host', 'port', 'username', 'auth_type', 'key_id', 'jump_host_id', 'domain', 'share',
            'socks_proxy_id', 'remote_dns', 'kind',
        }})
        self.target_token=data.get('credential_target_token')
        self.target_args=(user_id,auth.id,data['credential_id'],connection,self.target_token)
        self.args = (user_id, auth.id, kind, data['credential_id'], connection)
        self.token = (self.service.target_generation(*self.target_args) if self.target_token else self.service.connection_generation(*self.args))
        self.cancelled = False
        self._checked_at = time.monotonic()

    # Cancellation polling runs every 20-100 ms while a connection is pending.
    # Each full check reads every owned store and several database rows, so
    # polls reuse a result for this long; check() before authentication is
    # always fresh.
    POLL_INTERVAL = 0.25

    def is_set(self, *, fresh=False):
        if self.cancelled:
            return True
        now = time.monotonic()
        if not fresh and now - self._checked_at < self.POLL_INTERVAL:
            return False
        try:
            with self.app.app_context():
                self.cancelled = (self.service.target_generation(*self.target_args) if self.target_token else self.service.connection_generation(*self.args)) != self.token
        except Exception:
            self.cancelled = True
        self._checked_at = now
        return self.cancelled

    def check(self):
        if self.is_set(fresh=True):
            raise AutomationError('vault_locked')


def connection_password(user_id, kind, data):
    reference = data.get('credential_id')
    if reference is None:
        return data.get('password')
    from .auth_assurance import current_authentication_session
    auth = current_authentication_session()
    if not request_reached_over_https():
        raise AutomationError('https_required')
    if auth is None or auth.user_id != user_id:
        raise AutomationError('authentication_required')
    if not isinstance(reference, str) or not reference or data.get('password'):
        raise AutomationError('invalid_request')
    connection = _connection_target(kind, data)
    if data.get('credential_target_token'):
        return current_app.extensions['credentials'].target_password(user_id,auth.id,reference,connection,data['credential_target_token'])
    return current_app.extensions['credentials'].connection_password(
        user_id, auth.id, kind, reference, connection,
    )


def credential_error(error):
    """Do not expose the endpoint or any resolver exception detail."""
    messages = {
        'https_required': 'Saved passwords require HTTPS.',
        'vault_locked': 'Unlock your credential vault and try again.',
        'vault_missing': 'Set up your credential vault first.',
        'credential_missing': 'Save a password for this connection first.',
        'authentication_required': 'Sign in again to use saved passwords.',
    }
    return {'error': messages.get(error.code, 'Saved credentials no longer match this connection. Review it and try again.'),
            'code': error.code if error.code in messages else 'credential_unavailable'}
