"""Fail-closed deployment, readiness, and administrator feature gates."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from importlib.util import find_spec

import config
from flask import current_app

from .audit_logger import log_security_event
from .models import SecurityFeatureState, User, db


FEATURE_NAMES = ('passkey', 'totp', 'oidc', 'ldap', 'recovery')

_DISPLAY_NAMES = {
    'passkey': 'Passkeys',
    'totp': 'TOTP',
    'oidc': 'OIDC',
    'ldap': 'LDAP',
    'recovery': 'Recovery codes',
}
_DEPLOYMENT_FLAGS = {
    'passkey': 'WEBAUTHN_ENABLED',
    'totp': 'TOTP_ENABLED',
    'oidc': 'OIDC_ENABLED',
    'ldap': 'LDAP_ENABLED',
    'recovery': 'RECOVERY_CODES_ENABLED',
}
_UPGRADE_COMPATIBLE_DEFAULTS = frozenset({
    'passkey',
    'oidc',
    'ldap',
    'recovery',
})
_CONFIGURATION_KEYS = {
    'passkey': (
        'WEBAUTHN_ENABLED', 'WEBAUTHN_RP_ID', 'WEBAUTHN_ORIGIN',
    ),
    'totp': ('TOTP_ENABLED',),
    'oidc': (
        'OIDC_ENABLED',
        'OIDC_ISSUER',
        'OIDC_CLIENT_ID',
        'OIDC_CLIENT_SECRET_FILE',
        'OIDC_REDIRECT_URI',
    ),
    'ldap': (
        'LDAP_ENABLED',
        'LDAP_URL',
        'LDAP_BACKUP_URL',
        'LDAP_BASE_DN',
        'LDAP_BIND_DN',
        'LDAP_BIND_PASSWORD_FILE',
        'LDAP_CA_FILE',
        'LDAP_USER_FILTER',
        'LDAP_UNIQUE_ID_ATTRIBUTE',
    ),
    'recovery': ('RECOVERY_CODES_ENABLED',),
}
_DOCUMENTATION_URLS = {
    'passkey': 'https://github.com/bifrost0x/webssh#authentication-features',
    'totp': 'https://github.com/bifrost0x/webssh#authentication-features',
    'oidc': (
        'https://github.com/bifrost0x/webssh/wiki/OpenID-Connect'
    ),
    'ldap': (
        'https://github.com/bifrost0x/webssh/blob/main/'
        'docs/ldap-authentication.md'
    ),
    'recovery': 'https://github.com/bifrost0x/webssh#authentication-features',
}


@dataclass(frozen=True)
class FeatureStatus:
    name: str
    deployment_allowed: bool
    ready: bool
    admin_enabled: bool
    active: bool
    reason: str | None
    configuration_keys: tuple[str, ...]
    documentation_url: str

    def to_dict(self):
        return asdict(self)


class UnknownSecurityFeature(ValueError):
    """Raised when a feature name is outside the supported registry."""


class FeatureUnavailable(RuntimeError):
    """Raised when an administrator tries to exceed the deployment ceiling."""

    def __init__(self, status):
        super().__init__(status.reason)
        self.status = status


def _module_available(name):
    try:
        return find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def initialize_feature_readiness(app, *, oidc_ready=False, ldap_ready=False):
    """Record startup validation results without retaining or rereading secrets."""
    passkey_ready = _module_available('webauthn')
    totp_ready = _module_available('pyotp') and _module_available('qrcode')
    app.extensions['security_feature_readiness'] = {
        'passkey': (
            passkey_ready,
            None if passkey_ready else 'Passkey dependency is unavailable.',
        ),
        'totp': (
            totp_ready,
            None if totp_ready else 'TOTP dependencies are unavailable.',
        ),
        'oidc': (
            bool(oidc_ready),
            None if oidc_ready else (
                'OIDC provider initialization did not complete.'
            ),
        ),
        'ldap': (
            bool(ldap_ready),
            None if ldap_ready else 'LDAP runtime validation did not complete.',
        ),
        'recovery': (True, None),
    }


def _normalize_name(name):
    normalized = str(name or '').strip().lower()
    if normalized not in FEATURE_NAMES:
        raise UnknownSecurityFeature(normalized)
    return normalized


def _readiness(name):
    readiness = current_app.extensions.get('security_feature_readiness', {})
    value = readiness.get(name, (False, f'{_DISPLAY_NAMES[name]} is not ready.'))
    if isinstance(value, tuple):
        ready, reason = value
    else:
        ready, reason = bool(value), None
    return bool(ready), reason


def feature_status(name):
    """Return the immutable effective status for one supported feature."""
    name = _normalize_name(name)
    deployment_allowed = bool(getattr(config, _DEPLOYMENT_FLAGS[name], False))
    ready, readiness_reason = _readiness(name)
    stored = db.session.get(SecurityFeatureState, name)
    if stored is None:
        admin_enabled = (
            deployment_allowed and name in _UPGRADE_COMPATIBLE_DEFAULTS
        )
    else:
        admin_enabled = bool(stored.enabled)
    active = deployment_allowed and ready and admin_enabled

    display_name = _DISPLAY_NAMES[name]
    if not deployment_allowed:
        reason = f'{display_name} is disabled by deployment configuration.'
    elif not ready:
        reason = readiness_reason or f'{display_name} is not ready.'
    elif not admin_enabled:
        reason = f'{display_name} is not activated in the admin panel.'
    else:
        reason = None

    return FeatureStatus(
        name=name,
        deployment_allowed=deployment_allowed,
        ready=ready,
        admin_enabled=admin_enabled,
        active=active,
        reason=reason,
        configuration_keys=_CONFIGURATION_KEYS[name],
        documentation_url=_DOCUMENTATION_URLS[name],
    )


def feature_is_active(name):
    return feature_status(name).active


def all_feature_statuses():
    return tuple(feature_status(name) for name in FEATURE_NAMES)


def request_feature_name(path):
    """Return the feature protecting an authentication endpoint, if any."""
    path = str(path or '')
    if path.startswith('/oidc/') or (
        path.startswith('/admin/api/users/')
        and ('/oidc-' in path or path.endswith('/oidc-identities'))
    ):
        return 'oidc'
    if path == '/login/ldap' or path.startswith('/admin/api/ldap/') or (
        path.startswith('/admin/api/users/') and '/ldap-' in path
    ):
        return 'ldap'
    if path.startswith('/api/webauthn/'):
        return 'passkey'
    if path.startswith('/api/totp/'):
        return 'totp'
    if (
        path.startswith('/api/recovery-codes')
        or path in {
            '/login/recovery',
            '/api/auth/recovery',
            '/api/auth/mfa/disable',
        }
        or (
            path.startswith('/admin/api/users/')
            and path.endswith('/recovery')
        )
    ):
        return 'recovery'
    return None


def set_feature_active(name, enabled, admin_id):
    """Persist an administrator gate without exceeding deployment readiness."""
    name = _normalize_name(name)
    if type(enabled) is not bool:
        raise TypeError('enabled must be a boolean')
    admin = db.session.get(User, admin_id)
    if admin is None or not admin.is_admin:
        raise ValueError('admin_id must identify an administrator')

    current = feature_status(name)
    if enabled and (
        not current.deployment_allowed or not current.ready
    ):
        raise FeatureUnavailable(current)

    stored = db.session.get(SecurityFeatureState, name)
    if stored is None:
        stored = SecurityFeatureState(feature=name)
        db.session.add(stored)
    stored.enabled = enabled
    stored.updated_by = admin.id
    stored.updated_at = datetime.now(timezone.utc)
    db.session.commit()

    status = feature_status(name)
    log_security_event(
        'SECURITY_FEATURE_CHANGED',
        admin=admin.username,
        feature=name,
        enabled=enabled,
        active=status.active,
    )
    return status
