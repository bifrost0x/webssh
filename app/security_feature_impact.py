"""Concrete, expiring disable approvals bound to the account configuration."""
from collections import Counter
import hashlib
import hmac
import json

from flask import current_app
from itsdangerous import BadData, URLSafeTimedSerializer

from .models import AuthenticationSession, User, db
from .security_features import all_feature_statuses, feature_status


def _snapshot(feature):
    from .github_auth_service import github_auth_is_active

    feature = feature_status(feature).name  # Normalize before account inspection.
    gates = {status.name: status.to_dict() for status in all_feature_statuses()}
    github_active = github_auth_is_active()
    accounts = []
    def identity(row):
        return [row.id, row.created_at.isoformat()]

    for user in User.query.order_by(User.id).all():
        accounts.append({
            'id': user.id,
            'created_at': user.created_at.isoformat(),
            'username': user.username,
            'generation': user.auth_generation,
            'admin': user.is_admin,
            'locked': user.is_locked,
            'mfa': user.mfa_enabled,
            'password': not user.is_ldap_managed and not user.is_github_managed,
            'passkey': [identity(row) for row in user.webauthn_credentials.order_by('id').all()],
            'totp': [identity(row) for row in user.totp_authenticators.filter_by(active=True).order_by('id').all()],
            # A consumed recovery verifier is deleted, not retained as used.
            'recovery': [identity(row) for row in user.recovery_codes.order_by('id').all()],
            'oidc': [identity(row) for row in user.oidc_identities.order_by('id').all()],
            'ldap': identity(user.ldap_identity) if user.ldap_identity else None,
            'github': identity(user.github_identity) if user.github_identity else None,
        })
    snapshot = {'gates': gates, 'github_active': github_active, 'accounts': accounts}
    digest = hashlib.sha256(json.dumps(snapshot, sort_keys=True).encode()).hexdigest()
    active = {name: status['active'] and name != feature for name, status in gates.items()}
    primary = Counter()
    factors = Counter()
    affected = [account for account in accounts if account[feature]]
    details = []
    no_primary = no_primary_admins = no_mfa = no_mfa_admins = 0
    for account in affected:
        configured_primary = [name for name in ('password', 'passkey', 'oidc', 'ldap', 'github') if account[name] and (
            name == 'password' or name == 'github' and github_active or active.get(name, False)
        ) and not (name == 'oidc' and account['ldap'])]
        configured_factors = [name for name in ('passkey', 'totp', 'recovery') if account[name] and active[name]]
        details.append({
            'username': account['username'], 'admin': account['admin'], 'locked': account['locked'],
            'mfa_required': account['mfa'], 'remaining_primary': configured_primary,
            'remaining_factors': configured_factors,
        })
        if account['locked']:
            continue
        primary.update(configured_primary)
        factors.update(configured_factors)
        if not configured_primary:
            no_primary += 1
            no_primary_admins += int(account['admin'])
        if account['mfa'] and not any(name in configured_factors for name in ('passkey', 'totp')):
            no_mfa += 1
            no_mfa_admins += int(account['admin'])
    return digest, {
        'feature': feature,
        'active': gates[feature]['active'],
        'affected_accounts': len(affected),
        'affected_admins': sum(account['admin'] for account in affected),
        'locked_affected_accounts': sum(account['locked'] for account in affected),
        'remaining_primary': dict(primary),
        'remaining_factors': dict(factors),
        'accounts_without_primary': no_primary,
        'admins_without_primary': no_primary_admins,
        'mfa_required_without_local_factor': no_mfa,
        'admins_without_local_factor': no_mfa_admins,
        'tested': False,
        'accounts': details,
    }


def _signer():
    return URLSafeTimedSerializer(current_app.secret_key, salt='security-feature-impact-v1')


def _bound_digest(digest, user_id, auth_id):
    row = db.session.get(AuthenticationSession, auth_id)
    if row is None or row.user_id != user_id:
        return None
    # A row ID may be reused after expiry; bind the exact login without
    # returning its authentication hash in the signed, readable payload.
    return hmac.new(str(current_app.secret_key).encode(),
        f'feature-impact:{digest}:{row.session_hash}'.encode(), hashlib.sha256).hexdigest()


def feature_impact_preview(feature, user_id, auth_id):
    digest, impact = _snapshot(feature)
    return {
        'impact': impact,
        'approval': _signer().dumps([feature, user_id, auth_id, _bound_digest(digest, user_id, auth_id)]),
    }


def verify_impact_approval(token, feature, user_id, auth_id):
    if not isinstance(token, str) or len(token) > 2048:
        return False
    try:
        approved = _signer().loads(token, max_age=300)
    except BadData:
        return False
    if not isinstance(approved, list) or len(approved) != 4 or approved[:3] != [feature, user_id, auth_id]:
        return False
    digest, _impact = _snapshot(feature)
    bound = _bound_digest(digest, user_id, auth_id)
    return bound is not None and isinstance(approved[3], str) and hmac.compare_digest(approved[3], bound)
