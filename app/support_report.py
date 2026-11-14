"""Explicit, allowlisted diagnostic snapshots for the signed-in account."""

from datetime import datetime, timezone
import re

from flask import Blueprint, current_app, jsonify, request
from flask_login import current_user, login_required

import config
from .app_settings import is_automation_enabled, is_credentials_enabled, runtime_feature_status
from .security_features import feature_is_active
from .version import display_version


support_report_blueprint = Blueprint('support_report', __name__)
_AREAS = ('general', 'ssh', 'files', 'sign_in', 'automation')
_REFERENCE = re.compile(r'SMB-[A-F0-9]{12}\Z', re.ASCII)
_READINESS_FAILURES = ('maintenance', 'runtime', 'database', 'data_directory')


@support_report_blueprint.post('/api/account/support-report')
@login_required
def create_support_report():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) - {'area', 'reference'}:
        return jsonify(error='Invalid report options'), 400
    area = data.get('area', 'general')
    reference = data.get('reference', '')
    if (not isinstance(area, str) or area not in _AREAS
            or not isinstance(reference, str)
            or (reference and not _REFERENCE.fullmatch(reference))):
        return jsonify(error='Invalid report options'), 400

    # Reuse the local readiness checks; never connect to a remote target,
    # collect logs, or enumerate account data to generate a support report.
    from .health import ready
    result = ready()
    readiness = (result[0] if isinstance(result, tuple) else result).get_json()
    features = {
        'ssh': True,
        'sftp': True,
        'smb': bool(config.SMB_ENABLED),
        'tmux': bool(runtime_feature_status('tmux_enabled')['enabled']),
        'automation': bool(is_automation_enabled()),
        'saved_passwords': bool(is_credentials_enabled()),
        **{name: bool(feature_is_active(name))
           for name in ('passkey', 'totp', 'oidc', 'ldap', 'recovery')},
    }
    report = {
        'schema': 1,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'version': display_version(),
        'area': area,
        'reference': reference or None,
        'https': bool(request.is_secure),
        'readiness': {
            'status': 'ready' if readiness.get('status') == 'ready' else 'not_ready',
            'failed': [name for name in _READINESS_FAILURES
                       if name in readiness.get('failed', [])],
        },
        'features': features,
    }
    if current_user.is_admin:
        profile = config.DEPLOYMENT_PROFILE
        report['deployment'] = {
            'profile': profile if profile in ('homelab', 'production') else 'unknown',
            'secure_cookie': bool(current_app.config.get('SESSION_COOKIE_SECURE')),
            'internal_ssh_blocked': bool(config.BLOCK_INTERNAL_SSH),
        }
    response = jsonify(report)
    response.headers['Cache-Control'] = 'no-store'
    return response
