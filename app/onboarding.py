"""Account-scoped introductory tour and allowlisted deployment facts."""
import os

from flask import Blueprint, jsonify, request, url_for
from flask_login import current_user, login_required

import config
from .app_settings import is_automation_enabled, is_credentials_enabled, is_registration_enabled
from .user_settings import get_user_settings, save_user_settings
from .security_features import feature_is_active

onboarding_blueprint = Blueprint('onboarding', __name__)
_ADMIN_ONLY_FACTS = frozenset({'SESSION_COOKIE_SECURE', 'BOOTSTRAP_REGISTRATION_ENABLED'})


@onboarding_blueprint.route('/api/account/tour', methods=['GET', 'POST'])
@login_required
def tour():
    if request.method == 'POST':
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or set(data) - {'state', 'acknowledged'} or 'state' not in data or data['state'] not in ('completed', 'dismissed', 'new'):
            return jsonify(error='Invalid tour state'), 400
        if data['state'] == 'completed' and data.get('acknowledged') is not True:
            return jsonify(error='Explicit acknowledgement required'), 400
        updates = {'intro_tour': data['state'], 'intro_tour_v3_acknowledged': data['state'] == 'completed'}
        if not save_user_settings(current_user.id, updates):
            return jsonify(error='Could not save tour progress'), 500
        return jsonify(state=data['state'])
    # Never serialize environment variables, configuration dictionaries or paths.
    facts = [
        {'key': name, 'enabled': bool(getattr(config, name, False)), 'source': 'environment'}
        for name in ('SMB_ENABLED', 'SFTP_CHMOD_ENABLED', 'SERVER_OPERATIONS_ENABLED',
                     'TMUX_ENABLED', 'TAILSCALE_SSH_ENABLED', 'OIDC_ENABLED',
                     'LDAP_ENABLED', 'TOTP_ENABLED', 'WEBAUTHN_ENABLED',
                     'BOOTSTRAP_REGISTRATION_ENABLED', 'SESSION_COOKIE_SECURE')
    ]
    from .app_settings import RUNTIME_FEATURES, runtime_feature_status
    for name, key in RUNTIME_FEATURES.items():
        if name == 'tmux_default':
            continue
        status = runtime_feature_status(name)
        fact = next(item for item in facts if item['key'] == key)
        fact.update(enabled=status['enabled'], source=status['source'])
    facts.extend([
        {'key': 'credentials_enabled', 'enabled': is_credentials_enabled(), 'source': 'admin'},
        {'key': 'automation_enabled', 'enabled': is_automation_enabled(), 'source': 'admin'},
        {'key': 'registration_enabled', 'enabled': is_registration_enabled(), 'source': 'admin'},
    ])
    for key, feature in {'OIDC_ENABLED': 'oidc', 'LDAP_ENABLED': 'ldap',
                         'TOTP_ENABLED': 'totp', 'WEBAUTHN_ENABLED': 'passkey'}.items():
        fact = next(item for item in facts if item['key'] == key)
        fact['configured'] = fact['enabled']
        fact['enabled'] = feature_is_active(feature)
        fact['source'] = 'deployment_and_admin'
    settings = get_user_settings(current_user.id)
    if settings.get('intro_tour_v3_acknowledged') is True:
        state = 'completed'
    elif settings.get('intro_tour') == 'dismissed':
        # Skipping is a decision too: never reopen the modal on every page
        # load. The account menu can still restart the tour.
        state = 'dismissed'
    else:
        state = 'new'
    administrator = bool(current_user.is_admin)
    if not administrator:
        # Users learn what they can use; deployment posture (where a value
        # comes from, cookie and bootstrap settings, process identity) is
        # administrator information.
        facts = [dict(key=item['key'], enabled=item['enabled']) for item in facts
                 if item['key'] not in _ADMIN_ONLY_FACTS]
    response = jsonify(
        state=state,
        administrator=administrator,
        admin_url=url_for('admin_page') if administrator and config.ADMIN_PANEL_ENABLED else None,
        process_root=(os.geteuid() == 0 if hasattr(os, 'geteuid') else None) if administrator else None,
        facts=facts,
    )
    response.headers['Cache-Control'] = 'no-store'
    return response
