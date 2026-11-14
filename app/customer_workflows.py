"""Account-owned workspace presets and post-restore recovery guidance."""
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request
from flask_login import current_user, login_required

import config
from .data_access import user_data_access
from .storage_utils import atomic_write_json, storage_lock
from .user_settings import get_user_settings, save_user_settings

customer_workflows_blueprint = Blueprint('customer_workflows', __name__)
_IDENTIFIER = re.compile(r'^[A-Za-z0-9_-]{1,128}$')


def valid_presets(value):
    if not isinstance(value, list) or len(value) > 12:
        return False
    ids = set()
    for preset in value:
        if not isinstance(preset, dict) or set(preset) != {'id', 'name', 'layout', 'profile_ids'}:
            return False
        identifier, name = preset['id'], preset['name']
        hosts, layout = preset['profile_ids'], preset['layout']
        if (not isinstance(identifier, str) or not _IDENTIFIER.fullmatch(identifier)
                or identifier in ids or not isinstance(name, str) or not name.strip()
                or len(name) > 80 or any(not char.isprintable() for char in name)
                or type(layout) is not int or layout not in (1, 2, 4)
                or not isinstance(hosts, list) or len(hosts) > layout
                or any(not isinstance(host, str) or not _IDENTIFIER.fullmatch(host) for host in hosts)
                or len(set(hosts)) != len(hosts)):
            return False
        ids.add(identifier)
    return True


@customer_workflows_blueprint.route('/api/account/workspace-presets', methods=['GET', 'PUT'])
@login_required
def workspace_presets():
    from .profile_manager import load_profiles
    with user_data_access(current_user.id):
        if request.method == 'PUT':
            body = request.get_json(silent=True)
            if not isinstance(body, dict) or set(body) != {'presets'} or not valid_presets(body['presets']):
                return jsonify(error='Invalid workspace presets'), 400
            owned = {item['id'] for item in load_profiles(current_user.id)}
            previous = {item['id']: set(item['profile_ids']) for item in
                        get_user_settings(current_user.id).get('workspace_presets', [])}
            if any(host not in owned and host not in previous.get(preset['id'], set())
                   for preset in body['presets'] for host in preset['profile_ids']):
                return jsonify(error='Choose existing hosts from your account'), 400
            if not save_user_settings(current_user.id, {'workspace_presets': body['presets']}):
                return jsonify(error='Could not save workspace presets'), 500
        response = jsonify(presets=get_user_settings(current_user.id).get('workspace_presets', []))
    response.headers['Cache-Control'] = 'no-store'
    return response


def valid_recovery_timestamp(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        return False
    try:
        timestamp = datetime.fromisoformat(value)
        return timestamp.tzinfo is not None and timestamp.utcoffset() is not None
    except (ValueError, TypeError, OverflowError):
        return False


def _restore_marker():
    # A corrupt or missing reminder is never proof of restored credentials.
    try:
        with (Path(config.DATA_DIR) / 'recovery-check.json').open(encoding='utf-8') as stream:
            content = stream.read(513)
        if len(content) > 512:
            return None
        marker = json.loads(content)
        candidate = marker.get('restored_at') if isinstance(marker, dict) else None
        return candidate if valid_recovery_timestamp(candidate) else None
    except (OSError, ValueError, TypeError):
        return None


def mark_restore_recovery(data_dir):
    try:
        with storage_lock('restore-recovery-check'):
            atomic_write_json(Path(data_dir) / 'recovery-check.json', {
                'restored_at': datetime.now(timezone.utc).isoformat(),
                'remote_credentials_excluded': True,
            })
    except OSError:
        from .audit_logger import log_warning
        log_warning('Restore completed but optional recovery reminder could not be saved')


@customer_workflows_blueprint.route('/api/account/recovery-check', methods=['GET', 'POST'])
@login_required
def recovery_check():
    from .profile_manager import load_profiles
    from .key_manager import load_keys
    from .jump_host_manager import load_jump_hosts
    from .socks_proxy_manager import load_socks_proxies
    from .host_key_store import HostKeyStore
    with user_data_access(current_user.id):
        if request.method == 'POST':
            body = request.get_json(silent=True)
            if (not isinstance(body, dict) or set(body) != {'restored_at'}
                    or not valid_recovery_timestamp(body.get('restored_at'))):
                return jsonify(error='Invalid recovery review'), 400
            # Serialize marker comparison and account acknowledgement against a
            # concurrent restore. An older checklist cannot dismiss a new restore.
            with storage_lock('restore-recovery-check'):
                current = _restore_marker()
                if current is None or body['restored_at'] != current:
                    return jsonify(error='The restore marker changed. Review the current checklist.', code='restore_changed'), 409
                if not save_user_settings(current_user.id, {'recovery_reviewed_at': current}):
                    return jsonify(error='Could not save recovery review'), 500
            response = jsonify(restored_at=current, needs_review=False)
            response.headers['Cache-Control'] = 'no-store'
            return response
        profiles = load_profiles(current_user.id)
        keys = {key['id'] for key in load_keys(current_user.id)}
        jumps = {jump['id'] for jump in load_jump_hosts(current_user.id)}
        socks = {proxy['id'] for proxy in load_socks_proxies(current_user.id)}
        credentials = current_app.extensions['credentials']
        resources = {item['id']: item for item in credentials.resources(current_user.id) if item.get('kind') == 'ssh'}
        trust = HostKeyStore(current_user.id, config.KNOWN_HOSTS_FILE, config.USERS_DIR).trust_checker()
        hosts = []
        for host in profiles:
            if host['auth_type'] == 'key':
                credential = 'ready' if host.get('key_id') in keys else 'key_required'
            elif host['auth_type'] == 'password':
                resource = resources.get(host['id'])
                credential = 'ready' if resource and credentials.credential_status(current_user.id, resource) == 'ready' else 'password_required'
            else:
                credential = 'interactive'
            route = 'missing_jump' if host.get('jump_host_id') and host['jump_host_id'] not in jumps else 'configured'
            if host.get('socks_proxy_id') and host['socks_proxy_id'] not in socks:
                route = 'missing_socks'
            hosts.append(dict(id=host['id'], name=host['name'], credential=credential,
                              route=route,
                              host_key='trusted' if trust(host['host'], host.get('port', 22)) else 'review_required'))
        schedules = current_app.extensions['automation_schedules'].list(current_user.id)
        with storage_lock('restore-recovery-check'):
            restored_at = _restore_marker()
            needs_review = bool(restored_at and get_user_settings(current_user.id).get('recovery_reviewed_at') != restored_at)
        response = jsonify(restored_at=restored_at, needs_review=needs_review,
                           coverage={'configuration': 'included', 'account_authentication': 'included', 'remote_credentials': 'excluded', 'live_sessions': 'excluded'},
                           hosts=hosts, schedules=[{'id': row['id'], 'name': row['name'], 'enabled': row['enabled'], 'status': row['last_status']} for row in schedules])
    response.headers['Cache-Control'] = 'no-store'
    return response
