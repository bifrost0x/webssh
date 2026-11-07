"""Overview data: per-host readiness and an optional, bounded reachability check.

Both endpoints only describe the signed-in user's own saved hosts. Readiness
is derived from stored configuration and never contacts a host. The
reachability check opens a plain TCP connection to the SSH port (no SSH
handshake, no credentials) under the same network policy as a real
connection, and is limited in size, concurrency, rate and frequency.
"""
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
import threading
import time

from flask import Blueprint, current_app, jsonify, request
from flask_login import current_user, login_required

import config
from .audit_logger import log_info
from .auth import check_user_rate_limit

overview_blueprint = Blueprint('overview', __name__)

MAX_PROBES = 50
PROBE_TIMEOUT_SECONDS = 3
CHECK_DEADLINE_SECONDS = 8
CACHE_SECONDS = 60
# The last answer stays on display across page loads, never as a fresh check.
RESULT_RETENTION_SECONDS = 30 * 60
RATE_LIMIT = '6 per minute'
# Probed endpoints per account and minute, across requests.
PROBE_BUDGET = '150 per minute'

# Shared by all users: at most this many probes run at once in the process.
_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix='overview-reachability')
_CACHE_LOCK = threading.Lock()
_CACHE = {}
# Accounts whose probes are still running; one check per account at a time.
_IN_FLIGHT = set()


def _owned_inventory(user_id):
    from .profile_manager import load_profiles
    from .jump_host_manager import load_jump_hosts
    from .key_manager import load_keys
    return load_profiles(user_id), load_jump_hosts(user_id), load_keys(user_id)


def _endpoint(record):
    from .network_policy import canonicalize_hostname
    try:
        return canonicalize_hostname(record.get('host')), int(record.get('port') or 22)
    except (TypeError, ValueError):
        return None


def _readiness(user_id, profiles, jumps, keys):
    from .host_key_store import HostKeyStore
    trusted = HostKeyStore(user_id, config.KNOWN_HOSTS_FILE, config.USERS_DIR).trust_checker()
    credentials = current_app.extensions.get('credentials')
    # Credential bindings are fingerprinted against the resource view, which
    # includes the jump route; use the same view as real connections.
    resources = {item['id']: item for item in credentials.resources(user_id) if item.get('kind') == 'ssh'} if credentials else {}
    key_ids = {key.get('id') for key in keys}
    jump_by_id = {jump.get('id'): jump for jump in jumps}
    result = []
    for profile in profiles:
        endpoint = _endpoint(profile)
        jump = jump_by_id.get(profile.get('jump_host_id')) if profile.get('jump_host_id') else None
        route = 'direct' if not profile.get('jump_host_id') else 'jump' if jump else 'missing'
        host_key = 'trusted' if endpoint and trusted(*endpoint) else 'unknown'
        if profile.get('auth_type') == 'key':
            auth = 'ready' if profile.get('key_id') in key_ids else 'key_missing'
        elif profile.get('auth_type') == 'password' and profile.get('id') in resources:
            status = credentials.credential_status(user_id, resources[profile['id']])
            auth = {'ready': 'saved_password', 'changed': 'password_changed'}.get(status, 'prompt')
        else:
            auth = 'prompt'
        if route == 'missing':
            state = 'broken'
        elif host_key != 'trusted' or auth in {'key_missing', 'password_changed'}:
            state = 'action'
        else:
            state = 'ready'
        result.append(dict(id=profile.get('id'), state=state, route=route, host_key=host_key, auth=auth))
    return result


@overview_blueprint.get('/api/overview/status')
@login_required
def status():
    from .data_access import user_data_access
    with user_data_access(current_user.id):
        profiles, jumps, keys = _owned_inventory(current_user.id)
        hosts = _readiness(current_user.id, profiles, jumps, keys)
    response = jsonify(hosts=hosts, generated_at=time.time())
    response.headers['Cache-Control'] = 'no-store'
    return response


def _probe(host, port):
    """One TCP connect under the network policy; never sends data."""
    from .network_policy import open_validated_socket, resolve_allowed_target
    started = time.monotonic()
    try:
        target = resolve_allowed_target(host, port, allow_internal=not config.BLOCK_INTERNAL_SSH,
                                        allowed_internal_networks=config.SSH_ALLOWED_INTERNAL_NETWORKS)
    except ValueError as error:
        message = str(error)
        return dict(state='unresolved' if 'resolved' in message else 'blocked')
    try:
        connection = open_validated_socket(target, PROBE_TIMEOUT_SECONDS)
    except OSError:
        return dict(state='unreachable')
    connection.close()
    return dict(state='reachable', latency_ms=round((time.monotonic() - started) * 1000))


def _plans(user_id, wanted=None):
    from .data_access import user_data_access
    with user_data_access(user_id):
        profiles, jumps, _keys = _owned_inventory(user_id)
    jump_by_id = {jump.get('id'): jump for jump in jumps}
    plans = {}
    for profile in profiles:
        if wanted is not None and profile.get('id') not in wanted:
            continue
        if len(plans) >= MAX_PROBES:
            break
        record = jump_by_id.get(profile.get('jump_host_id')) if profile.get('jump_host_id') else profile
        endpoint = _endpoint(record) if record else None
        plans[profile.get('id')] = dict(endpoint=endpoint, via_jump=bool(profile.get('jump_host_id')))
    # A stored answer belongs to exactly this set of destinations.
    signature = tuple(sorted((key, str(plan['endpoint']), plan['via_jump']) for key, plan in plans.items()))
    return plans, signature


@overview_blueprint.get('/api/overview/reachability')
@login_required
def last_reachability():
    """Return the last check for the current hosts without contacting any host."""
    _unused, signature = _plans(current_user.id)
    with _CACHE_LOCK:
        cached = _CACHE.get(current_user.id)
        current = bool(cached and cached['signature'] == signature
                       and time.monotonic() - cached['at'] < RESULT_RETENTION_SECONDS)
        payload = dict(results=cached['results'], checked_at=cached['checked_at']) if current else dict(results=None)
    response = jsonify(**payload)
    response.headers['Cache-Control'] = 'no-store'
    return response


@overview_blueprint.post('/api/overview/reachability')
@login_required
def reachability():
    if not current_app.extensions['runtime_lifecycle'].accepting_work():
        return jsonify(error='WebSSH is not accepting new work.', code='unavailable'), 503
    data = request.get_json(silent=True)
    if data is not None and not isinstance(data, dict):
        return jsonify(error='Invalid request.', code='invalid_request'), 400
    requested = (data or {}).get('ids')
    if requested is not None and (not isinstance(requested, list) or len(requested) > MAX_PROBES
                                  or not all(isinstance(item, str) and len(item) <= 128 for item in requested)):
        return jsonify(error='Invalid request.', code='invalid_request'), 400
    user_id = current_user.id
    plans, signature = _plans(user_id, set(requested) if requested is not None else None)
    endpoints = {plan['endpoint'] for plan in plans.values() if plan['endpoint']}
    with _CACHE_LOCK:
        cached = _CACHE.get(user_id)
        if cached and cached['signature'] == signature and time.monotonic() - cached['at'] < CACHE_SECONDS:
            return jsonify(results=cached['results'], cached=True, checked_at=cached['checked_at'])
    if (check_user_rate_limit(user_id, 'overview_reachability', RATE_LIMIT)
            or check_user_rate_limit(user_id, 'overview_reachability_probes', PROBE_BUDGET, cost=len(endpoints))):
        return jsonify(error='Too many checks. Wait a minute and try again.', code='busy'), 429
    with _CACHE_LOCK:
        if user_id in _IN_FLIGHT:
            return jsonify(error='A check is still running.', code='busy'), 429
        _IN_FLIGHT.add(user_id)
    futures = {endpoint: _EXECUTOR.submit(_probe, *endpoint) for endpoint in endpoints}
    try:
        deadline = time.monotonic() + CHECK_DEADLINE_SECONDS
        outcomes = {}
        for endpoint, future in futures.items():
            try:
                outcomes[endpoint] = future.result(timeout=max(0.0, deadline - time.monotonic()))
            except FutureTimeout:
                outcomes[endpoint] = dict(state='unreachable')
    finally:
        # Probes that did not start before the deadline leave the shared queue.
        for future in futures.values():
            future.cancel()
        with _CACHE_LOCK:
            _IN_FLIGHT.discard(user_id)
    results = {}
    for profile_id, plan in plans.items():
        outcome = dict(outcomes.get(plan['endpoint']) or dict(state='unresolved'))
        if plan['via_jump']:
            outcome['via_jump'] = True
        results[profile_id] = outcome
    checked_at = time.time()
    with _CACHE_LOCK:
        _CACHE[user_id] = dict(at=time.monotonic(), signature=signature, results=results, checked_at=checked_at)
    log_info('Overview reachability check', user_id=user_id, hosts=len(plans), endpoints=len(endpoints))
    response = jsonify(results=results, cached=False, checked_at=checked_at)
    response.headers['Cache-Control'] = 'no-store'
    return response


@overview_blueprint.put('/api/overview/preferences')
@login_required
def save_preferences():
    """Store the account's panel arrangement and acknowledged attention items."""
    from .user_settings import (get_user_settings, save_user_settings,
                                valid_overview_dismissed, valid_overview_layout)
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not data or set(data) - {'panels', 'dismissed'}:
        return jsonify(error='Invalid request.', code='invalid_request'), 400
    updates = {}
    if 'panels' in data:
        if not valid_overview_layout(data['panels']):
            return jsonify(error='Invalid layout.', code='invalid_layout'), 400
        updates['overview_panels'] = data['panels']
    if 'dismissed' in data:
        if not valid_overview_dismissed(data['dismissed']):
            return jsonify(error='Invalid acknowledgement list.', code='invalid_dismissed'), 400
        updates['overview_dismissed'] = data['dismissed']
    if not save_user_settings(current_user.id, updates):
        return jsonify(error='The overview settings could not be saved.', code='storage'), 500
    settings = get_user_settings(current_user.id)
    return jsonify(panels=settings.get('overview_panels'), dismissed=settings.get('overview_dismissed', []))
