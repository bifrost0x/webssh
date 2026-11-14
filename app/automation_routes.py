"""Authenticated HTTP control plane for native automation and write-only vault."""
import ipaddress
import csv
import io
import json
from flask import Blueprint, current_app, jsonify, request, redirect, url_for, Response
from flask_login import current_user, login_required
import config
from .automation_store import AutomationError, runbooks, save_runbook, delete_runbook
from .auth_assurance import current_authentication_session
from .transport_security import request_reached_over_https
from .auth import check_reauth_rate_limit
from .step_up import consume_account_step_up_grant, StepUpError
from .storage_errors import StorageCorruptionError
from .quota_manager import QuotaExceeded

automation_blueprint = Blueprint('automation', __name__)

def service():
    return current_app.extensions['automation']

def _auth():
    auth = current_authentication_session()
    if auth is None:
        raise AutomationError('authentication_required')
    return auth

def _secure():
    if request_reached_over_https():
        return
    try:
        loopback = ipaddress.ip_address(request.remote_addr or '').is_loopback
    except ValueError:
        loopback = False
    proxied = bool(config.TRUSTED_PROXIES) or any(
        name.lower() == 'forwarded' or name.lower().startswith('x-forwarded-')
        for name in request.headers.keys()
    )
    if not (config.DEBUG and config.DEPLOYMENT_PROFILE == 'homelab'
            and config.AUTOMATION_ALLOW_INSECURE_LOOPBACK and loopback and not proxied):
        raise AutomationError('https_required')

def _enabled():
    from .app_settings import is_automation_enabled
    if not is_automation_enabled():
        raise AutomationError('disabled')
    _secure()
    if not current_app.extensions['runtime_lifecycle'].accepting_work():
        raise AutomationError('unavailable')

def _data():
    value = request.get_json(silent=True)
    if not isinstance(value, dict):
        raise AutomationError('invalid_request')
    return value

def _grant(action, token):
    try:
        consume_account_step_up_grant(action, token)
    except StepUpError as error:
        raise AutomationError('step_up_required') from error

@automation_blueprint.before_request
def bounds():
    request.max_content_length = 256 * 1024

@automation_blueprint.after_request
def private(response):
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    return response

@automation_blueprint.errorhandler(AutomationError)
def failure(error):
    status = {'authentication_required':401, 'disabled':403, 'https_required':403,
        'step_up_required':403, 'busy':429, 'not_found':404, 'invalid_intent':409,
        'preview_changed':409, 'vault_locked':423, 'unavailable':503,
        'credentials_disabled':403, 'host_key_required':409, 'run_active':409}.get(error.code, 400)
    body = dict(error='Automation request could not be completed.', code=error.code)
    # Names of the user's own saved hosts let the browser say which host to verify.
    if getattr(error, 'hosts', None):
        body['hosts'] = error.hosts
    return jsonify(body), status

@automation_blueprint.errorhandler(StorageCorruptionError)
def corrupt(_error):
    return jsonify(error='Automation storage could not be validated.', code='storage_unavailable'), 409

@automation_blueprint.errorhandler(OSError)
def storage_failure(_error):
    return jsonify(error='Automation storage is unavailable.', code='storage_unavailable'), 503

@automation_blueprint.errorhandler(QuotaExceeded)
def quota(_error):
    return jsonify(error='Automation capacity is exhausted.', code='busy'), 429

@automation_blueprint.get('/automation')
@login_required
def page():
    return redirect(url_for('index') + '#automation')

@automation_blueprint.get('/api/automation/state')
@login_required
def state():
    auth = _auth()
    _enabled()
    from .app_settings import is_credentials_enabled
    from .automation_service import supported_login
    credentials = service().credentials
    # Resources carry the jump host's fingerprint, which saved-password bindings use.
    resources = credentials.resources(current_user.id)
    routes = {item['id']: item for item in resources if item['kind'] == 'jump'}

    def status(item):
        return credentials.credential_status(current_user.id, item) if item.get('auth_type') == 'password' else 'ready'

    def target(profile):
        route = routes.get('jump:' + profile['jump_host_id']) if profile.get('jump_host_id') else None
        entry = dict(**service().display_target(profile), auth_type=profile.get('auth_type'),
                     credential_status=status(profile),
                     supported=supported_login(profile) and (route is None and not profile.get('jump_host_id')
                                                             or supported_login(route)))
        if route is not None:
            entry.update(via=route['name'], route_id=route['id'], route_auth_type=route.get('auth_type'),
                         route_credential_status=status(route))
        if profile.get('socks_proxy_id'):
            entry.update(socks_proxy_id=profile['socks_proxy_id'],
                         unsupported_reason='SOCKS5 routes are not supported for automation yet')
        return entry

    return jsonify(enabled=True, credentials_enabled=is_credentials_enabled(), runbooks=runbooks(current_user.id),
        profiles=[target(item) for item in resources if item['kind'] == 'ssh'],
        vault=credentials.vault_status(current_user.id, auth.id))

@automation_blueprint.post('/api/automation/runbooks')
@login_required
def save():
    _auth()
    _enabled()
    return jsonify(runbook=save_runbook(current_user.id, _data()))

@automation_blueprint.delete('/api/automation/runbooks/<book_id>')
@login_required
def remove(book_id):
    _auth()
    _enabled()
    delete_runbook(current_user.id, book_id)
    return jsonify(deleted=True)

@automation_blueprint.post('/api/automation/preview')
@login_required
def preview():
    auth = _auth()
    _enabled()
    return jsonify(service().prepare_run(current_user.id, auth.id, _data()))

@automation_blueprint.post('/api/automation/start')
@login_required
def start():
    auth = _auth()
    _enabled()
    data = _data()
    intent = service().intent(data.get('intent'), current_user.id, auth.id)
    if intent['kind'] != 'run' or data.get('confirmation') != str(len(intent['targets'])):
        raise AutomationError('confirmation_required')
    _grant('automation.run', data.get('intent'))
    return jsonify(run=service().start(data['intent'], current_user.id, auth.id, data['confirmation'])), 202

@automation_blueprint.get('/api/automation/runs')
@login_required
def runs():
    _auth()
    _enabled()
    return jsonify(runs=service().history(current_user.id))

@automation_blueprint.post('/api/automation/runs/<run_id>/cancel')
@login_required
def cancel(run_id):
    _auth()
    _enabled()
    service().cancel(current_user.id, run_id)
    return jsonify(cancellation_requested=True)

@automation_blueprint.delete('/api/automation/runs/<run_id>')
@login_required
def delete_run(run_id):
    _auth()
    _enabled()
    return jsonify(deleted=service().delete_runs(current_user.id, [run_id]))

@automation_blueprint.post('/api/automation/runs/clear')
@login_required
def clear_runs():
    _auth()
    _enabled()
    return jsonify(deleted=service().delete_runs(current_user.id))

@automation_blueprint.post('/api/automation/vault/intents')
@login_required
def vault_intent():
    auth = _auth()
    _enabled()
    if check_reauth_rate_limit(current_user.id, request.remote_addr, 'automation_vault', '10 per minute'):
        raise AutomationError('busy')
    return jsonify(service().prepare_vault(current_user.id, auth.id, _data()))

@automation_blueprint.post('/api/automation/vault/apply')
@login_required
def vault_apply():
    auth = _auth()
    _enabled()
    data = _data()
    intent = service().intent(data.get('intent'), current_user.id, auth.id)
    if intent['kind'] != 'vault':
        raise AutomationError('invalid_intent')
    _grant('automation.vault', data['intent'])
    return jsonify(service().apply_vault(data['intent'], current_user.id, auth.id, data))

@automation_blueprint.post('/api/automation/vault/lock')
@login_required
def vault_lock():
    auth = _auth()
    _enabled()
    service().lock_vault(current_user.id)
    return jsonify(service().credentials.vault_status(current_user.id, auth.id))


@automation_blueprint.get('/api/automation/schedules')
@login_required
def schedules():
    _auth()
    _secure()
    return jsonify(schedules=current_app.extensions['automation_schedules'].list(current_user.id))


@automation_blueprint.post('/api/automation/schedules/preview')
@login_required
def schedule_preview():
    auth = _auth()
    _enabled()
    return jsonify(current_app.extensions['automation_schedules'].prepare(current_user.id, auth.id, _data()))


@automation_blueprint.post('/api/automation/schedules')
@login_required
def schedule_apply():
    auth = _auth()
    _enabled()
    data = _data()
    token = data.get('intent')
    intent = service().intent(token, current_user.id, auth.id)
    if intent['kind'] != 'schedule' or data.get('confirmation') != str(len(intent['targets'])):
        raise AutomationError('confirmation_required')
    _grant('automation.schedule', token)
    return jsonify(schedule=current_app.extensions['automation_schedules'].apply(current_user.id, auth.id, token, data['confirmation']))


@automation_blueprint.post('/api/automation/schedules/<schedule_id>/pause')
@login_required
def schedule_pause(schedule_id):
    _auth()
    _secure()
    return jsonify(schedule=current_app.extensions['automation_schedules'].pause(current_user.id, schedule_id))


@automation_blueprint.post('/api/automation/schedules/<schedule_id>/preview-run')
@login_required
def schedule_run_preview(schedule_id):
    auth = _auth()
    _enabled()
    return jsonify(current_app.extensions['automation_schedules'].prepare_run(current_user.id, auth.id, schedule_id))


@automation_blueprint.delete('/api/automation/schedules/<schedule_id>')
@login_required
def schedule_delete(schedule_id):
    _auth()
    _secure()
    current_app.extensions['automation_schedules'].pause(current_user.id, schedule_id, delete=True)
    return jsonify(deleted=True)


@automation_blueprint.get('/api/automation/runs/<run_id>/export')
@login_required
def export_run(run_id):
    _auth()
    _enabled()
    format_name = request.args.get('format', 'json')
    if format_name not in {'json', 'csv'}:
        raise AutomationError('invalid_request')
    # Same validated, size-bounded, owner-fenced source as the run history UI.
    run = next((item for item in service().history(current_user.id) if item['id'] == run_id), None)
    if run is None:
        raise AutomationError('not_found')
    if format_name == 'json':
        body = json.dumps(run, ensure_ascii=True)
        mimetype = 'application/json'
    else:
        output = io.StringIO(newline='')
        writer = csv.writer(output)
        writer.writerow(['run_id', 'workflow', 'created_at', 'finished_at', 'run_status',
            'target_id', 'target', 'host', 'port', 'username', 'group', 'target_status', 'target_reason',
            'step', 'status', 'reason', 'exit_code', 'duration', 'output_truncated', 'stdout', 'stderr'])
        def safe(value):
            value = '' if value is None else str(value)
            return "'" + value if value.lstrip('\ufeff \t\r\n\v\f').startswith(('=', '+', '-', '@')) or value.startswith(('\t', '\r', '\n')) else value
        for target in run['targets']:
            for step in target['steps']:
                values = [run['id'], run['name'], run['created_at'], run.get('finished_at'), run['status'],
                    target['id'], target['name'], target['host'], target['port'], target['username'], target['group'],
                    target['status'], target['reason'], step['name'], step['status'], step.get('reason'),
                    step['exit_code'], step['duration'], step.get('output_truncated'),
                    step.get('stdout', ''), step.get('stderr', '')]
                writer.writerow([safe(value) for value in values])
        body, mimetype = output.getvalue(), 'text/csv'
    response = Response(body, mimetype=mimetype)
    response.headers['Content-Disposition'] = f'attachment; filename="workflow-run.{format_name}"'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response
