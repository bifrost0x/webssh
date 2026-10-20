"""Session-scoped server diagnostics and explicitly authorized mutations."""

from flask import Blueprint, current_app, jsonify, request
from flask_login import current_user, login_required

import config

from . import server_operations as operations
from .audit_logger import log_security_event
from .auth_assurance import current_authentication_session
from .step_up import consume_account_step_up_grant, StepUpError

server_operations_blueprint = Blueprint('server_operations', __name__)


def _data():
    request.max_content_length = 16 * 1024
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise operations.OperationError('invalid_request')
    return data


def _auth():
    auth = current_authentication_session()
    if auth is None:
        raise operations.OperationError('authentication_required')
    if not current_app.extensions['runtime_lifecycle'].accepting_work():
        raise operations.OperationError('unavailable')
    return auth


def _enabled():
    if not config.SERVER_OPERATIONS_ENABLED:
        raise operations.OperationError('disabled')


@server_operations_blueprint.errorhandler(operations.OperationError)
def operation_error(error):
    status = {
        'unavailable': 404, 'authentication_required': 401, 'disabled': 403,
        'busy': 429, 'invalid_intent': 409, 'unknown': 409,
        'timeout': 504, 'output_limit': 413,
    }.get(error.code, 400)
    return jsonify({'error': 'Server operation could not be completed.',
                    'code': error.code}), status


@server_operations_blueprint.get('/api/server-operations/<session_id>')
@login_required
def capabilities(session_id):
    _auth()
    session = operations.owned_session(session_id, current_user.id)
    return jsonify({
        'mutations_enabled': config.SERVER_OPERATIONS_ENABLED,
        'host': session.get('host', ''),
        'username': session.get('username', ''),
        'read_actions': sorted(operations.READ_ACTIONS),
        'write_actions': sorted(operations.WRITE_ACTIONS) if config.SERVER_OPERATIONS_ENABLED else [],
    })


@server_operations_blueprint.post('/api/server-operations/read')
@login_required
def read():
    _auth()
    data = _data()
    action = data.get('action')
    if not isinstance(action, str) or action not in operations.READ_ACTIONS:
        raise operations.OperationError('invalid_action')
    command = operations.build_command(action, data.get('target', {}),
                                       use_sudo=data.get('use_sudo', False))
    session_id = data.get('session_id')
    session = operations.owned_session(session_id, current_user.id)
    lifecycle = current_app.extensions['runtime_lifecycle']
    result = operations.execute_command(
        session_id, current_user.id, session, command,
        cancelled=lambda: not lifecycle.accepting_work(),
    )
    if action == 'process.list' and result.get('status') == 'completed':
        result['processes'] = operations.parse_process_list(result.get('output', ''))
        result['output'] = ''
    if action == 'container.logs':
        result['output'], result['error_output'] = operations.newest_container_logs(
            result.get('output', ''), result.get('error_output', ''),
        )
    return jsonify(result)


@server_operations_blueprint.post('/api/server-operations/intents')
@login_required
def prepare():
    _enabled()
    auth = _auth()
    data = _data()
    token, intent = operations.prepare_intent(
        data.get('session_id'), current_user.id, auth.id, data.get('action'),
        data.get('target', {}), use_sudo=data.get('use_sudo', False),
    )
    return jsonify({
        'intent': token, 'action': intent.action, 'command': intent.command,
        'host': intent.session.get('host', ''), 'username': intent.session.get('username', ''),
        'confirmation': intent.confirmation, 'expires_in': operations.INTENT_TTL,
    })


@server_operations_blueprint.post('/api/server-operations/execute')
@login_required
def execute():
    _enabled()
    auth = _auth()
    data = _data()
    token = data.get('intent')
    intent = operations.get_intent(token, current_user.id, auth.id)
    if intent.confirmation and data.get('confirmation') != intent.confirmation:
        raise operations.OperationError('confirmation_required')
    try:
        consume_account_step_up_grant('server.operation', token)
    except StepUpError:
        return jsonify({'error': 'Reauthentication is required.', 'code': 'step_up_required'}), 403
    intent = operations.get_intent(token, current_user.id, auth.id, consume=True)
    log_security_event('SERVER_OPERATION_REQUESTED', user=current_user.username,
                       action=intent.action, session_id=intent.session_id)
    try:
        lifecycle = current_app.extensions['runtime_lifecycle']
        result = operations.execute_command(
            intent.session_id, current_user.id, intent.session, intent.command,
            mutating=True, expected_client=intent.client,
            cancelled=lambda: not lifecycle.accepting_work(),
        )
    except operations.OperationError as error:
        log_security_event('SERVER_OPERATION_RESULT', user=current_user.username,
                           action=intent.action, outcome=error.code)
        raise
    if intent.action == 'system.reboot' and result['status'] == 'completed':
        result['status'] = 'requested'
    log_security_event('SERVER_OPERATION_RESULT', user=current_user.username,
                       action=intent.action, outcome=result['status'])
    return jsonify(result)
