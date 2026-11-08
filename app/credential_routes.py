"""HTTPS-only personal credential management, independent of Automation."""
from flask import Blueprint, current_app, jsonify, redirect, url_for, request
from flask_login import current_user, login_required
from .automation_store import AutomationError
from .automation_routes import _auth, _data, _grant, bounds, private, corrupt, storage_failure
from .auth import check_reauth_rate_limit
from .storage_errors import StorageCorruptionError

credentials_blueprint = Blueprint('credentials', __name__)
credentials_blueprint.before_request(bounds)
credentials_blueprint.after_request(private)
credentials_blueprint.register_error_handler(StorageCorruptionError, corrupt)
credentials_blueprint.register_error_handler(OSError, storage_failure)


def service():
    return current_app.extensions['credentials']


def _available():
    if not request.is_secure:
        raise AutomationError('https_required')
    if not current_app.extensions['runtime_lifecycle'].accepting_work():
        raise AutomationError('unavailable')


@credentials_blueprint.errorhandler(AutomationError)
def failure(error):
    status = {'authentication_required':401, 'https_required':403, 'step_up_required':403,
              'busy':429, 'not_found':404, 'invalid_intent':409, 'preview_changed':409,
              'vault_locked':423, 'unavailable':503, 'credentials_disabled':403, 'credential_in_use':409}.get(error.code, 400)
    return jsonify(error='Credential request could not be completed.', code=error.code), status


@credentials_blueprint.get('/credentials')
@login_required
def page():
    return redirect(url_for('index') + '#passwords')


@credentials_blueprint.get('/api/credentials/state')
@login_required
def state():
    auth = _auth()
    _available()
    return jsonify(service().native_state(current_user.id,auth.id))


@credentials_blueprint.post('/api/credentials/intents')
@login_required
def intent():
    auth = _auth()
    _available()
    data = _data()
    native = data.get('operation') == 'native'
    mutation = data.get('mutation') if native else None
    passphrase_attempt = isinstance(mutation, dict) and mutation.get('method') == 'import'
    # Native assignment batches are ordinary authenticated mutations, not
    # attempts to guess a vault passphrase. Keep a separate bounded budget.
    # A legacy vault import decrypts with a submitted passphrase and shares
    # the vault unlock budget.
    if native and not passphrase_attempt:
        bucket, limit = 'credential_change', '120 per minute'
    else:
        bucket, limit = 'automation_vault', '10 per minute'
    if check_reauth_rate_limit(current_user.id, request.remote_addr, bucket, limit):
        raise AutomationError('busy')
    return jsonify(service().prepare_vault(current_user.id, auth.id, data))


@credentials_blueprint.post('/api/credentials/apply')
@login_required
def apply():
    auth = _auth()
    _available()
    data = _data()
    service().intent(data.get('intent'), current_user.id, auth.id)
    _grant('credentials.vault', data['intent'])
    return jsonify(service().apply_vault(data['intent'], current_user.id, auth.id, data))


@credentials_blueprint.post('/api/credentials/lock')
@login_required
def lock():
    auth = _auth()
    _available()
    service().revoke(current_user.id)
    automation = current_app.extensions.get('automation')
    if automation is not None:
        automation.cancel(current_user.id, manual_only=True)
    return jsonify(service().vault_status(current_user.id, auth.id))


def _binds_saved_secret(method, data):
    """Mutations that let the server send an existing saved secret somewhere.

    Assigning a saved password to a destination, authorizing a one-off target
    and importing the legacy vault all disclose a stored secret to a
    destination chosen in this request. They are treated like reading the
    secret and require account reauthentication. Typing a new password,
    renaming, unassigning and deleting do not.
    """
    if method == 'assign':
        return bool(data.get('credential_id'))
    return method in {'import', 'authorize_target'}


def _require_binding_step_up(uid, auth_id, token):
    if service().binding_assured(uid, auth_id):
        return
    _grant('credentials.vault', token)
    service().assure_binding(uid, auth_id)


def _native(method, rid=None):
    from .automation_store import digest
    auth=_auth()
    _available()
    data=_data()
    token=data.pop('intent',None)
    if method=='assign' and not data.get('resource_id'):
        raise AutomationError('invalid_targets')
    mutation=dict(data,method=method)
    if rid is not None: mutation['credential_id']=rid
    intent=service().intent(token,current_user.id,auth.id)
    if intent.get('kind')!='native' or intent.get('mutation_digest')!=digest(mutation):
        raise AutomationError('invalid_intent')
    uid=current_user.id
    if _binds_saved_secret(method, data):
        # Checked before the intent is consumed, so the browser can complete
        # reauthentication for this exact intent and retry it.
        _require_binding_step_up(uid, auth.id, token)
    if method=='authorize_target':
        service().intent(token,uid,auth.id,consume=True)
        result=service().authorize_target(uid,auth.id,data)
        log_security_event('CREDENTIAL_CHANGED',user_id=uid,action=method)
        return jsonify(result)
    result={}
    assignment=method in {'create','assign'} and bool(data.get('resource_id'))
    if not assignment:
        service().intent(token,uid,auth.id,consume=True)
    if method in {'create','assign'} and data.get('resource_id'):
        service().apply_native_assignment(uid,auth.id,token,mutation)
    elif method=='create_for_resource': result=service().create_for_resource(uid,data)
    elif method=='create': service().create_named(uid,data)
    elif method=='update': service().update_named(uid,rid,data)
    elif method=='delete': service().delete_named(uid,rid)
    elif method=='import': service().import_legacy(uid,auth.id,data.get('passphrase'))
    log_security_event('CREDENTIAL_CHANGED',user_id=uid,action=method)
    return jsonify(dict(service().native_state(uid,auth.id),**result))


from .audit_logger import log_security_event

@credentials_blueprint.post('/api/credentials')
@login_required
def native_create():
    return _native('create')

@credentials_blueprint.patch('/api/credentials/<rid>')
@login_required
def native_update(rid):
    return _native('update',rid)

@credentials_blueprint.delete('/api/credentials/<rid>')
@login_required
def native_delete(rid):
    return _native('delete',rid)

@credentials_blueprint.post('/api/credentials/assign')
@login_required
def native_assign():
    return _native('assign')

@credentials_blueprint.post('/api/credentials/import-legacy')
@login_required
def native_import():
    return _native('import')

@credentials_blueprint.post('/api/credentials/authorize-target')
@login_required
def native_target():
    return _native('authorize_target')

@credentials_blueprint.post('/api/credentials/create-for-resource')
@login_required
def native_create_for_resource():
    return _native('create_for_resource')
