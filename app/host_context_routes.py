"""Authenticated access to private saved-host context."""

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from .host_context import ContextError, read_context, write_context

host_context_blueprint = Blueprint('host_context', __name__)


@host_context_blueprint.route('/api/profiles/<profile_id>/context', methods=['GET', 'PUT'])
@login_required
def context(profile_id):
    try:
        if request.method == 'GET':
            return jsonify(read_context(current_user.id, profile_id))
        request.max_content_length = 1024 * 1024
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or set(data) != {'revision', 'notes', 'directories', 'command_sets'}:
            raise ContextError('invalid')
        content = {key: value for key, value in data.items() if key != 'revision'}
        return jsonify(write_context(current_user.id, profile_id, content, data['revision']))
    except ContextError as error:
        status = {'not_found': 404, 'conflict': 409, 'quota': 413}.get(error.code, 400)
        return jsonify({'error': 'Host context could not be saved or loaded.', 'code': error.code}), status
