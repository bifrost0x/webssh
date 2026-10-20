"""Authenticated metadata import with server-side preview revalidation."""

import io
import json
import zipfile

from flask import Blueprint, jsonify, request, send_file
from flask_login import current_user, login_required

from .connection_storage_policy import ConnectionStorageLimitError
from .jump_host_manager import load_jump_hosts
from .key_manager import load_key_summaries
from .profile_exchange import ExchangeError, export_batches, preview_import
from .profile_manager import load_profiles, upsert_profile

profile_exchange_blueprint = Blueprint('profile_exchange', __name__)


def _data():
    request.max_content_length = 512 * 1024
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ExchangeError('Invalid import request.')
    return data


@profile_exchange_blueprint.post('/api/profiles/exchange/preview')
@login_required
def preview():
    try:
        data = _data()
        result = preview_import(data.get('source'), data.get('format'))
        result['keys'] = [
            {'id': key['id'], 'name': key['name']}
            for key in load_key_summaries(current_user.id)
            if key.get('usable') is True
        ]
        result['jump_hosts'] = [
            {'id': item['id'], 'name': item['name']}
            for item in load_jump_hosts(current_user.id)
        ]
        return jsonify(result)
    except ExchangeError as error:
        return jsonify({'error': str(error)}), 400


@profile_exchange_blueprint.get('/api/profiles/exchange')
@login_required
def export():
    batches = export_batches(
        load_profiles(current_user.id), load_jump_hosts(current_user.id),
    )
    if len(batches) == 1:
        return jsonify(batches[0])
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED) as archive:
        for number, batch in enumerate(batches, 1):
            archive.writestr(f'webssh-hosts-{number}.json', json.dumps(batch))
    output.seek(0)
    return send_file(output, mimetype='application/zip',
                     as_attachment=True, download_name='webssh-hosts.zip')


@profile_exchange_blueprint.post('/api/profiles/exchange')
@login_required
def import_hosts():
    try:
        data = _data()
        rows = preview_import(data.get('source'), data.get('format'))['records']
        selections = data.get('selections')
        if not isinstance(selections, list) or len(selections) > 100:
            raise ExchangeError('Choose up to 100 hosts.')
        seen = set()
        for selection in selections:
            if not isinstance(selection, dict) or set(selection) - {'index', 'username', 'key_id', 'jump_host_id'}:
                raise ExchangeError('Invalid host selection.')
            index = selection.get('index')
            if type(index) is not int or not 0 <= index < len(rows) or index in seen:
                raise ExchangeError('Invalid host selection.')
            seen.add(index)
            if rows[index]['blocked']:
                raise ExchangeError('Unsupported configuration cannot be imported.')
            for field in ('username', 'key_id', 'jump_host_id'):
                if field in selection and (
                    not isinstance(selection[field], str) or len(selection[field]) > 128
                ):
                    raise ExchangeError('Invalid host mapping.')
    except ExchangeError as error:
        return jsonify({'error': str(error)}), 400

    results = []
    for selection in selections:
        index = selection['index']
        row = rows[index]
        if (row['requires_key'] and not selection.get('key_id')) or (
            row['requires_jump'] and not selection.get('jump_host_id')
        ):
            results.append({'index': index, 'status': 'error', 'error': 'Required mapping is missing.'})
            continue
        payload = {
            field: row[field] for field in
            ('name', 'host', 'port', 'username', 'group', 'favorite', 'use_tmux')
            if field in row
        }
        payload.update({
            'username': selection.get('username', row['username']),
            'auth_type': (
                'tailscale' if row.get('auth_type') == 'tailscale'
                else ('key' if selection.get('key_id') else 'password')
            ),
            'key_id': selection.get('key_id'),
            'jump_host_id': selection.get('jump_host_id'),
            'startup_mode': 'none',
        })
        try:
            profile, error = upsert_profile(current_user.id, payload, skip_duplicate=True)
        except ConnectionStorageLimitError:
            profile, error = None, 'Connection storage quota exceeded.'
        results.append({
            'index': index,
            'status': 'imported' if profile else ('skipped' if error == 'Duplicate profile' else 'error'),
            **({'id': profile['id']} if profile else {'error': error}),
        })
    return jsonify({'results': results})
