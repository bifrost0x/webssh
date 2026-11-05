"""Reproduce supported payloads rejected by early transport limits."""
import io
import json

import pytest
from werkzeug.test import EnvironBuilder
from werkzeug.wrappers import Response


@pytest.fixture
def signed_in(app, client):
    from app.auth import register_user
    from app.profile_manager import upsert_profile
    with app.app_context():
        user, error = register_user('budget_probe', 'password123')
        assert error is None
        profile, error = upsert_profile(user.id, {
            'name': 'Probe', 'host': 'example.com', 'username': 'deploy', 'auth_type': 'password',
        })
        assert error is None
    assert client.post('/login', data={'username': 'budget_probe', 'password': 'password123'}).status_code == 302
    return profile['id']


@pytest.mark.parametrize('character', ['n', '\u00e4', '\U0001f680'])
def test_supported_large_notes_round_trip(client, signed_in, character):
    url = f'/api/profiles/{signed_in}/context'
    notes = character * 100000
    payload = {'revision': 0, 'notes': notes, 'directories': [], 'command_sets': []}
    # Match browser JSON.stringify: UTF-8 without ASCII escaping.
    response = client.put(url, data=json.dumps(payload, ensure_ascii=False).encode('utf-8'), content_type='application/json')
    assert response.status_code == 200, response.get_data(as_text=True)
    assert client.get(url).json['notes'] == notes


@pytest.mark.parametrize('method,path,limit', [
    ('PUT', '/api/profiles/probe/context', 1024 * 1024),
    ('POST', '/api/profiles/exchange/preview', 512 * 1024),
    ('POST', '/api/profiles/exchange', 512 * 1024),
])
@pytest.mark.parametrize('declared', [True, False])
def test_endpoint_body_budget_still_bounds_reads_before_csrf(app, method, path, limit, declared):
    from tests.test_request_limits import TrackingInput
    body = b'x' * (limit + 4096)
    environ = EnvironBuilder(path=path, method=method, input_stream=io.BytesIO(body), content_type='application/json').get_environ()
    if not declared:
        environ.pop('CONTENT_LENGTH', None)
        environ['wsgi.input_terminated'] = True
    stream = TrackingInput(body)
    environ['wsgi.input'] = stream
    app.config['WTF_CSRF_ENABLED'] = True
    try:
        response = Response.from_app(app.wsgi_app, environ)
    finally:
        app.config['WTF_CSRF_ENABLED'] = False
    assert response.status_code == 413
    assert response.json == {'error': 'Request body too large'}
    assert stream.bytes_read == (0 if declared else limit + 1)


def test_supported_import_near_source_byte_limit(client, signed_in):
    from app.profile_exchange import preview_import
    prefix = 'Host import-probe\n HostName import.example.com\n User deploy\n#'
    source = prefix + 'x' * (65536 - len(prefix.encode()))
    assert len(source.encode()) == 65536
    assert len(preview_import(source, 'openssh')['records']) == 1
    response = client.post('/api/profiles/exchange/preview', json={'format': 'openssh', 'source': source})
    assert response.status_code == 200, response.get_data(as_text=True)
    imported = client.post('/api/profiles/exchange', json={
        'format': 'openssh', 'source': source, 'selections': [{'index': 0}],
    })
    assert imported.status_code == 200, imported.get_data(as_text=True)
    assert imported.json['results'][0]['status'] == 'imported'
