"""HTTP contract for terminal share links."""

import json

import pytest

from app import ssh_manager
from app.terminal_share import share_hub


SESSION_ID = 'route-share-session'


def _create_user(app, username):
    from app.auth import register_user
    from app.models import db

    with app.app_context():
        user, error = register_user(username, 'password123')
        assert error is None
        db.session.commit()
        return user.id


def _login(client, username):
    response = client.post(
        '/login',
        data={'username': username, 'password': 'password123'},
    )
    assert response.status_code == 302


@pytest.fixture(autouse=True)
def isolated_browsers(app):
    """Resolve each request's user from its own cookies, as in production.

    The test app keeps one app context open, so Flask-Login's per-context
    user cache would otherwise leak between the owner and guest clients.
    """
    from flask import g

    def forget_cached_user():
        g.pop('_login_user', None)

    app.before_request_funcs.setdefault(None, []).insert(0, forget_cached_user)
    yield
    app.before_request_funcs[None].remove(forget_cached_user)


@pytest.fixture
def owner(app, client):
    user_id = _create_user(app, 'share_owner')
    _login(client, 'share_owner')
    with ssh_manager.sessions_lock:
        ssh_manager.sessions[SESSION_ID] = {
            'client': None,
            'channel': None,
            'user_id': user_id,
            'connected': True,
            'output_buffer': ['$ '],
            'output_buffer_size': 2,
            'output_buffer_max': 512000,
            'output_sequence': 1,
            'cols': 100,
            'rows': 30,
        }
    yield user_id
    share_hub.end_all()
    with ssh_manager.sessions_lock:
        ssh_manager.sessions.pop(SESSION_ID, None)


@pytest.fixture
def guest(app):
    # A separate browser with no WebSSH session at all.
    return app.test_client()


@pytest.fixture
def fast_heartbeat(monkeypatch):
    import config

    monkeypatch.setattr(config, 'TERMINAL_SHARE_HEARTBEAT_SECONDS', 1)


def _create_share(client, **overrides):
    payload = {'session_id': SESSION_ID, 'title': 'Pairing', **overrides}
    response = client.post('/api/terminal-shares', json=payload)
    assert response.status_code == 201, response.get_json()
    return response.get_json()['share']


def _join(guest, token, name='Guest'):
    response = guest.post('/api/share-view/join', json={'token': token, 'name': name})
    assert response.status_code == 200, response.get_json()
    return response.get_json()


def _read_events(response, count):
    events = []
    buffer = ''
    chunks = iter(response.response)
    while len(events) < count:
        chunk = next(chunks)
        buffer += chunk.decode('utf-8') if isinstance(chunk, bytes) else chunk
        while '\n\n' in buffer:
            block, buffer = buffer.split('\n\n', 1)
            fields = {}
            for line in block.split('\n'):
                if line.startswith(':') or ': ' not in line:
                    continue
                key, value = line.split(': ', 1)
                fields[key] = value
            if 'event' in fields:
                events.append((fields['event'], json.loads(fields['data']), fields.get('id')))
    return events


def test_owner_api_requires_authentication(app, guest):
    for method, path in (
        ('get', '/api/terminal-shares'),
        ('post', '/api/terminal-shares'),
        ('delete', '/api/terminal-shares/abc'),
        ('patch', '/api/terminal-shares/abc'),
    ):
        response = getattr(guest, method)(path, json={})
        assert response.status_code in (302, 401), (method, path)


def test_owner_can_create_list_and_revoke_a_share(client, owner):
    share = _create_share(client, mode='control', ttl_minutes=15, max_viewers=2)
    assert share['mode'] == 'control'
    assert share['max_viewers'] == 2
    assert share['title'] == 'Pairing'

    listed = client.get(f'/api/terminal-shares?session_id={SESSION_ID}')
    assert listed.status_code == 200
    body = listed.get_json()
    assert [item['id'] for item in body['shares']] == [share['id']]
    assert body['limits']['enabled'] is True
    assert listed.headers['Cache-Control'] == 'no-store'

    revoked = client.delete(f"/api/terminal-shares/{share['id']}")
    assert revoked.status_code == 200
    assert client.get('/api/terminal-shares').get_json()['shares'] == []


def test_users_cannot_share_or_manage_other_peoples_sessions(app, client, owner):
    share = _create_share(client)
    other = app.test_client()
    _create_user(app, 'share_intruder')
    _login(other, 'share_intruder')

    created = other.post('/api/terminal-shares', json={'session_id': SESSION_ID})
    assert created.status_code == 404
    assert created.get_json()['code'] == 'session_not_found'
    assert other.get(f'/api/terminal-shares?session_id={SESSION_ID}').get_json()['shares'] == []
    assert other.delete(f"/api/terminal-shares/{share['id']}").status_code == 404
    assert other.patch(
        f"/api/terminal-shares/{share['id']}", json={'mode': 'control'},
    ).status_code == 404


def test_create_rejects_unknown_fields_and_bad_values(client, owner):
    for payload in (
        {'session_id': SESSION_ID, 'host': 'x'},
        {'session_id': SESSION_ID, 'mode': 'root'},
        {'session_id': SESSION_ID, 'ttl_minutes': 99999},
        {'session_id': 5},
        {},
    ):
        response = client.post('/api/terminal-shares', json=payload)
        assert response.status_code in (400, 404), payload
        assert response.get_json()['success'] is False


def test_viewer_page_is_public_and_does_not_leak(guest, owner):
    response = guest.get('/share')
    assert response.status_code == 200
    assert response.headers['Referrer-Policy'] == 'no-referrer'
    assert 'noindex' in response.headers['X-Robots-Tag']
    assert response.headers['Cache-Control'] == 'no-store'
    page = response.get_data(as_text=True)
    assert 'share-viewer.js' in page
    assert 'i18n-share.js' in page
    assert 'csrf-token' not in page
    assert 'Set-Cookie' not in response.headers


def test_guest_streams_snapshot_and_live_output(client, guest, owner, fast_heartbeat):
    share = _create_share(client, title='Deploy watch')
    joined = _join(guest, share['token'], 'Rae')
    assert joined['viewer']['title'] == 'Deploy watch'
    assert joined['viewer']['cols'] == 100
    assert 'host' not in json.dumps(joined)

    stream = guest.post('/api/share-view/stream', json={'ticket': joined['ticket']})
    assert stream.status_code == 200
    assert stream.mimetype == 'text/event-stream'
    assert stream.headers['X-Accel-Buffering'] == 'no'
    hello, reset = _read_events(stream, 2)
    assert hello[0] == 'hello'
    assert hello[1]['heartbeat'] == 1
    assert reset[0] == 'reset'
    assert reset[1]['data'] == '$ '
    assert reset[2] == '1'

    ssh_manager.record_output(SESSION_ID, 'ls\r\n', now=1)
    share_hub.publish(SESSION_ID, 2, 'ls\r\n')
    (output,) = _read_events(stream, 1)
    assert output == ('output', {'data': 'ls\r\n', 'seq': 2}, '2')

    client.delete(f"/api/terminal-shares/{share['id']}")
    (end,) = _read_events(stream, 1)
    assert end[0] == 'end'
    assert end[1]['reason'] == 'revoked'
    stream.close()


def test_stream_refuses_unknown_tickets(guest, owner):
    response = guest.post('/api/share-view/stream', json={'ticket': 'x' * 43})
    assert response.status_code == 404
    assert response.get_json()['code'] == 'ticket_invalid'


def test_view_only_guests_cannot_type(client, guest, owner, monkeypatch):
    sent = []
    monkeypatch.setattr(ssh_manager, 'send_ssh_input', lambda *a, **k: sent.append(a) or (True, None))
    share = _create_share(client, mode='view')
    ticket = _join(guest, share['token'])['ticket']

    response = guest.post('/api/share-view/input', json={'ticket': ticket, 'data': 'rm -rf /\r'})
    assert response.status_code == 403
    assert response.get_json()['code'] == 'view_only'
    assert sent == []


def test_control_guests_type_into_the_owners_session(client, guest, owner, monkeypatch):
    sent = []

    def fake_send(session_id, data, require_complete=False, cancel_event=None):
        sent.append((session_id, data, require_complete))
        return True, None

    monkeypatch.setattr(ssh_manager, 'send_ssh_input', fake_send)
    share = _create_share(client, mode='control')
    ticket = _join(guest, share['token'])['ticket']

    response = guest.post('/api/share-view/input', json={'ticket': ticket, 'data': 'uptime\r'})
    assert response.status_code == 200
    assert sent == [(SESSION_ID, 'uptime\r', True)]

    client.patch(f"/api/terminal-shares/{share['id']}", json={'mode': 'view'})
    blocked = guest.post('/api/share-view/input', json={'ticket': ticket, 'data': 'x'})
    assert blocked.status_code == 403
    assert len(sent) == 1


def test_guest_input_draws_from_the_owners_budget(client, guest, owner, monkeypatch):
    from app.socket_events import ssh_input_budget

    monkeypatch.setattr(ssh_manager, 'send_ssh_input', lambda *a, **k: (True, None))
    calls = []

    def deny(user_id, session_id, byte_count, **_kwargs):
        calls.append((user_id, session_id, byte_count))
        return False, 120

    monkeypatch.setattr(ssh_input_budget(), 'allow', deny)
    share = _create_share(client, mode='control')
    ticket = _join(guest, share['token'])['ticket']
    response = guest.post('/api/share-view/input', json={'ticket': ticket, 'data': 'abc'})
    assert response.status_code == 429
    assert response.get_json()['retry_after_ms'] == 120
    assert calls == [(owner, SESSION_ID, 3)]


def test_oversized_input_is_rejected(client, guest, owner, monkeypatch):
    import config

    monkeypatch.setattr(config, 'SSH_INPUT_MAX_BYTES', 8)
    share = _create_share(client, mode='control')
    ticket = _join(guest, share['token'])['ticket']
    response = guest.post('/api/share-view/input', json={'ticket': ticket, 'data': 'x' * 9})
    assert response.status_code == 413


def test_viewer_endpoints_require_json(guest, owner):
    for path in ('/api/share-view/join', '/api/share-view/stream', '/api/share-view/input'):
        response = guest.post(path, data='token=x', content_type='application/x-www-form-urlencoded')
        assert response.status_code == 415, path


def test_reloading_viewer_keeps_its_seat(client, guest, owner):
    share = _create_share(client, max_viewers=1)
    joined = _join(guest, share['token'])
    again = guest.post('/api/share-view/join', json={
        'token': share['token'],
        'ticket': joined['ticket'],
    })
    assert again.status_code == 200
    assert again.get_json()['ticket'] == joined['ticket']

    other = _create_share(client)
    # A ticket from one link never resumes a seat on another.
    crossed = guest.post('/api/share-view/join', json={
        'token': other['token'],
        'ticket': joined['ticket'],
    })
    assert crossed.get_json()['ticket'] != joined['ticket']


def test_join_is_rate_limited_per_ip(client, guest, owner, monkeypatch):
    import config

    monkeypatch.setattr(config, 'RATELIMIT_TERMINAL_SHARE_JOIN', '2 per minute')
    for _ in range(2):
        guest.post('/api/share-view/join', json={'token': 'z' * 43})
    response = guest.post('/api/share-view/join', json={'token': 'z' * 43})
    assert response.status_code == 429
    assert response.get_json()['code'] == 'rate_limited'


def test_owner_receives_presence_updates(client, guest, owner, monkeypatch):
    from app import socketio

    emitted = []
    monkeypatch.setattr(socketio, 'emit', lambda event, payload, room=None, **_: emitted.append((event, payload, room)))
    share = _create_share(client, require_approval=True)
    joined = _join(guest, share['token'], 'Lee')
    assert joined['viewer']['status'] == 'pending'

    updates = [item for item in emitted if item[0] == 'terminal_share_update']
    assert updates[-1][2] == f'user_{owner}'
    assert updates[-1][1]['event'] == {'kind': 'pending', 'viewer': 'Lee'}
    assert updates[-1][1]['shares'][0]['viewers'][0]['status'] == 'pending'

    approved = client.post(
        f"/api/terminal-shares/{share['id']}/viewers/{joined['viewer']['viewer_id']}/approve"
    )
    assert approved.status_code == 200
    removed = client.delete(
        f"/api/terminal-shares/{share['id']}/viewers/{joined['viewer']['viewer_id']}"
    )
    assert removed.status_code == 200


def test_logout_ends_every_share(client, guest, owner):
    share = _create_share(client)
    _join(guest, share['token'])
    client.post('/logout')
    response = guest.post('/api/share-view/join', json={'token': share['token']})
    assert response.status_code == 404


@pytest.fixture
def csrf_app(app):
    app.config['WTF_CSRF_ENABLED'] = True
    yield app
    app.config['WTF_CSRF_ENABLED'] = False


def test_only_bearer_viewer_endpoints_skip_csrf(owner, csrf_app):
    browser = csrf_app.test_client()
    # Owner mutations stay CSRF protected even for a signed-in browser.
    _create_user(csrf_app, 'csrf_owner')
    login_page = browser.get('/login').get_data(as_text=True)
    token = login_page.split('name="csrf-token" content="', 1)[1].split('"', 1)[0]
    browser.post('/login', data={
        'username': 'csrf_owner', 'password': 'password123', 'csrf_token': token,
    })
    refused = browser.post('/api/terminal-shares', json={'session_id': SESSION_ID})
    assert refused.status_code == 400

    share = share_hub.create(owner, SESSION_ID)
    guest = csrf_app.test_client()
    joined = guest.post('/api/share-view/join', json={'token': share['token']})
    assert joined.status_code == 200
    ticket = joined.get_json()['ticket']
    left = guest.post('/api/share-view/leave', json={'ticket': ticket})
    assert left.status_code == 200


def test_guest_and_owner_chat_round_trip(client, guest, owner, fast_heartbeat, monkeypatch):
    from app import socketio

    emitted = []
    monkeypatch.setattr(socketio, 'emit', lambda event, payload, room=None, **_: emitted.append((event, payload, room)))
    share = _create_share(client)
    joined = _join(guest, share['token'], 'Kai')
    assert joined['viewer']['chat_enabled'] is True
    assert joined['viewer']['chat'] == []

    sent = guest.post('/api/share-view/chat', json={'ticket': joined['ticket'], 'text': 'hello owner'})
    assert sent.status_code == 200
    assert sent.get_json()['message']['name'] == 'Kai'
    chat_events = [item for item in emitted if item[0] == 'terminal_share_chat']
    assert chat_events[-1][2] == f'user_{owner}'
    assert chat_events[-1][1]['session_id'] == SESSION_ID
    assert chat_events[-1][1]['chat']['text'] == 'hello owner'

    stream = guest.post('/api/share-view/stream', json={'ticket': joined['ticket']})
    _hello, reset = _read_events(stream, 2)
    assert [item['text'] for item in reset[1]['chat']] == ['hello owner']

    reply = client.post('/api/terminal-shares/chat', json={'session_id': SESSION_ID, 'text': 'hi Kai'})
    assert reply.status_code == 200
    assert reply.get_json()['message']['role'] == 'owner'
    (chat,) = _read_events(stream, 1)
    assert chat[0] == 'chat'
    assert chat[1]['text'] == 'hi Kai'
    stream.close()

    history = client.get(f'/api/terminal-shares/chat?session_id={SESSION_ID}').get_json()
    assert [item['text'] for item in history['messages']] == ['hello owner', 'hi Kai']


def test_pointers_flow_between_guest_and_owner(client, guest, owner, fast_heartbeat, monkeypatch):
    from app import socketio

    emitted = []
    monkeypatch.setattr(socketio, 'emit', lambda event, payload, room=None, **_: emitted.append((event, payload, room)))
    share = _create_share(client)
    joined = _join(guest, share['token'], 'Ivy')
    response = guest.post('/api/share-view/pointer', json={'ticket': joined['ticket'], 'col': 5, 'row': 2})
    assert response.status_code == 200
    pointers = [item for item in emitted if item[0] == 'terminal_share_pointer']
    assert pointers[-1][1]['pointer'] == {
        'name': 'Ivy', 'role': 'guest', 'sender': joined['viewer']['viewer_id'], 'col': 5, 'row': 2,
    }
    outside = guest.post('/api/share-view/pointer', json={'ticket': joined['ticket'], 'col': 100, 'row': 0})
    assert outside.status_code == 400

    stream = guest.post('/api/share-view/stream', json={'ticket': joined['ticket']})
    _read_events(stream, 2)
    assert client.post(
        '/api/terminal-shares/pointer', json={'session_id': SESSION_ID, 'col': 1, 'row': 1},
    ).status_code == 200
    (pointer,) = _read_events(stream, 1)
    assert pointer[0] == 'pointer'
    assert pointer[1]['role'] == 'owner'
    stream.close()


def test_owner_chat_is_scoped_to_their_own_shared_sessions(app, client, owner):
    assert client.post(
        '/api/terminal-shares/chat', json={'session_id': SESSION_ID, 'text': 'nobody here'},
    ).get_json()['code'] == 'not_shared'
    _create_share(client)
    _create_user(app, 'chat_intruder')
    other = app.test_client()
    _login(other, 'chat_intruder')
    refused = other.post('/api/terminal-shares/chat', json={'session_id': SESSION_ID, 'text': 'hi'})
    assert refused.status_code == 409
    assert other.get(f'/api/terminal-shares/chat?session_id={SESSION_ID}').get_json()['messages'] == []
    assert other.post(
        '/api/terminal-shares/pointer', json={'session_id': SESSION_ID, 'col': 0, 'row': 0},
    ).status_code == 409


def test_guest_chat_rejects_bad_input(client, guest, owner):
    share = _create_share(client)
    ticket = _join(guest, share['token'])['ticket']
    for body in ({'ticket': ticket, 'text': ''}, {'ticket': ticket, 'text': 5}, {'ticket': ticket}):
        assert guest.post('/api/share-view/chat', json=body).status_code == 400
    assert guest.post(
        '/api/share-view/chat', json={'ticket': 'y' * 43, 'text': 'hi'},
    ).status_code == 404


def test_chat_routes_follow_csrf_scope(owner, csrf_app):
    share = share_hub.create(owner, SESSION_ID)
    guest = csrf_app.test_client()
    ticket = guest.post('/api/share-view/join', json={'token': share['token']}).get_json()['ticket']
    assert guest.post('/api/share-view/chat', json={'ticket': ticket, 'text': 'hi'}).status_code == 200
    assert guest.post(
        '/api/share-view/pointer', json={'ticket': ticket, 'col': 0, 'row': 0},
    ).status_code == 200
    assert guest.post(
        '/api/terminal-shares/chat', json={'session_id': SESSION_ID, 'text': 'forged'},
    ).status_code in (302, 400, 401)
