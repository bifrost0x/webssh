from flask import request


def _register_socket_user(app, username):
    from app.auth import register_socket_session, register_user
    from app.models import db

    with app.app_context():
        user, error = register_user(username, 'socket-password-123')
        assert error is None
        register_socket_session(user.id, f'{username}-sid')
        db.session.commit()
        return user.id, f'{username}-sid'


def _capture_emits(monkeypatch, socket_events):
    emitted = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, payload=None, **kwargs: emitted.append((event, payload)),
    )
    return emitted


def test_upload_encrypted_key_requires_passphrase_code(
        app, monkeypatch, encrypted_rsa_private_key_pem):
    from app import socket_events

    _user_id, sid = _register_socket_user(app, 'upload_required')
    emitted = _capture_emits(monkeypatch, socket_events)

    with app.test_request_context(
            '/socket.io', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        request.sid = sid
        socket_events.handle_upload_key({
            'name': 'encrypted key',
            'key_content': encrypted_rsa_private_key_pem,
        })

    payload = next(payload for event, payload in emitted if event == 'error')
    assert payload == {
        'error': 'SSH key passphrase required',
        'code': 'KEY_PASSPHRASE_REQUIRED',
    }


def test_upload_encrypted_key_returns_metadata_without_secret(
        app, monkeypatch, encrypted_ed25519_private_key_pem):
    from app import key_manager, socket_events

    user_id, sid = _register_socket_user(app, 'upload_encrypted')
    emitted = _capture_emits(monkeypatch, socket_events)
    secret = 'test-passphrase'

    with app.test_request_context(
            '/socket.io', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        request.sid = sid
        socket_events.handle_upload_key({
            'name': 'encrypted key',
            'key_content': encrypted_ed25519_private_key_pem,
            'key_passphrase': secret,
        })

    uploaded = next(
        payload['key'] for event, payload in emitted if event == 'key_uploaded'
    )
    assert uploaded['passphrase_required'] is True
    assert secret not in repr(emitted)
    with app.app_context():
        assert secret not in repr(key_manager.load_keys(user_id))


def test_ssh_connect_passes_secret_transiently_and_returns_invalid_code(
        app, monkeypatch, encrypted_ecdsa_private_key_pem):
    from app import key_manager, socket_events, ssh_manager

    user_id, sid = _register_socket_user(app, 'connect_invalid')
    with app.app_context():
        key, error = key_manager.save_key(
            user_id,
            'encrypted key',
            encrypted_ecdsa_private_key_pem,
            key_passphrase='test-passphrase',
        )
        assert error is None

    emitted = _capture_emits(monkeypatch, socket_events)
    monkeypatch.setattr(
        socket_events,
        'check_socket_rate_limit',
        lambda *_args, **_kwargs: False,
    )
    secret = 'wrong-connection-passphrase'
    captured = {}

    def fake_create_ssh_connection(**kwargs):
        captured.update(kwargs)
        return None, 'Invalid SSH key passphrase'

    monkeypatch.setattr(
        ssh_manager, 'create_ssh_connection', fake_create_ssh_connection
    )

    with app.test_request_context(
            '/socket.io', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        request.sid = sid
        socket_events.handle_ssh_connect({
            'host': '8.8.8.8',
            'port': 22,
            'username': 'root',
            'auth_type': 'key',
            'key_id': key['id'],
            'key_passphrase': secret,
        })

    payload = next(payload for event, payload in emitted if event == 'ssh_error')
    assert captured['key_passphrase'] == secret
    assert payload['code'] == 'KEY_PASSPHRASE_INVALID'
    assert secret not in repr(payload)


def test_quick_connect_requires_passphrase_before_pool_connect(
        app, monkeypatch, encrypted_rsa_private_key_pem):
    from app import connection_pool, key_manager, socket_events

    user_id, sid = _register_socket_user(app, 'quick_required')
    with app.app_context():
        key, error = key_manager.save_key(
            user_id,
            'encrypted key',
            encrypted_rsa_private_key_pem,
            key_passphrase='test-passphrase',
        )
        assert error is None

    emitted = _capture_emits(monkeypatch, socket_events)
    monkeypatch.setattr(
        socket_events,
        'check_socket_rate_limit',
        lambda *_args, **_kwargs: False,
    )
    called = False

    def fake_create_connection(**_kwargs):
        nonlocal called
        called = True
        return 'unexpected', None

    monkeypatch.setattr(
        connection_pool.temp_connection_pool,
        'create_connection',
        fake_create_connection,
    )

    with app.test_request_context(
            '/socket.io', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        request.sid = sid
        socket_events.handle_quick_connect({
            'host': '8.8.4.4',
            'port': 22,
            'username': 'root',
            'key_id': key['id'],
        })

    payload = next(
        payload for event, payload in emitted
        if event == 'quick_connect_error'
    )
    assert called is False
    assert payload == {
        'error': 'SSH key passphrase required',
        'code': 'KEY_PASSPHRASE_REQUIRED',
    }
