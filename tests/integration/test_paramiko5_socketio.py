import base64
import os
import tempfile
import time
import importlib
import uuid
from pathlib import Path

import pytest


pytestmark = pytest.mark.skipif(
    os.environ.get('PARAMIKO5_INTEGRATION') != '1',
    reason='set PARAMIKO5_INTEGRATION=1 to run disposable OpenSSH tests',
)

TARGET_HOST = os.environ.get('PARAMIKO5_TARGET_HOST', 'target')
TARGET_PORT = int(os.environ.get('PARAMIKO5_TARGET_PORT', '22'))
BASTION_HOST = os.environ.get('PARAMIKO5_BASTION_HOST', 'bastion')
BASTION_PORT = int(os.environ.get('PARAMIKO5_BASTION_PORT', '22'))
USERNAME = 'testuser'
PASSWORD = 'Paramiko5-Test-Only!'
KEY_PASSPHRASE = 'Paramiko5-Key-Passphrase!'
RUNTIME_DIR = (
    Path(__file__).resolve().parent / 'paramiko5' / 'runtime'
)


@pytest.fixture(scope='module')
def app():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        os.environ['DATA_DIR'] = tmpdir
        import config
        importlib.reload(config)

        from app import create_app
        from app.models import db

        test_app = create_app()
        test_app.config['TESTING'] = True
        test_app.config['WTF_CSRF_ENABLED'] = False
        with test_app.app_context():
            db.create_all()
        yield test_app
        with test_app.app_context():
            db.session.remove()
            db.engine.dispose()


def wait_for_event(socket_client, event_name, timeout=10):
    deadline = time.monotonic() + timeout
    seen = []
    while time.monotonic() < deadline:
        received = socket_client.get_received()
        seen.extend(received)
        for event in received:
            if event['name'] == event_name:
                payload = event.get('args', [])
                return payload[0] if payload else None
        time.sleep(0.05)
    raise AssertionError(
        f'event {event_name!r} not received; saw '
        f'{[(event["name"], event.get("args")) for event in seen]!r}'
    )


def wait_for_output(socket_client, marker, timeout=10):
    deadline = time.monotonic() + timeout
    output = ''
    errors = []
    while time.monotonic() < deadline:
        for event in socket_client.get_received():
            payloads = event.get('args', [])
            payload = payloads[0] if payloads else {}
            if event['name'] == 'ssh_output':
                output += payload.get('data', '')
                if marker in output:
                    return output
            elif event['name'] in ('ssh_error', 'error'):
                errors.append(payload)
        time.sleep(0.05)
    raise AssertionError(
        f'output marker {marker!r} not received; '
        f'output={output!r}, errors={errors!r}'
    )


def terminal_marker_command(marker, prefix=''):
    """Build a command whose PTY echo cannot contain the complete marker."""
    split_at = len(marker) // 2
    return (
        prefix
        + "printf '%s%s\\n' "
        + f"'{marker[:split_at]}' '{marker[split_at:]}'\n"
    )


def create_authenticated_socket(app, username):
    from app import socketio
    from app.auth import register_user

    with app.app_context():
        user, error = register_user(username, 'socket-password-123')
        assert error is None
        user_id = user.id

    http_client = app.test_client()
    response = http_client.post('/login', data={
        'username': username,
        'password': 'socket-password-123',
    })
    assert response.status_code == 302

    socket_client = socketio.test_client(
        app,
        flask_test_client=http_client,
    )
    assert socket_client.is_connected()
    wait_for_event(socket_client, 'connected')
    return socket_client, user_id


def emit_ssh_connect(socket_client, **overrides):
    payload = {
        'host': TARGET_HOST,
        'port': TARGET_PORT,
        'username': USERNAME,
        'client_request_id': 'integration-request',
    }
    payload.update(overrides)
    socket_client.emit('ssh_connect', payload)
    connected = wait_for_event(socket_client, 'ssh_connected')
    assert connected['host'] == TARGET_HOST
    assert connected['port'] == TARGET_PORT
    assert connected['username'] == USERNAME
    assert connected['client_request_id'] == 'integration-request'
    return connected['session_id']


def save_integration_key(app, user_id, key_name):
    from app import key_manager

    key_content = (RUNTIME_DIR / f'{key_name}.pem').read_text(
        encoding='utf-8'
    )
    with app.app_context():
        key_meta, error = key_manager.save_key(
            user_id,
            f'integration {key_name}',
            key_content,
            key_passphrase=(
                KEY_PASSPHRASE if key_name.endswith('_encrypted') else None
            ),
        )
    assert error is None
    return key_meta['id']


@pytest.fixture(autouse=True)
def clean_global_connections():
    from app import connection_pool, ssh_manager

    for session_id in list(ssh_manager.sessions):
        ssh_manager.close_session(session_id)
    connection_pool.temp_connection_pool.close_all_user_connections('1')
    yield
    for session_id in list(ssh_manager.sessions):
        ssh_manager.close_session(session_id)
    for user_id in range(1, 20):
        connection_pool.temp_connection_pool.close_all_user_connections(
            str(user_id)
        )


def test_socket_password_terminal_resize_and_disconnect(app, monkeypatch):
    import config

    monkeypatch.setattr(config, 'RATELIMIT_ENABLED', False)
    socket_client, _user_id = create_authenticated_socket(
        app,
        'socket_password_user',
    )
    try:
        session_id = emit_ssh_connect(
            socket_client,
            password=PASSWORD,
        )
        socket_client.emit('ssh_resize', {
            'session_id': session_id,
            'rows': 40,
            'cols': 120,
        })
        marker = 'PARAMIKO5_SOCKET_PASSWORD_OK'
        socket_client.emit('ssh_input', {
            'session_id': session_id,
            'data': terminal_marker_command(marker, prefix='stty size; '),
        })
        output = wait_for_output(socket_client, marker)
        assert '40 120' in output

        socket_client.emit('ssh_disconnect', {'session_id': session_id})
        disconnected = wait_for_event(
            socket_client,
            'ssh_disconnected',
        )
        assert disconnected['session_id'] == session_id
    finally:
        if socket_client.is_connected():
            socket_client.disconnect()


@pytest.mark.parametrize('key_name', ['rsa', 'ed25519', 'ecdsa'])
def test_socket_stored_key_terminal_roundtrip(
        app, monkeypatch, key_name):
    import config

    monkeypatch.setattr(config, 'RATELIMIT_ENABLED', False)
    socket_client, user_id = create_authenticated_socket(
        app,
        f'socket_{key_name}_user',
    )
    try:
        key_id = save_integration_key(app, user_id, key_name)

        session_id = emit_ssh_connect(
            socket_client,
            key_id=key_id,
        )
        marker = f'PARAMIKO5_SOCKET_{key_name.upper()}_OK'
        socket_client.emit('ssh_input', {
            'session_id': session_id,
            'data': terminal_marker_command(marker),
        })
        assert marker in wait_for_output(socket_client, marker)
        socket_client.emit('ssh_disconnect', {'session_id': session_id})
        wait_for_event(socket_client, 'ssh_disconnected')
    finally:
        if socket_client.is_connected():
            socket_client.disconnect()


@pytest.mark.parametrize('key_name', ['rsa', 'ed25519', 'ecdsa'])
def test_socket_encrypted_stored_key_terminal_roundtrip(
        app, monkeypatch, key_name):
    import config

    monkeypatch.setattr(config, 'RATELIMIT_ENABLED', False)
    socket_client, user_id = create_authenticated_socket(
        app,
        f'socket_encrypted_{key_name}_user',
    )
    try:
        key_id = save_integration_key(
            app, user_id, f'{key_name}_encrypted'
        )

        session_id = emit_ssh_connect(
            socket_client,
            key_id=key_id,
            key_passphrase=KEY_PASSPHRASE,
        )
        marker = f'PARAMIKO5_SOCKET_{key_name.upper()}_ENCRYPTED_OK'
        socket_client.emit('ssh_input', {
            'session_id': session_id,
            'data': terminal_marker_command(marker),
        })
        assert marker in wait_for_output(socket_client, marker)
        socket_client.emit('ssh_disconnect', {'session_id': session_id})
        wait_for_event(socket_client, 'ssh_disconnected')
    finally:
        if socket_client.is_connected():
            socket_client.disconnect()


@pytest.mark.parametrize(
    'auth',
    [
        'password',
        'rsa', 'ed25519', 'ecdsa',
        'rsa_encrypted', 'ed25519_encrypted', 'ecdsa_encrypted',
    ],
)
def test_socket_quick_connect_sftp_crud_and_disconnects(
        app, monkeypatch, auth):
    import config

    monkeypatch.setattr(config, 'RATELIMIT_ENABLED', False)
    socket_client, user_id = create_authenticated_socket(
        app,
        f'socket_quick_{auth}_user',
    )
    auth_payload = {'password': PASSWORD}
    if auth != 'password':
        auth_payload = {
            'key_id': save_integration_key(app, user_id, auth),
        }
        if auth.endswith('_encrypted'):
            auth_payload['key_passphrase'] = KEY_PASSPHRASE
    try:
        socket_client.emit('quick_connect', {
            'host': TARGET_HOST,
            'port': TARGET_PORT,
            'username': USERNAME,
            **auth_payload,
        })
        connected = wait_for_event(
            socket_client,
            'quick_connect_success',
        )
        connection_id = connected['connection_id']

        remote_dir = f'/tmp/paramiko5-socket-{auth}-{uuid.uuid4().hex}'
        remote_file = f'{remote_dir}/payload.bin'
        payload = os.urandom(4096)

        socket_client.emit('create_directory', {
            'session_id': connection_id,
            'remote_path': remote_dir,
        })
        created = wait_for_event(socket_client, 'directory_created')
        assert created['path'] == remote_dir

        socket_client.emit('upload_file', {
            'session_id': connection_id,
            'filename': 'payload.bin',
            'file_data': base64.b64encode(payload).decode('ascii'),
            'remote_path': remote_file,
        })
        completed = wait_for_event(socket_client, 'file_complete')
        assert completed['type'] == 'upload'
        assert completed['remote_path'] == remote_file

        socket_client.emit('list_directory', {
            'session_id': connection_id,
            'remote_path': remote_dir,
        })
        listing = wait_for_event(socket_client, 'directory_listing')
        assert listing['session_id'] == connection_id
        assert listing['path'] == remote_dir
        assert {item['name'] for item in listing['files']} == {'payload.bin'}

        socket_client.emit('download_file', {
            'session_id': connection_id,
            'remote_path': remote_file,
        })
        downloaded = wait_for_event(socket_client, 'file_download_ready')
        assert downloaded['filename'] == 'payload.bin'
        assert base64.b64decode(downloaded['file_data']) == payload

        socket_client.emit('delete_item', {
            'session_id': connection_id,
            'path': remote_dir,
        })
        deleted = wait_for_event(socket_client, 'item_deleted')
        assert deleted['path'] == remote_dir

        socket_client.emit('quick_disconnect', {
            'connection_id': connection_id,
        })
        disconnected = wait_for_event(
            socket_client,
            'quick_disconnect_success',
        )
        assert disconnected['connection_id'] == connection_id
    finally:
        if socket_client.is_connected():
            socket_client.disconnect()


@pytest.mark.parametrize('auth', ['password', 'rsa', 'rsa_encrypted'])
def test_socket_proxy_jump_terminal_and_sftp_roundtrip(
        app, monkeypatch, auth):
    import config

    monkeypatch.setattr(config, 'RATELIMIT_ENABLED', False)
    socket_client, user_id = create_authenticated_socket(
        app,
        f'socket_jump_{auth}_user',
    )
    if auth == 'password':
        target_auth = {'password': PASSWORD}
        jump_auth = {'password': PASSWORD}
    else:
        key_id = save_integration_key(app, user_id, auth)
        target_auth = {'key_id': key_id}
        jump_auth = {'key_id': key_id}
        if auth.endswith('_encrypted'):
            target_auth['key_passphrase'] = KEY_PASSPHRASE
            jump_auth['key_passphrase'] = KEY_PASSPHRASE
    try:
        session_id = emit_ssh_connect(
            socket_client,
            **target_auth,
            proxy_jump={
                'host': BASTION_HOST,
                'port': BASTION_PORT,
                'username': USERNAME,
                **jump_auth,
            },
        )
        marker = f'PARAMIKO5_SOCKET_JUMP_{auth.upper()}_OK'
        socket_client.emit('ssh_input', {
            'session_id': session_id,
            'data': terminal_marker_command(marker),
        })
        assert marker in wait_for_output(socket_client, marker)

        socket_client.emit('list_directory', {
            'session_id': session_id,
            'remote_path': '/tmp',
        })
        listing = wait_for_event(socket_client, 'directory_listing')
        assert listing['session_id'] == session_id

        socket_client.emit('ssh_disconnect', {'session_id': session_id})
        wait_for_event(socket_client, 'ssh_disconnected')
    finally:
        if socket_client.is_connected():
            socket_client.disconnect()


def test_socket_invalid_credentials_keep_generic_error(app, monkeypatch):
    import config

    monkeypatch.setattr(config, 'RATELIMIT_ENABLED', False)
    socket_client, _user_id = create_authenticated_socket(
        app,
        'socket_invalid_user',
    )
    try:
        socket_client.emit('ssh_connect', {
            'host': TARGET_HOST,
            'port': TARGET_PORT,
            'username': USERNAME,
            'password': 'wrong-password-marker',
        })
        error = wait_for_event(socket_client, 'ssh_error')
        assert error['error'] == 'Authentication failed - invalid credentials'
        assert 'wrong-password-marker' not in error['error']
    finally:
        if socket_client.is_connected():
            socket_client.disconnect()


def test_socket_missing_key_id_keeps_generic_key_error(app, monkeypatch):
    import config

    monkeypatch.setattr(config, 'RATELIMIT_ENABLED', False)
    socket_client, _user_id = create_authenticated_socket(
        app,
        'socket_missing_key_user',
    )
    try:
        socket_client.emit('ssh_connect', {
            'host': TARGET_HOST,
            'port': TARGET_PORT,
            'username': USERNAME,
            'key_id': 'does-not-exist',
        })
        error = wait_for_event(socket_client, 'ssh_error')
        assert error['error'] == 'SSH key error: Key not found'
        assert 'does-not-exist' not in error['error']
    finally:
        if socket_client.is_connected():
            socket_client.disconnect()


def test_socket_dsa_upload_is_rejected_without_storage(
        app, monkeypatch, dsa_private_key_pem):
    import config
    from app import key_manager

    monkeypatch.setattr(config, 'RATELIMIT_ENABLED', False)
    socket_client, user_id = create_authenticated_socket(
        app,
        'socket_dsa_user',
    )
    try:
        socket_client.emit('upload_key', {
            'name': 'unsupported DSA',
            'key_content': dsa_private_key_pem,
        })
        error = wait_for_event(socket_client, 'error')
        assert error['error'] == (
            'DSA private keys are not supported; '
            'use Ed25519, ECDSA, or RSA'
        )
        with app.app_context():
            assert key_manager.load_keys(user_id) == []
    finally:
        if socket_client.is_connected():
            socket_client.disconnect()


def test_revocation_closes_real_paramiko_transport(app, monkeypatch):
    import config
    from app import ssh_manager
    from app.user_lifecycle import revoke_user_access

    monkeypatch.setattr(config, 'RATELIMIT_ENABLED', False)
    socket_client, user_id = create_authenticated_socket(
        app,
        'socket_revoke_user',
    )
    session_id = emit_ssh_connect(socket_client, password=PASSWORD)
    assert session_id in ssh_manager.sessions

    with app.app_context():
        result = revoke_user_access(user_id)

    assert result['ssh_sessions'] == 1
    assert result['errors'] == []
    assert session_id not in ssh_manager.sessions
    assert socket_client.is_connected() is False
