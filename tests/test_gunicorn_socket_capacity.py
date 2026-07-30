import os
import re
import socket
import subprocess
import sys
import time

import pytest


pytestmark = pytest.mark.skipif(
    os.name == 'nt',
    reason='Gunicorn gthread is supported on Unix production hosts',
)


def _free_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def _wait_until_ready(requests, base_url, process):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            pytest.fail(
                f'Gunicorn exited early.\nstdout:\n{stdout}\nstderr:\n{stderr}'
            )
        try:
            if requests.get(f'{base_url}/ready', timeout=0.5).status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(0.1)
    pytest.fail('Gunicorn did not become ready')


def _login_session(requests, base_url):
    session = requests.Session()
    login_page = session.get(f'{base_url}/login', timeout=2)
    csrf_match = re.search(
        r'name="csrf_token"[^>]*value="([^"]+)"',
        login_page.text,
    )
    assert csrf_match is not None
    response = session.post(
        f'{base_url}/login',
        data={
            'csrf_token': csrf_match.group(1),
            'username': 'capacityadmin',
            'password': 'capacity-admin-password',
        },
        allow_redirects=False,
        timeout=2,
    )
    assert response.status_code == 302
    return session


def test_socket_limit_keeps_ready_endpoint_responsive(tmp_path):
    import requests
    import socketio

    project_root = os.path.dirname(os.path.dirname(__file__))
    data_dir = tmp_path / 'data'
    password_file = tmp_path / 'password'
    password_file.write_text('capacity-admin-password\n', encoding='utf-8')
    port = _free_port()
    base_url = f'http://127.0.0.1:{port}'
    environment = os.environ.copy()
    environment.update({
        'DATA_DIR': str(data_dir),
        'DEBUG': 'True',
        'SECRET_KEY': 'gunicorn-capacity-test-secret',
        'SESSION_COOKIE_SECURE': 'false',
        'GUNICORN_THREADS': '8',
        'MAX_SOCKET_CONNECTIONS': '4',
        'MAX_SOCKET_CONNECTIONS_PER_USER': '4',
    })
    bootstrap = subprocess.run(
        [
            sys.executable,
            '-m',
            'flask',
            '--app',
            'start',
            'create-admin',
            '--username',
            'capacityadmin',
            '--password-file',
            str(password_file),
        ],
        cwd=project_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert bootstrap.returncode == 0, bootstrap.stderr

    process = subprocess.Popen(
        [
            sys.executable,
            '-m',
            'gunicorn',
            '--worker-class',
            'gthread',
            '--workers',
            '1',
            '--threads',
            '8',
            '--bind',
            f'127.0.0.1:{port}',
            'start:app',
        ],
        cwd=project_root,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    clients = []
    try:
        _wait_until_ready(requests, base_url, process)
        authenticated = _login_session(requests, base_url)
        for _ in range(4):
            session = requests.Session()
            session.cookies.update(authenticated.cookies)
            client = socketio.Client(
                http_session=session,
                reconnection=False,
            )
            client.connect(
                base_url,
                transports=['polling'],
                wait_timeout=5,
            )
            clients.append(client)

        response = requests.get(f'{base_url}/ready', timeout=2)
        assert response.status_code == 200

        rejected = socketio.Client(
            http_session=authenticated,
            reconnection=False,
        )
        with pytest.raises(socketio.exceptions.ConnectionError):
            rejected.connect(
                base_url,
                transports=['polling'],
                wait_timeout=5,
            )
    finally:
        for client in clients:
            if client.connected:
                client.disconnect()
        process.terminate()
        try:
            process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)
