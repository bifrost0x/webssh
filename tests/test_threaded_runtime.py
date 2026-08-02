"""Runtime contracts for the native-threading Socket.IO canary."""

import os
import socket
import subprocess
import sys
import time
import threading
import urllib.request
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _free_loopback_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def _config_probe(gunicorn_threads):
    """Load production configuration in an isolated interpreter."""
    environment = os.environ.copy()
    environment.update({
        'DEBUG': 'True',
        'SECRET_KEY': 'threading-runtime-test-secret',
        'GUNICORN_THREADS': gunicorn_threads,
    })
    return subprocess.run(
        [
            sys.executable,
            '-c',
            'import config; print(config.GUNICORN_THREADS)',
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_app_uses_native_threading_socketio_runtime(app):
    """An Eventlet fallback would change Socket.IO scheduling semantics."""
    from app import socketio

    assert app.config['SOCKETIO_ASYNC_MODE'] == 'threading'
    assert socketio.async_mode == 'threading'


def test_socketio_handlers_use_the_bounded_gthread_request_context(app):
    """Per-event daemon threads would bypass the configured gthread limit."""
    from app import socketio

    assert app.config['SOCKETIO_ASYNC_HANDLERS'] is False
    assert socketio.server.async_handlers is False


def test_synchronous_socketio_handler_never_queues_an_unbounded_task():
    """A saturated caller waits in its worker instead of creating another thread."""
    import socketio as python_socketio

    server = python_socketio.Server(
        async_mode='threading',
        async_handlers=False,
    )
    eio_sid = 'bounded-eio-sid'
    server.manager.connect(eio_sid, '/')
    observed_threads = []
    server.on('bounded_event', lambda _sid: observed_threads.append(
        threading.get_ident()
    ))
    server.start_background_task = lambda *_args, **_kwargs: pytest.fail(
        'async handler queue attempted to create a background task'
    )

    caller_thread = threading.get_ident()
    server._handle_event(eio_sid, '/', None, ['bounded_event'])

    assert observed_threads == [caller_thread]


@pytest.mark.parametrize('thread_count', ['0', '1', '7', '257', 'invalid'])
def test_gunicorn_threads_rejects_values_outside_the_safe_range(thread_count):
    """An unbounded gthread worker could exhaust process memory under load."""
    result = _config_probe(thread_count)

    assert result.returncode != 0
    assert 'CONFIGURATION ERROR: GUNICORN_THREADS must be between 8 and 256' in (
        result.stderr
    )


def test_gunicorn_threads_preserves_an_http_reserve_by_default():
    """Held WebSockets must leave request threads for login and transfers."""
    environment = os.environ.copy()
    environment.update({
        'DEBUG': 'True',
        'SECRET_KEY': 'threading-runtime-test-secret',
    })
    environment.pop('GUNICORN_THREADS', None)
    result = subprocess.run(
        [
            sys.executable,
            '-c',
            'import config; print(config.GUNICORN_THREADS)',
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[-1] == '64'


def test_socket_capacity_rejects_configuration_without_http_reserve():
    environment = os.environ.copy()
    environment.update({
        'DEBUG': 'True',
        'SECRET_KEY': 'threading-runtime-test-secret',
        'GUNICORN_THREADS': '16',
        'MAX_SOCKET_CONNECTIONS': '13',
    })

    result = subprocess.run(
        [sys.executable, '-c', 'import config'],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert 'at least 4 Gunicorn threads available for HTTP' in result.stderr


def test_playwright_uses_the_configured_e2e_port():
    """A shared workstation must not force browser tests onto port 4173."""
    environment = os.environ.copy()
    port = str(_free_loopback_port())
    environment['WEBSSH_E2E_PORT'] = port
    result = subprocess.run(
        [
            'node',
            '-e',
            "console.log(require('./playwright.config').use.baseURL)",
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f'http://127.0.0.1:{port}'


def test_e2e_runner_listens_on_the_configured_port():
    """The browser server and its base URL must select the same free port."""
    environment = os.environ.copy()
    port = _free_loopback_port()
    environment['WEBSSH_E2E_PORT'] = str(port)
    process = subprocess.Popen(
        [sys.executable, 'tests/e2e/run_app.py'],
        cwd=PROJECT_ROOT,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 15
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            try:
                with urllib.request.urlopen(
            f'http://127.0.0.1:{port}/login', timeout=1) as response:
                    assert response.status == 200
                    return
            except OSError:
                time.sleep(0.1)
        raise AssertionError('E2E runner did not listen on WEBSSH_E2E_PORT')
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)


def test_e2e_runner_accepts_a_socketio_handshake_on_its_configured_origin():
    """A custom E2E port must update CORS as well as the HTTP base URL."""
    environment = os.environ.copy()
    port = _free_loopback_port()
    environment['WEBSSH_E2E_PORT'] = str(port)
    base_url = f'http://127.0.0.1:{port}'
    process = subprocess.Popen(
        [sys.executable, 'tests/e2e/run_app.py'],
        cwd=PROJECT_ROOT,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 15
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            try:
                with urllib.request.urlopen(
                        f'{base_url}/login', timeout=1) as response:
                    if response.status == 200:
                        break
            except OSError:
                time.sleep(0.1)
        else:
            raise AssertionError('E2E runner did not start for Socket.IO test')

        handshake_url = (
            f'{base_url}/socket.io/?EIO=4&transport=polling&t=threading-test'
        )
        try:
            with urllib.request.urlopen(urllib.request.Request(
                    handshake_url,
                    headers={'Origin': base_url}), timeout=5) as response:
                assert response.status == 200
                assert response.headers['Access-Control-Allow-Origin'] == base_url
                assert response.read().startswith(b'0{')
        except urllib.error.HTTPError as error:
            raise AssertionError(
                f'Socket.IO handshake rejected configured origin: {error}'
            ) from error
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
