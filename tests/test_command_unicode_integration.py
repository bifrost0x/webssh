"""Unicode round trips through real processes, storage, and loopback SSH."""

import json
import locale
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import uuid

import paramiko
import pytest


ROOT = Path(__file__).resolve().parents[1]
SAMPLE = 'Grüße ÄÖÜ ß € | 東京 中文 한국어 | e\u0301 café 👩\u200d💻 🐧'
PROBE = r'''
import importlib.util
import json
import locale
from pathlib import Path
import sys
import config
from app import command_manager

root = Path(sys.argv[1])
config.DATA_DIR = root
config.SYSTEM_COMMANDS_FILE = root / 'resources/system_commands.json'
if len(sys.argv) > 2:
    spec = importlib.util.spec_from_file_location('app._unicode_baseline', sys.argv[2])
    command_manager = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(command_manager)
result = {'encoding': locale.getpreferredencoding(False), 'utf8_mode': sys.flags.utf8_mode}
try:
    result['commands'] = command_manager.load_system_commands()
    result['ok'] = True
except (UnicodeError, ValueError) as exc:
    result.update(ok=False, error_type=type(exc).__name__)
print(json.dumps(result, ensure_ascii=True))
'''


def run_loader_process(directory, utf8_mode, baseline=None):
    environment = {**os.environ, 'PYTHONPATH': str(ROOT),
                   'DATA_DIR': str(directory / 'data'),
                   'DEPLOYMENT_PROFILE': 'homelab', 'DEBUG': 'False',
                   'CORS_ORIGINS': 'http://localhost:5000',
                   'SECRET_KEY': 'unicode-probe-synthetic-secret-only'}
    arguments = [sys.executable, '-X', f'utf8={utf8_mode}', '-c', PROBE, str(directory)]
    if baseline is not None:
        arguments.append(str(baseline))
    result = subprocess.run(arguments, cwd=ROOT, env=environment,
                            capture_output=True, timeout=20, check=True)
    return json.loads(result.stdout.decode('ascii'))


@pytest.mark.parametrize('scenario,overrides,warning', [
    ('local-cors', {'DEBUG': 'False', 'CORS_ORIGINS': ''}, 'CORS_ORIGINS'),
    ('debug-secret', {'DEBUG': 'True', 'SECRET_KEY': ''}, 'SECRET_KEY'),
    ('debug-cors', {'DEBUG': 'True', 'CORS_ORIGINS': '*'}, 'CORS'),
    ('opt-in-cors', {'DEBUG': 'False', 'CORS_ORIGINS': '*',
                     'ALLOW_CORS_WILDCARD': 'true'}, 'CORS'),
])
def test_configuration_warnings_survive_real_cp1252_stdout(tmp_path, scenario, overrides, warning):
    environment = {**os.environ, 'PYTHONPATH': str(ROOT),
                   'DATA_DIR': str(tmp_path / scenario), 'DEPLOYMENT_PROFILE': 'homelab',
                   'PYTHONIOENCODING': 'cp1252:strict',
                   'CORS_ORIGINS': 'http://localhost:5000',
                   'ALLOW_CORS_WILDCARD': 'false',
                   'SECRET_KEY': 'unicode-probe-synthetic-secret-only', **overrides}
    result = subprocess.run(
        [sys.executable, '-X', 'utf8=0', '-c', "import config; print('CONFIG_READY')"],
        cwd=ROOT, env=environment, capture_output=True, timeout=20,
    )
    assert result.returncode == 0, result.stderr.decode('cp1252')
    output = result.stdout.decode('cp1252')
    assert warning in output
    assert 'CONFIG_READY' in output


@pytest.mark.parametrize('legacy', [False, True])
@pytest.mark.parametrize('utf8_mode', [0, 1])
def test_unicode_system_library_in_real_python_process(tmp_path, legacy, utf8_mode):
    directory = tmp_path / 'Grüße_東京_🐧'
    source = directory / ('commands' if legacy else 'resources') / 'system_commands.json'
    source.parent.mkdir(parents=True)
    expected = [{'id': 'unicode', 'name': SAMPLE, 'command': 'printf',
                 'parameters': SAMPLE, 'description': SAMPLE, 'category': SAMPLE}]
    source.write_text(json.dumps(expected, ensure_ascii=False), encoding='utf-8')
    original = source.read_bytes()

    result = run_loader_process(directory, utf8_mode)

    assert result['ok'], result
    assert result['commands'] == expected
    assert result['utf8_mode'] == utf8_mode
    assert source.read_bytes() == original


def test_unicode_command_survives_real_user_storage_and_profile_resolution(app):
    from app import command_manager, post_connect_manager, profile_manager
    from app.models import User, db

    with app.app_context():
        user = User(username='unicode-roundtrip', password_hash='unused')
        db.session.add(user)
        db.session.commit()
        command = command_manager.add_user_command(
            user.id, SAMPLE, 'printf', SAMPLE, SAMPLE, ['all'], SAMPLE,
        )
        assert command is not None
        path = command_manager.get_user_commands_file(user.id)
        stored = json.loads(path.read_text(encoding='utf-8'))
        assert stored[0]['name'] == SAMPLE
        assert stored[0]['parameters'] == SAMPLE
        loaded = next(item for item in command_manager.get_all_commands(user.id)
                      if item['id'] == command['id'])
        assert loaded['description'] == SAMPLE

        profile, error = profile_manager.upsert_profile(user.id, {
            'name': SAMPLE, 'host': 'unicode.example.test', 'port': 22,
            'username': 'unicode-test', 'auth_type': 'password',
            'startup_mode': 'command', 'command_id': command['id'],
        })
        assert error is None
        reloaded = profile_manager.get_profile(user.id, profile['id'])
        assert reloaded['name'] == SAMPLE
        assert post_connect_manager.resolve_configuration(user.id, reloaded) == (
            'printf ' + SAMPLE, None,
        )


@pytest.mark.skipif(sys.platform != 'win32' or locale.getencoding() != 'cp1252',
                    reason='Requires the real Windows CP1252 legacy locale')
@pytest.mark.parametrize('utf8_mode', [0, 1])
def test_ansi_legacy_library_preserved_in_real_process(tmp_path, utf8_mode):
    source = tmp_path / 'commands' / 'system_commands.json'
    source.parent.mkdir()
    expected = [{'id': 'legacy', 'name': 'Grüße €', 'command': 'echo café'}]
    original = json.dumps(expected, ensure_ascii=False).encode('cp1252')
    source.write_bytes(original)

    result = run_loader_process(tmp_path, utf8_mode)

    assert result['ok'], result
    assert result['commands'] == expected
    assert source.read_bytes() == original
    assert sorted(p.name for p in source.parent.iterdir()) == [source.name]


@pytest.mark.parametrize('legacy', [False, True])
def test_invalid_system_library_is_not_rewritten(tmp_path, legacy):
    source = tmp_path / ('commands' if legacy else 'resources') / 'system_commands.json'
    source.parent.mkdir()
    original = b'[{"name": "\x81'
    source.write_bytes(original)
    result = run_loader_process(tmp_path, 0)
    assert not result['ok']
    assert source.read_bytes() == original


def test_primary_system_library_does_not_accept_ansi(tmp_path):
    source = tmp_path / 'resources' / 'system_commands.json'
    source.parent.mkdir()
    original = '[{"name": "Grüße"}]'.encode('cp1252')
    source.write_bytes(original)
    result = run_loader_process(tmp_path, 0)
    assert not result['ok']
    assert result['error_type'] == 'UnicodeDecodeError'
    assert source.read_bytes() == original


@pytest.mark.parametrize('complete', [False, True])
def test_unicode_bytes_round_trip_over_real_ssh(complete):
    from app import ssh_manager
    from app.startup_commands import normalize_startup_commands, to_terminal_input

    # The larger payload crosses SSH packet boundaries and contains combining
    # characters, four-byte code points and a zero-width joiner.
    text = 'printf ' + (SAMPLE * 70 if complete else SAMPLE)
    normalized, error = normalize_startup_commands(text)
    assert error is None
    terminal_input = to_terminal_input(normalized) + '\r'
    expected = terminal_input.encode('utf-8')
    host_key = paramiko.RSAKey.generate(2048)
    stop = threading.Event()
    shell_ready = threading.Event()
    received = bytearray()
    failures = []
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(5)

    class Server(paramiko.ServerInterface):
        def check_auth_password(self, username, password):
            return (paramiko.AUTH_SUCCESSFUL if (username, password) ==
                    ('unicode-test', 'synthetic-test-only') else paramiko.AUTH_FAILED)

        def check_channel_request(self, kind, chanid):
            return (paramiko.OPEN_SUCCEEDED if kind == 'session'
                    else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)

        def check_channel_pty_request(self, *args):
            return True

        def check_channel_shell_request(self, channel):
            shell_ready.set()
            return True

    def serve():
        transport = None
        connection = None
        try:
            connection, _address = listener.accept()
            transport = paramiko.Transport(connection, default_max_packet_size=4096)
            transport.add_server_key(host_key)
            transport.start_server(server=Server())
            channel = transport.accept(5)
            assert channel is not None
            assert shell_ready.wait(5)
            channel.settimeout(5)
            while len(received) < len(expected):
                chunk = channel.recv(32768)
                assert chunk, 'SSH stream ended before the complete UTF-8 payload'
                received.extend(chunk)
            channel.sendall(bytes(received))
            stop.wait(5)
        except Exception as exc:
            failures.append(exc)
        finally:
            if transport is not None:
                transport.close()
            if connection is not None:
                connection.close()

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    transport = None
    session_id = 'unicode-probe-' + uuid.uuid4().hex
    try:
        connection = socket.create_connection(listener.getsockname(), timeout=5)
        transport = paramiko.Transport(connection)
        transport.connect(hostkey=host_key, username='unicode-test', password='synthetic-test-only')
        channel = transport.open_session(timeout=5)
        channel.settimeout(5)
        channel.get_pty()
        channel.invoke_shell()
        if complete:
            assert len(expected) > channel.out_max_packet_size
        with ssh_manager.sessions_lock:
            ssh_manager.sessions[session_id] = {'connected': True, 'channel': channel}

        assert ssh_manager.send_ssh_input(session_id, terminal_input, require_complete=complete) == (True, None)
        echoed = bytearray()
        while len(echoed) < len(expected):
            chunk = channel.recv(32768)
            assert chunk
            echoed.extend(chunk)
        assert bytes(echoed) == expected
        assert bytes(received) == expected
        assert echoed.decode('utf-8') == terminal_input
    finally:
        with ssh_manager.sessions_lock:
            ssh_manager.sessions.pop(session_id, None)
        stop.set()
        if transport is not None:
            transport.close()
        listener.close()
        worker.join(6)
    assert not worker.is_alive()
    assert not failures, failures
