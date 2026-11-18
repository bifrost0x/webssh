"""Herdr overview against a real Herdr release on the disposable OpenSSH lab."""
import os
import shlex
import socket
import time
from threading import BoundedSemaphore

import paramiko
import pytest

from app import herdr, ssh_manager

pytestmark = pytest.mark.skipif(
    os.environ.get('PARAMIKO5_INTEGRATION') != '1'
    or os.environ.get('PARAMIKO5_DISPOSABLE_LAB') != '1',
    reason='requires disposable OpenSSH lab',
)
HOST = '127.0.0.1'
PORT = 2225
PASSWORD = 'Paramiko5-Test-Only!'
# The lab installs Herdr for agentuser only where the official installer puts it.
HERDR = '$HOME/.local/bin/herdr'
SERVER_ANSWERS = f'{HERDR} api snapshot >/dev/null 2>&1'
COUNT_HERDR = 'cat /proc/[0-9]*/comm 2>/dev/null | grep -c -x herdr'


def connect(username):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, port=PORT, username=username, password=PASSWORD,
                   allow_agent=False, look_for_keys=False, timeout=10)
    return client


def run(client, command, timeout=15):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode('utf-8', 'replace')
    stderr.read()
    return stdout.channel.recv_exit_status(), output.strip()


def stop_herdr(client):
    run(client, f'{HERDR} server stop >/dev/null 2>&1; sleep 1; rm -rf "$HOME/.config/herdr"')
    deadline = time.monotonic() + 10
    while run(client, COUNT_HERDR)[1] != '0':
        assert time.monotonic() < deadline, 'Herdr server did not stop'
        time.sleep(0.2)


@pytest.fixture
def lab(app, monkeypatch):
    """Yield a factory that registers a live session for one lab account."""
    from app import app_settings, profile_manager
    from app.auth import register_user

    monkeypatch.setattr(herdr, '_snapshot_slots', BoundedSemaphore(herdr.MAX_CONCURRENT_SNAPSHOTS))
    monkeypatch.setattr(ssh_manager, 'sessions', {})
    clients = []
    with app.app_context():
        user, error = register_user('herdr_integration', 'integration-password')
        assert error is None
        assert app_settings.set_herdr_enabled(True) is True

        def session(username):
            profile, error = profile_manager.upsert_profile(user.id, {
                'name': f'Lab {username}', 'host': HOST, 'port': PORT, 'username': username,
                'auth_type': 'password', 'herdr': True,
            })
            assert error is None
            client = connect(username)
            clients.append(client)
            ssh_manager.sessions[username] = {
                'connected': True, 'client': client, 'user_id': user.id,
                'profile_id': profile['id'], 'herdr': True,
            }
            return client

        yield session
    for client in clients:
        client.close()


@pytest.fixture
def agent_host(lab):
    client = lab('agentuser')
    stop_herdr(client)
    yield client
    stop_herdr(client)


def test_binary_outside_the_exec_path_is_found_by_every_command(agent_host):
    assert run(agent_host, 'command -v herdr')[0] != 0
    assert run(agent_host, herdr.AVAILABLE_COMMAND)[0] == 0
    assert run(agent_host, f'{HERDR} --version') == (0, 'herdr 0.9.5')


def test_without_a_server_nothing_is_started(agent_host):
    assert herdr.collect_snapshot('agentuser') == (None, 'no_server')
    assert run(agent_host, COUNT_HERDR)[1] == '0'
    assert run(agent_host, 'test -e "$HOME/.config/herdr"')[0] != 0


def test_running_server_reports_its_agents(agent_host):
    start_server(agent_host)
    assert run(agent_host, f'{HERDR} workspace create --label lab --no-focus >/dev/null')[0] == 0
    assert herdr.collect_snapshot('agentuser') == ({'agents': [], 'truncated': False}, None)

    assert run(agent_host, f'{HERDR} pane rename w1:p1 build >/dev/null')[0] == 0
    assert run(
        agent_host,
        f'{HERDR} pane report-agent w1:p1 --source lab --agent codex --state blocked >/dev/null',
    )[0] == 0
    ssh_manager.sessions['agentuser']['herdr_snapshot_not_before'] = 0
    snapshot, reason = herdr.collect_snapshot('agentuser')
    assert reason is None
    assert snapshot == {'truncated': False, 'agents': [{
        'id': 'w1:p1', 'kind': 'codex', 'label': 'build',
        'cwd': '/home/agentuser', 'status': 'blocked',
    }]}


def test_host_without_herdr_is_not_installed(lab):
    client = lab('testuser')
    assert run(client, herdr.AVAILABLE_COMMAND)[0] != 0
    assert herdr.collect_snapshot('testuser') == (None, 'not_installed')


def install_fake_herdr(client, script):
    fake = '$HOME/.local/bin/herdr'
    assert run(client, (
        f'mkdir -p "$HOME/.local/bin" && printf %s {shlex.quote(script)} > {fake} '
        f'&& chmod +x {fake}'
    ))[0] == 0


def remove_fake_herdr(client):
    run(client, 'rm -f "$HOME/.local/bin/herdr"; rmdir "$HOME/.local/bin" "$HOME/.local" 2>/dev/null')


def test_stuck_command_is_ended_on_the_host(lab):
    client = lab('testuser')
    # A script keeps its own name as the process name, so the stuck call is a
    # process called herdr that ignores the closed channel.
    install_fake_herdr(client, '#!/bin/sh\nwhile :; do sleep 1; done\n')
    try:
        started = time.monotonic()
        assert herdr.collect_snapshot('testuser') == (None, 'timeout')
        assert herdr.SNAPSHOT_TIMEOUT <= time.monotonic() - started < herdr.SNAPSHOT_TIMEOUT + 2
        # Closing the channel did not end it; the host-side limit does.
        assert run(client, COUNT_HERDR)[1] == '1'
        assert herdr.collect_snapshot('testuser') == (None, 'busy')
        deadline = started + 10
        while run(client, COUNT_HERDR)[1] != '0':
            assert time.monotonic() < deadline, 'stuck Herdr call survived the host limit'
            time.sleep(0.25)
        assert time.monotonic() - started >= 5
    finally:
        remove_fake_herdr(client)


def test_snapshot_command_passes_the_cli_exit_status_through(agent_host, lab):
    assert run(agent_host, herdr.SNAPSHOT_COMMAND)[0] == 1
    assert run(lab('testuser'), herdr.SNAPSHOT_COMMAND)[0] == 127
    start_server(agent_host)
    status, output = run(agent_host, herdr.SNAPSHOT_COMMAND)
    assert status == 0 and '"session_snapshot"' in output


def wait_for_server(client, message):
    # "herdr status server" succeeds before the socket accepts requests.
    deadline = time.monotonic() + 15
    while run(client, SERVER_ANSWERS)[0] != 0:
        assert time.monotonic() < deadline, message
        time.sleep(0.2)


def start_server(client):
    assert run(client, f'nohup {HERDR} server >/dev/null 2>&1 &')[0] == 0
    wait_for_server(client, 'Herdr server did not start')


@pytest.fixture
def terminals(lab, tmp_path, monkeypatch):
    """Open WebSSH terminal sessions as create_ssh_connection does for the browser."""
    monkeypatch.setattr(ssh_manager.config, 'KNOWN_HOSTS_FILE', tmp_path / 'known_hosts')
    monkeypatch.setattr(ssh_manager.config, 'USERS_DIR', tmp_path / 'users')
    opened = []

    def open_terminal(username, **options):
        user_id = ssh_manager.sessions[username]['user_id']
        session_id, error = ssh_manager.create_ssh_connection(
            host=HOST, port=PORT, username=username, password=PASSWORD, user_id=user_id,
            host_key_decision=lambda details: details['fingerprint'].startswith('SHA256:'),
            **options,
        )
        assert error is None
        opened.append(session_id)
        channel = ssh_manager.sessions[session_id]['channel']
        channel.resize_pty(width=160, height=48)
        return session_id, channel

    yield open_terminal
    for session_id in opened:
        ssh_manager.close_session(session_id, kill_tmux=True)


def read_until(channel, marker, timeout=20):
    received = bytearray()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            chunk = channel.recv(65536)
        except socket.timeout:
            continue
        if not chunk:
            break
        received.extend(chunk)
        if marker in received:
            return bytes(received)
    raise AssertionError(f'{marker!r} not received; got {bytes(received[-400:])!r}')


def test_session_mode_starts_herdr_and_a_second_connection_attaches(agent_host, terminals):
    assert run(agent_host, COUNT_HERDR)[1] == '0'
    first, first_channel = terminals('agentuser', herdr=True, use_herdr=True)
    assert ssh_manager.get_session(first)['use_herdr'] is True
    read_until(first_channel, b'\x1b[?1049h')
    wait_for_server(agent_host, 'session mode did not start a Herdr server')
    # Found only through the fixed lookup, like the overview.
    assert herdr.collect_snapshot('agentuser')[1] is None
    marker = 'attachmark'
    assert run(agent_host, f'{HERDR} workspace create --label {marker} --no-focus >/dev/null')[0] == 0
    ssh_manager.sessions['agentuser']['herdr_snapshot_not_before'] = 0
    workspaces = run(agent_host, herdr.SNAPSHOT_COMMAND)[1].count('"workspace_id"')

    second, second_channel = terminals('agentuser', herdr=True, use_herdr=True)
    assert ssh_manager.get_session(second)['use_herdr'] is True
    read_until(second_channel, marker.encode())
    assert run(agent_host, herdr.SNAPSHOT_COMMAND)[1].count('"workspace_id"') == workspaces

    # Closing WebSSH sessions detaches only; the Herdr server keeps running.
    ssh_manager.close_session(first, kill_tmux=True)
    ssh_manager.close_session(second, kill_tmux=True)
    time.sleep(1)
    assert run(agent_host, SERVER_ANSWERS)[0] == 0


def test_session_mode_without_herdr_is_a_normal_shell(lab, terminals):
    lab('testuser')
    session_id, channel = terminals('testuser', herdr=True, use_herdr=True)
    assert ssh_manager.get_session(session_id)['use_herdr'] is False
    channel.send("printf 'shell%s\\n' ready\n")
    read_until(channel, b'shellready')
    assert herdr.collect_snapshot('testuser') == (None, 'not_installed')
