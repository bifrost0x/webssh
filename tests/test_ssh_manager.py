import paramiko
import pytest

from app import ssh_manager


class FakeForwardChannel:
    pass


class FakeTransport:
    def __init__(self):
        self.keepalive = None
        self.opened_channel = None
        self.forward_channel = FakeForwardChannel()
        self.session_channels = []

    def set_keepalive(self, seconds):
        self.keepalive = seconds

    def open_channel(self, kind, destination, source):
        self.opened_channel = (kind, destination, source)
        return self.forward_channel

    def open_session(self):
        channel = FakeChannel()
        self.session_channels.append(channel)
        return channel

    def is_active(self):
        return True


class FakeChannel:
    def __init__(self):
        self.closed = False
        self.timeout = None
        self.command = None
        self.pty = None

    def settimeout(self, timeout):
        self.timeout = timeout

    def exec_command(self, command):
        self.command = command

    def recv(self, _size):
        return b'/usr/bin/tmux\n'

    def recv_exit_status(self):
        return 0

    def get_pty(self, term, width, height):
        self.pty = (term, width, height)

    def close(self):
        self.closed = True


class FakeSSHClient:
    def __init__(self, connect_error=None):
        self.connect_error = connect_error
        self.connect_kwargs = None
        self.transport = FakeTransport()
        self.channel = FakeChannel()
        self.policy = None
        self.loaded_host_keys = None
        self.shell_kwargs = None
        self.closed = False

    def load_host_keys(self, path):
        self.loaded_host_keys = path

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def connect(self, **kwargs):
        self.connect_kwargs = kwargs
        if self.connect_error:
            raise self.connect_error

    def get_transport(self):
        return self.transport

    def invoke_shell(self, **kwargs):
        self.shell_kwargs = kwargs
        return self.channel

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def clean_sessions():
    with ssh_manager.sessions_lock:
        ssh_manager.sessions.clear()
    yield
    for session_id in list(ssh_manager.sessions):
        ssh_manager.close_session(session_id)


def install_ssh_clients(monkeypatch, *connect_errors):
    clients = []

    def client_factory():
        index = len(clients)
        error = connect_errors[index] if index < len(connect_errors) else None
        client = FakeSSHClient(connect_error=error)
        clients.append(client)
        return client

    monkeypatch.setattr(ssh_manager.paramiko, 'SSHClient', client_factory)
    monkeypatch.setattr(ssh_manager.time, 'sleep', lambda _seconds: None)
    return clients


def connect_target(**overrides):
    kwargs = {
        'host': 'target.example',
        'port': 22,
        'username': 'alice',
        'user_id': 7,
    }
    kwargs.update(overrides)
    return ssh_manager.create_ssh_connection(**kwargs)


def test_ssh_manager_exposes_the_shared_loader():
    from app.ssh_key_loader import load_private_key

    assert ssh_manager._load_private_key is load_private_key


def test_direct_password_connect_preserves_connect_contract(monkeypatch):
    clients = install_ssh_clients(monkeypatch)

    session_id, error = connect_target(password='secret')

    assert error is None
    assert session_id in ssh_manager.sessions
    assert clients[0].connect_kwargs == {
        'hostname': 'target.example',
        'port': 22,
        'username': 'alice',
        'timeout': ssh_manager.config.SSH_CONNECT_TIMEOUT,
        'look_for_keys': False,
        'allow_agent': False,
        'password': 'secret',
    }
    assert clients[0].transport.keepalive == 30
    assert clients[0].shell_kwargs == {
        'term': 'xterm-256color',
        'width': 80,
        'height': 24,
    }
    assert clients[0].channel.timeout == 0.1


@pytest.mark.parametrize(
    ('fixture_name', 'expected_class'),
    [
        ('rsa_private_key_pem', paramiko.RSAKey),
        ('ed25519_private_key_pem', paramiko.Ed25519Key),
        ('ecdsa_private_key_pem', paramiko.ECDSAKey),
    ],
)
def test_direct_supported_key_passes_pkey_not_password(
        monkeypatch, request, fixture_name, expected_class):
    clients = install_ssh_clients(monkeypatch)
    key_content = request.getfixturevalue(fixture_name)

    session_id, error = connect_target(
        password='must-not-be-used',
        key_content=key_content,
    )

    assert error is None
    assert session_id in ssh_manager.sessions
    assert isinstance(clients[0].connect_kwargs['pkey'], expected_class)
    assert 'password' not in clients[0].connect_kwargs
    assert 'key_filename' not in clients[0].connect_kwargs


def test_tailscale_tmux_forces_utf8_locale(monkeypatch):
    clients = install_ssh_clients(monkeypatch)

    session_id, error = connect_target(
        auth_type='tailscale',
        use_tmux=True,
        reconnect_tmux_name='existing_session',
    )

    assert error is None
    assert session_id in ssh_manager.sessions
    strategy = clients[0].connect_kwargs['auth_strategy']
    assert isinstance(strategy, ssh_manager.TailscaleSSHAuthStrategy)
    assert clients[0].connect_kwargs == {
        'hostname': 'target.example',
        'port': 22,
        'username': 'alice',
        'timeout': ssh_manager.config.SSH_CONNECT_TIMEOUT,
        'auth_strategy': strategy,
    }
    assert ssh_manager.sessions[session_id]['auth_type'] == 'tailscale'
    probe_channel, tmux_channel = clients[0].transport.session_channels
    assert probe_channel.command == 'command -v tmux'
    assert tmux_channel.pty == ('xterm-256color', 80, 24)
    assert tmux_channel.command == (
        'env LANG=C.UTF-8 LC_ALL=C.UTF-8 tmux -u '
        'new-session -A -s existing_session'
    )


def test_password_tmux_preserves_remote_locale(monkeypatch):
    clients = install_ssh_clients(monkeypatch)

    session_id, error = connect_target(
        password='secret',
        use_tmux=True,
        reconnect_tmux_name='existing_session',
    )

    assert error is None
    assert session_id in ssh_manager.sessions
    _, tmux_channel = clients[0].transport.session_channels
    assert tmux_channel.command == 'tmux new-session -A -s existing_session'


def test_proxy_jump_password_opens_direct_tcpip_channel(monkeypatch):
    clients = install_ssh_clients(monkeypatch)

    session_id, error = connect_target(
        password='target-password',
        proxy_jump_host='bastion.example',
        proxy_jump_port=2222,
        proxy_jump_username='jump-user',
        proxy_jump_password='jump-password',
    )

    assert error is None
    assert session_id in ssh_manager.sessions
    bastion, target = clients
    assert bastion.connect_kwargs == {
        'hostname': 'bastion.example',
        'port': 2222,
        'username': 'jump-user',
        'timeout': ssh_manager.config.SSH_CONNECT_TIMEOUT,
        'look_for_keys': False,
        'allow_agent': False,
        'password': 'jump-password',
    }
    assert bastion.transport.opened_channel == (
        'direct-tcpip',
        ('target.example', 22),
        ('127.0.0.1', 0),
    )
    assert target.connect_kwargs['sock'] is bastion.transport.forward_channel
    assert ssh_manager.sessions[session_id]['bastion_client'] is bastion


def test_proxy_jump_key_uses_supported_pkey(
        monkeypatch, rsa_private_key_pem):
    clients = install_ssh_clients(monkeypatch)

    session_id, error = connect_target(
        password='target-password',
        proxy_jump_host='bastion.example',
        proxy_jump_port=22,
        proxy_jump_username='jump-user',
        proxy_jump_key_content=rsa_private_key_pem,
    )

    assert error is None
    assert session_id in ssh_manager.sessions
    assert isinstance(clients[0].connect_kwargs['pkey'], paramiko.RSAKey)
    assert 'password' not in clients[0].connect_kwargs


def test_target_failure_closes_bastion(monkeypatch):
    clients = install_ssh_clients(
        monkeypatch,
        None,
        paramiko.SSHException('target-marker'),
    )

    session_id, error = connect_target(
        password='target-password',
        proxy_jump_host='bastion.example',
        proxy_jump_port=22,
        proxy_jump_username='jump-user',
        proxy_jump_password='jump-password',
    )

    assert session_id is None
    assert error == 'SSH connection failed'
    assert clients[0].closed is True
    assert ssh_manager.sessions == {}


def test_authentication_exception_keeps_generic_client_error(monkeypatch):
    install_ssh_clients(
        monkeypatch,
        paramiko.AuthenticationException('credential-marker'),
    )

    session_id, error = connect_target(password='secret')

    assert session_id is None
    assert error == 'Authentication failed - invalid credentials'
    assert 'credential-marker' not in error


def test_ssh_exception_keeps_detail_in_server_log_only(monkeypatch):
    install_ssh_clients(monkeypatch, paramiko.SSHException('server-marker'))
    logged = []
    monkeypatch.setattr(
        ssh_manager,
        'log_warning',
        lambda message, **fields: logged.append((message, fields)),
    )

    session_id, error = connect_target(password='secret')

    assert session_id is None
    assert error == 'SSH connection failed'
    assert 'server-marker' not in error
    assert logged == [(
        'SSH connection failed',
        {'host': 'target.example:22', 'error': 'server-marker'},
    )]
