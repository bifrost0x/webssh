import paramiko
import pytest
import threading

from app import ssh_manager
from app.network_policy import ResolvedTarget


class FakeForwardChannel:
    pass


class FakeValidatedSocket:
    def __init__(self, host):
        self.host = host
        self.closed = False

    def close(self):
        self.closed = True


class ClientList(list):
    pass


class FakeTransport:
    def __init__(self):
        self.keepalive = None
        self.opened_channel = None
        self.forward_channel = FakeForwardChannel()
        self.session_channels = []
        self.open_timeout = None
        self.channel_timeout = None

    def set_keepalive(self, seconds):
        self.keepalive = seconds

    def open_channel(self, kind, destination, source, timeout=None):
        self.opened_channel = (kind, destination, source)
        self.channel_timeout = timeout
        return self.forward_channel

    def open_session(self, timeout=None):
        self.open_timeout = timeout
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
        self.host_keys = paramiko.HostKeys()
        self.loaded_host_keys = None
        self.shell_kwargs = None
        self.closed = False

    def load_host_keys(self, path):
        self.loaded_host_keys = path

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def get_host_keys(self):
        return self.host_keys

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
    clients = ClientList()
    opened_sockets = []

    def client_factory():
        index = len(clients)
        error = connect_errors[index] if index < len(connect_errors) else None
        client = FakeSSHClient(connect_error=error)
        clients.append(client)
        return client

    monkeypatch.setattr(ssh_manager.paramiko, 'SSHClient', client_factory)
    monkeypatch.setattr(ssh_manager.time, 'sleep', lambda _seconds: None)
    monkeypatch.setattr(
        ssh_manager,
        'resolve_allowed_target',
        lambda host, port, allow_internal=False: ResolvedTarget(
            host,
            port,
            '1.1.1.1' if host == 'target.example' else '8.8.8.8',
            2,
        ),
    )

    def open_socket(target, timeout):
        result = FakeValidatedSocket(target.hostname)
        opened_sockets.append(result)
        return result

    monkeypatch.setattr(ssh_manager, 'open_validated_socket', open_socket)
    clients.opened_sockets = opened_sockets
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


def test_open_exec_channel_bounds_paramiko_request_handshake():
    class BlockingTransport:
        def __init__(self):
            self.open_timeout = None
            self.channel = paramiko.Channel(1)
            self.channel.active = True
            self.channel.remote_chanid = 1
            self.channel.transport = self

        def open_session(self, timeout=None):
            self.open_timeout = timeout
            return self.channel

        def _send_user_message(self, _message):
            pass

        def get_exception(self):
            return None

    transport = BlockingTransport()
    finished = threading.Event()
    errors = []

    def execute():
        try:
            ssh_manager._open_exec_channel(
                transport, 'command -v tmux', timeout=0.05)
        except Exception as error:
            errors.append(error)
        finally:
            finished.set()

    worker = threading.Thread(target=execute, daemon=True)
    worker.start()
    completed = finished.wait(0.5)
    if not completed:
        transport.channel.close()
    worker.join(2)

    assert completed, 'Paramiko exec request exceeded its deadline'
    assert transport.open_timeout == 0.05
    assert transport.channel.closed is True
    assert errors


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
        'sock': clients.opened_sockets[0],
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


def test_direct_connection_pins_real_resolution_through_paramiko(monkeypatch):
    import socket
    import app.network_policy as network_policy

    clients = install_ssh_clients(monkeypatch)
    monkeypatch.setattr(
        ssh_manager,
        'resolve_allowed_target',
        network_policy.resolve_allowed_target,
    )
    monkeypatch.setattr(
        ssh_manager,
        'open_validated_socket',
        network_policy.open_validated_socket,
    )
    dns_calls = []

    def fake_getaddrinfo(host, port, **kwargs):
        dns_calls.append((host, port))
        if len(dns_calls) > 1:
            raise AssertionError('second DNS lookup reached private address')
        return [(
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            '',
            ('1.1.1.1', port),
        )]

    class PinnedSocket:
        def __init__(self, family, socktype):
            self.family = family
            self.socktype = socktype
            self.timeout = None
            self.destination = None

        def settimeout(self, timeout):
            self.timeout = timeout

        def connect(self, destination):
            self.destination = destination

        def close(self):
            pass

    created = []

    def socket_factory(family, socktype):
        result = PinnedSocket(family, socktype)
        created.append(result)
        return result

    monkeypatch.setattr(network_policy.socket, 'getaddrinfo', fake_getaddrinfo)
    monkeypatch.setattr(network_policy.socket, 'socket', socket_factory)

    session_id, error = connect_target(password='secret')

    assert error is None
    assert session_id
    assert dns_calls == [('target.example', 22)]
    assert created[0].destination == ('1.1.1.1', 22)
    assert clients[0].connect_kwargs['hostname'] == 'target.example'
    assert clients[0].connect_kwargs['sock'] is created[0]


def test_direct_connection_uses_canonical_per_user_host_key_store(
        monkeypatch, tmp_path):
    clients = install_ssh_clients(monkeypatch)
    monkeypatch.setattr(ssh_manager.config, "KNOWN_HOSTS_FILE", tmp_path / "global")
    monkeypatch.setattr(ssh_manager.config, "USERS_DIR", tmp_path / "users")

    session_id, error = connect_target(password="secret", user_id="007")

    assert error is None
    assert session_id
    assert clients[0].loaded_host_keys is None
    assert clients[0].policy.store.user_path == (
        tmp_path / "users" / "user_7" / "known_hosts"
    )


def test_proxy_and_target_share_only_the_current_users_host_key_store(
        monkeypatch, tmp_path):
    clients = install_ssh_clients(monkeypatch)
    monkeypatch.setattr(ssh_manager.config, "KNOWN_HOSTS_FILE", tmp_path / "global")
    monkeypatch.setattr(ssh_manager.config, "USERS_DIR", tmp_path / "users")

    session_id, error = connect_target(
        password="target",
        user_id=8,
        proxy_jump_host="bastion.example",
        proxy_jump_username="jump",
        proxy_jump_password="jump-secret",
    )

    assert error is None
    assert session_id
    assert [client.policy.store.user_id for client in clients] == [8, 8]
    assert {
        client.policy.store.user_path for client in clients
    } == {tmp_path / "users" / "user_8" / "known_hosts"}


def test_connection_rejects_missing_user_id_before_creating_client(monkeypatch):
    clients = install_ssh_clients(monkeypatch)

    session_id, error = connect_target(password="secret", user_id=None)

    assert session_id is None
    assert error == "User identity is required"
    assert clients == []


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
        'sock': clients.opened_sockets[0],
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


def test_tmux_reconnect_quotes_session_name_at_ssh_boundary(monkeypatch):
    clients = install_ssh_clients(monkeypatch)

    session_id, error = connect_target(
        password='secret',
        use_tmux=True,
        reconnect_tmux_name='name; touch /tmp/marker',
    )

    assert error is None
    assert session_id in ssh_manager.sessions
    _, tmux_channel = clients[0].transport.session_channels
    assert tmux_channel.command == (
        "tmux new-session -A -s 'name; touch /tmp/marker'"
    )


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
        'sock': clients.opened_sockets[0],
        'look_for_keys': False,
        'allow_agent': False,
        'password': 'jump-password',
    }
    assert bastion.transport.opened_channel == (
        'direct-tcpip',
        ('1.1.1.1', 22),
        ('127.0.0.1', 0),
    )
    assert (
        bastion.transport.channel_timeout
        == ssh_manager.config.SSH_CONNECT_TIMEOUT
    )
    assert target.connect_kwargs['sock'] is bastion.transport.forward_channel
    assert ssh_manager.sessions[session_id]['bastion_client'] is bastion


def test_proxy_jump_remote_dns_is_rejected_when_internal_blocking_is_on(
        monkeypatch):
    clients = install_ssh_clients(monkeypatch)
    original_resolver = ssh_manager.resolve_allowed_target

    def resolver(host, port, allow_internal=False):
        if host == 'remote-only.example':
            raise ValueError('Host could not be resolved')
        return original_resolver(host, port, allow_internal)

    monkeypatch.setattr(ssh_manager, 'resolve_allowed_target', resolver)
    monkeypatch.setattr(ssh_manager.config, 'BLOCK_INTERNAL_SSH', True)
    monkeypatch.setattr(
        ssh_manager.config, 'PROXY_JUMP_REMOTE_DNS_ALLOWLIST', ()
    )
    session_id, error = connect_target(
        host='remote-only.example',
        password='target-password',
        proxy_jump_host='bastion.example',
        proxy_jump_username='jump-user',
        proxy_jump_password='jump-password',
    )

    assert session_id is None
    assert error == 'Connections to this address are not allowed'
    assert clients == []


def test_proxy_jump_exact_allowlist_preserves_remote_dns_when_blocked(
        monkeypatch):
    clients = install_ssh_clients(monkeypatch)
    original_resolver = ssh_manager.resolve_allowed_target

    def resolver(host, port, allow_internal=False):
        if host == 'xn--bcher-kva.example':
            raise ValueError('Host could not be resolved')
        return original_resolver(host, port, allow_internal)

    monkeypatch.setattr(ssh_manager, 'resolve_allowed_target', resolver)
    monkeypatch.setattr(ssh_manager.config, 'BLOCK_INTERNAL_SSH', True)
    monkeypatch.setattr(
        ssh_manager.config,
        'PROXY_JUMP_REMOTE_DNS_ALLOWLIST',
        ('BÜCHER.EXAMPLE.',),
    )

    session_id, error = connect_target(
        host='BÜCHER.EXAMPLE.',
        password='target-password',
        proxy_jump_host='bastion.example',
        proxy_jump_username='jump-user',
        proxy_jump_password='jump-password',
    )

    assert error is None
    assert session_id
    assert clients[0].transport.opened_channel[1] == (
        'xn--bcher-kva.example',
        22,
    )
    assert clients[1].connect_kwargs['hostname'] == (
        'xn--bcher-kva.example'
    )


def test_proxy_jump_remote_dns_remains_compatible_when_blocking_is_off(
        monkeypatch):
    clients = install_ssh_clients(monkeypatch)
    original_resolver = ssh_manager.resolve_allowed_target

    def resolver(host, port, allow_internal=False):
        if host == 'remote-only.example':
            raise ValueError('Host could not be resolved')
        return original_resolver(host, port, allow_internal)

    monkeypatch.setattr(ssh_manager, 'resolve_allowed_target', resolver)
    monkeypatch.setattr(ssh_manager.config, 'BLOCK_INTERNAL_SSH', False)
    monkeypatch.setattr(
        ssh_manager.config, 'PROXY_JUMP_REMOTE_DNS_ALLOWLIST', ()
    )

    session_id, error = connect_target(
        host='remote-only.example',
        password='target-password',
        proxy_jump_host='bastion.example',
        proxy_jump_username='jump-user',
        proxy_jump_password='jump-password',
    )

    assert error is None
    assert session_id
    assert clients[0].transport.opened_channel[1] == (
        'remote-only.example',
        22,
    )


@pytest.mark.parametrize(
    'failure',
    [
        OSError('proxy-os-secret-marker'),
        paramiko.SSHException('proxy-ssh-secret-marker'),
    ],
)
def test_proxy_jump_failure_is_generic_and_logs_only_error_type(
        monkeypatch, failure):
    clients = install_ssh_clients(monkeypatch, failure)
    logged = []
    monkeypatch.setattr(
        ssh_manager,
        'log_warning',
        lambda message, **fields: logged.append((message, fields)),
    )

    session_id, error = connect_target(
        password='target-password',
        proxy_jump_host='bastion.example',
        proxy_jump_username='jump-user',
        proxy_jump_password='jump-password',
    )

    assert session_id is None
    assert error == 'Jump host connection failed'
    assert logged == [(
        'Jump host connection failed',
        {
            'bastion': 'bastion.example',
            'error_type': type(failure).__name__,
        },
    )]
    assert 'secret-marker' not in str(logged)
    assert clients[0].closed is True
    assert clients.opened_sockets[0].closed is True


def test_proxy_jump_authentication_keeps_specific_safe_error(monkeypatch):
    clients = install_ssh_clients(
        monkeypatch,
        paramiko.AuthenticationException('proxy-auth-secret-marker'),
    )

    session_id, error = connect_target(
        password='target-password',
        proxy_jump_host='bastion.example',
        proxy_jump_username='jump-user',
        proxy_jump_password='jump-password',
    )

    assert session_id is None
    assert error == 'Jump host authentication failed - invalid credentials'
    assert 'secret-marker' not in error
    assert clients[0].closed is True
    assert clients.opened_sockets[0].closed is True


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
    clients = install_ssh_clients(
        monkeypatch,
        paramiko.AuthenticationException('credential-marker'),
    )

    session_id, error = connect_target(password='secret')

    assert session_id is None
    assert error == 'Authentication failed - invalid credentials'
    assert 'credential-marker' not in error
    assert clients[0].closed is True
    assert clients.opened_sockets[0].closed is True


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
