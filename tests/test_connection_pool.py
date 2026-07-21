import threading

import paramiko
import pytest

from app import connection_pool, ssh_manager


class FakeTransport:
    def __init__(self):
        self.keepalive = None

    def set_keepalive(self, seconds):
        self.keepalive = seconds

    def is_active(self):
        return True


class FakeSFTP:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class FakeSSHClient:
    def __init__(self, connect_error=None):
        self.connect_error = connect_error
        self.connect_kwargs = None
        self.transport = FakeTransport()
        self.sftp = FakeSFTP()
        self.policy = None
        self.loaded_host_keys = None
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

    def open_sftp(self):
        return self.sftp

    def close(self):
        self.closed = True


def make_pool(max_connections_per_user=3):
    pool = connection_pool.TemporaryConnectionPool.__new__(
        connection_pool.TemporaryConnectionPool
    )
    pool.connections = {}
    pool.cleanup_interval = 300
    pool.max_connections_per_user = max_connections_per_user
    pool.lock = threading.Lock()
    return pool


def install_ssh_client(monkeypatch, connect_error=None):
    clients = []

    def client_factory():
        client = FakeSSHClient(connect_error=connect_error)
        clients.append(client)
        return client

    monkeypatch.setattr(connection_pool.paramiko, 'SSHClient', client_factory)
    return clients


def create_connection(pool, **overrides):
    kwargs = {
        'host': 'target.example',
        'port': 22,
        'username': 'alice',
        'user_id': '7',
    }
    kwargs.update(overrides)
    return pool.create_connection(**kwargs)


def test_connection_pool_exposes_the_shared_loader():
    assert connection_pool._load_private_key is ssh_manager._load_private_key


def test_pool_password_connection_opens_sftp(monkeypatch):
    pool = make_pool()
    clients = install_ssh_client(monkeypatch)

    connection_id, error = create_connection(pool, password='secret')

    assert error is None
    assert connection_id in pool.connections
    assert clients[0].connect_kwargs == {
        'hostname': 'target.example',
        'port': 22,
        'username': 'alice',
        'timeout': 10,
        'look_for_keys': False,
        'allow_agent': False,
        'password': 'secret',
    }
    assert clients[0].transport.keepalive == 30
    record = pool.connections[connection_id]
    assert record['client'] is clients[0]
    assert record['sftp'] is clients[0].sftp
    assert record['user_id'] == '7'
    assert record['host'] == 'target.example'
    assert record['port'] == 22
    assert record['username'] == 'alice'
    assert record['created_at'] <= record['last_used']


@pytest.mark.parametrize(
    ('fixture_name', 'expected_class'),
    [
        ('rsa_private_key_pem', paramiko.RSAKey),
        ('ed25519_private_key_pem', paramiko.Ed25519Key),
        ('ecdsa_private_key_pem', paramiko.ECDSAKey),
    ],
)
def test_pool_supported_key_uses_pkey(
        monkeypatch, request, fixture_name, expected_class):
    pool = make_pool()
    clients = install_ssh_client(monkeypatch)
    key_content = request.getfixturevalue(fixture_name)

    connection_id, error = create_connection(
        pool,
        password='must-not-be-used',
        key_content=key_content,
    )

    assert error is None
    assert connection_id in pool.connections
    assert isinstance(clients[0].connect_kwargs['pkey'], expected_class)
    assert 'password' not in clients[0].connect_kwargs
    assert 'key_filename' not in clients[0].connect_kwargs


def test_pool_encrypted_key_uses_transient_passphrase(
        monkeypatch, encrypted_ecdsa_private_key_pem):
    pool = make_pool()
    clients = install_ssh_client(monkeypatch)

    connection_id, error = create_connection(
        pool,
        key_content=encrypted_ecdsa_private_key_pem,
        key_passphrase='test-passphrase',
    )

    assert error is None
    assert connection_id in pool.connections
    assert isinstance(clients[0].connect_kwargs['pkey'], paramiko.ECDSAKey)
    assert 'key_passphrase' not in pool.connections[connection_id]


@pytest.mark.parametrize(
    ('passphrase', 'expected_error'),
    [
        (None, 'SSH key passphrase required'),
        ('wrong-pool-passphrase', 'Invalid SSH key passphrase'),
    ],
)
def test_pool_encrypted_key_returns_safe_passphrase_errors(
        monkeypatch, encrypted_rsa_private_key_pem, passphrase, expected_error):
    pool = make_pool()
    install_ssh_client(monkeypatch)

    connection_id, error = create_connection(
        pool,
        key_content=encrypted_rsa_private_key_pem,
        key_passphrase=passphrase,
    )

    assert connection_id is None
    assert error == expected_error
    assert 'wrong-pool-passphrase' not in error


def test_pool_invalid_key_returns_generic_error(monkeypatch):
    pool = make_pool()
    install_ssh_client(monkeypatch)
    key_material = 'invalid-private-key-marker'

    connection_id, error = create_connection(pool, key_content=key_material)

    assert connection_id is None
    assert error == 'SSH connection failed'
    assert key_material not in error
    assert pool.connections == {}


def test_pool_authentication_failure_returns_existing_message(monkeypatch):
    pool = make_pool()
    install_ssh_client(
        monkeypatch,
        paramiko.AuthenticationException('credential-marker'),
    )

    connection_id, error = create_connection(pool, password='secret')

    assert connection_id is None
    assert error == 'Authentication failed: Invalid username or password'
    assert 'credential-marker' not in error
    assert pool.connections == {}


def test_pool_enforces_per_user_connection_limit(monkeypatch):
    pool = make_pool(max_connections_per_user=1)
    clients = install_ssh_client(monkeypatch)
    pool.connections['existing'] = {
        'user_id': '7',
    }

    connection_id, error = create_connection(pool, password='secret')

    assert connection_id is None
    assert error == 'Maximum 1 connections per user exceeded'
    assert clients == []
