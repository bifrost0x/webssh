import threading

import paramiko
import pytest

from app import connection_pool, ssh_manager
from app.network_policy import ResolvedTarget
from app.quota_manager import QuotaKind, QuotaManager


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


class FakeValidatedSocket:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class ClientList(list):
    pass


class FailingReservation:
    def release(self):
        raise RuntimeError('release failed')


class FakeSSHClient:
    def __init__(self, connect_error=None):
        self.connect_error = connect_error
        self.connect_kwargs = None
        self.transport = FakeTransport()
        self.sftp = FakeSFTP()
        self.policy = None
        self.host_keys = paramiko.HostKeys()
        self.loaded_host_keys = None
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

    def open_sftp(self):
        return self.sftp

    def close(self):
        self.closed = True


def make_pool(global_limit=12, per_user_limit=3):
    pool = connection_pool.TemporaryConnectionPool.__new__(
        connection_pool.TemporaryConnectionPool
    )
    pool.connections = {}
    pool.cleanup_interval = 300
    pool.lock = threading.Lock()
    limits = {
        kind: {'global': 100, 'per_user': 50}
        for kind in QuotaKind
    }
    limits[QuotaKind.QUICK_CONNECTION] = {
        'global': global_limit,
        'per_user': per_user_limit,
    }
    pool.quota_manager = QuotaManager(limits)
    pool.cleanup_handle = None
    pool._cleanup_lifecycle = None
    return pool


def test_pool_constructor_keeps_deprecated_limit_argument():
    pool = connection_pool.TemporaryConnectionPool(
        max_connections_per_user=1
    )

    assert pool.quota_manager is connection_pool.quota_manager
    assert not hasattr(pool, 'max_connections_per_user')


def test_pool_cleanup_is_untracked_until_bound_to_an_app_lifecycle():
    """Import-time cleanup threads escape test app factories and shutdown."""
    from app.runtime_lifecycle import RuntimeLifecycle

    pool = connection_pool.TemporaryConnectionPool(cleanup_interval=1)
    lifecycle = RuntimeLifecycle(max_workers=1)
    try:
        assert not hasattr(pool, 'cleanup_thread')

        handle = pool.bind_lifecycle(lifecycle)

        assert pool.cleanup_handle is handle
        assert handle.name == 'temporary_connection_cleanup'
    finally:
        lifecycle.begin_shutdown(1)


def test_rebinding_global_pool_closes_old_connections_and_releases_quotas(
        monkeypatch):
    """Replacing a pool without closing it leaks live clients and quota slots."""
    from app.runtime_lifecycle import RuntimeLifecycle

    class Resource:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    class Reservation:
        def __init__(self):
            self.release_calls = 0

        def release(self):
            self.release_calls += 1

    old_pool = connection_pool.TemporaryConnectionPool()
    client = Resource()
    sftp = Resource()
    reservation = Reservation()
    old_pool.connections['live'] = {
        'client': client,
        'sftp': sftp,
        'quota_reservation': reservation,
    }
    monkeypatch.setattr(connection_pool, 'temp_connection_pool', old_pool)
    lifecycle = RuntimeLifecycle(max_workers=1)

    try:
        replacement = connection_pool.bind_temp_connection_pool(lifecycle)

        assert replacement is not old_pool
        assert old_pool.connections == {}
        assert client.closed is True
        assert sftp.closed is True
        assert reservation.release_calls == 1
    finally:
        lifecycle.begin_shutdown(1)


def test_pool_lifecycle_shutdown_closes_all_live_resources_once(monkeypatch):
    """Cancelling pool cleanup must release active connections and their quota."""
    from app.runtime_lifecycle import RuntimeLifecycle

    class Resource:
        def __init__(self):
            self.close_calls = 0

        def close(self):
            self.close_calls += 1

    class Reservation:
        def __init__(self):
            self.release_calls = 0

        def release(self):
            self.release_calls += 1

    pool = connection_pool.TemporaryConnectionPool()
    lifecycle = RuntimeLifecycle(max_workers=1)
    client = Resource()
    sftp = Resource()
    reservation = Reservation()
    pool.connections['live'] = {
        'client': client,
        'sftp': sftp,
        'quota_reservation': reservation,
    }
    monkeypatch.setattr(
        'app.sftp_handler.close_sftp_cache', lambda _connection_id: None
    )

    handle = pool.bind_lifecycle(lifecycle)
    report = lifecycle.begin_shutdown(1)

    assert handle.join(1) is True
    assert report.remaining == ()
    assert pool.connections == {}
    assert sftp.close_calls == 1
    assert client.close_calls == 1
    assert reservation.release_calls == 1
    lifecycle.begin_shutdown(1)
    assert reservation.release_calls == 1


def test_close_all_detaches_registry_before_blocking_resource_close(monkeypatch):
    """A slow remote close must not keep pool APIs behind the registry lock."""
    pool = connection_pool.TemporaryConnectionPool()
    close_started = threading.Event()
    release_close = threading.Event()
    lookup_finished = threading.Event()
    lookup = []

    class BlockingResource:
        def close(self):
            close_started.set()
            assert release_close.wait(1)

    class Resource:
        def close(self):
            pass

    class Reservation:
        def __init__(self):
            self.release_calls = 0

        def release(self):
            self.release_calls += 1

    reservation = Reservation()
    pool.connections['live'] = {
        'client': Resource(),
        'sftp': BlockingResource(),
        'quota_reservation': reservation,
        'host': 'target',
        'port': 22,
        'username': 'alice',
        'created_at': 0,
        'last_used': 0,
        'user_id': '7',
    }
    monkeypatch.setattr(
        'app.sftp_handler.close_sftp_cache', lambda _connection_id: None
    )
    closer = threading.Thread(target=pool.close_all_connections)
    closer.start()

    try:
        assert close_started.wait(1)

        def get_connection_info():
            lookup.append(pool.get_connection_info('live'))
            lookup_finished.set()

        reader = threading.Thread(target=get_connection_info)
        reader.start()
        assert lookup_finished.wait(0.5)
        assert lookup == [None]
    finally:
        release_close.set()
        closer.join(1)
        if 'reader' in locals():
            reader.join(1)

    assert not closer.is_alive()
    assert reservation.release_calls == 1


def install_ssh_client(monkeypatch, connect_error=None):
    clients = ClientList()
    opened_sockets = []

    def client_factory():
        client = FakeSSHClient(connect_error=connect_error)
        clients.append(client)
        return client

    monkeypatch.setattr(connection_pool.paramiko, 'SSHClient', client_factory)
    monkeypatch.setattr(
        connection_pool,
        'resolve_allowed_target',
        lambda host, port, allow_internal=False: ResolvedTarget(
            host, port, '1.1.1.1', 2
        ),
    )

    def open_socket(target, timeout):
        result = FakeValidatedSocket()
        opened_sockets.append(result)
        return result

    monkeypatch.setattr(connection_pool, 'open_validated_socket', open_socket)
    clients.append_sockets = opened_sockets
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
        'sock': clients.append_sockets[0],
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


def test_pool_uses_canonical_per_user_host_key_store(monkeypatch, tmp_path):
    pool = make_pool()
    clients = install_ssh_client(monkeypatch)
    monkeypatch.setattr(
        connection_pool.config, "KNOWN_HOSTS_FILE", tmp_path / "global"
    )
    monkeypatch.setattr(connection_pool.config, "USERS_DIR", tmp_path / "users")

    connection_id, error = create_connection(
        pool, password="secret", user_id="007"
    )

    assert error is None
    assert connection_id
    assert clients[0].loaded_host_keys is None
    assert clients[0].policy.store.user_id == 7
    assert clients[0].policy.store.user_path == (
        tmp_path / "users" / "user_7" / "known_hosts"
    )


def test_pool_rejects_missing_user_id_before_creating_client(monkeypatch):
    pool = make_pool()
    clients = install_ssh_client(monkeypatch)

    connection_id, error = create_connection(
        pool, password="secret", user_id=None
    )

    assert connection_id is None
    assert error == "User identity is required"
    assert clients == []


def test_pool_rejects_new_connection_after_runtime_shutdown(monkeypatch):
    pool = make_pool()
    clients = install_ssh_client(monkeypatch)
    pool._cleanup_lifecycle = type(
        'ClosedLifecycle', (), {'accepting_work': lambda self: False}
    )()

    connection_id, error = create_connection(pool, password='secret')

    assert connection_id is None
    assert error == 'Runtime is shutting down'
    assert clients == []


def test_pool_discards_connection_if_shutdown_wins_before_registry_store(
        monkeypatch):
    pool = make_pool()
    clients = install_ssh_client(monkeypatch)

    class ClosingLifecycle:
        def __init__(self):
            self.checks = 0

        def accepting_work(self):
            self.checks += 1
            return self.checks == 1

    pool._cleanup_lifecycle = ClosingLifecycle()

    connection_id, error = create_connection(pool, password='secret')

    assert connection_id is None
    assert error == 'Runtime is shutting down'
    assert pool.connections == {}
    assert clients[0].closed is True
    assert clients[0].sftp.closed is True


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
    clients = install_ssh_client(
        monkeypatch,
        paramiko.AuthenticationException('credential-marker'),
    )

    connection_id, error = create_connection(pool, password='secret')

    assert connection_id is None
    assert error == 'Authentication failed: Invalid username or password'
    assert 'credential-marker' not in error
    assert pool.connections == {}
    assert clients[0].closed is True
    assert clients.append_sockets[0].closed is True


def test_pool_reserves_before_network_and_enforces_concurrent_limit(monkeypatch):
    pool = make_pool(global_limit=2, per_user_limit=1)
    clients = install_ssh_client(monkeypatch)
    connect_started = threading.Event()
    connect_release = threading.Event()

    def blocking_connect(**_kwargs):
        connect_started.set()
        assert connect_release.wait(2)

    clients_factory = connection_pool.paramiko.SSHClient

    def client_factory():
        client = clients_factory()
        if len(clients) == 1:
            client.connect = blocking_connect
        return client

    monkeypatch.setattr(connection_pool.paramiko, 'SSHClient', client_factory)
    first_result = []
    first_thread = threading.Thread(
        target=lambda: first_result.append(
            create_connection(pool, password='secret')
        ),
        daemon=True,
    )
    first_thread.start()
    assert connect_started.wait(2)

    connection_id, error = create_connection(pool, password='secret')

    assert connection_id is None
    assert error == 'Maximum number of quick connections reached'
    assert len(clients) == 1

    connect_release.set()
    first_thread.join(2)
    assert not first_thread.is_alive()
    assert first_result[0][1] is None
    record = pool.connections[first_result[0][0]]
    assert record['quota_reservation'].released is False


def test_pool_failure_releases_reserved_quota(monkeypatch):
    pool = make_pool(global_limit=2, per_user_limit=1)
    install_ssh_client(
        monkeypatch, paramiko.SSHException('connection failed')
    )

    connection_id, error = create_connection(pool, password='secret')

    assert connection_id is None
    assert error == 'SSH connection failed'
    replacement = pool.quota_manager.reserve(
        QuotaKind.QUICK_CONNECTION, user_id=7
    )
    replacement.release()


def test_pool_close_releases_quota_exactly_once(monkeypatch):
    pool = make_pool(global_limit=2, per_user_limit=1)
    install_ssh_client(monkeypatch)
    connection_id, error = create_connection(pool, password='secret')
    assert error is None

    reservation = pool.connections[connection_id]['quota_reservation']
    monkeypatch.setattr(
        'app.sftp_handler.close_sftp_cache', lambda _connection_id: None
    )

    assert pool.close_connection(connection_id) is True
    assert pool.close_connection(connection_id) is False
    assert reservation.released is True

    replacement = pool.quota_manager.reserve(
        QuotaKind.QUICK_CONNECTION, user_id=7
    )
    replacement.release()


def test_pool_close_succeeds_when_quota_release_fails(monkeypatch):
    pool = make_pool()
    client = FakeSSHClient()
    sftp = FakeSFTP()
    pool.connections['connection-1'] = {
        'client': client,
        'sftp': sftp,
        'quota_reservation': FailingReservation(),
    }
    monkeypatch.setattr(
        'app.sftp_handler.close_sftp_cache', lambda _connection_id: None
    )

    assert pool.close_connection('connection-1') is True
    assert sftp.closed is True
    assert client.closed is True
