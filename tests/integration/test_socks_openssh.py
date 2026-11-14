"""Real SSH and session SFTP over a local SOCKS5 relay to disposable OpenSSH."""

from contextlib import contextmanager
from dataclasses import replace
import io
import os
import socket
import threading
import uuid

import paramiko
import pytest

import config
from app import sftp_handler, ssh_manager
from app.host_key_store import HostKeyStore
from app.quota_manager import QuotaManager
from tests.integration.socks_forwarder import SocksForwarder
from tests.integration.test_paramiko5_openssh import read_terminal_marker


pytestmark = pytest.mark.skipif(
    os.environ.get('PARAMIKO5_INTEGRATION') != '1',
    reason='run scripts/run_integration_tests.py for disposable SOCKS/OpenSSH tests',
)

TARGET_HOST = os.environ.get('PARAMIKO5_SOCKS_TARGET_HOST', 'target')
TARGET_PORT = int(os.environ.get('PARAMIKO5_SOCKS_TARGET_PORT', '22'))


@pytest.fixture(autouse=True)
def isolated_socks_state(tmp_path, monkeypatch):
    monkeypatch.setattr(config, 'KNOWN_HOSTS_FILE', tmp_path / 'known_hosts')
    monkeypatch.setattr(config, 'USERS_DIR', tmp_path / 'users')
    monkeypatch.setattr(config, 'BLOCK_INTERNAL_SSH', True)
    monkeypatch.setattr(config, 'SSH_ALLOWED_INTERNAL_NETWORKS', ())
    monkeypatch.setattr(config, 'SSH_CONNECT_TIMEOUT', 5)
    monkeypatch.setattr(config, 'SOCKS_REMOTE_DNS_ALLOWLIST', ('target',))
    quotas = QuotaManager.from_config()
    monkeypatch.setattr(ssh_manager, 'quota_manager', quotas)
    assert not ssh_manager.sessions
    yield HostKeyStore(1, config.KNOWN_HOSTS_FILE, config.USERS_DIR)
    for session_id in list(ssh_manager.sessions):
        ssh_manager.close_session(session_id)
    assert quotas._global_counts == {}
    assert quotas._user_counts == {}


@pytest.fixture
def socks_proxy(monkeypatch):
    @contextmanager
    def start(*, auth_type='none', changed_host_key=False, allow_proxy=True):
        credentials = (
            {'username': 'fixture-proxy-user', 'password': 'Fixture-Proxy-Only!'}
            if auth_type == 'password' else {}
        )
        with SocksForwarder(changed_host_key=changed_host_key, **credentials) as proxy:
            resolve = ssh_manager.resolve_allowed_target

            def resolve_proxy(host, port, **kwargs):
                if allow_proxy and (host, port) == (proxy.host, proxy.port):
                    # Production deliberately forbids loopback with internal
                    # blocking. Only this ephemeral fixture endpoint is exempt.
                    kwargs['allow_internal'] = True
                return resolve(host, port, **kwargs)

            with monkeypatch.context() as scoped:
                scoped.setattr(ssh_manager, 'resolve_allowed_target', resolve_proxy)
                route = ssh_manager.SocksProxyRoute(
                    proxy_id='disposable-socks-proxy', host=proxy.host, port=proxy.port,
                    auth_type=auth_type, **credentials,
                )
                yield proxy, route
    return start


def connect(route, **overrides):
    arguments = {
        'host': TARGET_HOST, 'port': TARGET_PORT, 'username': 'testuser',
        'password': 'Paramiko5-Test-Only!', 'user_id': 1,
        'host_key_decision': lambda details: details['context'] == 'target',
        'socks_proxy': route,
    }
    arguments.update(overrides)
    return ssh_manager.create_ssh_connection(**arguments)


@pytest.mark.parametrize('auth_type', ['none', 'password'])
def test_socks_remote_dns_terminal_and_session_sftp(
    monkeypatch, socks_proxy, isolated_socks_state, auth_type,
):
    original_lookup = socket.getaddrinfo

    def no_local_target_dns(host, *args, **kwargs):
        assert host != 'target', 'Allowlisted SOCKS target was resolved locally'
        return original_lookup(host, *args, **kwargs)

    monkeypatch.setattr(socket, 'getaddrinfo', no_local_target_dns)
    with socks_proxy(auth_type=auth_type) as (proxy, route):
        session_id, error = connect(route)
        assert error is None
        assert session_id
        info = ssh_manager.get_session(session_id)
        assert info['via_socks'] is True
        assert info['socks_proxy_id'] == route.proxy_id
        assert info['host'] == 'target'
        assert info['port'] == 22
        marker = 'SOCKS_TERMINAL_' + uuid.uuid4().hex
        remote_path = '/tmp/webssh-socks-' + uuid.uuid4().hex + '.txt'
        sftp = None
        try:
            assert marker.encode() in read_terminal_marker(session_id, marker)
            sftp, error = sftp_handler.get_sftp_client(session_id)
            assert error is None
            payload = b'SOCKS session SFTP upload\n'
            assert sftp_handler.upload_request_stream(
                session_id, remote_path, io.BytesIO(payload),
                chunk_size=7, max_bytes=1024,
            ) == len(payload)
            listing, error = sftp_handler.list_directory(session_id, '/tmp')
            assert error is None
            assert remote_path.rsplit('/', 1)[-1] in {item['name'] for item in listing}
            with sftp.file(remote_path, 'rb') as uploaded:
                assert uploaded.read() == payload
            assert proxy.requests == [(3, 'target', 22)]
            assert proxy.authenticated is (auth_type == 'password')
            keys = paramiko.HostKeys(str(isolated_socks_state.user_path))
            assert keys.lookup('target') is not None
            assert keys.lookup(f'[{proxy.host}]:{proxy.port}') is None
        finally:
            if sftp is not None:
                try:
                    sftp.remove(remote_path)
                except FileNotFoundError:
                    pass
            assert ssh_manager.close_session(session_id) is True
        assert proxy.disconnected.wait(3)


def test_socks_target_without_remote_dns_allowlist_is_blocked(monkeypatch, socks_proxy):
    monkeypatch.setattr(config, 'SOCKS_REMOTE_DNS_ALLOWLIST', ())
    # A jump-host grant must never implicitly grant a SOCKS route remote DNS.
    monkeypatch.setattr(config, 'PROXY_JUMP_REMOTE_DNS_ALLOWLIST', ('target',))
    original_lookup = socket.getaddrinfo
    resolved = []

    def private_target_dns(host, port, *args, **kwargs):
        if host == 'target':
            resolved.append(host)
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('10.29.0.2', port))]
        return original_lookup(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, 'getaddrinfo', private_target_dns)
    with socks_proxy() as (proxy, route):
        session_id, error = connect(route)
        assert session_id is None
        assert str(error) == 'Connections to this address are not allowed'
        assert resolved == ['target']
        assert proxy.requests == []
        assert not ssh_manager.sessions


def test_socks_loopback_proxy_remains_blocked_without_fixture_exception(socks_proxy):
    with socks_proxy(allow_proxy=False) as (proxy, route):
        session_id, error = connect(route)
        assert session_id is None
        assert 'not allowed' in str(error)
        assert proxy.requests == []


def test_socks_bad_proxy_password_never_connects_to_target(socks_proxy):
    with socks_proxy(auth_type='password') as (proxy, route):
        session_id, error = connect(replace(route, password='wrong-test-password'))
        assert session_id is None
        assert error.code == 'socks_auth_failed'
        assert proxy.requests == []
        assert proxy.disconnected.wait(3)
        assert not ssh_manager.sessions


def test_socks_target_host_key_rejection_closes_tunnel(socks_proxy, isolated_socks_state):
    details = []
    with socks_proxy() as (proxy, route):
        session_id, error = connect(
            route, host_key_decision=lambda challenge: details.append(challenge) or False,
        )
        assert session_id is None
        assert error.code == 'host_key_not_accepted'
        assert error.context == 'target'
        assert len(details) == 1
        assert details[0]['host'] == 'target'
        assert details[0]['context'] == 'target'
        assert not isolated_socks_state.user_path.exists()
        assert proxy.disconnected.wait(3)
        assert not ssh_manager.sessions


def test_socks_changed_target_host_key_is_rejected(socks_proxy):
    with socks_proxy() as (_proxy, route):
        session_id, error = connect(route)
        assert error is None
        assert ssh_manager.close_session(session_id) is True
    with socks_proxy(changed_host_key=True) as (proxy, route):
        session_id, error = connect(route)
        assert session_id is None
        assert error.code == 'host_key_changed'
        assert error.context == 'target'
        assert proxy.disconnected.wait(3)
        assert not ssh_manager.sessions


def test_socks_cancelled_after_target_trust_closes_tunnel(socks_proxy):
    cancelled = threading.Event()

    def accept_then_cancel(_challenge):
        cancelled.set()
        return True

    with socks_proxy() as (proxy, route):
        session_id, error = connect(
            route, host_key_decision=accept_then_cancel, cancel_event=cancelled,
        )
        assert cancelled.is_set()
        assert session_id is None
        assert str(error) == 'Connection cancelled'
        assert proxy.disconnected.wait(3)
        assert not ssh_manager.sessions
