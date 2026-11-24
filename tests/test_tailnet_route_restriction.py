"""Ordinary SSH must not reach tailnet-routed addresses while Tailscale SSH is on."""
import ipaddress
import socket
from types import SimpleNamespace

import pytest

import config
from app import network_policy, tailscale_ssh
from app.network_policy import TailnetRouteRestricted, resolve_allowed_target
from tests.test_automation_service import context  # noqa: F401  (fixture)

TAILNET = ipaddress.ip_network('100.64.0.0/10')


class LookupLog(list):
    def __init__(self):
        super().__init__()
        self.off_tailnet = set()


@pytest.fixture
def tailnet(monkeypatch):
    """Enable Tailscale SSH on a node whose default route leaves through tailscale0.

    That models an exit node plus subnet routes: every address uses the tailnet
    interface unless a test lists it in ``lookups.off_tailnet``.
    """
    lookups = LookupLog()

    def uses_route(address):
        lookups.append(address)
        return address not in lookups.off_tailnet

    monkeypatch.setattr(config, 'TAILSCALE_SSH_ENABLED', True)
    monkeypatch.setattr(config, 'TAILSCALE_SSH_RESTRICT_TAILNET_ROUTES', True)
    monkeypatch.setattr(config, 'TAILSCALE_SSH_INTERFACE', 'tailscale0')
    monkeypatch.setattr(config, 'BLOCK_INTERNAL_SSH', False)
    monkeypatch.setattr(config, 'SSH_ALLOWED_INTERNAL_NETWORKS', ())
    monkeypatch.setattr(tailscale_ssh, 'target_uses_tailscale_route', uses_route)
    return lookups


def _addresses(*ips):
    return lambda *_args, **_kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', (ip, 22))
        for ip in ips
    ]


def test_ordinary_resolution_rejects_tailnet_route(tailnet):
    with pytest.raises(TailnetRouteRestricted) as raised:
        resolve_allowed_target('100.64.0.10', 22, allow_internal=True)
    assert raised.value.code == 'tailscale_route_restricted'
    assert isinstance(raised.value, ValueError)
    assert 'resolved' not in str(raised.value)
    assert tailnet == ['100.64.0.10']


def test_internal_allowlist_does_not_readmit_tailnet_route(tailnet, monkeypatch):
    monkeypatch.setattr(config, 'BLOCK_INTERNAL_SSH', True)
    with pytest.raises(TailnetRouteRestricted):
        resolve_allowed_target(
            '100.64.0.10', 22,
            allowed_internal_networks=(ipaddress.ip_network('100.64.0.0/10'),),
        )


def test_tailnet_node_ipv6_address_is_restricted(tailnet):
    with pytest.raises(TailnetRouteRestricted):
        resolve_allowed_target('fd7a:115c:a1e0::10', 22, allow_internal=True)


def test_ipv4_mapped_tailnet_node_address_is_restricted(tailnet):
    with pytest.raises(TailnetRouteRestricted):
        resolve_allowed_target('::ffff:100.64.0.10', 22, allow_internal=True)


@pytest.mark.parametrize('address', [
    '192.168.1.5',          # subnet route through tailscale0
    '203.0.113.7',          # exit node route through tailscale0
    '2001:db8::7',          # exit node route, IPv6
    'fd7a:115c:a1e1::7',    # just outside the Tailscale ULA prefix
    '100.128.0.1',          # just outside 100.64.0.0/10
])
def test_subnet_route_and_exit_node_destinations_are_unaffected(tailnet, address):
    assert resolve_allowed_target(address, 22, allow_internal=True).ip == address
    # Only tailnet node addresses trigger a route lookup.
    assert tailnet == []


def test_cgnat_address_off_the_tailnet_stays_allowed(tailnet):
    tailnet.off_tailnet.add('100.64.0.10')
    assert resolve_allowed_target('100.64.0.10', 22, allow_internal=True).ip == '100.64.0.10'
    assert tailnet == ['100.64.0.10']


def test_hostname_skips_tailnet_candidate_for_another_allowed_address(tailnet, monkeypatch):
    monkeypatch.setattr(socket, 'getaddrinfo', _addresses('100.64.0.10', '192.168.1.5'))
    assert resolve_allowed_target('nas.example', 22, allow_internal=True).ip == '192.168.1.5'

    monkeypatch.setattr(socket, 'getaddrinfo', _addresses('100.64.0.10'))
    with pytest.raises(TailnetRouteRestricted):
        resolve_allowed_target('nas.example', 22, allow_internal=True)


def test_policy_block_keeps_its_own_error(tailnet, monkeypatch):
    monkeypatch.setattr(socket, 'getaddrinfo', _addresses('127.0.0.1'))
    with pytest.raises(ValueError) as raised:
        resolve_allowed_target('loop.example', 22)
    assert not isinstance(raised.value, TailnetRouteRestricted)


def test_operator_opt_out_allows_tailnet_route(tailnet, monkeypatch):
    monkeypatch.setattr(config, 'TAILSCALE_SSH_RESTRICT_TAILNET_ROUTES', False)
    assert resolve_allowed_target('100.64.0.10', 22, allow_internal=True).ip == '100.64.0.10'
    assert tailnet == []


@pytest.mark.parametrize('change', [
    {'TAILSCALE_SSH_ENABLED': False},
    {'TAILSCALE_SSH_INTERFACE': ''},
])
def test_disabled_or_unconfigured_tailscale_skips_route_lookup(tailnet, monkeypatch, change):
    for name, value in change.items():
        monkeypatch.setattr(config, name, value)
    assert resolve_allowed_target('100.64.0.10', 22, allow_internal=True).ip == '100.64.0.10'
    assert tailnet == []


def test_missing_interface_route_is_unaffected(monkeypatch):
    """Without a route through the interface, behavior matches the disabled state."""
    monkeypatch.setattr(config, 'TAILSCALE_SSH_ENABLED', True)
    monkeypatch.setattr(config, 'TAILSCALE_SSH_RESTRICT_TAILNET_ROUTES', True)
    monkeypatch.setattr(config, 'TAILSCALE_SSH_INTERFACE', 'tailscale0')
    monkeypatch.setattr(tailscale_ssh, '_route_interface_for_ip', lambda _address: None)
    assert resolve_allowed_target('100.64.0.10', 22, allow_internal=True).ip == '100.64.0.10'


def test_tailscale_strategy_keeps_its_route(tailnet, monkeypatch):
    monkeypatch.setattr(config, 'TAILSCALE_SSH_ALLOWED_TARGETS', frozenset({'100.64.0.10'}))
    monkeypatch.setattr(config, 'TAILSCALE_SSH_ALLOWED_WEBSSH_USERS', frozenset())
    monkeypatch.setattr(config, 'TAILSCALE_SSH_ALLOWED_REMOTE_USERS', frozenset())
    admin = SimpleNamespace(id=1, username='admin', is_admin=True)
    authorization, error = tailscale_ssh.authorize_tailscale_ssh_access(admin, '100.64.0.10', 'root')
    assert error is None
    assert authorization.resolved_target.ip == '100.64.0.10'


def test_unauthorized_user_cannot_use_tailscale_strategy_instead(tailnet, monkeypatch):
    monkeypatch.setattr(config, 'TAILSCALE_SSH_ALLOWED_TARGETS', frozenset({'100.64.0.10'}))
    monkeypatch.setattr(config, 'TAILSCALE_SSH_ALLOWED_WEBSSH_USERS', frozenset())
    user = SimpleNamespace(id=2, username='mallory', is_admin=False)
    authorization, error = tailscale_ssh.authorize_tailscale_ssh_access(user, '100.64.0.10', 'root')
    assert authorization is None and error


def test_socks_destination_cannot_fall_back_after_restriction(tailnet):
    with pytest.raises(TailnetRouteRestricted):
        network_policy.socks_destination(
            '100.64.0.10', 22, True, allow_internal=False,
            allowed_internal_networks=(TAILNET,),
        )


# Interactive terminal connections -------------------------------------------

def _ssh_clients(monkeypatch):
    from app import ssh_manager
    from tests.test_ssh_manager import install_ssh_clients
    clients = install_ssh_clients(monkeypatch)
    monkeypatch.setattr(ssh_manager, 'resolve_allowed_target', resolve_allowed_target)
    return clients


def _assert_restricted(error, context):
    assert error.code == 'tailscale_route_restricted'
    assert error.context == context


def test_password_connection_to_tailnet_target_opens_no_socket(tailnet, monkeypatch):
    from tests.test_ssh_manager import connect_target
    clients = _ssh_clients(monkeypatch)
    session_id, error = connect_target(host='100.64.0.10', password='dummy')
    assert session_id is None
    _assert_restricted(error, 'target')
    assert clients.opened_sockets == [] and clients == []


def test_password_connection_allowed_with_opt_out(tailnet, monkeypatch):
    from tests.test_ssh_manager import connect_target
    monkeypatch.setattr(config, 'TAILSCALE_SSH_RESTRICT_TAILNET_ROUTES', False)
    clients = _ssh_clients(monkeypatch)
    session_id, error = connect_target(host='100.64.0.10', password='dummy')
    assert error is None and session_id
    assert clients[0].connect_kwargs['hostname'] == '100.64.0.10'


def test_password_connection_unchanged_when_tailscale_disabled(tailnet, monkeypatch):
    from tests.test_ssh_manager import connect_target
    monkeypatch.setattr(config, 'TAILSCALE_SSH_ENABLED', False)
    clients = _ssh_clients(monkeypatch)
    session_id, error = connect_target(host='100.64.0.10', password='dummy')
    assert error is None and session_id
    assert len(clients.opened_sockets) == 1
    assert tailnet == []


def test_tailnet_jump_host_is_rejected(tailnet, monkeypatch):
    from tests.test_ssh_manager import connect_target
    clients = _ssh_clients(monkeypatch)
    session_id, error = connect_target(
        host='192.168.1.5', password='dummy',
        proxy_jump_host='100.64.0.20', proxy_jump_username='ops', proxy_jump_password='dummy',
    )
    assert session_id is None
    _assert_restricted(error, 'jump_host')
    assert clients.opened_sockets == []


@pytest.mark.parametrize('block_internal', [False, True])
def test_tailnet_target_behind_jump_is_not_passed_to_bastion_dns(tailnet, monkeypatch, block_internal):
    from tests.test_ssh_manager import connect_target
    # Both ways a tailnet address can pass the network policy: internal SSH
    # open, or the tailnet range on the internal allowlist.
    monkeypatch.setattr(config, 'BLOCK_INTERNAL_SSH', block_internal)
    monkeypatch.setattr(config, 'SSH_ALLOWED_INTERNAL_NETWORKS', (TAILNET,) if block_internal else ())
    monkeypatch.setattr(config, 'PROXY_JUMP_REMOTE_DNS_ALLOWLIST', ('tailnode.example',))
    monkeypatch.setattr(socket, 'getaddrinfo', _addresses('100.64.0.10'))
    clients = _ssh_clients(monkeypatch)
    session_id, error = connect_target(
        host='tailnode.example', password='dummy',
        proxy_jump_host='203.0.113.7', proxy_jump_username='ops', proxy_jump_password='dummy',
    )
    assert session_id is None
    _assert_restricted(error, 'target')
    assert clients.opened_sockets == []


def test_tailnet_socks_proxy_and_destination_are_rejected(tailnet, monkeypatch):
    from tests.test_ssh_manager import connect_target, socks_route
    clients = _ssh_clients(monkeypatch)
    session_id, error = connect_target(
        host='192.168.1.5', password='dummy', socks_proxy=socks_route(host='100.64.0.30'),
    )
    assert session_id is None
    _assert_restricted(error, 'socks_proxy')

    session_id, error = connect_target(
        host='100.64.0.10', password='dummy', socks_proxy=socks_route(host='192.168.1.9'),
    )
    assert session_id is None
    _assert_restricted(error, 'target')
    assert clients.opened_sockets == []


# File transfer pool ----------------------------------------------------------

def test_file_transfer_pool_rejects_tailnet_target(tailnet, monkeypatch):
    from app import connection_pool
    from tests.test_connection_pool import create_connection, install_ssh_client, make_pool
    pool = make_pool()
    clients = install_ssh_client(monkeypatch)
    monkeypatch.setattr(connection_pool, 'resolve_allowed_target', resolve_allowed_target)
    connection_id, error = create_connection(pool, host='100.64.0.10', password='dummy')
    assert connection_id is None
    _assert_restricted(error, 'target')
    assert clients == [] and clients.append_sockets == []


# Automation ------------------------------------------------------------------

def _forbid_sockets(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail('a socket was opened for a restricted tailnet route')
    monkeypatch.setattr('app.automation_transport.open_validated_socket', forbidden)


def test_automation_direct_target_is_rejected_with_its_own_reason(tailnet, monkeypatch):
    from app.automation_transport import connect_profile, connection_reason, CONNECTION_REASONS
    _forbid_sockets(monkeypatch)
    profile = dict(host='100.64.0.10', port=22, username='u', auth_type='password')
    with pytest.raises(TailnetRouteRestricted) as raised:
        with connect_profile(1, profile, 'dummy', lambda: False):
            pytest.fail('restricted destination connected')
    assert connection_reason(raised.value) == 'tailscale_route_restricted'
    assert 'tailscale_route_restricted' in CONNECTION_REASONS


@pytest.mark.parametrize('block_internal', [False, True])
def test_automation_target_behind_jump_is_rejected(tailnet, monkeypatch, block_internal):
    from app.automation_transport import connect_profile
    # Both ways a tailnet address can pass the network policy: internal SSH
    # open, or the tailnet range on the internal allowlist.
    monkeypatch.setattr(config, 'BLOCK_INTERNAL_SSH', block_internal)
    monkeypatch.setattr(config, 'SSH_ALLOWED_INTERNAL_NETWORKS', (TAILNET,) if block_internal else ())
    monkeypatch.setattr(config, 'PROXY_JUMP_REMOTE_DNS_ALLOWLIST', ('tailnode.example',))
    monkeypatch.setattr(socket, 'getaddrinfo', _addresses('100.64.0.10'))
    _forbid_sockets(monkeypatch)
    profile = dict(host='tailnode.example', port=22, username='u', auth_type='password')
    route = dict(host='203.0.113.7', port=22, username='ops', auth_type='password')
    with pytest.raises(TailnetRouteRestricted):
        with connect_profile(1, profile, 'dummy', lambda: False, route=route, route_password='dummy'):
            pytest.fail('restricted destination connected')


def test_automation_tailnet_jump_host_is_rejected(tailnet, monkeypatch):
    from app.automation_transport import connect_profile
    _forbid_sockets(monkeypatch)
    profile = dict(host='192.168.1.5', port=22, username='u', auth_type='password')
    route = dict(host='100.64.0.20', port=22, username='ops', auth_type='password')
    with pytest.raises(TailnetRouteRestricted):
        with connect_profile(1, profile, 'dummy', lambda: False, route=route, route_password='dummy'):
            pytest.fail('restricted jump host connected')


# Discovery and overview probes -------------------------------------------------

def _forbid_probe_sockets(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail('a probe socket was opened for a restricted tailnet route')
    monkeypatch.setattr(network_policy, 'open_validated_socket', forbidden)


def test_discovery_probe_reports_tailnet_route_as_blocked(tailnet, monkeypatch):
    from app import discovery_routes
    _forbid_probe_sockets(monkeypatch)
    assert discovery_routes._probe('100.64.0.10', 22) == {'state': 'blocked'}


def test_overview_probe_reports_tailnet_route_as_blocked(tailnet, monkeypatch):
    from app import overview_routes
    _forbid_probe_sockets(monkeypatch)
    assert overview_routes._probe('100.64.0.10', 22) == {'state': 'blocked'}


def test_overview_probe_keeps_tailscale_profiles_checkable(tailnet, monkeypatch):
    from app import overview_routes

    class Connection:
        def settimeout(self, _value):
            pass

        def recv(self, _size):
            return b''

        def close(self):
            pass

    opened = []
    monkeypatch.setattr(
        network_policy, 'open_validated_socket',
        lambda target, _timeout: opened.append(target.ip) or Connection(),
    )
    result = overview_routes._probe('100.64.0.10', 22, True)
    assert result['state'] == 'reachable'
    assert opened == ['100.64.0.10']


@pytest.mark.parametrize('authorized', [True, False])
def test_overview_marks_only_authorized_tailscale_profiles(app, client, context, monkeypatch, authorized):
    from app import overview_routes
    from app.profile_manager import add_profile
    uid = context[0]
    with app.app_context():
        profile, error = add_profile(uid, 'Tail', '100.64.0.10', 22, 'root', 'tailscale')
    assert error is None
    monkeypatch.setattr(tailscale_ssh, 'profile_is_authorized_for_launch',
                        lambda _user, _profile: authorized)
    calls = []

    def probe(host, port, *flags):
        calls.append((host, port, *flags))
        return {'state': 'reachable', 'latency_ms': 1}

    overview_routes._CACHE.clear()
    monkeypatch.setattr(overview_routes, '_probe', probe)
    response = client.post('/api/overview/reachability', json={'ids': [profile['id']]})
    overview_routes._CACHE.clear()
    assert response.status_code == 200
    assert calls == [('100.64.0.10', 22, True) if authorized else ('100.64.0.10', 22)]
