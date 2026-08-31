import socket

import pytest

from app.network_policy import (
    ResolvedTarget,
    canonicalize_hostname,
    open_validated_socket,
    proxy_jump_remote_dns_allowed,
    resolve_allowed_target,
)


def addr(family, ip, port=22, socktype=socket.SOCK_STREAM):
    sockaddr = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
    return family, socktype, socket.IPPROTO_TCP, '', sockaddr


class RecordingSocket:
    def __init__(self, family, socktype):
        self.family = family
        self.socktype = socktype
        self.timeout = None
        self.connected_to = None
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, address):
        self.connected_to = address

    def close(self):
        self.closed = True


def test_resolution_selects_first_allowed_candidate_without_second_dns(
        monkeypatch):
    calls = []

    def fake_getaddrinfo(host, port, **kwargs):
        calls.append((host, port, kwargs))
        return [
            addr(socket.AF_INET, '10.0.0.4', port),
            addr(socket.AF_INET6, '2606:4700:4700::1111', port),
            addr(socket.AF_INET, '1.1.1.1', port),
        ]

    created = []

    def fake_socket(family, socktype):
        result = RecordingSocket(family, socktype)
        created.append(result)
        return result

    monkeypatch.setattr(socket, 'getaddrinfo', fake_getaddrinfo)
    monkeypatch.setattr(socket, 'socket', fake_socket)

    target = resolve_allowed_target('Example.COM.', 2222)
    connected = open_validated_socket(target, timeout=4.5)

    assert target == ResolvedTarget(
        hostname='example.com',
        port=2222,
        ip='2606:4700:4700::1111',
        family=socket.AF_INET6,
    )
    assert len(calls) == 1
    assert calls[0][:2] == ('example.com', 2222)
    assert calls[0][2] == {
        'family': socket.AF_UNSPEC,
        'type': socket.SOCK_STREAM,
    }
    assert connected is created[0]
    assert connected.family == socket.AF_INET6
    assert connected.timeout == 4.5
    assert connected.connected_to == ('2606:4700:4700::1111', 2222, 0, 0)


@pytest.mark.parametrize(
    'ip',
    [
        '127.0.0.1',
        '10.0.0.1',
        '169.254.169.254',
        '224.0.0.1',
        '0.0.0.0',
        '240.0.0.1',
        '100.64.0.1',
        '::1',
        'fc00::1',
        'fec0::1',
        'fe80::1',
        'ff02::1',
        '::',
    ],
)
def test_resolution_rejects_every_non_public_address(monkeypatch, ip):
    family = socket.AF_INET6 if ':' in ip else socket.AF_INET
    monkeypatch.setattr(
        socket,
        'getaddrinfo',
        lambda *args, **kwargs: [addr(family, ip)],
    )

    with pytest.raises(ValueError, match='not allowed'):
        resolve_allowed_target('blocked.example', 22)


def test_resolution_rejects_when_no_address_is_usable(monkeypatch):
    monkeypatch.setattr(
        socket,
        'getaddrinfo',
        lambda *args, **kwargs: [
            addr(socket.AF_INET, '10.0.0.1'),
            addr(socket.AF_INET6, '::1'),
            addr(socket.AF_INET, '1.1.1.1', socktype=socket.SOCK_DGRAM),
        ],
    )

    with pytest.raises(ValueError, match='not allowed'):
        resolve_allowed_target('mixed.example', 22)


def test_allow_internal_selects_private_candidate(monkeypatch):
    monkeypatch.setattr(
        socket,
        'getaddrinfo',
        lambda *args, **kwargs: [addr(socket.AF_INET, '10.0.0.8')],
    )

    assert resolve_allowed_target(
        'internal.example', 22, allow_internal=True
    ).ip == '10.0.0.8'


@pytest.mark.parametrize(
    ('raw', 'canonical', 'ip', 'family'),
    [
        ('8.8.8.8', '8.8.8.8', '8.8.8.8', socket.AF_INET),
        (
            '[2606:4700:4700::1111]',
            '2606:4700:4700::1111',
            '2606:4700:4700::1111',
            socket.AF_INET6,
        ),
    ],
)
def test_literal_addresses_are_normalized_and_never_resolved(
        monkeypatch, raw, canonical, ip, family):
    monkeypatch.setattr(
        socket,
        'getaddrinfo',
        lambda *args, **kwargs: pytest.fail('literal triggered DNS'),
    )

    assert resolve_allowed_target(raw, 22) == ResolvedTarget(
        hostname=canonical,
        port=22,
        ip=ip,
        family=family,
    )


def test_resolution_errors_are_safe_and_deterministic(monkeypatch):
    monkeypatch.setattr(
        socket,
        'getaddrinfo',
        lambda *args, **kwargs: (_ for _ in ()).throw(
            socket.gaierror('resolver details')
        ),
    )

    with pytest.raises(ValueError, match='could not be resolved') as error:
        resolve_allowed_target('missing.example', 22)

    assert 'resolver details' not in str(error.value)


def test_open_socket_closes_it_when_connect_fails(monkeypatch):
    class FailingSocket(RecordingSocket):
        def connect(self, address):
            raise TimeoutError('no route')

    created = []

    def fake_socket(family, socktype):
        result = FailingSocket(family, socktype)
        created.append(result)
        return result

    monkeypatch.setattr(socket, 'socket', fake_socket)
    target = ResolvedTarget('example.com', 22, '1.1.1.1', socket.AF_INET)

    with pytest.raises(TimeoutError):
        open_validated_socket(target, timeout=3)

    assert created[0].closed is True


def test_ipv6_preserves_exact_resolver_sockaddr(monkeypatch):
    resolver_sockaddr = (
        '2606:4700:4700::1111',
        2222,
        37,
        9,
    )
    monkeypatch.setattr(
        socket,
        'getaddrinfo',
        lambda *args, **kwargs: [(
            socket.AF_INET6,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            '',
            resolver_sockaddr,
        )],
    )
    created = []

    def fake_socket(family, socktype):
        result = RecordingSocket(family, socktype)
        created.append(result)
        return result

    monkeypatch.setattr(socket, 'socket', fake_socket)

    target = resolve_allowed_target('example.com', 2222)
    open_validated_socket(target, 5)

    assert target.sockaddr == resolver_sockaddr
    assert created[0].connected_to is resolver_sockaddr


def test_duplicate_full_sockaddr_is_evaluated_only_once(monkeypatch):
    candidate = addr(socket.AF_INET, '10.0.0.1', 22)
    monkeypatch.setattr(
        socket,
        'getaddrinfo',
        lambda *args, **kwargs: [
            candidate,
            candidate,
            addr(socket.AF_INET, '8.8.8.8', 22),
        ],
    )
    checked = []
    import app.network_policy as policy
    original_policy = policy._ip_is_internal

    def record_policy(address):
        checked.append(address.compressed)
        return original_policy(address)

    monkeypatch.setattr(policy, '_ip_is_internal', record_policy)

    target = resolve_allowed_target('example.com', 22)

    assert target.ip == '8.8.8.8'
    assert checked == ['10.0.0.1', '8.8.8.8']


@pytest.mark.parametrize(
    ('raw', 'expected'),
    [
        ('BÜCHER.Example.', 'xn--bcher-kva.example'),
        ('example.com', 'example.com'),
        ('[2606:4700:4700::1111]', '2606:4700:4700::1111'),
    ],
)
def test_hostname_canonicalization(raw, expected):
    assert canonicalize_hostname(raw) == expected


def test_proxy_jump_remote_dns_allowlist_is_exact_idna_and_hostname_only():
    allowlist = (
        'TARGET',
        'bücher.example.',
        '*.example.com',
        '10.0.0.8',
        '',
    )

    assert proxy_jump_remote_dns_allowed('target', allowlist)
    assert proxy_jump_remote_dns_allowed('BÜCHER.EXAMPLE', allowlist)
    assert not proxy_jump_remote_dns_allowed('sub.example.com', allowlist)
    assert not proxy_jump_remote_dns_allowed('other-target', allowlist)
    assert not proxy_jump_remote_dns_allowed('10.0.0.8', allowlist)
    assert not proxy_jump_remote_dns_allowed('bad host name', allowlist)
