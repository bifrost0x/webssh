import socket

import pytest

from app.smb_network_policy import (
    parse_smb_allowed_targets,
    resolve_allowed_smb_target,
)


@pytest.mark.parametrize(
    'entry',
    ['*', 'smb://nas/share', 'nas:1445', 'user@nas', 'nas/share', r'nas\share'],
)
def test_allowlist_rejects_non_host_entries(entry):
    with pytest.raises(ValueError):
        parse_smb_allowed_targets(entry)


def test_allowlist_is_exact_canonical_and_deduplicated():
    assert parse_smb_allowed_targets('NAS.Example., 10.0.0.8, nas.example') == (
        'nas.example',
        '10.0.0.8',
    )


def test_target_must_be_exactly_allowlisted(monkeypatch):
    monkeypatch.setattr(
        socket,
        'getaddrinfo',
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.8', 445)),
        ],
    )

    with pytest.raises(ValueError, match='not allowed'):
        resolve_allowed_smb_target('other.example', ('nas.example',))


def test_allowlisted_private_dns_target_returns_validated_ip(monkeypatch):
    monkeypatch.setattr(
        socket,
        'getaddrinfo',
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.8', 445)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('fd00::8', 445, 0, 0)),
        ],
    )

    target = resolve_allowed_smb_target('NAS.Example.', ('nas.example',))

    assert target.hostname == 'nas.example'
    assert target.ip == '10.0.0.8'
    assert target.port == 445
    assert target.sockaddr == ('10.0.0.8', 445)


@pytest.mark.parametrize(
    'blocked',
    [
        '127.0.0.1',
        '169.254.1.2',
        '224.0.0.1',
        '0.0.0.0',
        '192.0.2.1',
        '::1',
        'fe80::1',
        'ff02::1',
        '::',
        '2001:db8::1',
    ],
)
def test_dangerous_literal_classes_are_rejected_even_when_allowlisted(blocked):
    with pytest.raises(ValueError, match='not allowed'):
        resolve_allowed_smb_target(blocked, (blocked,))


def test_one_forbidden_dns_answer_rejects_entire_hostname(monkeypatch):
    monkeypatch.setattr(
        socket,
        'getaddrinfo',
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.8', 445)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 445)),
        ],
    )

    with pytest.raises(ValueError, match='not allowed'):
        resolve_allowed_smb_target('nas.example', ('nas.example',))


def test_literal_private_and_ula_addresses_require_exact_allowlist():
    assert resolve_allowed_smb_target('10.0.0.8', ('10.0.0.8',)).ip == '10.0.0.8'
    assert resolve_allowed_smb_target('fd00::8', ('fd00::8',)).ip == 'fd00::8'
    with pytest.raises(ValueError, match='not allowed'):
        resolve_allowed_smb_target('10.0.0.8', ('10.0.0.9',))
