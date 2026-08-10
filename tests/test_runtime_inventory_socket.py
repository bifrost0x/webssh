from types import SimpleNamespace

import pytest

from app import socket_events


def invoke(monkeypatch, payload, *, owned=True, collector_result=None,
           collector_exception=None, rate_limited=False):
    emitted = []
    collector_calls = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, data: emitted.append((event, data)),
    )
    monkeypatch.setattr(
        socket_events,
        'verify_session_ownership',
        lambda session_id, user_id: owned,
    )
    monkeypatch.setattr(
        socket_events,
        'check_socket_rate_limit',
        lambda user_id, endpoint, limit: rate_limited,
    )

    def collect(session_id):
        collector_calls.append(session_id)
        if collector_exception is not None:
            raise collector_exception
        return collector_result or ({'systemd': {
            'total': 0,
            'active': 0,
            'failed': 0,
            'returned': 0,
            'truncated': False,
            'services': [],
        }}, None)

    monkeypatch.setattr(
        socket_events.runtime_inventory,
        'collect_runtime_inventory',
        collect,
    )
    socket_events.handle_request_session_runtime_inventory.__wrapped__(
        payload,
        current_user=SimpleNamespace(id=7, username='operator'),
    )
    return emitted, collector_calls


def test_runtime_inventory_socket_returns_owned_correlated_inventory(monkeypatch):
    inventory = {'systemd': {
        'total': 0,
        'active': 0,
        'failed': 0,
        'returned': 0,
        'truncated': False,
        'services': [],
    }}
    monkeypatch.setattr(socket_events.time, 'time', lambda: 1786350000)

    emitted, calls = invoke(
        monkeypatch,
        {'session_id': 'owned-session', 'request_id': 'inventory-1'},
        collector_result=(inventory, None),
    )

    assert calls == ['owned-session']
    assert emitted == [('session_runtime_inventory', {
        'success': True,
        'session_id': 'owned-session',
        'request_id': 'inventory-1',
        'sampled_at': 1786350000,
        'systemd': inventory['systemd'],
    })]


@pytest.mark.parametrize(
    'payload',
    [
        None,
        {},
        {'session_id': 123, 'request_id': 'inventory'},
        {'session_id': 'owned-session', 'request_id': None},
        {'session_id': 'x' * 129, 'request_id': 'inventory'},
        {'session_id': 'owned-session', 'request_id': 'x' * 129},
    ],
)
def test_runtime_inventory_socket_rejects_malformed_identifiers(monkeypatch, payload):
    emitted, calls = invoke(monkeypatch, payload)

    assert calls == []
    assert emitted == [('session_runtime_inventory', {
        'success': False,
        'session_id': '',
        'request_id': '',
        'error': 'Runtime inventory unavailable',
    })]


def test_runtime_inventory_socket_rate_limits_before_ownership(monkeypatch):
    emitted = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, data: emitted.append((event, data)),
    )
    monkeypatch.setattr(socket_events, 'check_socket_rate_limit', lambda *_args: True)
    monkeypatch.setattr(
        socket_events,
        'verify_session_ownership',
        lambda *_args: pytest.fail('ownership lookup must not follow rate limit'),
    )

    socket_events.handle_request_session_runtime_inventory.__wrapped__(
        {'session_id': 'owned-session', 'request_id': 'inventory-limited'},
        current_user=SimpleNamespace(id=7, username='operator'),
    )

    assert emitted == [('session_runtime_inventory', {
        'success': False,
        'session_id': 'owned-session',
        'request_id': 'inventory-limited',
        'error': 'Runtime inventory unavailable',
    })]


def test_runtime_inventory_socket_rejects_unowned_session_before_collection(
        monkeypatch):
    emitted, calls = invoke(
        monkeypatch,
        {'session_id': 'foreign-session', 'request_id': 'inventory-2'},
        owned=False,
    )

    assert calls == []
    assert emitted == [('session_runtime_inventory', {
        'success': False,
        'session_id': 'foreign-session',
        'request_id': 'inventory-2',
        'error': 'Runtime inventory unavailable',
    })]


@pytest.mark.parametrize(
    ('collector_result', 'collector_exception'),
    [
        ((None, 'remote output must not leak'), None),
        (None, RuntimeError('remote stderr must not leak')),
    ],
)
def test_runtime_inventory_socket_returns_only_generic_failures(
        monkeypatch, collector_result, collector_exception):
    emitted, calls = invoke(
        monkeypatch,
        {'session_id': 'owned-session', 'request_id': 'inventory-3'},
        collector_result=collector_result,
        collector_exception=collector_exception,
    )

    assert calls == ['owned-session']
    assert emitted == [('session_runtime_inventory', {
        'success': False,
        'session_id': 'owned-session',
        'request_id': 'inventory-3',
        'error': 'Runtime inventory unavailable',
    })]
