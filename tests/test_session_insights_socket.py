from types import SimpleNamespace

import pytest

from app import socket_events


def invoke(monkeypatch, payload, *, owned=True, collector_result=None):
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

    def collect(session_id):
        collector_calls.append(session_id)
        return collector_result or ({'cpu': [1, 2, 3, 4]}, None)

    monkeypatch.setattr(
        socket_events.session_insights,
        'collect_linux_stats',
        collect,
    )

    socket_events.handle_request_session_insights.__wrapped__(
        payload,
        current_user=SimpleNamespace(id=7, username='operator'),
    )
    return emitted, collector_calls


def test_session_insights_socket_returns_owned_sample_and_request_identity(
        monkeypatch):
    stats = {
        'cpu': [10, 0, 5, 85],
        'memory': {
            'total_kib': 1000,
            'available_kib': 400,
            'used_kib': 600,
        },
        'disk': {
            'total_kib': 2000,
            'used_kib': 500,
            'available_kib': 1500,
            'percent': 25,
        },
        'uptime_seconds': 3600,
        'os_name': 'Debian GNU/Linux 13',
    }
    emitted, calls = invoke(
        monkeypatch,
        {'session_id': 'owned-session', 'request_id': 'sample-1'},
        collector_result=(stats, None),
    )

    assert calls == ['owned-session']
    assert emitted == [('session_insights', {
        'success': True,
        'session_id': 'owned-session',
        'request_id': 'sample-1',
        'stats': stats,
    })]


def test_session_insights_socket_rejects_unowned_session_before_collection(
        monkeypatch):
    emitted, calls = invoke(
        monkeypatch,
        {'session_id': 'foreign-session', 'request_id': 'sample-2'},
        owned=False,
    )

    assert calls == []
    assert emitted == [('session_insights', {
        'success': False,
        'session_id': 'foreign-session',
        'request_id': 'sample-2',
        'error': 'Session insights unavailable',
    })]


@pytest.mark.parametrize(
    'payload',
    [
        None,
        {},
        {'session_id': 123, 'request_id': 'sample'},
        {'session_id': 'owned-session', 'request_id': None},
        {'session_id': 'x' * 129, 'request_id': 'sample'},
        {'session_id': 'owned-session', 'request_id': 'x' * 129},
    ],
)
def test_session_insights_socket_rejects_malformed_identifiers(
        monkeypatch, payload):
    emitted, calls = invoke(monkeypatch, payload)

    assert calls == []
    assert emitted == [('session_insights', {
        'success': False,
        'session_id': '',
        'request_id': '',
        'error': 'Session insights unavailable',
    })]


def test_session_insights_socket_returns_generic_collector_failure(monkeypatch):
    emitted, calls = invoke(
        monkeypatch,
        {'session_id': 'owned-session', 'request_id': 'sample-3'},
        collector_result=(None, 'unavailable'),
    )

    assert calls == ['owned-session']
    assert emitted == [('session_insights', {
        'success': False,
        'session_id': 'owned-session',
        'request_id': 'sample-3',
        'error': 'Session insights unavailable',
    })]

