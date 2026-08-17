from types import SimpleNamespace

import pytest

from app import socket_events


def invoke(monkeypatch, payload, *, owned=True, collector_result=None,
           rate_limited=False):
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

    def collect(session_id, *, include_diagnostics=False):
        collector_calls.append((session_id, include_diagnostics))
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

    assert calls == [('owned-session', False)]
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


def test_session_insights_socket_rate_limits_before_ownership_and_collection(
        monkeypatch):
    emitted, calls = invoke(
        monkeypatch,
        {'session_id': 'owned-session', 'request_id': 'sample-limited'},
        rate_limited=True,
    )

    assert calls == []
    assert emitted == [('session_insights', {
        'success': False,
        'session_id': 'owned-session',
        'request_id': 'sample-limited',
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
        collector_result=(None, 'unsupported'),
    )

    assert calls == [('owned-session', False)]
    assert emitted == [('session_insights', {
        'success': False,
        'session_id': 'owned-session',
        'request_id': 'sample-3',
        'error': 'Session insights unavailable',
        'reason': 'unsupported',
    })]


@pytest.mark.parametrize(
    ('requested_value', 'expected'),
    [
        (True, True),
        (False, False),
        ('true', False),
        (1, False),
        (None, False),
    ],
)
def test_session_insights_socket_only_accepts_literal_diagnostics_flag(
        monkeypatch, requested_value, expected):
    emitted, calls = invoke(
        monkeypatch,
        {
            'session_id': 'owned-session',
            'request_id': 'sample-diagnostics',
            'include_diagnostics': requested_value,
        },
    )

    assert calls == [('owned-session', expected)]
    assert emitted[0][1]['success'] is True
