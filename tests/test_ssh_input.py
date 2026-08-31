from types import SimpleNamespace

import pytest


pytestmark = pytest.mark.usefixtures('direct_socket_authentication')


def _socket_user(app, username):
    from app.auth import register_socket_session, register_user
    from app.models import db

    with app.app_context():
        user, error = register_user(username, 'socket-password-123')
        assert error is None
        register_socket_session(user.id, f'{username}-socket')
        db.session.commit()
        return user.id, f'{username}-socket'


def _call_handler(app, monkeypatch, sid, payload):
    from flask import request
    import app.socket_events as socket_events

    emitted = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, data=None, **kwargs: emitted.append((event, data)),
    )
    with app.test_request_context('/socket.io'):
        request.sid = sid
        acknowledgement = socket_events.handle_ssh_input(payload)
    return acknowledgement, emitted


def test_ssh_input_budget_enforces_session_and_user_throughput():
    from app.ssh_input_budget import SSHInputBudget

    budget = SSHInputBudget(
        session_capacity=8,
        session_rate=4,
        user_capacity=10,
        user_rate=5,
    )

    assert budget.allow(1, 'a', 8, now=0) == (True, 0)
    assert budget.allow(1, 'a', 1, now=0) == (False, 250)
    assert budget.allow(1, 'b', 2, now=0) == (True, 0)
    assert budget.allow(1, 'b', 1, now=0) == (False, 200)
    assert budget.allow(1, 'a', 1, now=1) == (True, 0)
    assert budget.allow(2, 'a', 8, now=0) == (True, 0)


def test_ssh_input_rejects_utf8_bytes_before_ownership_or_channel_work(
    app,
    monkeypatch,
):
    import config
    import app.socket_events as socket_events

    user_id, sid = _socket_user(app, 'oversized_input')
    monkeypatch.setattr(config, 'SSH_INPUT_MAX_BYTES', 4)
    monkeypatch.setattr(
        socket_events,
        'verify_session_ownership',
        lambda *_args: pytest.fail('oversized input reached ownership lookup'),
    )
    monkeypatch.setattr(
        socket_events.ssh_manager,
        'send_ssh_input',
        lambda *_args, **_kwargs: pytest.fail('oversized input reached SSH'),
    )

    result, emitted = _call_handler(
        app,
        monkeypatch,
        sid,
        {'session_id': 'owned', 'data': 'ééé'},
    )

    assert user_id > 0
    assert result['success'] is False
    assert result['code'] == 'ssh_input_too_large'
    assert emitted == [('ssh_error', result)]


def test_ssh_input_rejects_oversized_ignored_event_fields_before_ownership(
    app,
    monkeypatch,
):
    import app.socket_events as socket_events

    _user_id, sid = _socket_user(app, 'padded_input')
    monkeypatch.setattr(
        socket_events,
        'verify_session_ownership',
        lambda *_args: pytest.fail('invalid envelope reached ownership lookup'),
    )

    result, emitted = _call_handler(
        app,
        monkeypatch,
        sid,
        {
            'session_id': 'owned',
            'data': 'x',
            'padding': 'y' * (1024 * 1024),
        },
    )

    assert result == {'success': False, 'error': 'Invalid SSH input'}
    assert emitted == []


def test_ssh_input_rejects_unbounded_session_identifier_before_ownership(
    app,
    monkeypatch,
):
    import app.socket_events as socket_events

    _user_id, sid = _socket_user(app, 'long_session_input')
    monkeypatch.setattr(
        socket_events,
        'verify_session_ownership',
        lambda *_args: pytest.fail('invalid session id reached ownership lookup'),
    )

    result, emitted = _call_handler(
        app,
        monkeypatch,
        sid,
        {'session_id': 's' * 129, 'data': 'x'},
    )

    assert result == {'success': False, 'error': 'Invalid SSH input'}
    assert emitted == []


def test_ssh_input_accepts_exact_multibyte_boundary_and_sends_completely(
    app,
    monkeypatch,
):
    import config
    import app.socket_events as socket_events

    _user_id, sid = _socket_user(app, 'bounded_input')
    monkeypatch.setattr(config, 'SSH_INPUT_MAX_BYTES', 4)
    monkeypatch.setattr(
        socket_events,
        '_ssh_input_budget',
        SimpleNamespace(allow=lambda *_args: (True, 0)),
    )
    monkeypatch.setattr(
        socket_events,
        'verify_session_ownership',
        lambda *_args: True,
    )
    calls = []
    monkeypatch.setattr(
        socket_events.ssh_manager,
        'send_ssh_input',
        lambda *args, **kwargs: calls.append((args, kwargs)) or (True, None),
    )

    result, emitted = _call_handler(
        app,
        monkeypatch,
        sid,
        {'session_id': 'owned', 'data': 'éé'},
    )

    assert result == {'success': True}
    assert emitted == []
    assert calls == [(('owned', 'éé'), {'require_complete': True})]


def test_ssh_input_returns_ack_only_backpressure_for_chunked_paste(
    app,
    monkeypatch,
):
    import app.socket_events as socket_events

    _user_id, sid = _socket_user(app, 'backpressured_input')
    monkeypatch.setattr(
        socket_events,
        '_ssh_input_budget',
        SimpleNamespace(allow=lambda *_args: (False, 125)),
    )
    monkeypatch.setattr(
        socket_events,
        'verify_session_ownership',
        lambda *_args: True,
    )

    result, emitted = _call_handler(
        app,
        monkeypatch,
        sid,
        {
            'session_id': 'owned',
            'data': 'paste',
            'acknowledge_backpressure': True,
        },
    )

    assert result['code'] == 'ssh_input_backpressure'
    assert result['retry_after_ms'] == 125
    assert emitted == []
