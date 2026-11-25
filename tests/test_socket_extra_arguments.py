"""Socket.IO events with surplus positional arguments reach their handler."""

import pytest

from app import socket_events  # noqa: F401  (registers the event handlers)
from app.decorators import _positional_arguments


@pytest.fixture
def socket_client(app, monkeypatch):
    import config
    from app import socketio
    from app.auth import register_user
    from app.socket_protocol import SOCKET_WIRE_REVISION

    monkeypatch.setattr(config, 'RATELIMIT_ENABLED', False)
    user, error = register_user('extra_arguments', 'password123')
    assert error is None
    http = app.test_client()
    assert http.post('/login', data={
        'username': 'extra_arguments', 'password': 'password123',
    }).status_code == 302
    client = socketio.test_client(
        app, flask_test_client=http, auth={'wire_revision': SOCKET_WIRE_REVISION},
    )
    assert client.is_connected()
    client.get_received()
    yield client
    if client.is_connected():
        client.disconnect()


def _names(client):
    return [message['name'] for message in client.get_received()]


def test_handler_without_payload_ignores_a_null_argument(socket_client):
    # A wrapper such as (event, payload, ack) => emit(event, payload, ack)
    # sends undefined values, which arrive as None.
    socket_client.emit('get_notepad', None, None)

    assert _names(socket_client) == ['notepad_data']
    assert socket_client.is_connected()


def test_handler_with_payload_ignores_trailing_arguments(socket_client):
    socket_client.emit('save_notepad', {'text': 'kept'}, None, 'surplus')
    socket_client.get_received()
    socket_client.emit('get_notepad')

    received = [
        message for message in socket_client.get_received()
        if message['name'] == 'notepad_data'
    ]
    assert received[-1]['args'][0] == {'notepad': 'kept'}


def test_positional_limit_counts_only_event_arguments():
    def without_payload(current_user=None):
        return None

    def with_payload(data, current_user=None):
        return None

    def with_optional(data=None, current_user=None):
        return None

    def variadic(*args, current_user=None):
        return None

    assert _positional_arguments(without_payload)[1] == 0
    assert _positional_arguments(with_payload)[1] == 1
    assert _positional_arguments(with_optional)[1] == 1
    assert _positional_arguments(variadic)[1] is None


def _events_with_payload():
    import re
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / 'app/socket_events.py').read_text(encoding='utf-8')
    return sorted(set(re.findall(
        r"@socketio\.on\('([a-z0-9_]+)'\)\s*\n@socket_login_required\s*\ndef \w+\(data\b",
        source,
    )))


@pytest.mark.parametrize('event', _events_with_payload())
def test_event_without_payload_is_rejected_without_an_exception(socket_client, event):
    socket_client.emit(event)

    assert socket_client.is_connected()
