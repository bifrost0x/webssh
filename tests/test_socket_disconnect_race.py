"""Real namespace teardown must survive an Engine.IO environment race."""
import importlib
import json

import pytest

from tests.test_threaded_runtime import (
    ENGINEIO_BASE_URL, _close_engineio_socket, _engineio_handshake,
    _engineio_sid, _logged_in_http_client,
)


@pytest.mark.parametrize('lose_environment', [False, True])
def test_server_disconnect_cleans_exact_namespace_when_client_environment_disappears(app, monkeypatch, lose_environment):
    from app import socket_events, socketio
    from app.models import SocketSession
    from app.socket_capacity import socket_capacity
    from app.socket_protocol import SOCKET_WIRE_REVISION

    importlib.reload(socket_events)
    client, user_id = _logged_in_http_client(app, 'disconnect_race_owner')
    unrelated_client, unrelated_id = _logged_in_http_client(app, 'disconnect_race_other')
    transports = []

    def connect(http_client, label):
        engineio_sid = _engineio_sid(_engineio_handshake(http_client, label))
        transports.append(engineio_sid)
        response = http_client.post(
            f'/socket.io/?EIO=4&transport=polling&sid={engineio_sid}',
            base_url=ENGINEIO_BASE_URL,
            headers={'Content-Type': 'text/plain;charset=UTF-8', 'Origin': ENGINEIO_BASE_URL},
            data='40' + json.dumps({'wire_revision': SOCKET_WIRE_REVISION}),
        )
        assert response.status_code == 200
        return engineio_sid, socketio.server.manager.sid_from_eio_sid(engineio_sid, '/')

    try:
        target_eio, target_sid = connect(client, 'disconnect-race-target')
        _, sibling_sid = connect(client, 'disconnect-race-sibling')
        _, unrelated_sid = connect(unrelated_client, 'disconnect-race-unrelated')
        original_send = socketio.server._send_packet
        original_cancel = socket_events.transfer_manager.cancel_all_for_socket
        cancelled = []

        def cancel_socket(user_id, socket_sid):
            cancelled.append((user_id, socket_sid))
            return original_cancel(user_id, socket_sid)

        monkeypatch.setattr(socket_events.transfer_manager, 'cancel_all_for_socket', cancel_socket)
        observed = []

        def send_then_lose_environment(engineio_sid, packet):
            original_send(engineio_sid, packet)
            if lose_environment and engineio_sid == target_eio and packet.packet_type == 1:
                # python-socketio sends DISCONNECT before invoking Flask's
                # callback. A fast transport close can remove this environment.
                observed.append(socketio.server.environ.pop(target_eio, None))

        monkeypatch.setattr(socketio.server, '_send_packet', send_then_lose_environment)
        with app.app_context():
            assert socket_events.disconnect_socket_transport(socketio.server, target_sid) is True
        assert bool(observed) is lose_environment
        if observed:
            assert observed[0] is not None
        assert cancelled == [(user_id, target_sid)]
        with app.app_context():
            socket_events.disconnect_socket_transport(socketio.server, target_sid)
        assert cancelled == [(user_id, target_sid)]
        assert socket_capacity.owner(target_sid) is None
        assert socket_capacity.owner(sibling_sid) == user_id
        assert socket_capacity.owner(unrelated_sid) == unrelated_id
        with app.app_context():
            assert SocketSession.query.filter_by(socket_sid=target_sid).first() is None
            assert SocketSession.query.filter_by(socket_sid=sibling_sid).first() is not None
            assert SocketSession.query.filter_by(socket_sid=unrelated_sid).first() is not None
    finally:
        for engineio_sid in transports:
            if engineio_sid in socketio.server.eio.sockets:
                _close_engineio_socket(engineio_sid)


@pytest.mark.parametrize('disconnect_raises', [False, True])
def test_failed_server_disconnect_does_not_release_a_still_connected_namespace(app, monkeypatch, disconnect_raises):
    from app import socket_events, socketio
    from app.models import SocketSession
    from app.socket_capacity import socket_capacity
    from app.socket_protocol import SOCKET_WIRE_REVISION

    importlib.reload(socket_events)
    client, user_id = _logged_in_http_client(app, 'disconnect_failed_owner')
    engineio_sid = _engineio_sid(_engineio_handshake(client, 'disconnect-failed'))
    response = client.post(
        f'/socket.io/?EIO=4&transport=polling&sid={engineio_sid}',
        base_url=ENGINEIO_BASE_URL,
        headers={'Content-Type': 'text/plain;charset=UTF-8', 'Origin': ENGINEIO_BASE_URL},
        data='40' + json.dumps({'wire_revision': SOCKET_WIRE_REVISION}),
    )
    assert response.status_code == 200
    namespace_sid = socketio.server.manager.sid_from_eio_sid(engineio_sid, '/')
    original_disconnect = socketio.server.disconnect
    scheduled = []

    def fail_disconnect(*_args, **_kwargs):
        if disconnect_raises:
            raise RuntimeError('disconnect send failed')

    try:
        monkeypatch.setattr(socketio.server, 'disconnect', fail_disconnect)
        monkeypatch.setattr(socket_events, '_schedule_engineio_cleanup',
                            lambda context, **_kwargs: scheduled.append(context))
        with app.app_context():
            if disconnect_raises:
                with pytest.raises(RuntimeError, match='disconnect send failed'):
                    socket_events.disconnect_socket_transport(socketio.server, namespace_sid)
            else:
                socket_events.disconnect_socket_transport(socketio.server, namespace_sid)
        assert socketio.server.manager.is_connected(namespace_sid, '/') is True
        assert socket_capacity.owner(namespace_sid) == user_id
        with app.app_context():
            assert SocketSession.query.filter_by(socket_sid=namespace_sid).first() is not None
        assert len(scheduled) == 1
        assert scheduled[0][3] == engineio_sid
    finally:
        monkeypatch.setattr(socketio.server, 'disconnect', original_disconnect)
        if engineio_sid in socketio.server.eio.sockets:
            _close_engineio_socket(engineio_sid)
