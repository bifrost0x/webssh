import threading

import pytest


class FakeManager:
    def __init__(self, participants):
        self.participants = participants

    def get_participants(self, namespace, room):
        assert namespace == '/'
        assert room == 'user_7'
        return iter((sid, f'eio-{sid}') for sid in self.participants)


class FakeServer:
    def __init__(self, participants):
        self.manager = FakeManager(participants)
        self.disconnected = []
        self.disconnect_event = threading.Event()

    def disconnect(self, sid, namespace='/'):
        self.disconnected.append((sid, namespace))
        self.disconnect_event.set()


class FakeSocketIO:
    def __init__(self, participants, *, auto_ack=()):
        self.server = FakeServer(participants)
        self.emitted = []
        self.auto_ack = set(auto_ack)

    def emit(self, event, payload, to=None, callback=None):
        self.emitted.append((event, payload, to, callback))
        if event == 'ssh_output' and to in self.auto_ack:
            callback()


def _configure_limits(monkeypatch, size, *, events=8, timeout=1):
    import config

    monkeypatch.setattr(
        config, 'SSH_OUTPUT_MAX_UNACKED_BYTES_PER_SOCKET', size
    )
    monkeypatch.setattr(
        config, 'SSH_OUTPUT_MAX_UNACKED_EVENTS_PER_SOCKET', events
    )
    monkeypatch.setattr(
        config, 'SSH_OUTPUT_MAX_UNACKED_EVENTS_PER_USER', events * 4
    )
    monkeypatch.setattr(
        config, 'SSH_OUTPUT_MAX_UNACKED_EVENTS_GLOBAL', events * 8
    )
    monkeypatch.setattr(
        config, 'SSH_OUTPUT_MAX_UNACKED_BYTES_PER_USER', size * 4
    )
    monkeypatch.setattr(
        config, 'SSH_OUTPUT_MAX_UNACKED_BYTES_GLOBAL', size * 8
    )
    monkeypatch.setattr(config, 'SSH_OUTPUT_ACK_TIMEOUT_SECONDS', timeout)


def test_ssh_output_reservation_is_released_only_by_browser_ack(
        monkeypatch):
    import app.ssh_output_flow as output_flow

    controller = output_flow.SSHOutputFlowController()
    monkeypatch.setattr(output_flow, 'ssh_output_flow', controller)
    payload = {'session_id': 's1', 'data': 'hello', 'sequence': 1}
    size = controller.event_size(payload)
    _configure_limits(monkeypatch, size * 4)
    controller.register_socket('browser-1')
    socketio = FakeSocketIO(['browser-1'])

    output_flow.emit_ssh_output(
        socketio, 'user_7', 7, 's1', payload
    )

    assert controller.usage()['reservations'] == 1
    assert socketio.emitted[0][2] == 'browser-1'
    socketio.emitted[0][3]()
    socketio.emitted[0][3]()
    assert controller.usage()['reservations'] == 0
    assert controller.usage()['global_bytes'] == 0


def test_lagging_browser_is_bounded_without_closing_ssh_session(
        monkeypatch):
    import app.ssh_output_flow as output_flow

    controller = output_flow.SSHOutputFlowController()
    monkeypatch.setattr(output_flow, 'ssh_output_flow', controller)
    payload = {'session_id': 's1', 'data': 'next', 'sequence': 2}
    size = controller.event_size(payload)
    _configure_limits(monkeypatch, size, events=1, timeout=0.01)
    controller.register_socket('slow')
    controller.register_socket('healthy')
    token, reason = controller.reserve('slow', 7, 's1', size)
    assert reason is None
    socketio = FakeSocketIO(['slow', 'healthy'], auto_ack=['healthy'])

    output_flow.emit_ssh_output(
        socketio, 'user_7', 7, 's1', payload
    )

    assert [
        entry[2] for entry in socketio.emitted if entry[0] == 'ssh_output'
    ] == ['healthy']
    assert (
        'ssh_output_resync_required',
        {'reason': 'backpressure'},
        'slow',
        None,
    ) in socketio.emitted
    assert socketio.server.disconnected == [('slow', '/')]
    assert controller.release(token) is False
    # Browser eviction never receives or closes the underlying SSH session.
    assert controller.usage()['reservations'] == 0


def test_quiet_browser_is_evicted_at_the_ack_deadline(monkeypatch):
    import app.ssh_output_flow as output_flow

    controller = output_flow.SSHOutputFlowController()
    monkeypatch.setattr(output_flow, 'ssh_output_flow', controller)
    payload = {'session_id': 's1', 'data': 'quiet', 'sequence': 1}
    size = controller.event_size(payload)
    _configure_limits(monkeypatch, size * 4, timeout=0.02)
    controller.register_socket('quiet-browser')
    socketio = FakeSocketIO(['quiet-browser'])

    output_flow.emit_ssh_output(
        socketio, 'user_7', 7, 's1', payload
    )

    assert socketio.server.disconnect_event.wait(1)
    assert socketio.server.disconnected == [('quiet-browser', '/')]
    assert (
        'ssh_output_resync_required',
        {'reason': 'backpressure'},
        'quiet-browser',
        None,
    ) in socketio.emitted
    assert controller.usage()['reservations'] == 0


def test_cancelled_reader_does_not_wait_for_ack_timeout(monkeypatch):
    import app.ssh_output_flow as output_flow

    controller = output_flow.SSHOutputFlowController()
    monkeypatch.setattr(output_flow, 'ssh_output_flow', controller)
    payload = {'session_id': 's1', 'data': 'next', 'sequence': 2}
    size = controller.event_size(payload)
    _configure_limits(monkeypatch, size, events=1, timeout=30)
    controller.register_socket('slow')
    controller.reserve('slow', 7, 's1', size)
    cancel_event = threading.Event()
    cancel_event.set()
    socketio = FakeSocketIO(['slow'])

    output_flow.emit_ssh_output(
        socketio,
        'user_7',
        7,
        's1',
        payload,
        cancel_event=cancel_event,
    )

    assert socketio.emitted == []
    assert socketio.server.disconnected == []
    controller.release_socket('slow')
    assert controller.usage()['reservations'] == 0


def test_new_session_cannot_reuse_unacknowledged_socket_budget(monkeypatch):
    import app.ssh_output_flow as output_flow

    controller = output_flow.SSHOutputFlowController()
    size = 100
    _configure_limits(monkeypatch, size, events=1, timeout=0.01)
    controller.register_socket('browser')
    first, reason = controller.reserve('browser', 7, 'closed-session', size)
    assert reason is None

    second, reason = controller.reserve(
        'browser', 7, 'new-session', size
    )

    assert second is None
    assert reason == 'timeout'
    assert controller.usage()['reservations'] == 1
    controller.release_socket('browser')
    assert controller.release(first) is False


def test_expired_global_budget_holder_is_evicted_for_healthy_user(
        monkeypatch):
    import config
    import app.ssh_output_flow as output_flow

    controller = output_flow.SSHOutputFlowController()
    monkeypatch.setattr(output_flow, 'ssh_output_flow', controller)
    payload = {'session_id': 'healthy-session', 'data': 'next', 'sequence': 1}
    size = controller.event_size(payload)
    _configure_limits(monkeypatch, size, timeout=0.01)
    monkeypatch.setattr(
        config, 'SSH_OUTPUT_MAX_UNACKED_BYTES_GLOBAL', size
    )
    controller.register_socket('expired-holder')
    controller.register_socket('healthy')
    controller.reserve('expired-holder', 8, 'old-session', size)
    socketio = FakeSocketIO(['healthy'])

    output_flow.emit_ssh_output(
        socketio, 'user_7', 7, 'healthy-session', payload
    )

    assert socketio.server.disconnected == [('expired-holder', '/')]
    assert [
        entry[2] for entry in socketio.emitted if entry[0] == 'ssh_output'
    ] == ['healthy']
    next(
        entry[3] for entry in socketio.emitted
        if entry[0] == 'ssh_output'
    )()
    assert controller.usage()['reservations'] == 0


def test_user_and_global_event_budgets_bound_small_callbacks(monkeypatch):
    import config
    import app.ssh_output_flow as output_flow

    size = 1
    _configure_limits(monkeypatch, 1000, events=8, timeout=0.01)
    monkeypatch.setattr(config, 'SSH_OUTPUT_MAX_UNACKED_EVENTS_PER_USER', 1)
    controller = output_flow.SSHOutputFlowController()
    controller.register_socket('user-a')
    controller.register_socket('user-b')
    controller.reserve('user-a', 7, 's1', size)
    token, reason = controller.reserve('user-b', 7, 's2', size)
    assert token is None
    assert reason == 'timeout'

    controller.release_socket('user-a')
    controller.register_socket('user-a')
    monkeypatch.setattr(config, 'SSH_OUTPUT_MAX_UNACKED_EVENTS_PER_USER', 8)
    monkeypatch.setattr(config, 'SSH_OUTPUT_MAX_UNACKED_EVENTS_GLOBAL', 1)
    controller.reserve('user-a', 7, 's1', size)
    token, reason = controller.reserve('user-b', 8, 's2', size)
    assert token is None
    assert reason == 'timeout'


def test_failed_socket_disconnect_does_not_free_retained_callbacks(
        monkeypatch):
    import app.ssh_output_flow as output_flow

    controller = output_flow.SSHOutputFlowController()
    monkeypatch.setattr(output_flow, 'ssh_output_flow', controller)
    _configure_limits(monkeypatch, 1000)
    controller.register_socket('browser')
    controller.reserve('browser', 7, 's1', 100)
    socketio = FakeSocketIO(['browser'])
    socketio.server.disconnect = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        RuntimeError('disconnect failed')
    )

    with pytest.raises(RuntimeError, match='disconnect failed'):
        output_flow._disconnect_lagging_socket(socketio, 'browser')

    assert controller.usage()['reservations'] == 1
