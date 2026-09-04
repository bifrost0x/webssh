"""Bound acknowledged Socket.IO delivery for live SSH output."""

from collections import defaultdict
import json
import threading
import time
import uuid

import config

from .audit_logger import log_warning


class SSHOutputFlowController:
    """Track live output until each browser acknowledges accepting it."""

    def __init__(self):
        self._condition = threading.Condition(threading.RLock())
        self._reservations = {}
        self._socket_bytes = defaultdict(int)
        self._socket_events = defaultdict(int)
        self._user_bytes = defaultdict(int)
        self._user_events = defaultdict(int)
        self._global_bytes = 0
        self._global_events = 0
        self._active_sockets = set()

    @staticmethod
    def event_size(payload):
        """Return the exact UTF-8 size of the Socket.IO event JSON payload."""
        serialized = json.dumps(
            ['ssh_output', payload],
            ensure_ascii=True,
            separators=(',', ':'),
        )
        return len(serialized.encode('utf-8'))

    def register_socket(self, socket_sid):
        with self._condition:
            self._active_sockets.add(socket_sid)

    def can_reserve(self, socket_sid, user_id, size):
        with self._condition:
            return self._fits(socket_sid, user_id, size)

    def has_pending(self, socket_sid):
        with self._condition:
            return self._socket_events.get(socket_sid, 0) > 0

    def _fits(self, socket_sid, user_id, size):
        if socket_sid not in self._active_sockets:
            return False
        return (
            self._socket_bytes.get(socket_sid, 0) + size
            <= config.SSH_OUTPUT_MAX_UNACKED_BYTES_PER_SOCKET
            and self._socket_events.get(socket_sid, 0) + 1
            <= config.SSH_OUTPUT_MAX_UNACKED_EVENTS_PER_SOCKET
            and self._user_bytes.get(user_id, 0) + size
            <= config.SSH_OUTPUT_MAX_UNACKED_BYTES_PER_USER
            and self._user_events.get(user_id, 0) + 1
            <= config.SSH_OUTPUT_MAX_UNACKED_EVENTS_PER_USER
            and self._global_bytes + size
            <= config.SSH_OUTPUT_MAX_UNACKED_BYTES_GLOBAL
            and self._global_events + 1
            <= config.SSH_OUTPUT_MAX_UNACKED_EVENTS_GLOBAL
        )

    def reserve(
        self,
        socket_sid,
        user_id,
        session_id,
        size,
        *,
        cancel_event=None,
        timeout=None,
    ):
        """Wait for bounded capacity and return ``(token, reason)``."""
        timeout = (
            config.SSH_OUTPUT_ACK_TIMEOUT_SECONDS
            if timeout is None else timeout
        )
        deadline = time.monotonic() + timeout
        with self._condition:
            while not self._fits(socket_sid, user_id, size):
                if socket_sid not in self._active_sockets:
                    return None, 'disconnected'
                if cancel_event is not None and cancel_event.is_set():
                    return None, 'cancelled'
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None, 'timeout'
                self._condition.wait(min(0.1, remaining))

            token = uuid.uuid4().hex
            self._reservations[token] = (
                socket_sid, user_id, session_id, size, time.monotonic()
            )
            self._socket_bytes[socket_sid] += size
            self._socket_events[socket_sid] += 1
            self._user_bytes[user_id] += size
            self._user_events[user_id] += 1
            self._global_bytes += size
            self._global_events += 1
            return token, None

    def release(self, token):
        with self._condition:
            reservation = self._reservations.pop(token, None)
            if reservation is None:
                return False
            socket_sid, user_id, _session_id, size, _created_at = reservation
            self._socket_bytes[socket_sid] -= size
            self._socket_events[socket_sid] -= 1
            self._user_bytes[user_id] -= size
            self._user_events[user_id] -= 1
            self._global_bytes -= size
            self._global_events -= 1
            self._prune(socket_sid, user_id)
            self._condition.notify_all()
            return True

    def _prune(self, socket_sid, user_id):
        if self._socket_bytes[socket_sid] == 0:
            self._socket_bytes.pop(socket_sid, None)
        if self._socket_events[socket_sid] == 0:
            self._socket_events.pop(socket_sid, None)
        if self._user_bytes[user_id] == 0:
            self._user_bytes.pop(user_id, None)
        if self._user_events[user_id] == 0:
            self._user_events.pop(user_id, None)

    def stale_sockets(self, *, exclude=None, now=None, timeout=None):
        """Return sockets holding ACK reservations past the timeout."""
        now = time.monotonic() if now is None else now
        timeout = (
            config.SSH_OUTPUT_ACK_TIMEOUT_SECONDS
            if timeout is None else timeout
        )
        with self._condition:
            oldest = {}
            for reservation in self._reservations.values():
                socket_sid, _user_id, _session_id, _size, created_at = (
                    reservation
                )
                if socket_sid == exclude:
                    continue
                oldest[socket_sid] = min(
                    oldest.get(socket_sid, created_at), created_at
                )
            return [
                socket_sid
                for socket_sid, created_at in oldest.items()
                if now - created_at >= timeout
            ]

    def release_socket(self, socket_sid):
        with self._condition:
            self._active_sockets.discard(socket_sid)
            tokens = [
                token
                for token, reservation in self._reservations.items()
                if reservation[0] == socket_sid
            ]
            for token in tokens:
                (
                    socket,
                    user_id,
                    _session_id,
                    size,
                    _created_at,
                ) = self._reservations.pop(token)
                self._socket_bytes[socket] -= size
                self._socket_events[socket] -= 1
                self._user_bytes[user_id] -= size
                self._user_events[user_id] -= 1
                self._global_bytes -= size
                self._global_events -= 1
                self._prune(socket, user_id)
            self._socket_bytes.pop(socket_sid, None)
            self._socket_events.pop(socket_sid, None)
            self._condition.notify_all()

    def usage(self):
        """Return a test/diagnostic snapshot without exposing payloads."""
        with self._condition:
            return {
                'global_bytes': self._global_bytes,
                'global_events': self._global_events,
                'reservations': len(self._reservations),
                'socket_bytes': dict(self._socket_bytes),
                'socket_events': dict(self._socket_events),
                'user_bytes': dict(self._user_bytes),
                'user_events': dict(self._user_events),
            }


ssh_output_flow = SSHOutputFlowController()


def _room_participants(socketio_instance, room):
    server = getattr(socketio_instance, 'server', None)
    manager = getattr(server, 'manager', None)
    if manager is None:
        return []
    participants = manager.get_participants('/', room)
    return list(dict.fromkeys(
        participant[0] if isinstance(participant, tuple) else participant
        for participant in participants
    ))


def _disconnect_lagging_socket(socketio_instance, socket_sid):
    server = getattr(socketio_instance, 'server', None)
    if server is None:
        return False
    try:
        socketio_instance.emit(
            'ssh_output_resync_required',
            {'reason': 'backpressure'},
            to=socket_sid,
        )
    except Exception:
        # The disconnect still releases server resources if the advisory
        # marker cannot be delivered over an already-broken transport.
        pass
    server.disconnect(socket_sid, namespace='/')
    # Production disconnect handlers release first; keep this idempotent
    # fallback for test servers and disconnects without an application event.
    ssh_output_flow.release_socket(socket_sid)
    return True


def emit_ssh_output(
    socketio_instance,
    room,
    user_id,
    session_id,
    payload,
    *,
    cancel_event=None,
):
    """Deliver one output event individually with bounded ACK reservations."""
    try:
        participants = _room_participants(socketio_instance, room)
    except Exception:
        participants = []
    if not participants:
        return

    size = ssh_output_flow.event_size(payload)
    # Browsers with immediate capacity receive the current chunk before a
    # lagging peer can make the Paramiko reader wait for its bounded timeout.
    participants.sort(key=lambda sid: (
        0 if ssh_output_flow.can_reserve(sid, user_id, size)
        else 1 if ssh_output_flow.has_pending(sid)
        else 2
    ))
    for socket_sid in participants:
        while True:
            token, reason = ssh_output_flow.reserve(
                socket_sid,
                user_id,
                session_id,
                size,
                cancel_event=cancel_event,
            )
            if reason == 'cancelled':
                return
            if reason == 'disconnected':
                break
            if reason != 'timeout':
                break
            if not ssh_output_flow.has_pending(socket_sid):
                # A user/global budget can be occupied by a different browser.
                # Keep bounded SSH backpressure without blaming this healthy
                # subscriber; disconnect/ping cleanup elsewhere will wake us.
                stale_sockets = ssh_output_flow.stale_sockets(
                    exclude=socket_sid
                )
                if not stale_sockets:
                    continue
                stale_sid = stale_sockets[0]
                log_warning(
                    'Disconnecting browser holding expired SSH output budget',
                    user_id=user_id,
                    session_id=session_id,
                    sid=stale_sid,
                )
                try:
                    _disconnect_lagging_socket(
                        socketio_instance, stale_sid
                    )
                except Exception:
                    pass
                continue
            log_warning(
                'Disconnecting browser that stopped acknowledging SSH output',
                user_id=user_id,
                session_id=session_id,
                sid=socket_sid,
            )
            try:
                _disconnect_lagging_socket(socketio_instance, socket_sid)
            except Exception:
                pass
            break
        if token is None:
            continue

        release_state = {'released': False}

        def acknowledge(*_args, _token=token, _state=release_state):
            if _state['released']:
                return
            _state['released'] = True
            ssh_output_flow.release(_token)

        try:
            socketio_instance.emit(
                'ssh_output', payload, to=socket_sid, callback=acknowledge
            )
        except Exception as error:
            try:
                _disconnect_lagging_socket(socketio_instance, socket_sid)
            except Exception:
                pass
            log_warning(
                'Failed to deliver SSH output to browser',
                user_id=user_id,
                session_id=session_id,
                sid=socket_sid,
                error_type=type(error).__name__,
            )
