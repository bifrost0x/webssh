"""Bounded, socket-owned gateway interactions. No credentials are persisted."""
from collections import deque
import secrets
import time

from .ssh_connection_attempt import SSHConnectionAttempt


class GatewayCancelled(ValueError):
    def __init__(self):
        super().__init__("Gateway connection cancelled or timed out")


class GatewayAttempt(SSHConnectionAttempt):
    """MFA and setup I/O shared by SSH terminals and gateway Quick SFTP."""

    timeout = 300
    cancellation_error = GatewayCancelled

    def __init__(self, user_id, sid, request_id, emit, *,
                 reservation=None, kind='terminal', require_gateway=True):
        self.require_gateway = require_gateway
        self.emit = emit
        self.auth_deadline = time.monotonic() + 180
        self.prompt = None
        self.responses = None
        self.phase = "auth"
        self.inputs = deque()
        self.input_bytes = 0
        self.output_bytes = 0
        self.sequence = 0
        self.unacked = {}
        super().__init__(
            user_id, sid, request_id, reservation=reservation, kind=kind,
        )

    def check(self):
        with self.condition:
            super().check()
            if self.require_gateway and not self.committed:
                from .app_settings import is_ssh_gateway_enabled
                if not is_ssh_gateway_enabled():
                    raise GatewayCancelled()
            if (not self.committed and self.phase == 'auth'
                    and time.monotonic() >= self.auth_deadline):
                raise GatewayCancelled()

    def _clear_pending(self):
        self.responses = None
        self.inputs.clear()

    def send(self, event, **data):
        self.emit(event, {"client_request_id": self.request_id, **data})

    def challenge(self, title, instructions, prompts):
        if not isinstance(title, str) or not isinstance(instructions, str):
            raise ValueError("Invalid gateway challenge")
        if len(prompts) > 8 or any(
            not isinstance(p, (tuple, list)) or len(p) != 2 or not isinstance(p[0], str)
            for p in prompts
        ):
            raise ValueError("Invalid gateway challenge")
        if sum(len(s.encode("utf-8")) for s in [title, instructions, *[p[0] for p in prompts]]) > 16384:
            raise ValueError("Gateway challenge exceeds byte limit")
        with self.condition:
            self.check()
            if self.prompt is not None:
                raise ValueError("Gateway challenge already pending")
            challenge_id = secrets.token_urlsafe(24)
            self.prompt = (challenge_id, len(prompts))
            self.responses = None
            self.send("ssh_gateway_challenge", challenge_id=challenge_id,
                      title=title, instructions=instructions,
                      prompts=[{"label": p[0]} for p in prompts])
            deadline = min(self.deadline, self.auth_deadline, time.monotonic() + 120)
            try:
                while self.responses is None:
                    self.check()
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise GatewayCancelled()
                    self.condition.wait(min(remaining, .25))
                return self.responses
            finally:
                self.prompt = None
                self.responses = None

    def answer(self, user_id, sid, challenge_id, answers):
        with self.condition:
            if self.cancelled or self.finished or self.user_id != str(user_id) or self.sid != sid:
                return False
            if self.prompt is None or self.prompt[0] != challenge_id or self.responses is not None:
                return False
            if not isinstance(answers, list) or len(answers) != self.prompt[1]:
                return False
            if any(not isinstance(a, str) for a in answers):
                return False
            try:
                if sum(len(a.encode("utf-8")) for a in answers) > 16384:
                    return False
            except UnicodeError:
                return False
            self.responses = list(answers)
            self.condition.notify_all()
            return True

    def start_setup(self):
        with self.condition:
            self.check()
            self.phase = "setup"
            self.send("ssh_gateway_progress", phase="setup")

    def input(self, value):
        if not isinstance(value, str):
            return False
        try:
            data = value.encode("utf-8")
        except UnicodeError:
            return False
        with self.condition:
            if self.phase != "setup" or self.cancelled or self.finished:
                return False
            if not data or len(data) > 1024 or self.input_bytes + len(data) > 8192:
                return False
            self.input_bytes += len(data)
            self.inputs.append(data)
            return True

    def take_input(self):
        with self.condition:
            return self.inputs.popleft() if self.inputs else None

    def output(self, data):
        if not isinstance(data, bytes) or len(data) > 4096:
            raise ValueError("Invalid gateway output frame")
        with self.condition:
            self.check()
            self.output_bytes += len(data)
            if self.output_bytes > 8 * 1024 * 1024:
                raise ValueError("Gateway output limit exceeded")
            deadline = time.monotonic() + 5
            while len(self.unacked) >= 4:
                self.check()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise GatewayCancelled()
                self.condition.wait(min(remaining, .25))
            self.sequence += 1
            self.unacked[self.sequence] = True
            self.send("ssh_gateway_output", sequence=self.sequence,
                      data=data.decode("utf-8", errors="replace"))

    def ack(self, sequence):
        with self.condition:
            if type(sequence) is not int or sequence not in self.unacked:
                return False
            del self.unacked[sequence]
            self.condition.notify_all()
            return True
