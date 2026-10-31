"""Explicit multi-factor authentication using Paramiko's public transport API."""
import time
import threading

from paramiko import AuthenticationException, BadAuthenticationType, ServiceRequestingTransport
from paramiko.auth_strategy import AuthStrategy
from paramiko.auth_handler import AuthOnlyHandler
from paramiko import Message
from paramiko.common import cMSG_USERAUTH_REQUEST

from .ssh_gateway import parse_selector


class GatewayAuthStrategy(AuthStrategy):
    def __init__(self, username, *, password=None, pkey=None, interact, check=None):
        super().__init__(ssh_config=None)
        if ":" in username:
            parse_selector(username)
        self.username = username
        self.password = password or None
        self.pkey = pkey
        self.interact = interact
        self.check = check or (lambda: None)

    def authenticate(self, transport):
        deadline = time.monotonic() + 180
        guard = threading.Timer(180, transport.close)
        guard.daemon = True
        guard.start()

        def remaining_timeout():
            self.check()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AuthenticationException("Gateway authentication timed out")
            transport.auth_timeout = remaining

        method = "publickey" if self.pkey is not None else (
            "password" if self.password else "keyboard-interactive"
        )
        attempted = set()
        try:
            for _round in range(8):
                self.check()
                if time.monotonic() >= deadline:
                    raise AuthenticationException("Gateway authentication timed out")
                if method in attempted:
                    raise AuthenticationException("Gateway authentication did not complete")
                attempted.add(method)
                try:
                    if method == "publickey":
                        remaining_timeout()
                        methods = transport.auth_publickey(self.username, self.pkey)
                    elif method == "password":
                        password = self.password
                        if password is None:
                            answers = self.interact("", "", [("Password", False)])
                            if len(answers) != 1:
                                raise AuthenticationException("Invalid authentication response")
                            password = answers[0]
                        try:
                            remaining_timeout()
                            methods = transport.auth_password(self.username, password, fallback=False)
                        finally:
                            password = None
                    else:
                        rounds = 0
                        def handler(title, instructions, prompts):
                            nonlocal rounds
                            rounds += 1
                            self.check()
                            if rounds > 8 or time.monotonic() >= deadline:
                                raise AuthenticationException("Gateway authentication limit exceeded")
                            return self.interact(title, instructions, prompts)
                        remaining_timeout()
                        methods = transport.auth_interactive(self.username, handler)
                except BadAuthenticationType as error:
                    methods = error.allowed_types
                self.check()
                remaining_timeout()
                if transport.is_authenticated():
                    return
                if not isinstance(methods, (list, tuple)):
                    raise AuthenticationException("Gateway authentication failed")
                method = next((candidate for candidate in (
                    "password", "keyboard-interactive"
                ) if candidate in methods and candidate not in attempted), None)
                if method is None:
                    raise AuthenticationException("Gateway authentication failed")
            raise AuthenticationException("Gateway authentication limit exceeded")
        finally:
            guard.cancel()
            self.password = None
            self.pkey = None

class GatewayAuthHandler(AuthOnlyHandler):
    """Register the reply event before a fast server can answer the request.

    Paramiko 5.1 AuthOnlyHandler installs it after sending, which can lose a
    success or partial-authentication reply. Keep this compatibility override
    aligned with AuthOnlyHandler.send_auth_request when upgrading Paramiko.
    """

    def send_auth_request(self, username, method, finish_message=None):
        self.auth_method = method
        self.username = username
        message = Message()
        message.add_byte(cMSG_USERAUTH_REQUEST)
        message.add_string(username)
        message.add_string('ssh-connection')
        message.add_string(method)
        if finish_message is not None:
            finish_message(message)
        event = threading.Event()
        self.auth_event = event
        with self.transport.lock:
            self.transport._send_message(message)
        return self.wait_for_response(event)


class GatewayTransport(ServiceRequestingTransport):
    """Request ssh-userauth once, with a bounded Paramiko 5 service handshake.

    Paramiko's public ServiceRequestingTransport supports multiple factors, but
    its ensure_session loop does not stop on close or timeout. This isolated
    override retains its protocol behavior and bounds that initial wait.
    """

    def get_auth_handler(self):
        return GatewayAuthHandler(self)

    def ensure_session(self):
        from paramiko import Message, SSHException
        from paramiko.common import cMSG_SERVICE_REQUEST
        if not self.active or not self.initial_kex_done:
            raise SSHException("No existing gateway session")
        if self._service_userauth_accepted:
            return
        message = Message()
        message.add_byte(cMSG_SERVICE_REQUEST)
        message.add_string("ssh-userauth")
        self._send_message(message)
        deadline = time.monotonic() + min(self.auth_timeout or 10, 10)
        while not self._service_userauth_accepted:
            if not self.active or time.monotonic() >= deadline:
                self.close()
                raise AuthenticationException("Gateway authentication service unavailable")
            time.sleep(.02)
        self.auth_handler = self.get_auth_handler()
