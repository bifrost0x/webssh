"""Exercise PAM-style MFA over the real SSH protocol without external servers."""
import socket
import threading

import paramiko
import pytest

from app.ssh_gateway_auth import GatewayAuthStrategy, GatewayTransport


class PAMServer(paramiko.ServerInterface):
    def __init__(self, mode):
        self.mode = mode
        self.first_factor = mode.startswith('interactive')
        self.round = 0
        self.answers = []

    def get_allowed_auths(self, username):
        if self.first_factor:
            return 'keyboard-interactive'
        return 'publickey' if self.mode == 'key' else 'password'

    def check_auth_password(self, username, password):
        if self.mode == 'password-only' and password == 'login-secret':
            return paramiko.AUTH_SUCCESSFUL
        if self.mode == 'password' and password == 'login-secret':
            self.first_factor = True
            return paramiko.AUTH_PARTIALLY_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        if self.mode == 'key':
            self.first_factor = True
            return paramiko.AUTH_PARTIALLY_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_interactive(self, username, submethods):
        if not self.first_factor:
            return paramiko.AUTH_FAILED
        if self.mode == 'interactive-multiple':
            return paramiko.InteractiveQuery('PAM', '', ('Password:', False), ('Verification code:', False))
        if self.mode == 'interactive-sequential':
            return paramiko.InteractiveQuery('PAM', '', ('Password:', False))
        return paramiko.InteractiveQuery('PAM', 'Enter verification code', ('Verification code:', False))

    def check_auth_interactive_response(self, responses):
        self.answers.append(responses)
        if self.mode == 'interactive-sequential' and self.round == 0:
            if responses != ['login-secret']:
                return paramiko.AUTH_FAILED
            self.round += 1
            return paramiko.InteractiveQuery('PAM', '', ('Verification code:', False))
        expected = ['login-secret', '123456'] if self.mode == 'interactive-multiple' else ['123456']
        return paramiko.AUTH_SUCCESSFUL if responses == expected else paramiko.AUTH_FAILED


@pytest.fixture(scope='module')
def protocol_key():
    return paramiko.RSAKey.generate(2048)


@pytest.mark.parametrize('mode', ['password', 'key', 'interactive-only', 'interactive-multiple', 'interactive-sequential', 'password-only'])
@pytest.mark.parametrize('valid_code', [True, False])
def test_real_ssh_pam_challenges(mode, valid_code, protocol_key):
    client_sock, server_sock = socket.socketpair()
    server = PAMServer(mode)
    transport = paramiko.Transport(server_sock)
    transport.add_server_key(protocol_key)
    client = paramiko.SSHClient()
    client.get_host_keys().add('pam.example', protocol_key.get_name(), protocol_key)
    challenges = []
    def answer(title, instructions, prompts):
        challenges.append(prompts)
        return ['login-secret' if label == 'Password:' else ('123456' if valid_code else '654321') for label, _echo in prompts]
    try:
        transport.start_server(event=threading.Event(), server=server)
        strategy = GatewayAuthStrategy('alice', password='login-secret',
                                      pkey=protocol_key if mode == 'key' else None, interact=answer)
        kwargs = dict(hostname='pam.example', username='alice', sock=client_sock,
                      timeout=5, auth_timeout=5, transport_factory=GatewayTransport, auth_strategy=strategy)
        if valid_code or mode == 'password-only':
            client.connect(**kwargs)
            assert client.get_transport().is_authenticated()
        else:
            with pytest.raises(paramiko.AuthenticationException):
                client.connect(**kwargs)
            assert not client.get_transport().is_authenticated()
        assert bool(challenges) == (mode != 'password-only')
        if mode in ('password', 'key', 'interactive-only'):
            assert server.answers == [['123456' if valid_code else '654321']]
        assert strategy.password is None and strategy.pkey is None
    finally:
        client.close()
        transport.close()
        client_sock.close()
        server_sock.close()
