"""Exercise SOCKS5 negotiation against a scripted loopback TCP peer."""

from contextlib import contextmanager
import importlib
import logging
import socket
import threading
import time

import pytest

from app.network_policy import ResolvedTarget


_IPV4_REQUEST = b'\x05\x01\x00\x01\xc0\x00\x02\x0a\x00\x16'
_SUCCESS = b'\x05\x00\x00\x01\x7f\x00\x00\x01\x12\x34'


def _receive(connection, size):
    data = bytearray()
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


@contextmanager
def _peer(script):
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(3)
    errors = []

    def serve():
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(3)
                script(connection)
        except Exception as error:
            errors.append(error)

    thread = threading.Thread(target=serve)
    thread.start()
    connection = None
    try:
        connection = socket.create_connection(listener.getsockname(), timeout=3)
        yield connection
    finally:
        if connection is not None:
            connection.close()
        listener.close()
        thread.join(4)
        assert not thread.is_alive(), 'SOCKS5 test peer did not stop'
        if errors:
            raise errors[0]


def _ipv4_target():
    return ResolvedTarget('target.example', 22, '192.0.2.10', socket.AF_INET)


def test_connects_ipv4_without_authentication_and_preserves_ssh_bytes():
    socks = importlib.import_module('app.socks5_client')

    def script(connection):
        assert _receive(connection, 3) == b'\x05\x01\x00'
        connection.sendall(b'\x05\x00')
        assert _receive(connection, len(_IPV4_REQUEST)) == _IPV4_REQUEST
        connection.sendall(_SUCCESS + b'SSH-2.0-test\r\n')

    with _peer(script) as connection:
        result = socks.open_socks5_tunnel(
            connection, _ipv4_target(), deadline=time.monotonic() + 2,
        )
        assert result is connection
        assert _receive(result, 14) == b'SSH-2.0-test\r\n'


def _exchange(steps):
    def script(connection):
        for request, response in steps:
            assert _receive(connection, len(request)) == request
            if response:
                connection.sendall(response)
    return script


def _assert_failure(script, code, **kwargs):
    socks = importlib.import_module('app.socks5_client')
    target = kwargs.pop('destination', _ipv4_target())
    with _peer(script) as connection:
        with pytest.raises(socks.Socks5Error) as caught:
            socks.open_socks5_tunnel(
                connection, target, deadline=time.monotonic() + 2, **kwargs,
            )
        assert caught.value.code == code
        assert connection.fileno() == -1
        return caught.value


@pytest.mark.parametrize('version', [b'\x01', b'\x05'])
def test_password_authentication_uses_utf8_byte_lengths(version, caplog):
    caplog.set_level(logging.DEBUG)
    socks = importlib.import_module('app.socks5_client')
    script = _exchange([
        (b'\x05\x01\x02', b'\x05\x02'),
        (b'\x01\x05m\xc3\xbcll\x05p\xc3\xa4ss', version + b'\x00'),
        (_IPV4_REQUEST, _SUCCESS),
    ])
    with _peer(script) as connection:
        assert socks.open_socks5_tunnel(
            connection, _ipv4_target(), username='müll', password='päss',
            deadline=time.monotonic() + 2,
        ) is connection
    assert 'müll' not in caplog.text
    assert 'päss' not in caplog.text


@pytest.mark.parametrize('kind,expected', [
    ('ipv6', b'\x05\x01\x00\x04\x20\x01\x0d\xb8' + b'\x00' * 11 + b'\x01\xff\xff'),
    ('domain', b'\x05\x01\x00\x03\x15xn--bcher-kva.example\x00\x16'),
])
def test_encodes_ipv6_and_idna_destinations_without_local_dns(kind, expected, monkeypatch):
    socks = importlib.import_module('app.socks5_client')
    destination = (
        ResolvedTarget('target.example', 65535, '2001:db8::1', socket.AF_INET6)
        if kind == 'ipv6' else socks.RemoteName('BÜCHER.example.', 22)
    )
    script = _exchange([(b'\x05\x01\x00', b'\x05\x00'), (expected, _SUCCESS)])
    with _peer(script) as connection:
        def unexpected_dns(*args, **kwargs):
            pytest.fail('SOCKS5 negotiation must not resolve destinations locally')
        monkeypatch.setattr(socket, 'getaddrinfo', unexpected_dns)
        assert socks.open_socks5_tunnel(
            connection, destination, deadline=time.monotonic() + 2,
        ) is connection


@pytest.mark.parametrize('address', [
    b'\x01\x7f\x00\x00\x01',
    b'\x04' + b'\x00' * 15 + b'\x01',
    b'\x03\x03foo',
    b'\x03\xff' + b'x' * 255,
])
def test_consumes_complete_bound_address_without_consuming_tunnel_bytes(address):
    socks = importlib.import_module('app.socks5_client')
    script = _exchange([
        (b'\x05\x01\x00', b'\x05\x00'),
        (_IPV4_REQUEST, b'\x05\x00\x00' + address + b'\x00\x00SSH'),
    ])
    with _peer(script) as connection:
        result = socks.open_socks5_tunnel(
            connection, _ipv4_target(), deadline=time.monotonic() + 2,
        )
        assert _receive(result, 3) == b'SSH'


@pytest.mark.parametrize('reply,code,message', [
    (1, 'socks_proxy_failure', 'The SOCKS5 proxy reported a general failure.'),
    (2, 'socks_not_allowed', 'The SOCKS5 proxy does not allow this connection.'),
    (3, 'socks_network_unreachable', 'The SOCKS5 proxy cannot reach the target network.'),
    (4, 'socks_host_unreachable', 'The SOCKS5 proxy cannot reach the target host.'),
    (5, 'socks_connection_refused', 'The target refused the connection through the SOCKS5 proxy.'),
    (6, 'socks_ttl_expired', 'The connection through the SOCKS5 proxy timed out.'),
    (7, 'socks_unsupported', 'The SOCKS5 proxy does not support this request.'),
    (8, 'socks_unsupported', 'The SOCKS5 proxy does not support this request.'),
    (9, 'socks_protocol_error', 'The SOCKS5 proxy sent an invalid response.'),
    (255, 'socks_protocol_error', 'The SOCKS5 proxy sent an invalid response.'),
])
def test_reply_errors_have_stable_safe_codes_and_close_socket(reply, code, message):
    error = _assert_failure(_exchange([
        (b'\x05\x01\x00', b'\x05\x00'),
        (_IPV4_REQUEST, b'\x05' + bytes([reply]) + _SUCCESS[2:]),
    ]), code)
    assert str(error) == message


@pytest.mark.parametrize('credentials,greeting,response,code', [
    ({}, b'\x05\x01\x00', b'\x05\xff', 'socks_auth_required'),
    ({'username': 'user', 'password': 'secret'}, b'\x05\x01\x02', b'\x05\xff', 'socks_auth_rejected'),
    ({}, b'\x05\x01\x00', b'\x05\x02', 'socks_protocol_error'),
    ({'username': 'user', 'password': 'secret'}, b'\x05\x01\x02', b'\x05\x00', 'socks_protocol_error'),
    ({}, b'\x05\x01\x00', b'\x04\x00', 'socks_protocol_error'),
])
def test_rejects_unoffered_authentication_methods_and_bad_versions(
    credentials, greeting, response, code,
):
    _assert_failure(_exchange([(greeting, response)]), code, **credentials)


@pytest.mark.parametrize('response,code', [
    (b'\x01\x01', 'socks_auth_failed'),
    (b'\x05\xff', 'socks_auth_failed'),
    (b'\x02\x00', 'socks_protocol_error'),
])
def test_rejects_failed_or_malformed_password_authentication(response, code, caplog):
    caplog.set_level(logging.DEBUG)
    error = _assert_failure(_exchange([
        (b'\x05\x01\x02', b'\x05\x02'),
        (b'\x01\x0aproxy-user\x06secret', response),
    ]), code, username='proxy-user', password='secret')
    assert 'secret' not in repr(error)
    assert 'proxy-user' not in repr(error.args)
    assert 'secret' not in caplog.text
    assert 'proxy-user' not in caplog.text


@pytest.mark.parametrize('response', [
    b'\x04\x00\x00\x01',
    b'\x05\x00\x01\x01',
    b'\x05\x00\x00\x05',
    b'\x05\x00\x00\x03\x00\x00\x16',
])
def test_rejects_invalid_connect_response(response):
    _assert_failure(_exchange([
        (b'\x05\x01\x00', b'\x05\x00'),
        (_IPV4_REQUEST, response),
    ]), 'socks_protocol_error')


@pytest.mark.parametrize('stage,partial', [
    ('greeting', b''), ('greeting', b'\x05'),
    ('auth', b''), ('auth', b'\x01'),
    ('connect', b''), ('connect', b'\x05\x00\x00'),
    ('connect', b'\x05\x00\x00\x01\x7f\x00'),
    ('connect', b'\x05\x00\x00\x04' + b'\x00' * 15),
    ('connect', b'\x05\x00\x00\x03'),
    ('connect', b'\x05\x00\x00\x03\x03ab'),
    ('connect', _SUCCESS[:-1]),
])
def test_eof_in_each_response_phase_is_a_protocol_error(stage, partial):
    if stage == 'auth':
        steps = [(b'\x05\x01\x02', b'\x05\x02'), (b'\x01\x01u\x01p', partial)]
        credentials = {'username': 'u', 'password': 'p'}
    else:
        steps = [(b'\x05\x01\x00', partial if stage == 'greeting' else b'\x05\x00')]
        if stage == 'connect':
            steps.append((_IPV4_REQUEST, partial))
        credentials = {}
    _assert_failure(_exchange(steps), 'socks_protocol_error', **credentials)


def test_accepts_fragmented_responses_in_every_phase():
    socks = importlib.import_module('app.socks5_client')

    def script(connection):
        for request, response in [
            (b'\x05\x01\x02', b'\x05\x02'),
            (b'\x01\x01u\x01p', b'\x01\x00'),
            (_IPV4_REQUEST, b'\x05\x00\x00\x03\x03foo\x00\x16'),
        ]:
            assert _receive(connection, len(request)) == request
            for value in response:
                connection.sendall(bytes([value]))
                threading.Event().wait(0.005)

    with _peer(script) as connection:
        assert socks.open_socks5_tunnel(
            connection, _ipv4_target(), username='u', password='p',
            deadline=time.monotonic() + 2,
        ) is connection


@pytest.mark.parametrize('username,password', [
    ('', 'secret'), ('user', ''), (None, 'secret'), ('user', None),
    ('u' * 256, 'secret'), ('user', 'p' * 256),
    ('ü' * 128, 'secret'), ('user', 'ä' * 128),
    (b'user', 'secret'), ('user', b'secret'),
    ('\ud800', 'secret'), ('user', '\ud800'),
])
def test_invalid_credentials_are_rejected_before_sending_bytes(username, password):
    _assert_failure(_expect_closed, 'socks_auth_failed',
                    username=username, password=password)


@pytest.mark.parametrize('field', ['username', 'password'])
def test_accepts_255_byte_credential_fields(field):
    socks = importlib.import_module('app.socks5_client')
    credentials = {'username': 'u', 'password': 'p'}
    credentials[field] = 'x' * 255
    packet = (b'\x01\xff' + b'x' * 255 + b'\x01p' if field == 'username'
              else b'\x01\x01u\xff' + b'x' * 255)
    script = _exchange([
        (b'\x05\x01\x02', b'\x05\x02'), (packet, b'\x01\x00'),
        (_IPV4_REQUEST, _SUCCESS),
    ])
    with _peer(script) as connection:
        assert socks.open_socks5_tunnel(
            connection, _ipv4_target(), deadline=time.monotonic() + 2, **credentials,
        ) is connection


@pytest.mark.parametrize('hostname,port', [
    ('', 22), ('a' * 256, 22), ('bad host', 22), ('\ud800', 22),
    ('target.example', 0), ('target.example', 65536),
    ('target.example', -1), ('target.example', 22.5),
    ('target.example', True), ('target.example', '22'),
])
def test_invalid_remote_destination_closes_socket_before_sending(hostname, port):
    socks = importlib.import_module('app.socks5_client')
    _assert_failure(_expect_closed, 'socks_protocol_error',
                    destination=socks.RemoteName(hostname, port))


@pytest.mark.parametrize('target', [
    ResolvedTarget('target', 22, '2001:db8::1', socket.AF_INET),
    ResolvedTarget('target', 22, '192.0.2.10', socket.AF_INET6),
    ResolvedTarget('target', 0, '192.0.2.10', socket.AF_INET),
    ResolvedTarget('target', 22, 'fe80::1%1', socket.AF_INET6),
    ResolvedTarget('target', 22, 'fe80::1', socket.AF_INET6, ('fe80::1', 22, 0, 1)),
    object(),
])
def test_invalid_resolved_destination_is_not_sent(target):
    _assert_failure(_expect_closed, 'socks_protocol_error', destination=target)


def test_deadline_applies_across_slow_partial_responses():
    socks = importlib.import_module('app.socks5_client')

    def script(connection):
        assert _receive(connection, 3) == b'\x05\x01\x00'
        connection.sendall(b'\x05')
        threading.Event().wait(0.12)
        connection.sendall(b'\x00')
        assert _receive(connection, len(_IPV4_REQUEST)) == _IPV4_REQUEST
        connection.sendall(b'\x05')
        threading.Event().wait(0.12)
        _expect_closed(connection)

    with _peer(script) as connection:
        started = time.monotonic()
        with pytest.raises(socks.Socks5Error) as caught:
            socks.open_socks5_tunnel(connection, _ipv4_target(), deadline=started + 0.2)
        assert caught.value.code == 'socks_timeout'
        assert connection.fileno() == -1
        assert time.monotonic() - started < 0.8


def test_expired_deadline_prevents_any_handshake_bytes():
    socks = importlib.import_module('app.socks5_client')
    with _peer(lambda connection: _expect_closed(connection)) as connection:
        with pytest.raises(socks.Socks5Error) as caught:
            socks.open_socks5_tunnel(connection, _ipv4_target(), deadline=time.monotonic() - 1)
        assert caught.value.code == 'socks_timeout'
        assert connection.fileno() == -1


def _expect_closed(connection):
    try:
        assert connection.recv(1) == b''
    except (ConnectionResetError, ConnectionAbortedError):
        pass


@pytest.mark.parametrize('stage', ['before', 'greeting', 'auth', 'connect', 'address', 'port'])
def test_cancellation_between_handshake_steps_closes_socket(stage):
    stopped = threading.Event()
    if stage == 'before':
        stopped.set()

    def script(connection):
        for step, request, response in [
            ('greeting', b'\x05\x01\x02', b'\x05\x02'),
            ('auth', b'\x01\x01u\x01p', b'\x01\x00'),
            ('connect', _IPV4_REQUEST, b'\x05\x00\x00\x01'),
            ('address', b'', b'\x7f\x00\x00\x01'),
            ('port', b'', b'\x00\x16'),
        ]:
            if stopped.is_set():
                _expect_closed(connection)
                return
            assert _receive(connection, len(request)) == request
            if step == stage:
                stopped.set()
            connection.sendall(response)
        _expect_closed(connection)

    error = _assert_failure(script, 'connection_cancelled', username='u', password='p',
                            cancelled=stopped.is_set)
    assert str(error) == 'Connection cancelled'


def test_cancellation_callback_failure_is_safe_and_closes_socket(caplog):
    caplog.set_level(logging.DEBUG)
    def cancelled():
        raise RuntimeError('private-username/private-password')

    error = _assert_failure(_expect_closed, 'connection_cancelled', cancelled=cancelled)
    assert error.__context__ is None
    assert 'private-' not in repr(error)
    assert 'private-' not in caplog.text


def test_closed_socket_error_has_no_raw_exception_details(caplog):
    caplog.set_level(logging.DEBUG)
    socks = importlib.import_module('app.socks5_client')
    connection = socket.socket()
    connection.close()
    with pytest.raises(socks.Socks5Error) as caught:
        socks.open_socks5_tunnel(connection, _ipv4_target(), deadline=time.monotonic() + 2)
    assert caught.value.code == 'socks_protocol_error'
    assert caught.value.__context__ is None
    assert not caplog.text


@pytest.mark.parametrize('deadline', [float('nan'), float('inf'), float('-inf'), None, 'later'])
def test_invalid_deadline_closes_socket_before_negotiation(deadline):
    socks = importlib.import_module('app.socks5_client')
    with _peer(_expect_closed) as connection:
        with pytest.raises(socks.Socks5Error) as caught:
            socks.open_socks5_tunnel(connection, _ipv4_target(), deadline=deadline)
        assert caught.value.code == 'socks_protocol_error'
        assert connection.fileno() == -1


def test_authentication_failure_does_not_retain_credentials_in_exception_frames():
    error = _assert_failure(_exchange([
        (b'\x05\x01\x02', b'\x05\x02'),
        (b'\x01\x0aprivate-id\x0cprivate-pass', b'\x01\x01'),
    ]), 'socks_auth_failed', username='private-id', password='private-pass')
    assert error.__context__ is None
    assert error.__cause__ is None
    traceback = error.__traceback__
    while traceback is not None:
        if traceback.tb_frame.f_globals.get('__name__') == 'app.socks5_client':
            for value in traceback.tb_frame.f_locals.values():
                if isinstance(value, (str, bytes, bytearray)):
                    assert 'private-' not in str(value)
        traceback = traceback.tb_next


def test_unknown_error_code_cannot_be_used_to_expose_proxy_details():
    socks = importlib.import_module('app.socks5_client')
    error = socks.Socks5Error('raw-private-proxy-response')
    assert error.code == 'socks_protocol_error'
    assert str(error) == 'The SOCKS5 proxy sent an invalid response.'
    assert 'private' not in repr(error)
