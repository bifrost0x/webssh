"""Bounded SOCKS5 fixture that can reach only the disposable OpenSSH lab."""

import select
import socket
import threading
import time


class SocksForwarder:
    """Relay one connection at a time to the fixed lab target, never arbitrary hosts."""

    def __init__(self, *, username=None, password=None, changed_host_key=False):
        self.username = username
        self.password = password
        self._upstream_port = 2224 if changed_host_key else 2223
        self.requests = []
        self.authenticated = False
        self.disconnected = threading.Event()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._sockets = set()
        self._errors = []

    def __enter__(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(2)
        self.listener.settimeout(0.1)
        self.host, self.port = self.listener.getsockname()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, _exc_value, _traceback):
        self._stop.set()
        self.listener.close()
        with self._lock:
            for stream in self._sockets:
                try:
                    stream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                stream.close()
        self._thread.join(timeout=4)
        assert not self._thread.is_alive(), 'SOCKS fixture did not stop'
        if exc_type is None:
            assert not self._errors, self._errors

    @staticmethod
    def _read(stream, count, deadline):
        data = bytearray()
        while len(data) < count:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('SOCKS fixture handshake deadline exceeded')
            stream.settimeout(remaining)
            chunk = stream.recv(count - len(data))
            if not chunk:
                raise EOFError
            data.extend(chunk)
        return bytes(data)

    @staticmethod
    def _reply(stream, status):
        stream.sendall(bytes([5, status, 0, 1]) + b'\x00' * 6)

    def _handshake(self, client):
        deadline = time.monotonic() + 3
        version, method_count = self._read(client, 2, deadline)
        assert version == 5
        methods = self._read(client, method_count, deadline)
        method = 2 if self.username is not None else 0
        if method not in methods:
            client.sendall(b'\x05\xff')
            return False
        client.sendall(bytes([5, method]))
        if method == 2:
            version, size = self._read(client, 2, deadline)
            assert version == 1
            username = self._read(client, size, deadline)
            size = self._read(client, 1, deadline)[0]
            password = self._read(client, size, deadline)
            self.authenticated = (
                username == self.username.encode('utf-8')
                and password == self.password.encode('utf-8')
            )
            client.sendall(bytes([1, 0 if self.authenticated else 1]))
            if not self.authenticated:
                return False

        version, command, reserved, address_type = self._read(client, 4, deadline)
        assert (version, command, reserved) == (5, 1, 0)
        if address_type == 3:
            size = self._read(client, 1, deadline)[0]
            host = self._read(client, size, deadline).decode('ascii')
        elif address_type in (1, 4):
            family = socket.AF_INET if address_type == 1 else socket.AF_INET6
            host = socket.inet_ntop(
                family, self._read(client, 4 if address_type == 1 else 16, deadline),
            )
        else:
            self._reply(client, 8)
            return False
        port = int.from_bytes(self._read(client, 2, deadline), 'big')
        self.requests.append((address_type, host, port))
        # Domain routing is deliberate: the fixture represents the proxy's DNS
        # view of the Compose service, using its guarded published loopback port.
        if (host, port) != ('target', 22):
            self._reply(client, 2)
            return False
        return True

    def _relay(self, client, upstream):
        deadline = time.monotonic() + 30
        transferred = 0
        client.settimeout(1)
        upstream.settimeout(1)
        while not self._stop.is_set() and time.monotonic() < deadline:
            readable, _, _ = select.select([client, upstream], [], [], 0.1)
            for source in readable:
                data = source.recv(65536)
                if not data:
                    return
                transferred += len(data)
                assert transferred <= 16 * 1024 * 1024, 'SOCKS fixture byte budget exceeded'
                (upstream if source is client else client).sendall(data)
        if not self._stop.is_set():
            raise TimeoutError('SOCKS fixture session deadline exceeded')

    def _serve(self):
        deadline = time.monotonic() + 60
        for _ in range(8):
            while not self._stop.is_set() and time.monotonic() < deadline:
                try:
                    client, _ = self.listener.accept()
                    break
                except socket.timeout:
                    continue
                except OSError:
                    return
            else:
                return
            upstream = None
            self.disconnected.clear()
            with self._lock:
                self._sockets.add(client)
            try:
                if self._handshake(client):
                    upstream = socket.create_connection(
                        ('127.0.0.1', self._upstream_port), timeout=3,
                    )
                    with self._lock:
                        self._sockets.add(upstream)
                    self._reply(client, 0)
                    self._relay(client, upstream)
            except (EOFError, ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                pass
            except Exception as error:
                if not self._stop.is_set():
                    self._errors.append(type(error).__name__)
            finally:
                for stream in (client, upstream):
                    if stream is not None:
                        stream.close()
                        with self._lock:
                            self._sockets.discard(stream)
                self.disconnected.set()
