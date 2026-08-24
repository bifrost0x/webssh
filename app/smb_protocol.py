"""Strict SMB 3.1.1 protocol boundary.

Only this module may import the SMB client packages.  It converts their broad,
reconnecting API into one encrypted, non-reconnecting connection per file
source and exposes stable public error codes to the rest of the application.
"""

from __future__ import annotations

from threading import RLock
import uuid

import smbclient
from smbclient._pool import ClientConfig
from smbprotocol.connection import Connection, Dialects
from smbprotocol.exceptions import (
    AccessDenied,
    BadNetworkName,
    DirectoryNotEmpty,
    IOTimeout,
    LogonFailure,
    ObjectNameCollision,
    ObjectNameNotFound,
    ObjectPathNotFound,
    SMBOSError,
    SharingViolation,
)
from smbprotocol.header import NtStatus
from smbprotocol.open import CreateOptions
from smbprotocol.session import Session, SessionFlags


class SMBProtocolError(Exception):
    """Protocol failure with a non-sensitive code suitable for clients."""

    def __init__(self, public_code: str, message: str = 'SMB operation failed'):
        super().__init__(message)
        self.public_code = public_code


def _mapped_protocol_error(exc):
    if isinstance(exc, LogonFailure):
        return SMBProtocolError('AUTHENTICATION_REQUIRED')
    if isinstance(exc, SMBOSError):
        if exc.ntstatus in {
            NtStatus.STATUS_LOGON_FAILURE,
            NtStatus.STATUS_WRONG_PASSWORD,
            NtStatus.STATUS_PASSWORD_EXPIRED,
        }:
            return SMBProtocolError('AUTHENTICATION_REQUIRED')
        if exc.ntstatus in {
            NtStatus.STATUS_ACCESS_DENIED,
            NtStatus.STATUS_PRIVILEGE_NOT_HELD,
        }:
            return SMBProtocolError('PERMISSION_DENIED')
        if exc.ntstatus in {
            NtStatus.STATUS_OBJECT_NAME_NOT_FOUND,
            NtStatus.STATUS_OBJECT_PATH_NOT_FOUND,
            NtStatus.STATUS_NOT_FOUND,
        }:
            return SMBProtocolError('NOT_FOUND')
        if exc.ntstatus == NtStatus.STATUS_BAD_NETWORK_NAME:
            return SMBProtocolError('SHARE_UNAVAILABLE')
        if exc.ntstatus in {
            NtStatus.STATUS_OBJECT_NAME_COLLISION,
            NtStatus.STATUS_SHARING_VIOLATION,
            NtStatus.STATUS_DIRECTORY_NOT_EMPTY,
        }:
            return SMBProtocolError('CONFLICT')
        return SMBProtocolError('OPERATION_FAILED')
    if isinstance(exc, AccessDenied):
        return SMBProtocolError('PERMISSION_DENIED')
    if isinstance(exc, (ObjectNameNotFound, ObjectPathNotFound)):
        return SMBProtocolError('NOT_FOUND')
    if isinstance(exc, BadNetworkName):
        return SMBProtocolError('SHARE_UNAVAILABLE')
    if isinstance(exc, (ObjectNameCollision, SharingViolation, DirectoryNotEmpty)):
        return SMBProtocolError('CONFLICT')
    if isinstance(exc, IOTimeout):
        return SMBProtocolError('TIMEOUT')
    return None


class _MappedIterator:
    """Keep deferred SMB directory failures inside the protocol boundary."""

    def __init__(self, iterator):
        self._iterator = iterator

    def __iter__(self):
        return self

    def __next__(self):
        try:
            return next(self._iterator)
        except StopIteration:
            raise
        except Exception as exc:
            mapped = _mapped_protocol_error(exc)
            if mapped is not None:
                raise mapped from exc
            raise

    def close(self):
        return self._iterator.close()


class _SealedConnectionCache(dict):
    """Per-source cache that cannot create or replace a connection."""

    def __init__(self, key, connection):
        super().__init__({key: connection})
        self._key = key
        self._sealed = True

    def get(self, key, default=None):
        if self._sealed and key != self._key:
            raise SMBProtocolError('SOURCE_UNAVAILABLE')
        return super().get(key, default)

    def __setitem__(self, key, value):
        if getattr(self, '_sealed', False):
            raise SMBProtocolError('SOURCE_UNAVAILABLE')
        return super().__setitem__(key, value)


class _RealSMBProtocol:
    smb_3_1_1 = Dialects.SMB_3_1_1

    def configure_global(self, **kwargs):
        ClientConfig(**kwargs)

    def new_connection(
        self,
        *,
        server,
        port,
        require_signing,
        dialect,
        timeout,
        io_idle_timeout,
    ):
        connection = Connection(
            uuid.uuid4(),
            server,
            port,
            require_signing=require_signing,
        )
        # smbprotocol intentionally exposes this as its experimental bounded
        # receive timeout.  Keeping the dependency access here contains API
        # drift to this single, pinned-version module.
        connection._receive_timeout = io_idle_timeout
        connection.connect(dialect=dialect, timeout=timeout)
        return connection

    @staticmethod
    def connection_supports_encryption(connection):
        # SMB 3.1.1 advertises the selected cipher in a negotiate context;
        # smbprotocol folds both the legacy capability bit and that context
        # into this version-pinned boolean.
        return connection.supports_encryption is True

    @staticmethod
    def new_session(
        connection,
        *,
        username,
        password,
        require_encryption,
        auth_protocol,
    ):
        return Session(
            connection,
            username=username,
            password=password,
            require_encryption=require_encryption,
            auth_protocol=auth_protocol,
        )

    @staticmethod
    def session_is_guest_or_null(session):
        flags = getattr(session, 'session_flags', 0)
        return bool(
            flags
            & (
                SessionFlags.SMB2_SESSION_FLAG_IS_GUEST
                | SessionFlags.SMB2_SESSION_FLAG_IS_NULL
            )
        )

    @staticmethod
    def close_connection(connection, *, timeout):
        connection.disconnect(close=True, timeout=timeout)

    @staticmethod
    def invoke(name, *args, **kwargs):
        no_follow_operations = {
            'open_file_no_follow': 'open_file',
            'scandir_no_follow': 'scandir',
            'mkdir_no_follow': 'mkdir',
        }
        if name in no_follow_operations:
            name = no_follow_operations[name]
            kwargs['create_options'] = (
                int(kwargs.get('create_options', 0))
                | int(CreateOptions.FILE_OPEN_REPARSE_POINT)
            )
        operation = getattr(smbclient, name, None)
        if operation is None or name.startswith('_'):
            raise SMBProtocolError('OPERATION_UNAVAILABLE')
        try:
            result = operation(*args, **kwargs)
            return _MappedIterator(result) if name == 'scandir' else result
        except Exception as exc:
            mapped = _mapped_protocol_error(exc)
            if mapped is not None:
                raise mapped from exc
            raise


class SMBProtocolSession:
    """One authenticated, encrypted SMB transport owned by one source."""

    def __init__(
        self,
        *,
        protocol,
        target_ip,
        canonical_host,
        raw_connection,
        raw_session,
        io_idle_timeout,
    ):
        self._protocol = protocol
        self.target_ip = target_ip
        self.canonical_host = canonical_host
        self.raw_connection = raw_connection
        self.raw_session = raw_session
        self.io_idle_timeout = io_idle_timeout
        self.dialect = raw_connection.dialect
        self.encrypted = True
        self.signed = True
        self.secure_negotiate = True
        self._lock = RLock()
        self._closed = False
        self.connection_cache = _SealedConnectionCache(
            f'{target_ip.lower()}:445',
            raw_connection,
        )

    def _ensure_alive(self):
        transport = getattr(self.raw_connection, 'transport', None)
        if self._closed or transport is None or not transport.connected:
            raise SMBProtocolError('SOURCE_UNAVAILABLE')

    def invoke(self, name, *args, **kwargs):
        """Run one high-level operation without allowing implicit reconnect."""

        with self._lock:
            self._ensure_alive()
            call_kwargs = {
                'username': self.raw_session.username,
                'password': None,
                'port': 445,
                'encrypt': True,
                'connection_timeout': self.io_idle_timeout,
                'connection_cache': self.connection_cache,
                'auth_protocol': 'ntlm',
                'require_signing': True,
            }
            call_kwargs.update(kwargs)
            try:
                return self._protocol.invoke(name, *args, **call_kwargs)
            except SMBProtocolError:
                raise
            except Exception as exc:
                raise SMBProtocolError('OPERATION_FAILED') from exc

    def close(self):
        with self._lock:
            if self._closed:
                return False
            self._closed = True
            self.connection_cache.clear()
            try:
                self._protocol.close_connection(
                    self.raw_connection,
                    timeout=self.io_idle_timeout,
                )
            except Exception:
                pass
            return True


class SMBProtocolClient:
    """Create strictly negotiated SMB sessions from already-approved IPs."""

    def __init__(self, protocol=None):
        self._protocol = protocol or _RealSMBProtocol()
        self._protocol.configure_global(
            username=None,
            password=None,
            domain_controller=None,
            skip_dfs=True,
            auth_protocol='ntlm',
            require_secure_negotiate=True,
        )

    @staticmethod
    def _cancelled(cancel_event):
        return cancel_event is not None and cancel_event.is_set()

    def connect(
        self,
        *,
        target_ip,
        canonical_host,
        username,
        password,
        timeout,
        io_idle_timeout,
        cancel_event=None,
    ):
        if self._cancelled(cancel_event):
            raise SMBProtocolError('CONNECT_CANCELLED')

        connection = None
        raw_session = None
        try:
            connection = self._protocol.new_connection(
                server=target_ip,
                port=445,
                require_signing=True,
                dialect=self._protocol.smb_3_1_1,
                timeout=timeout,
                io_idle_timeout=io_idle_timeout,
            )
            if connection.dialect != self._protocol.smb_3_1_1:
                raise SMBProtocolError('DIALECT_REQUIRED')
            if not self._protocol.connection_supports_encryption(connection):
                raise SMBProtocolError('ENCRYPTION_REQUIRED')
            if self._cancelled(cancel_event):
                raise SMBProtocolError('CONNECT_CANCELLED')

            raw_session = self._protocol.new_session(
                connection,
                username=username,
                password=password,
                require_encryption=True,
                auth_protocol='ntlm',
            )
            raw_session.connect()
            if self._protocol.session_is_guest_or_null(raw_session):
                raise SMBProtocolError('AUTHENTICATION_REQUIRED')
            if not getattr(raw_session, 'encrypt_data', False):
                raise SMBProtocolError('ENCRYPTION_REQUIRED')
            if self._cancelled(cancel_event):
                raise SMBProtocolError('CONNECT_CANCELLED')

            raw_session.password = None
            return SMBProtocolSession(
                protocol=self._protocol,
                target_ip=target_ip,
                canonical_host=canonical_host,
                raw_connection=connection,
                raw_session=raw_session,
                io_idle_timeout=io_idle_timeout,
            )
        except SMBProtocolError:
            if raw_session is not None:
                raw_session.password = None
            if connection is not None:
                try:
                    self._protocol.close_connection(
                        connection,
                        timeout=io_idle_timeout,
                    )
                except Exception:
                    pass
            raise
        except Exception as exc:
            if raw_session is not None:
                raw_session.password = None
            if connection is not None:
                try:
                    self._protocol.close_connection(
                        connection,
                        timeout=io_idle_timeout,
                    )
                except Exception:
                    pass
            mapped = _mapped_protocol_error(exc)
            if mapped is not None:
                raise mapped from exc
            raise SMBProtocolError('CONNECTION_FAILED') from exc
