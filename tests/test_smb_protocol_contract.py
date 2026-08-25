from __future__ import annotations

from dataclasses import dataclass
from threading import Event

import pytest
from smbprotocol.exceptions import LogonFailure, SMBOSError
from smbprotocol.header import NtStatus

from app.smb_protocol import (
    SMBProtocolClient,
    SMBProtocolError,
    SMBProtocolSession,
)


@dataclass
class _Transport:
    connected: bool = True


class _Connection:
    def __init__(self, events):
        self.events = events
        self.transport = _Transport()
        self.dialect = 'SMB_3_1_1'
        self.supports_encryption = True
        self.disconnected = 0

    def disconnect(self, close=True, timeout=None):
        self.disconnected += 1
        self.transport.connected = False


class _Session:
    def __init__(self, connection, username, password):
        self.connection = connection
        self.username = username
        self.password = password
        self.require_encryption = True
        self.auth_protocol = 'ntlm'
        self.encrypt_data = False
        self._connected = False

    def connect(self):
        self.connection.events.append(('session-connect', self.password))
        self.encrypt_data = True
        self._connected = True


class _FakeProtocol:
    smb_3_1_1 = 'SMB_3_1_1'

    def __init__(self):
        self.events = []
        self.connections = []
        self.sessions = []
        self.global_policy = None

    def configure_global(self, **kwargs):
        self.global_policy = kwargs

    def new_connection(self, **kwargs):
        self.events.append(('connection-connect', kwargs))
        connection = _Connection(self.events)
        self.connections.append(connection)
        return connection

    def connection_supports_encryption(self, connection):
        return connection.supports_encryption

    def new_session(self, connection, *, username, password, require_encryption, auth_protocol):
        self.events.append((
            'session-create',
            {
                'username': username,
                'password': password,
                'require_encryption': require_encryption,
                'auth_protocol': auth_protocol,
            },
        ))
        session = _Session(connection, username, password)
        self.sessions.append(session)
        return session

    def session_is_guest_or_null(self, _session):
        return False

    def close_connection(self, connection, *, timeout):
        connection.disconnect(close=True, timeout=timeout)

    def invoke(self, _name, *_args, **_kwargs):
        return 'ok'


def _connect(protocol=None, *, cancel_event=None):
    protocol = protocol or _FakeProtocol()
    session = SMBProtocolClient(protocol).connect(
        target_ip='192.0.2.10',
        canonical_host='nas.example',
        username=r'DOMAIN\alice',
        password='Secret-Sentinel-42!',
        timeout=10,
        io_idle_timeout=30,
        cancel_event=cancel_event or Event(),
    )
    return protocol, session


def test_global_policy_is_credential_free_ntlm_and_dfs_disabled():
    protocol = _FakeProtocol()

    SMBProtocolClient(protocol)

    assert protocol.global_policy == {
        'username': None,
        'password': None,
        'domain_controller': None,
        'skip_dfs': True,
        'auth_protocol': 'ntlm',
        'require_secure_negotiate': True,
    }


def test_connect_negotiates_exact_dialect_and_encryption_before_authentication():
    protocol, session = _connect()

    assert protocol.events[0] == ('connection-connect', {
        'server': '192.0.2.10',
        'port': 445,
        'require_signing': True,
        'dialect': 'SMB_3_1_1',
        'timeout': 10,
        'io_idle_timeout': 30,
    })
    assert protocol.events[1][0] == 'session-create'
    assert protocol.events[1][1]['require_encryption'] is True
    assert protocol.events[1][1]['auth_protocol'] == 'ntlm'
    assert session.dialect == 'SMB_3_1_1'
    assert session.encrypted is True
    assert session.signed is True
    assert session.secure_negotiate is True


def test_session_password_reference_is_cleared_after_connect():
    protocol, session = _connect()

    assert protocol.sessions[0].password is None
    assert session.raw_session.password is None


def test_encryption_failure_closes_before_credentials_reach_session():
    protocol = _FakeProtocol()

    original_new_connection = protocol.new_connection

    def unsupported_connection(**kwargs):
        connection = original_new_connection(**kwargs)
        connection.supports_encryption = False
        return connection

    protocol.new_connection = unsupported_connection

    with pytest.raises(SMBProtocolError) as exc:
        _connect(protocol)

    assert exc.value.public_code == 'ENCRYPTION_REQUIRED'
    assert exc.value.diagnostic_phase == 'security_requirements'
    assert exc.value.diagnostic_exception_type is None
    assert exc.value.diagnostic_nt_status is None
    assert not protocol.sessions
    assert protocol.connections[0].disconnected == 1


def test_unknown_negotiate_failure_keeps_safe_diagnostic_metadata():
    protocol = _FakeProtocol()

    def fail_connect(**_kwargs):
        raise ConnectionResetError(r'secret \\server\share')

    protocol.new_connection = fail_connect

    with pytest.raises(SMBProtocolError) as exc:
        _connect(protocol)

    assert exc.value.public_code == 'CONNECTION_FAILED'
    assert exc.value.diagnostic_phase == 'transport_negotiate'
    assert exc.value.diagnostic_exception_type == 'ConnectionResetError'
    assert exc.value.diagnostic_nt_status is None
    assert 'secret' not in str(exc.value)
    assert 'server' not in str(exc.value)


def test_cancel_before_connect_performs_no_protocol_operation():
    protocol = _FakeProtocol()
    cancel_event = Event()
    cancel_event.set()

    with pytest.raises(SMBProtocolError) as exc:
        _connect(protocol, cancel_event=cancel_event)

    assert exc.value.public_code == 'CONNECT_CANCELLED'
    assert protocol.events == []


@pytest.mark.parametrize(('status', 'expected_status'), [
    (NtStatus.STATUS_LOGON_FAILURE, '0xC000006D'),
    (NtStatus.STATUS_WRONG_PASSWORD, '0xC000006A'),
    (NtStatus.STATUS_PASSWORD_EXPIRED, '0xC0000071'),
])
def test_authentication_statuses_map_to_stable_authentication_error(
    status,
    expected_status,
):
    protocol = _FakeProtocol()
    original_new_session = protocol.new_session

    def failing_session(*args, **kwargs):
        session = original_new_session(*args, **kwargs)

        def fail_connect():
            raise SMBOSError(status, 'redacted')

        session.connect = fail_connect
        return session

    protocol.new_session = failing_session

    with pytest.raises(SMBProtocolError) as exc:
        _connect(protocol)

    assert exc.value.public_code == 'AUTHENTICATION_REQUIRED'
    assert exc.value.diagnostic_phase == 'session_authentication'
    assert exc.value.diagnostic_exception_type == 'SMBOSError'
    assert exc.value.diagnostic_nt_status == expected_status
    assert protocol.sessions[0].password is None
    assert protocol.connections[0].disconnected == 1


def test_smbprotocol_logon_failure_maps_to_authentication_error():
    protocol = _FakeProtocol()
    original_new_session = protocol.new_session

    def failing_session(*args, **kwargs):
        session = original_new_session(*args, **kwargs)
        session.connect = lambda: (_ for _ in ()).throw(LogonFailure())
        return session

    protocol.new_session = failing_session

    with pytest.raises(SMBProtocolError) as exc:
        _connect(protocol)

    assert exc.value.public_code == 'AUTHENTICATION_REQUIRED'
    assert protocol.sessions[0].password is None
    assert protocol.connections[0].disconnected == 1


def test_each_source_uses_a_private_sealed_connection_cache():
    _protocol, first = _connect()
    _protocol, second = _connect()

    assert first.connection_cache is not second.connection_cache
    assert len(first.connection_cache) == len(second.connection_cache) == 1
    with pytest.raises(SMBProtocolError) as exc:
        first.connection_cache.get('unexpected.example:445')
    assert exc.value.public_code == 'SOURCE_UNAVAILABLE'


def test_dead_source_fails_closed_before_high_level_operation():
    protocol, session = _connect()
    protocol.connections[0].transport.connected = False

    with pytest.raises(SMBProtocolError) as exc:
        session.invoke('stat', r'\\192.0.2.10\Docs\report.txt')

    assert exc.value.public_code == 'SOURCE_UNAVAILABLE'
    assert [event for event in protocol.events if event[0] == 'connection-connect'] == [
        protocol.events[0],
    ]


def test_close_is_idempotent_and_clears_private_cache():
    protocol, session = _connect()

    assert session.close() is True
    assert session.close() is False
    assert session.connection_cache == {}
    assert protocol.connections[0].disconnected == 1


def test_only_protocol_boundary_imports_smb_packages():
    from pathlib import Path

    app_root = Path(__file__).resolve().parents[1] / 'app'
    offenders = []
    for path in app_root.glob('*.py'):
        if path.name == 'smb_protocol.py':
            continue
        text = path.read_text(encoding='utf-8')
        if 'import smbclient' in text or 'import smbprotocol' in text or 'from smbprotocol' in text:
            offenders.append(path.name)
    assert offenders == []


def test_no_follow_open_sets_the_smb_reparse_point_option(monkeypatch):
    from smbprotocol.open import CreateOptions

    from app import smb_protocol

    captured = {}

    def open_file(path, **kwargs):
        captured['path'] = path
        captured['kwargs'] = kwargs
        return 'opened'

    monkeypatch.setattr(smb_protocol.smbclient, 'open_file', open_file)

    result = smb_protocol._RealSMBProtocol.invoke(
        'open_file_no_follow',
        r'\\server\Docs\report.txt',
        mode='wb',
    )

    assert result == 'opened'
    assert captured['path'] == r'\\server\Docs\report.txt'
    assert captured['kwargs']['create_options'] & int(
        CreateOptions.FILE_OPEN_REPARSE_POINT
    )


def test_no_follow_scandir_sets_the_smb_reparse_point_option(monkeypatch):
    from smbprotocol.open import CreateOptions

    from app import smb_protocol

    captured = {}

    class Iterator:
        def __iter__(self):
            return self

        def __next__(self):
            raise StopIteration

        def close(self):
            return None

    def scandir(path, **kwargs):
        captured['path'] = path
        captured['kwargs'] = kwargs
        return Iterator()

    monkeypatch.setattr(smb_protocol.smbclient, 'scandir', scandir)

    result = smb_protocol._RealSMBProtocol.invoke(
        'scandir_no_follow',
        r'\\server\Docs\folder',
    )

    assert list(result) == []
    assert captured['path'] == r'\\server\Docs\folder'
    assert captured['kwargs']['create_options'] & int(
        CreateOptions.FILE_OPEN_REPARSE_POINT
    )


def test_share_root_inspection_lists_and_probes_directory_access_without_mutation():
    from smbprotocol.open import DirectoryAccessMask

    protocol, session = _connect()
    calls = []
    closed = []

    class Iterator:
        def __iter__(self):
            return self

        def __next__(self):
            raise StopIteration

        def close(self):
            closed.append('listing')

    class DirectoryHandle:
        def close(self):
            closed.append('directory')

    def invoke(name, path, **kwargs):
        calls.append((name, path, kwargs))
        if name == 'scandir_no_follow':
            return Iterator()
        return DirectoryHandle()

    protocol.invoke = invoke

    access = session.inspect_directory_access(r'\\10.0.0.8\Docs')

    assert access == {
        'list': 'granted',
        'create_file': 'granted',
        'create_directory': 'granted',
        'delete_children': 'granted',
    }
    assert calls[0][0] == 'scandir_no_follow'
    assert [call[2]['desired_access'] for call in calls[1:]] == [
        int(DirectoryAccessMask.FILE_ADD_FILE),
        int(DirectoryAccessMask.FILE_ADD_SUBDIRECTORY),
        int(DirectoryAccessMask.FILE_DELETE_CHILD),
    ]
    for name, path, kwargs in calls[1:]:
        assert name == 'open_file_no_follow'
        assert path == r'\\10.0.0.8\Docs'
        assert kwargs['file_type'] == 'dir'
        assert kwargs['mode'] == 'rb'
        assert kwargs['buffering'] == 0
        assert 'create_disposition' not in kwargs
    assert closed == ['listing', 'directory', 'directory', 'directory']


def test_share_root_inspection_marks_only_access_denied_as_denied():
    protocol, session = _connect()
    responses = iter((
        SMBProtocolError('PERMISSION_DENIED'),
        SMBProtocolError('TIMEOUT'),
        SMBProtocolError('OPERATION_FAILED'),
    ))

    class Iterator:
        def __iter__(self):
            return self

        def __next__(self):
            raise StopIteration

        def close(self):
            return None

    def invoke(name, _path, **_kwargs):
        if name == 'scandir_no_follow':
            return Iterator()
        raise next(responses)

    protocol.invoke = invoke

    assert session.inspect_directory_access(r'\\10.0.0.8\Docs') == {
        'list': 'granted',
        'create_file': 'denied',
        'create_directory': 'unknown',
        'delete_children': 'unknown',
    }


def test_share_root_listing_failure_is_not_downgraded_to_unknown():
    protocol, session = _connect()
    protocol.invoke = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        SMBProtocolError('SHARE_UNAVAILABLE')
    )

    with pytest.raises(SMBProtocolError) as exc:
        session.inspect_directory_access(r'\\10.0.0.8\Missing')

    assert exc.value.public_code == 'SHARE_UNAVAILABLE'


def test_public_session_type_is_explicit():
    _protocol, session = _connect()

    assert isinstance(session, SMBProtocolSession)
