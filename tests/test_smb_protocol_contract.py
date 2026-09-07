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


def test_real_global_policy_clears_and_blocks_process_wide_dfs(monkeypatch):
    from app import smb_protocol

    config = smb_protocol.ClientConfig()
    # ClientConfig is a dependency-owned process singleton. Register every
    # mutated attribute with monkeypatch so this contract test cannot leak its
    # seeded caches or method overrides into another test.
    for attribute in (
        '_referral_cache',
        '_domain_cache',
        'lookup_referral',
        'lookup_domain',
        'cache_referral',
    ):
        monkeypatch.setattr(config, attribute, getattr(config, attribute))
    config._referral_cache = [object()]
    config._domain_cache = [object()]

    smb_protocol._RealSMBProtocol().configure_global(
        username=None,
        password=None,
        domain_controller=None,
        skip_dfs=True,
        auth_protocol='ntlm',
        require_secure_negotiate=True,
    )

    assert config._referral_cache == []
    assert config._domain_cache == []
    assert config.lookup_referral(['server', 'share']) is None
    assert config.lookup_domain('server') is None
    with pytest.raises(SMBProtocolError) as error:
        config.cache_referral(object())
    assert error.value.public_code == 'SHARE_UNAVAILABLE'


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


@pytest.mark.parametrize('status', [
    NtStatus.STATUS_FILE_IS_A_DIRECTORY,
    NtStatus.STATUS_NOT_A_DIRECTORY,
])
def test_object_type_race_statuses_map_to_conflict(status):
    from app import smb_protocol

    mapped = smb_protocol._mapped_protocol_error(
        SMBOSError(status, 'redacted')
    )

    assert mapped.public_code == 'CONFLICT'


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


@pytest.mark.parametrize(
    ('share_name', 'is_dfs_share'),
    (
        (r'\\server\OtherShare', False),
        (r'\\server\Docs', True),
        (None, False),
        (r'\\server\Docs', None),
    ),
)
def test_raw_open_rejects_dfs_and_cross_share_tree_bindings(
    monkeypatch,
    share_name,
    is_dfs_share,
):
    from types import SimpleNamespace

    from app import smb_protocol

    opened = []

    class Raw:
        def __init__(self, *_args, **_kwargs):
            self.fd = SimpleNamespace(
                file_attributes=int(
                    smb_protocol.FileAttributes.FILE_ATTRIBUTE_DIRECTORY
                ),
                tree_connect=SimpleNamespace(
                    share_name=share_name,
                    is_dfs_share=is_dfs_share,
                ),
            )
            self.closed = False
            self.opened = False
            opened.append(self)

        def open(self):
            self.opened = True

        def close(self):
            self.closed = True

    monkeypatch.setattr(smb_protocol, 'SMBDirectoryIO', Raw)

    with pytest.raises(SMBProtocolError) as error:
        smb_protocol._open_raw(
            r'\\server\Docs\folder',
            is_directory=True,
            desired_access=1,
            connection_kwargs={},
        )

    assert error.value.public_code == 'SHARE_UNAVAILABLE'
    assert opened[0].opened is False
    assert opened[0].closed is True


def test_raw_open_accepts_a_direct_binding_to_the_requested_share(monkeypatch):
    from types import SimpleNamespace

    from app import smb_protocol

    class Raw:
        def __init__(self, *_args, **_kwargs):
            self.fd = SimpleNamespace(
                file_attributes=int(
                    smb_protocol.FileAttributes.FILE_ATTRIBUTE_DIRECTORY
                ),
                tree_connect=SimpleNamespace(
                    share_name=r'\\SERVER\DOCS\\',
                    is_dfs_share=False,
                ),
            )
            self.closed = False

        def open(self):
            return None

        def close(self):
            self.closed = True

    monkeypatch.setattr(smb_protocol, 'SMBDirectoryIO', Raw)

    raw = smb_protocol._open_raw(
        r'\\server\Docs\folder',
        is_directory=True,
        desired_access=1,
        connection_kwargs={},
    )

    assert raw.closed is False
    raw.close()


def test_raw_open_rechecks_share_binding_after_create(monkeypatch):
    from types import SimpleNamespace

    from app import smb_protocol

    opened = []

    class Raw:
        def __init__(self, *_args, **_kwargs):
            self.fd = SimpleNamespace(
                file_attributes=int(
                    smb_protocol.FileAttributes.FILE_ATTRIBUTE_DIRECTORY
                ),
                tree_connect=SimpleNamespace(
                    share_name=r'\\server\Docs',
                    is_dfs_share=False,
                ),
            )
            self.closed = False
            opened.append(self)

        def open(self):
            self.fd.tree_connect = SimpleNamespace(
                share_name=r'\\server\Redirected',
                is_dfs_share=False,
            )

        def close(self):
            self.closed = True

    monkeypatch.setattr(smb_protocol, 'SMBDirectoryIO', Raw)

    with pytest.raises(SMBProtocolError) as error:
        smb_protocol._open_raw(
            r'\\server\Docs\folder',
            is_directory=True,
            desired_access=1,
            connection_kwargs={},
        )

    assert error.value.public_code == 'SHARE_UNAVAILABLE'
    assert opened[0].closed is True


def test_each_source_uses_a_private_sealed_connection_cache():
    _protocol, first = _connect()
    _protocol, second = _connect()

    assert first.connection_cache is not second.connection_cache
    assert len(first.connection_cache) == len(second.connection_cache) == 1
    with pytest.raises(SMBProtocolError) as exc:
        first.connection_cache.get('unexpected.example:445')
    assert exc.value.public_code == 'SOURCE_UNAVAILABLE'


def test_sealed_connection_cache_returns_only_its_live_connection():
    _protocol, session = _connect()
    key = '192.0.2.10:445'

    assert session.connection_cache.get(key) is session.raw_connection

    session.raw_connection.transport.connected = False
    with pytest.raises(SMBProtocolError) as exc:
        session.connection_cache.get(key)

    assert exc.value.public_code == 'SOURCE_UNAVAILABLE'
    assert session.connection_cache[key] is session.raw_connection


def test_sealed_dead_cache_stops_dependency_before_reconnect(monkeypatch):
    from smbclient import _pool

    _protocol, session = _connect()
    session.raw_connection.transport.connected = False
    constructions = []

    def unexpected_connection(*args, **kwargs):
        constructions.append((args, kwargs))
        raise AssertionError('a sealed source must never reconnect')

    monkeypatch.setattr(_pool, 'Connection', unexpected_connection)

    with pytest.raises(SMBProtocolError) as error:
        _pool.register_session(
            '192.0.2.10',
            connection_cache=session.connection_cache,
        )

    assert error.value.public_code == 'SOURCE_UNAVAILABLE'
    assert constructions == []


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


@pytest.mark.parametrize('transport_only_disconnect_fails', [False, True])
def test_real_close_forces_transport_shutdown_after_session_cleanup_failure(
    transport_only_disconnect_fails,
):
    from app import smb_protocol

    events = []

    class Transport:
        connected = True

        def close(self):
            events.append(('transport-close',))
            self.connected = False

    class Connection:
        def __init__(self):
            self.transport = Transport()

        def disconnect(self, close=True, timeout=None):
            events.append(('disconnect', close, timeout))
            if close:
                raise RuntimeError('session cleanup failed')
            if transport_only_disconnect_fails:
                raise RuntimeError('transport-only cleanup failed')
            self.transport.close()

    connection = Connection()

    with pytest.raises(RuntimeError, match='session cleanup failed'):
        smb_protocol._RealSMBProtocol.close_connection(
            connection,
            timeout=19,
        )

    assert events[:2] == [
        ('disconnect', True, 19),
        ('disconnect', False, 19),
    ]
    assert events[-1] == ('transport-close',)
    assert connection.transport.connected is False


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
        if name == 'scandir_verified':
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
    assert calls[0][0] == 'scandir_verified'
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
        if name == 'scandir_verified':
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


@pytest.mark.parametrize(
    ('operation', 'args', 'kwargs'),
    [
        ('remove', (r'\\10.0.0.8\Docs\file.txt',), {}),
        ('delete_verified', (r'\\10.0.0.8\Docs\file.txt',), {}),
        ('delete_open_handle_verified', (object(),), {}),
        ('create_file_move_verified', (r'\\10.0.0.8\Docs\file.txt',), {}),
        ('open_file_move_verified', (r'\\10.0.0.8\Docs\file.txt',), {}),
        (
            'rename',
            (
                r'\\10.0.0.8\Docs\old.txt',
                r'\\10.0.0.8\Docs\new.txt',
            ),
            {},
        ),
        (
            'rename_verified',
            (
                r'\\10.0.0.8\Docs\old.txt',
                r'\\10.0.0.8\Docs\new.txt',
            ),
            {},
        ),
        (
            'rename_open_handle_verified',
            (object(), r'\\10.0.0.8\Docs\new.txt'),
            {},
        ),
        (
            'open_file_no_follow',
            (r'\\10.0.0.8\Docs\new.txt',),
            {'mode': 'xb'},
        ),
        (
            'open_file_no_follow',
            (r'\\10.0.0.8\Docs\existing.txt',),
            {'mode': 'r+'},
        ),
        (
            'open_file_no_follow',
            (r'\\10.0.0.8\Docs\existing.txt',),
            {'mode': 'rb+'},
        ),
        (
            'open_file_no_follow',
            (r'\\10.0.0.8\Docs\existing.txt',),
            {'mode': 'r+b'},
        ),
        (
            'open_file',
            (r'\\10.0.0.8\Docs\existing.txt',),
            {'mode': 'wb'},
        ),
    ],
)
def test_protocol_rejects_mutations_without_pinned_ancestor_handles(
    operation,
    args,
    kwargs,
):
    protocol, session = _connect()

    with pytest.raises(SMBProtocolError) as error:
        session.invoke(operation, *args, **kwargs)

    assert error.value.public_code == 'MUTATION_GUARD_REQUIRED'
    assert protocol.events[-1][0] == 'session-connect'


@pytest.mark.parametrize('mode', ['r', 'rb', 'rt'])
def test_protocol_allows_read_only_file_opens_without_mutation_guard(mode):
    protocol, session = _connect()
    protocol.invoke = lambda name, *args, **kwargs: (name, args, kwargs)

    name, _args, kwargs = session.invoke(
        'open_file_no_follow',
        r'\\10.0.0.8\Docs\report.txt',
        mode=mode,
    )

    assert name == 'open_file_no_follow'
    assert kwargs['mode'] == mode


def test_verified_ancestor_handle_stays_open_through_mutation_guard():
    from app.smb_protocol import SMBObjectInfo

    protocol, session = _connect()
    calls = []

    class DirectoryHandle:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    handle = DirectoryHandle()
    info = SMBObjectInfo('safe', 72, 0x10, 0, 0, 1, (72,))

    def invoke(name, *args, **kwargs):
        calls.append((name, args, kwargs, handle.closed))
        if name == 'open_directory_verified':
            return handle, info
        return 'mutated'

    protocol.invoke = invoke
    parent = r'\\10.0.0.8\Docs\safe'
    leaf = parent + r'\file.txt'

    with session.pin_mutation_ancestors([parent]):
        assert session.invoke('remove', leaf) == 'mutated'
        assert handle.closed is False

    assert handle.closed is True
    assert [call[0] for call in calls] == [
        'open_directory_verified',
        'remove',
    ]


def test_verified_guard_rejects_reparse_ancestor_before_mutation():
    protocol, session = _connect()
    calls = []

    def invoke(name, *_args, **_kwargs):
        calls.append(name)
        if name == 'open_directory_verified':
            raise SMBProtocolError('REPARSE_POINT_REJECTED')
        raise AssertionError('mutation reached the protocol')

    protocol.invoke = invoke

    with pytest.raises(SMBProtocolError) as error:
        with session.pin_mutation_ancestors([
            r'\\10.0.0.8\Docs\unsafe'
        ]):
            session.invoke('remove', r'\\10.0.0.8\Docs\unsafe\file.txt')

    assert error.value.public_code == 'REPARSE_POINT_REJECTED'
    assert calls == ['open_directory_verified']


@pytest.mark.parametrize(
    ('identity', 'expected_code'),
    [(72, 'CONFLICT'), (0, 'IDENTITY_UNAVAILABLE')],
)
def test_verified_guard_rejects_bad_identity_and_closes_handle(
    identity,
    expected_code,
):
    from app.smb_protocol import SMBObjectInfo

    protocol, session = _connect()

    class DirectoryHandle:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    handle = DirectoryHandle()
    info = SMBObjectInfo('safe', identity, 0x10, 0, 0, 1)
    protocol.invoke = lambda *_args, **_kwargs: (handle, info)
    parent = r'\\10.0.0.8\Docs\safe'

    with pytest.raises(SMBProtocolError) as error:
        with session.pin_directories(
            [parent],
            expected_identities={parent: 71},
        ):
            pass

    assert error.value.public_code == expected_code
    assert handle.closed is True


def _object_info(
    name,
    identity,
    *,
    directory=False,
    links=1,
    chain=(),
    attributes=None,
):
    from app.smb_protocol import SMBObjectInfo

    return SMBObjectInfo(
        name,
        identity,
        (0x10 if directory else 0) if attributes is None else attributes,
        0,
        0,
        links,
        chain,
    )


def test_verified_walk_binds_each_parent_entry_to_the_opened_child(monkeypatch):
    from app import smb_protocol

    events = []

    class Handle:
        def __init__(self, path):
            self.path = path
            self.closed = False

        def close(self):
            self.closed = True
            events.append(('close', self.path))

    handles = {}

    def open_raw(path, **_kwargs):
        handle = handles[path] = Handle(path)
        events.append(('open', path))
        return handle

    entries = {
        (r'\\server\Docs', 'safe'): _object_info(
            'safe', 10, directory=True
        ),
        (r'\\server\Docs\safe', 'file.txt'): _object_info(
            'file.txt', 20
        ),
    }
    opened = {
        r'\\server\Docs': _object_info('', 1, directory=True),
        r'\\server\Docs\safe': _object_info('safe', 10, directory=True),
        r'\\server\Docs\safe\file.txt': _object_info('file.txt', 20),
    }
    monkeypatch.setattr(smb_protocol, '_open_raw', open_raw)
    monkeypatch.setattr(
        smb_protocol,
        '_query_exact_child',
        lambda handle, name: entries[(handle.path, name)],
    )
    monkeypatch.setattr(
        smb_protocol,
        '_query_open_info',
        lambda handle, **_kwargs: opened[handle.path],
    )

    raw, info = smb_protocol._open_verified_path(
        r'\\server\Docs\safe\file.txt',
        purpose='file_read',
    )

    assert raw is handles[r'\\server\Docs\safe\file.txt']
    assert raw.closed is False
    assert info.identity_chain == (10, 20)
    assert handles[r'\\server\Docs'].closed is True
    assert handles[r'\\server\Docs\safe'].closed is True


@pytest.mark.parametrize(
    ('opened_ids', 'expected_opens'),
    [
        ({'safe': 99, 'file.txt': 20}, 2),
        ({'safe': 10, 'file.txt': 99}, 3),
    ],
)
def test_verified_walk_rejects_intermediate_and_leaf_swaps(
    monkeypatch,
    opened_ids,
    expected_opens,
):
    from app import smb_protocol

    handles = []

    class Handle:
        def __init__(self, path):
            self.path = path
            self.closed = False

        def close(self):
            self.closed = True

    def open_raw(path, **_kwargs):
        handle = Handle(path)
        handles.append(handle)
        return handle

    def exact_child(handle, name):
        return _object_info(
            name,
            10 if name == 'safe' else 20,
            directory=name == 'safe',
        )

    def open_info(handle, **_kwargs):
        name = handle.path.rsplit('\\', 1)[-1]
        return _object_info(
            name,
            opened_ids.get(name, 1),
            directory=name in {'Docs', 'safe'},
        )

    monkeypatch.setattr(smb_protocol, '_open_raw', open_raw)
    monkeypatch.setattr(smb_protocol, '_query_exact_child', exact_child)
    monkeypatch.setattr(smb_protocol, '_query_open_info', open_info)

    with pytest.raises(SMBProtocolError) as error:
        smb_protocol._open_verified_path(
            r'\\server\Docs\safe\file.txt',
            purpose='file_read',
        )

    assert error.value.public_code == 'CONFLICT'
    assert len(handles) == expected_opens
    assert all(handle.closed for handle in handles)


@pytest.mark.parametrize('purpose', ['file_read', 'stat'])
def test_verified_walk_preserves_known_file_access_when_listing_is_denied(
    monkeypatch,
    purpose,
):
    from app import smb_protocol

    root = r'\\server\Docs'
    protected = root + r'\protected'
    leaf = protected + r'\file.txt'
    identities = {root: 1, protected: 10, leaf: 20}
    successful = []
    attempts = []

    list_access = int(
        smb_protocol.DirectoryAccessMask.FILE_LIST_DIRECTORY
        | smb_protocol.DirectoryAccessMask.FILE_READ_ATTRIBUTES
    )
    read_attributes = int(
        smb_protocol.FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES
    )

    class Handle:
        def __init__(self, path):
            self.path = path
            self.close_count = 0
            successful.append(self)

        def close(self):
            self.close_count += 1

    def open_raw(path, *, desired_access, **_kwargs):
        attempts.append((path, desired_access))
        if path == protected and desired_access == list_access:
            raise SMBProtocolError('PERMISSION_DENIED')
        return Handle(path)

    def exact_child(handle, name):
        assert handle.path == root
        assert name == 'protected'
        return _object_info(name, 10, directory=True)

    def open_info(handle, **_kwargs):
        return _object_info(
            handle.path.rsplit('\\', 1)[-1],
            identities[handle.path],
            directory=handle.path != leaf,
        )

    monkeypatch.setattr(smb_protocol, '_open_raw', open_raw)
    monkeypatch.setattr(smb_protocol, '_open_untyped_raw', open_raw)
    monkeypatch.setattr(smb_protocol, '_query_exact_child', exact_child)
    monkeypatch.setattr(smb_protocol, '_query_open_info', open_info)

    raw, info = smb_protocol._open_verified_path(
        leaf,
        purpose=purpose,
    )

    assert raw.path == leaf
    assert raw.close_count == 0
    assert info.identity_chain == (10, 20)
    assert attempts.count((protected, list_access)) == 1
    assert attempts.count((root, read_attributes)) == 1
    # One metadata handle is retained and one independent verifier reopens it.
    assert attempts.count((protected, read_attributes)) == 2
    initial_root = successful[0]
    held_protected = next(
        handle for handle in successful[1:] if handle.path == protected
    )
    assert initial_root.close_count == 1
    assert held_protected.close_count == 1
    raw.close()
    assert all(handle.close_count == 1 for handle in successful)


def test_verified_walk_preserves_access_when_exact_child_query_is_denied(
    monkeypatch,
):
    from app import smb_protocol

    root = r'\\server\Docs'
    visible = root + r'\visible'
    opaque = visible + r'\opaque'
    leaf = opaque + r'\file.txt'
    identities = {root: 1, visible: 10, opaque: 20, leaf: 30}
    exact_queries = []
    handles = []

    class Handle:
        def __init__(self, path, desired_access, share_access):
            self.path = path
            self.desired_access = desired_access
            self.share_access = share_access
            self.closed = False
            handles.append(self)

        def close(self):
            self.closed = True

    def open_raw(
        path,
        *,
        desired_access,
        share_access='rwd',
        **_kwargs,
    ):
        return Handle(path, desired_access, share_access)

    def exact_child(handle, name):
        exact_queries.append((handle.path, name))
        if handle.path == root:
            return _object_info('visible', 10, directory=True)
        if handle.path == visible:
            raise SMBProtocolError('PERMISSION_DENIED')
        raise AssertionError('opaque directory was queried')

    def open_info(handle, **_kwargs):
        return _object_info(
            handle.path.rsplit('\\', 1)[-1],
            identities[handle.path],
            directory=handle.path != leaf,
        )

    monkeypatch.setattr(smb_protocol, '_open_raw', open_raw)
    monkeypatch.setattr(smb_protocol, '_query_exact_child', exact_child)
    monkeypatch.setattr(smb_protocol, '_query_open_info', open_info)

    raw, info = smb_protocol._open_verified_path(
        leaf,
        purpose='file_read',
    )

    assert info.identity_chain == (10, 20, 30)
    assert exact_queries == [(root, 'visible'), (visible, 'opaque')]
    visible_handles = [handle for handle in handles if handle.path == visible]
    assert [handle.share_access for handle in visible_handles[:2]] == [
        'rwd',
        'r',
    ]
    opaque_handles = [handle for handle in handles if handle.path == opaque]
    assert opaque_handles[0].share_access == 'r'
    raw.close()
    assert all(handle.closed for handle in handles)


@pytest.mark.parametrize(
    ('purpose', 'suffix', 'leaf_is_directory', 'expected_chain'),
    [
        ('file_read', r'\protected\file.txt', False, (10, 20)),
        ('stat', r'\protected\file.txt', False, (10, 20)),
        ('directory', r'\protected', True, (10,)),
        ('directory_pin', r'\protected', True, (10,)),
    ],
)
def test_verified_walk_preserves_known_paths_when_share_listing_is_denied(
    monkeypatch,
    purpose,
    suffix,
    leaf_is_directory,
    expected_chain,
):
    from app import smb_protocol

    root = r'\\server\Docs'
    target = root + suffix
    identities = {
        root: 1,
        root + r'\protected': 10,
        root + r'\protected\file.txt': 20,
    }
    list_access = int(
        smb_protocol.DirectoryAccessMask.FILE_LIST_DIRECTORY
        | smb_protocol.DirectoryAccessMask.FILE_READ_ATTRIBUTES
    )
    read_attributes = int(
        smb_protocol.FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES
    )
    attempts = []
    handles = []

    class Handle:
        def __init__(self, path, desired_access):
            self.path = path
            self.desired_access = desired_access
            self.close_count = 0
            handles.append(self)

        def close(self):
            self.close_count += 1

    def open_raw(path, *, desired_access, **_kwargs):
        attempts.append((path, desired_access))
        if path == root and desired_access == list_access:
            raise SMBProtocolError('PERMISSION_DENIED')
        return Handle(path, desired_access)

    def open_info(handle, **_kwargs):
        return _object_info(
            handle.path.rsplit('\\', 1)[-1],
            identities[handle.path],
            directory=(
                handle.path != root + r'\protected\file.txt'
            ),
        )

    monkeypatch.setattr(smb_protocol, '_open_raw', open_raw)
    monkeypatch.setattr(smb_protocol, '_open_untyped_raw', open_raw)
    monkeypatch.setattr(
        smb_protocol,
        '_query_exact_child',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError('opaque root must not be enumerated')
        ),
    )
    monkeypatch.setattr(smb_protocol, '_query_open_info', open_info)

    raw, info = smb_protocol._open_verified_path(target, purpose=purpose)

    assert info.identity_chain == expected_chain
    assert bool(info.file_attributes & 0x10) is leaf_is_directory
    assert attempts[0] == (root, list_access)
    assert {
        handle.desired_access
        for handle in handles
        if handle.path == root
    } == {read_attributes}
    assert sum(handle.close_count == 0 for handle in handles) == 1
    raw.close()
    assert all(handle.close_count == 1 for handle in handles)


@pytest.mark.parametrize(
    ('replacement_identity', 'replacement_attributes', 'expected_code'),
    [
        (99, 0x10, 'CONFLICT'),
        (10, 0, 'CONFLICT'),
        (10, 0x410, 'REPARSE_POINT_REJECTED'),
    ],
)
@pytest.mark.parametrize('purpose', ['stat', 'file_read'])
def test_verified_walk_opaque_fallback_rejects_one_way_swap(
    monkeypatch,
    purpose,
    replacement_identity,
    replacement_attributes,
    expected_code,
):
    from app import smb_protocol

    root = r'\\server\Docs'
    protected = root + r'\protected'
    leaf = protected + r'\file.txt'
    identities = {root: 1, protected: 10, leaf: 20}
    open_counts = {}
    handles = []
    list_access = int(
        smb_protocol.DirectoryAccessMask.FILE_LIST_DIRECTORY
        | smb_protocol.DirectoryAccessMask.FILE_READ_ATTRIBUTES
    )

    class Handle:
        def __init__(self, path, identity, attributes):
            self.path = path
            self.identity = identity
            self.attributes = attributes
            self.closed = False
            handles.append(self)

        def close(self):
            self.closed = True

    def open_raw(path, *, desired_access, **_kwargs):
        open_counts[path] = open_counts.get(path, 0) + 1
        if path == protected and desired_access == list_access:
            raise SMBProtocolError('PERMISSION_DENIED')
        identity = identities[path]
        attributes = 0 if path == leaf else 0x10
        # The second open of the protected directory is the verification
        # pass.  A synchronized replacement must not be accepted.
        if path == protected and open_counts[path] == 3:
            identity = replacement_identity
            attributes = replacement_attributes
        return Handle(path, identity, attributes)

    def exact_child(handle, name):
        assert handle.path == root
        assert name == 'protected'
        return _object_info(name, 10, directory=True)

    def open_info(handle, **_kwargs):
        return _object_info(
            handle.path.rsplit('\\', 1)[-1],
            handle.identity,
            attributes=handle.attributes,
        )

    monkeypatch.setattr(smb_protocol, '_open_raw', open_raw)
    monkeypatch.setattr(smb_protocol, '_open_untyped_raw', open_raw)
    monkeypatch.setattr(smb_protocol, '_query_exact_child', exact_child)
    monkeypatch.setattr(smb_protocol, '_query_open_info', open_info)

    with pytest.raises(SMBProtocolError) as error:
        smb_protocol._open_verified_path(leaf, purpose=purpose)

    assert error.value.public_code == expected_code
    assert all(handle.closed for handle in handles)


def test_verified_walk_opaque_prefix_pin_blocks_synchronized_aba(monkeypatch):
    from app import smb_protocol

    root = r'\\server\Docs'
    protected = root + r'\protected'
    leaf = protected + r'\file.txt'
    list_access = int(
        smb_protocol.DirectoryAccessMask.FILE_LIST_DIRECTORY
        | smb_protocol.DirectoryAccessMask.FILE_READ_ATTRIBUTES
    )
    state = ['original']
    list_denied = [False]
    occurrences = {}
    handles = []
    swap_attempts = []

    class Handle:
        def __init__(self, path, share_access, info):
            self.path = path
            self.share_access = share_access
            self.info = info
            self.closed = False
            handles.append(self)

        def close(self):
            self.closed = True

    def try_swap(target):
        blocked = any(
            handle.path == protected
            and not handle.closed
            and 'd' not in handle.share_access
            for handle in handles
        )
        swap_attempts.append((target, blocked))
        if not blocked:
            state[0] = target

    def object_info(path):
        if path == root:
            return _object_info('', 1, directory=True)
        if path == protected:
            return _object_info(
                'protected',
                100 if state[0] == 'original' else 200,
                directory=True,
            )
        if path == leaf:
            return _object_info(
                'file.txt',
                101 if state[0] == 'original' else 201,
            )
        raise AssertionError(f'unexpected path: {path}')

    def open_raw(
        path,
        *,
        desired_access,
        share_access='rwd',
        **_kwargs,
    ):
        if path == root and desired_access == list_access and not list_denied[0]:
            list_denied[0] = True
            raise SMBProtocolError('PERMISSION_DENIED')

        occurrence = occurrences.get(path, 0) + 1
        occurrences[path] = occurrence
        if path == protected and occurrence == 2:
            try_swap('original')
        elif path == leaf and occurrence == 2:
            try_swap('alternate')
        handle = Handle(path, share_access, object_info(path))
        if path == protected and occurrence == 1:
            try_swap('alternate')
        return handle

    monkeypatch.setattr(smb_protocol, '_open_raw', open_raw)
    monkeypatch.setattr(
        smb_protocol,
        '_query_open_info',
        lambda handle, **_kwargs: handle.info,
    )
    monkeypatch.setattr(
        smb_protocol,
        '_query_exact_child',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError('opaque root must not be enumerated')
        ),
    )

    raw, info = smb_protocol._open_verified_path(
        leaf,
        purpose='file_read',
    )

    assert info.file_id == 101
    assert info.identity_chain == (100, 101)
    assert swap_attempts == [
        ('alternate', True),
        ('original', True),
        ('alternate', True),
    ]
    protected_pin = next(
        handle
        for handle in handles
        if handle.path == protected and handle.share_access == 'r'
    )
    assert protected_pin.closed is True
    raw.close()
    assert all(handle.closed for handle in handles)


def test_verified_walk_opaque_prefix_pin_blocks_reparse_aba(monkeypatch):
    from app import smb_protocol

    root = r'\\server\Docs'
    protected = root + r'\protected'
    leaf = protected + r'\file.txt'
    list_access = int(
        smb_protocol.DirectoryAccessMask.FILE_LIST_DIRECTORY
        | smb_protocol.DirectoryAccessMask.FILE_READ_ATTRIBUTES
    )
    state = ['original']
    list_denied = [False]
    occurrences = {}
    handles = []
    mutation_attempts = []

    class Handle:
        def __init__(self, path, share_access, info):
            self.path = path
            self.share_access = share_access
            self.info = info
            self.closed = False
            handles.append(self)

        def close(self):
            self.closed = True

    def try_reparse(target):
        blocked = any(
            handle.path == protected
            and not handle.closed
            and 'w' not in handle.share_access
            for handle in handles
        )
        mutation_attempts.append((target, blocked))
        if not blocked:
            state[0] = target

    def object_info(path):
        if path == root:
            return _object_info('', 1, directory=True)
        if path == protected:
            return _object_info(
                'protected',
                100 if state[0] == 'original' else 200,
                directory=True,
            )
        if path == leaf:
            return _object_info(
                'file.txt',
                101 if state[0] == 'original' else 201,
            )
        raise AssertionError(f'unexpected path: {path}')

    def open_raw(
        path,
        *,
        desired_access,
        share_access='rwd',
        **_kwargs,
    ):
        if path == root and desired_access == list_access and not list_denied[0]:
            list_denied[0] = True
            raise SMBProtocolError('PERMISSION_DENIED')

        occurrence = occurrences.get(path, 0) + 1
        occurrences[path] = occurrence
        if path == protected and occurrence == 2:
            try_reparse('original')
        elif path == leaf and occurrence == 2:
            try_reparse('alternate')
        handle = Handle(path, share_access, object_info(path))
        if path == protected and occurrence == 1:
            try_reparse('alternate')
        return handle

    monkeypatch.setattr(smb_protocol, '_open_raw', open_raw)
    monkeypatch.setattr(
        smb_protocol,
        '_query_open_info',
        lambda handle, **_kwargs: handle.info,
    )
    monkeypatch.setattr(
        smb_protocol,
        '_query_exact_child',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError('opaque root must not be enumerated')
        ),
    )

    raw, info = smb_protocol._open_verified_path(
        leaf,
        purpose='file_read',
    )

    assert info.file_id == 101
    assert info.identity_chain == (100, 101)
    assert mutation_attempts == [
        ('alternate', True),
        ('original', True),
        ('alternate', True),
    ]
    protected_pin = next(
        handle
        for handle in handles
        if handle.path == protected and handle.share_access == 'r'
    )
    assert protected_pin.closed is True
    raw.close()
    assert all(handle.closed for handle in handles)


def test_verified_walk_does_not_fallback_for_non_permission_errors(
    monkeypatch,
):
    from app import smb_protocol

    root = r'\\server\Docs'
    protected = root + r'\protected'
    handles = []
    attempts = []

    class Handle:
        path = root

        def __init__(self):
            self.closed = False
            handles.append(self)

        def close(self):
            self.closed = True

    def open_raw(path, **_kwargs):
        attempts.append(path)
        if path == protected:
            raise RuntimeError('transport failed')
        return Handle()

    monkeypatch.setattr(smb_protocol, '_open_raw', open_raw)
    monkeypatch.setattr(
        smb_protocol,
        '_query_open_info',
        lambda *_args, **_kwargs: _object_info('', 1, directory=True),
    )
    monkeypatch.setattr(
        smb_protocol,
        '_query_exact_child',
        lambda *_args, **_kwargs: _object_info(
            'protected', 10, directory=True
        ),
    )

    with pytest.raises(RuntimeError, match='transport failed'):
        smb_protocol._open_verified_path(
            protected + r'\file.txt',
            purpose='file_read',
        )

    assert attempts == [root, protected]
    assert all(handle.closed for handle in handles)


def test_directory_pin_requests_the_verified_leaf_purpose(
    monkeypatch,
):
    from app import smb_protocol

    captured = {}

    def open_verified(path, **kwargs):
        captured['path'] = path
        captured['kwargs'] = kwargs
        return object(), _object_info('protected', 10, directory=True)

    monkeypatch.setattr(smb_protocol, '_open_verified_path', open_verified)

    smb_protocol._verified_directory_handle(r'\\server\Docs\protected')

    assert captured == {
        'path': r'\\server\Docs\protected',
        'kwargs': {
            'purpose': 'directory_pin',
            'expected_identities': None,
        },
    }


def test_directory_pin_restricts_only_the_final_verified_handle(
    monkeypatch,
):
    from app import smb_protocol

    root = r'\\server\Docs'
    protected = root + r'\protected'
    calls = []

    class Handle:
        def __init__(self, path):
            self.path = path

        def close(self):
            return None

    def open_raw(path, **kwargs):
        calls.append((path, kwargs))
        return Handle(path)

    monkeypatch.setattr(smb_protocol, '_open_raw', open_raw)
    monkeypatch.setattr(
        smb_protocol,
        '_query_exact_child',
        lambda *_args, **_kwargs: _object_info(
            'protected', 10, directory=True
        ),
    )
    monkeypatch.setattr(
        smb_protocol,
        '_query_open_info',
        lambda handle, **_kwargs: _object_info(
            handle.path.rsplit('\\', 1)[-1],
            1 if handle.path == root else 10,
            directory=True,
        ),
    )

    handle, _info = smb_protocol._open_verified_path(
        protected,
        purpose='directory_pin',
    )

    assert calls[0][0] == root
    assert calls[0][1]['share_access'] == 'rwd'
    assert calls[0][1]['desired_access'] == int(
        smb_protocol.DirectoryAccessMask.FILE_LIST_DIRECTORY
        | smb_protocol.DirectoryAccessMask.FILE_READ_ATTRIBUTES
    )
    assert calls[1][0] == protected
    assert calls[1][1]['share_access'] == 'r'
    assert calls[1][1]['desired_access'] == int(
        smb_protocol.DirectoryAccessMask.FILE_READ_ATTRIBUTES
    )
    handle.close()


def test_share_root_directory_pin_uses_read_attributes_only(monkeypatch):
    from app import smb_protocol

    root = r'\\server\Docs'
    calls = []

    class Handle:
        def close(self):
            return None

    def open_raw(path, **kwargs):
        calls.append((path, kwargs))
        return Handle()

    monkeypatch.setattr(smb_protocol, '_open_raw', open_raw)
    monkeypatch.setattr(
        smb_protocol,
        '_query_open_info',
        lambda *_args, **_kwargs: _object_info('', 1, directory=True),
    )

    handle, _info = smb_protocol._open_verified_path(
        root,
        purpose='directory_pin',
    )

    assert calls == [(root, {
        'is_directory': True,
        'desired_access': int(
            smb_protocol.FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES
        ),
        'connection_kwargs': {},
        'share_access': 'r',
    })]
    handle.close()


def test_explicit_empty_expected_identity_chain_rejects_non_root_path(
    monkeypatch,
):
    from app import smb_protocol

    monkeypatch.setattr(
        smb_protocol,
        '_open_raw',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError('path was opened before validating the chain')
        ),
    )

    with pytest.raises(SMBProtocolError) as error:
        smb_protocol._open_verified_path(
            r'\\server\Docs\file.txt',
            purpose='file_read',
            expected_identities=(),
        )

    assert error.value.public_code == 'OPERATION_FAILED'


def test_exact_child_no_result_fails_closed():
    from app import smb_protocol

    class Directory:
        def query_directory(self, pattern, info_class):
            assert pattern == 'missing.txt'
            assert info_class == (
                smb_protocol.FileInformationClass
                .FILE_ID_FULL_DIRECTORY_INFORMATION
            )
            return iter(())

    with pytest.raises(SMBProtocolError) as error:
        smb_protocol._query_exact_child(Directory(), 'missing.txt')

    assert error.value.public_code == 'NOT_FOUND'


def test_verified_iterator_closes_raw_when_enumeration_setup_fails():
    from app import smb_protocol

    class Raw:
        closed = False

        def query_directory(self, *_args):
            raise RuntimeError('query setup failed')

        def close(self):
            self.closed = True

    raw = Raw()
    with pytest.raises(RuntimeError, match='query setup failed'):
        smb_protocol._VerifiedDirectoryIterator(
            raw,
            _object_info('', 1, directory=True),
        )
    assert raw.closed is True


def test_verified_iterator_opens_enumerated_child_without_root_rewalk(
    monkeypatch,
):
    from app import smb_protocol

    trusted = _object_info('child', 20, directory=True)
    opened = []

    class Raw:
        def __init__(self, entries):
            self.entries = entries
            self.closed = False

        def query_directory(self, *_args):
            return iter(self.entries)

        def close(self):
            self.closed = True

    parent_raw = Raw([object()])
    child_raw = Raw([])
    parent = smb_protocol._VerifiedDirectoryIterator(
        parent_raw,
        _object_info('', 10, directory=True, chain=(10,)),
        path=r'\\server\Docs\parent',
        connection_kwargs={'connection_timeout': 30},
    )
    monkeypatch.setattr(
        smb_protocol,
        '_entry_from_directory_info',
        lambda _raw_info: trusted,
    )

    def open_raw(path, **kwargs):
        opened.append((path, kwargs))
        return child_raw

    monkeypatch.setattr(smb_protocol, '_open_raw', open_raw)
    monkeypatch.setattr(
        smb_protocol,
        '_query_open_info',
        lambda *_args, **_kwargs: _object_info(
            'child', 20, directory=True
        ),
    )

    entry = next(parent)
    child = parent.open_child_directory(entry)

    assert child.identity == 20
    assert child.identity_chain == (10, 20)
    assert opened[0][0] == r'\\server\Docs\parent\child'
    assert opened[0][1]['connection_kwargs'] == {
        'connection_timeout': 30
    }
    assert opened[0][1]['desired_access'] == int(
        smb_protocol.DirectoryAccessMask.FILE_LIST_DIRECTORY
        | smb_protocol.DirectoryAccessMask.FILE_READ_ATTRIBUTES
    )
    assert parent_raw.closed is False
    child.close()
    parent.close()
    assert child_raw.closed is True
    assert parent_raw.closed is True


def test_verified_iterator_child_identity_mismatch_closes_child(
    monkeypatch,
):
    from app import smb_protocol

    class Raw:
        def __init__(self):
            self.closed = False

        def query_directory(self, *_args):
            return iter(())

        def close(self):
            self.closed = True

    parent_raw = Raw()
    child_raw = Raw()
    parent = smb_protocol._VerifiedDirectoryIterator(
        parent_raw,
        _object_info('', 10, directory=True, chain=(10,)),
        path=r'\\server\Docs\parent',
        connection_kwargs={},
    )
    monkeypatch.setattr(
        smb_protocol,
        '_open_raw',
        lambda *_args, **_kwargs: child_raw,
    )
    monkeypatch.setattr(
        smb_protocol,
        '_query_open_info',
        lambda *_args, **_kwargs: _object_info(
            'child', 99, directory=True
        ),
    )

    with pytest.raises(SMBProtocolError) as error:
        parent.open_child_directory(
            _object_info('child', 20, directory=True)
        )

    assert error.value.public_code == 'CONFLICT'
    assert child_raw.closed is True
    assert parent_raw.closed is False
    parent.close()
    assert parent_raw.closed is True


def test_open_handle_rename_uses_relative_unicode_target(monkeypatch):
    from types import SimpleNamespace

    from app import smb_protocol

    captured = {}

    class Raw:
        closed = False
        fd = SimpleNamespace(
            tree_connect=SimpleNamespace(
                share_name=r'\\server\Docs',
                is_dfs_share=False,
            ),
        )

    raw = Raw()

    class Transaction:
        def __init__(self, candidate):
            assert candidate is raw

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    monkeypatch.setattr(smb_protocol, 'SMBFileTransaction', Transaction)
    monkeypatch.setattr(
        smb_protocol,
        'set_info',
        lambda transaction, info: captured.update({
            'transaction': transaction,
            'info': info,
        }),
    )

    smb_protocol._rename_open_handle(
        raw,
        r'\\server\Docs\Berichte\Überblick.txt',
        replace=True,
    )

    info = captured['info']
    assert info['replace_if_exists'].get_value() is True
    assert info['root_directory'].get_value() == 0
    assert info['file_name'].get_value() == r'Berichte\Überblick.txt'


def test_open_handle_rename_rejects_closed_or_cross_share_handle(monkeypatch):
    from types import SimpleNamespace

    from app import smb_protocol

    transactions = []

    class Raw:
        def __init__(self, *, closed, share='Docs'):
            self.closed = closed
            self.fd = SimpleNamespace(
                tree_connect=SimpleNamespace(
                    share_name=rf'\\server\{share}',
                    is_dfs_share=False,
                ),
            )

    monkeypatch.setattr(
        smb_protocol,
        'SMBFileTransaction',
        lambda raw: transactions.append(raw),
    )

    with pytest.raises(SMBProtocolError) as closed_error:
        smb_protocol._rename_open_handle(
            Raw(closed=True),
            r'\\server\Docs\new.txt',
        )
    with pytest.raises(SMBProtocolError) as share_error:
        smb_protocol._rename_open_handle(
            Raw(closed=False),
            r'\\server\Other\new.txt',
        )

    assert closed_error.value.public_code == 'OPERATION_FAILED'
    assert share_error.value.public_code == 'SHARE_UNAVAILABLE'
    assert transactions == []


def test_open_handle_path_match_queries_the_existing_file_id(monkeypatch):
    from types import SimpleNamespace

    from smbprotocol.file_info import FileAllInformation

    from app import smb_protocol

    class Raw:
        closed = False
        fd = SimpleNamespace(
            tree_connect=SimpleNamespace(
                share_name=r'\\server\Docs',
                is_dfs_share=False,
            ),
        )

    raw = Raw()

    class Transaction:
        def __init__(self, candidate):
            assert candidate is raw
            self.results = []

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    def query(transaction, info_type, *, output_buffer_length=None):
        assert info_type is FileAllInformation
        assert output_buffer_length == 65536
        info = FileAllInformation()
        info['name_information']['file_name'] = (
            r'\Berichte\Überblick.txt'
        )
        transaction.results.append(info)

    monkeypatch.setattr(smb_protocol, 'SMBFileTransaction', Transaction)
    monkeypatch.setattr(smb_protocol, 'query_info', query)

    assert smb_protocol._open_handle_matches_path(
        raw,
        r'\\server\Docs\berichte\überblick.txt',
    ) is True
    assert smb_protocol._open_handle_matches_path(
        raw,
        r'\\server\Docs\berichte\anderes.txt',
    ) is False


def test_pinned_smbclient_builds_handle_name_query_with_sufficient_buffer():
    """Exercise smbclient 1.17's real query builder, not a protocol mock."""
    from types import SimpleNamespace

    from smbprotocol.file_info import FileAllInformation, InfoType
    from smbprotocol.open import FileInformationClass

    from app import smb_protocol

    queued = []

    class Transaction:
        raw = SimpleNamespace(fd=SimpleNamespace(file_id=b'\0' * 16))

        def __iadd__(self, operation):
            queued.append(operation)
            return self

    smb_protocol.query_info(
        Transaction(),
        FileAllInformation,
        output_buffer_length=65536,
    )

    request, receiver = queued[0]
    assert request['info_type'].get_value() == InfoType.SMB2_0_INFO_FILE
    assert (
        request['file_info_class'].get_value()
        == FileInformationClass.FILE_ALL_INFORMATION
    )
    assert request['output_buffer_length'].get_value() == 65536
    assert callable(receiver)


def test_closed_handle_delete_and_query_never_reopen_by_path(monkeypatch):
    from types import SimpleNamespace

    from app import smb_protocol

    raw = SimpleNamespace(
        closed=True,
        fd=SimpleNamespace(
            tree_connect=SimpleNamespace(
                share_name=r'\\server\Docs',
                is_dfs_share=False,
            ),
        ),
    )
    transactions = []
    monkeypatch.setattr(
        smb_protocol,
        'SMBFileTransaction',
        lambda candidate: transactions.append(candidate),
    )

    operations = (
        lambda: smb_protocol._set_delete_disposition(raw),
        lambda: smb_protocol._open_handle_matches_path(
            raw,
            r'\\server\Docs\renamed.txt',
        ),
    )
    for operation in operations:
        with pytest.raises(SMBProtocolError) as error:
            operation()
        assert error.value.public_code == 'OPERATION_FAILED'
    assert transactions == []


def test_verified_rename_mutates_and_closes_the_opened_source_handle(
    monkeypatch,
):
    from app import smb_protocol

    class Raw:
        closed = False

        def close(self):
            self.closed = True

    raw = Raw()
    calls = []
    monkeypatch.setattr(
        smb_protocol,
        '_open_verified_path',
        lambda path, **kwargs: (
            raw,
            _object_info('old.txt', 83, chain=(83,)),
        ),
    )
    monkeypatch.setattr(
        smb_protocol,
        '_rename_open_handle',
        lambda handle, destination, **kwargs: calls.append((
            handle,
            destination,
            kwargs,
        )),
    )

    smb_protocol._verified_rename(
        r'\\server\Docs\old.txt',
        r'\\server\Docs\new.txt',
        replace=False,
    )

    assert calls == [(
        raw,
        r'\\server\Docs\new.txt',
        {'replace': False},
    )]
    assert raw.closed is True


def test_editor_move_open_denies_concurrent_write_and_delete(monkeypatch):
    from app import smb_protocol

    root = r'\\server\Docs'
    leaf = root + r'\report.txt'
    opens = []

    class Raw:
        def __init__(self, path):
            self.path = path

        def close(self):
            return None

    def open_raw(path, **kwargs):
        opens.append((path, kwargs))
        return Raw(path)

    monkeypatch.setattr(smb_protocol, '_open_raw', open_raw)
    monkeypatch.setattr(
        smb_protocol,
        '_query_exact_child',
        lambda *_args: _object_info('report.txt', 83),
    )
    monkeypatch.setattr(
        smb_protocol,
        '_query_open_info',
        lambda raw, **_kwargs: _object_info(
            raw.path.rsplit('\\', 1)[-1],
            1 if raw.path == root else 83,
            directory=raw.path == root,
        ),
    )

    raw, info = smb_protocol._verified_file_move_handle(leaf)

    leaf_open = next(call for call in opens if call[0] == leaf)
    assert leaf_open[1]['share_access'] == 'r'
    assert leaf_open[1]['desired_access'] == int(
        smb_protocol.FilePipePrinterAccessMask.DELETE
        | smb_protocol.FilePipePrinterAccessMask.FILE_READ_DATA
        | smb_protocol.FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES
    )
    assert info.file_id == 83
    raw.close()


def test_atomic_temp_is_exclusively_created_with_same_handle_rename_rights(
    monkeypatch,
):
    from types import SimpleNamespace

    from app import smb_protocol

    captured = {}

    class Raw:
        def __init__(self, path, **kwargs):
            captured.update({'path': path, **kwargs})
            self.closed = True
            self.fd = SimpleNamespace(
                file_attributes=0,
                tree_connect=SimpleNamespace(
                    share_name=r'\\server\Docs',
                    is_dfs_share=False,
                ),
            )

        def open(self):
            self.closed = False

        def close(self):
            self.closed = True

    monkeypatch.setattr(smb_protocol, 'SMBFileIO', Raw)

    raw = smb_protocol._create_file_move_handle(
        r'\\server\Docs\.report.webssh-write.tmp'
    )

    assert captured['mode'] == 'xb'
    assert captured['share_access'] is None
    assert captured['desired_access'] == int(
        smb_protocol.FilePipePrinterAccessMask.DELETE
        | smb_protocol.FilePipePrinterAccessMask.FILE_WRITE_DATA
        | smb_protocol.FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES
    )
    assert captured['create_options'] & int(
        smb_protocol.CreateOptions.FILE_OPEN_REPARSE_POINT
    )
    assert raw.closed is False
    raw.close()


def test_verified_delete_preserves_multiple_hardlink_compatibility(monkeypatch):
    from smbprotocol.file_info import FileDispositionInformation

    from app import smb_protocol

    events = []

    class Raw:
        closed = False

        def close(self):
            self.closed = True
            events.append(('close', self))

    raw = Raw()

    class Transaction:
        def __init__(self, candidate):
            assert candidate is raw
            self.raw = candidate

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    monkeypatch.setattr(
        smb_protocol,
        '_open_verified_path',
        lambda *_args, **_kwargs: (
            raw,
            _object_info('file.txt', 83, links=2),
        ),
    )
    monkeypatch.setattr(smb_protocol, 'SMBFileTransaction', Transaction)
    monkeypatch.setattr(
        smb_protocol,
        'set_info',
        lambda transaction, info: events.append(('set', transaction.raw, info)),
    )

    smb_protocol._verified_delete(r'\\server\Docs\file.txt')

    set_events = [event for event in events if event[0] == 'set']
    assert len(set_events) == 1
    assert all(event[1] is raw for event in set_events)
    assert isinstance(set_events[-1][2], FileDispositionInformation)
    assert set_events[-1][2]['delete_pending'].get_value() is True
    assert events[-1] == ('close', raw)


def test_verified_delete_requests_no_write_attribute_right_on_fast_path(
    monkeypatch,
):
    from app import smb_protocol

    root = r'\\server\Docs'
    leaf = root + r'\file.txt'
    opened = []

    class Raw:
        def __init__(self, path):
            self.path = path

        def close(self):
            return None

    def open_raw(path, **kwargs):
        opened.append((path, kwargs))
        return Raw(path)

    monkeypatch.setattr(smb_protocol, '_open_raw', open_raw)
    monkeypatch.setattr(
        smb_protocol,
        '_query_exact_child',
        lambda *_args: _object_info('file.txt', 83),
    )
    monkeypatch.setattr(
        smb_protocol,
        '_query_open_info',
        lambda raw, **_kwargs: _object_info(
            raw.path.rsplit('\\', 1)[-1],
            1 if raw.path == root else 83,
            directory=raw.path == root,
        ),
    )
    monkeypatch.setattr(
        smb_protocol,
        '_set_delete_disposition',
        lambda _raw: None,
    )

    smb_protocol._verified_delete(leaf)

    leaf_open = next(call for call in opened if call[0] == leaf)
    desired_access = leaf_open[1]['desired_access']
    assert desired_access & int(
        smb_protocol.FilePipePrinterAccessMask.DELETE
    )
    assert desired_access & int(
        smb_protocol.FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES
    )
    assert not desired_access & int(
        smb_protocol.FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES
    )


@pytest.mark.parametrize(
    ('status', 'attributes'),
    [
        (NtStatus.STATUS_ACCESS_DENIED, 0x01),
        (NtStatus.STATUS_CANNOT_DELETE, 0x00),
    ],
)
def test_verified_delete_does_not_escalate_unrelated_failures(
    monkeypatch,
    status,
    attributes,
):
    from app import smb_protocol

    class StatusFailure(Exception):
        def __init__(self):
            self.ntstatus = status

    class Raw:
        closed = False

        def close(self):
            self.closed = True

    raw = Raw()
    opens = []

    def open_verified(*_args, **kwargs):
        opens.append(kwargs)
        return raw, _object_info(
            'file.txt',
            83,
            attributes=attributes,
            chain=(83,),
        )

    monkeypatch.setattr(smb_protocol, '_open_verified_path', open_verified)
    monkeypatch.setattr(
        smb_protocol,
        '_set_delete_disposition',
        lambda _raw: (_ for _ in ()).throw(StatusFailure()),
    )

    with pytest.raises(StatusFailure):
        smb_protocol._verified_delete(r'\\server\Docs\file.txt')

    assert [call['purpose'] for call in opens] == ['delete']
    assert raw.closed is True


def test_verified_delete_read_only_fallback_rebinds_identity(monkeypatch):
    from app import smb_protocol

    class CannotDelete(Exception):
        ntstatus = NtStatus.STATUS_CANNOT_DELETE

    class Raw:
        def __init__(self, name):
            self.name = name
            self.closed = False

        def close(self):
            self.closed = True

    primary = Raw('primary')
    fallback = Raw('fallback')
    opens = []
    attributes = []

    def open_verified(*_args, **kwargs):
        opens.append(kwargs)
        if len(opens) == 1:
            return primary, _object_info(
                'file.txt', 83, attributes=0x03, chain=(83,)
            )
        return fallback, _object_info(
            'file.txt', 83, attributes=0x03, chain=(83,)
        )

    def disposition(raw):
        if raw is primary:
            raise CannotDelete()

    monkeypatch.setattr(smb_protocol, '_open_verified_path', open_verified)
    monkeypatch.setattr(smb_protocol, '_set_delete_disposition', disposition)
    monkeypatch.setattr(
        smb_protocol,
        '_set_file_attributes',
        lambda raw, value: attributes.append((raw.name, value)),
    )

    smb_protocol._verified_delete(r'\\server\Docs\file.txt')

    assert [call['purpose'] for call in opens] == [
        'delete',
        'delete_read_only',
    ]
    assert opens[1]['expected_identities'] == (83,)
    assert attributes == [('fallback', 0x02)]
    assert primary.closed is True
    assert fallback.closed is True


def test_verified_delete_restores_exact_attributes_when_fallback_fails(
    monkeypatch,
):
    from app import smb_protocol

    class CannotDelete(Exception):
        ntstatus = NtStatus.STATUS_CANNOT_DELETE

    class Raw:
        def __init__(self, name):
            self.name = name

        def close(self):
            return None

    primary = Raw('primary')
    fallback = Raw('fallback')
    attributes = []
    opens = 0

    def open_verified(*_args, **_kwargs):
        nonlocal opens
        opens += 1
        raw = primary if opens == 1 else fallback
        return raw, _object_info(
            'file.txt', 83, attributes=0x23, chain=(83,)
        )

    def disposition(raw):
        if raw is primary:
            raise CannotDelete()
        raise RuntimeError('fallback delete failed')

    monkeypatch.setattr(smb_protocol, '_open_verified_path', open_verified)
    monkeypatch.setattr(smb_protocol, '_set_delete_disposition', disposition)
    monkeypatch.setattr(
        smb_protocol,
        '_set_file_attributes',
        lambda raw, value: attributes.append((raw.name, value)),
    )

    with pytest.raises(RuntimeError, match='fallback delete failed'):
        smb_protocol._verified_delete(r'\\server\Docs\file.txt')

    assert attributes == [('fallback', 0x22), ('fallback', 0x23)]


def test_verified_delete_handles_disappearing_read_only_flag(monkeypatch):
    from app import smb_protocol

    class CannotDelete(Exception):
        ntstatus = NtStatus.STATUS_CANNOT_DELETE

    class Raw:
        def close(self):
            return None

    opens = 0

    def open_verified(*_args, **_kwargs):
        nonlocal opens
        opens += 1
        return Raw(), _object_info(
            'file.txt',
            83,
            attributes=0x01 if opens == 1 else 0x00,
            chain=(83,),
        )

    monkeypatch.setattr(smb_protocol, '_open_verified_path', open_verified)
    monkeypatch.setattr(
        smb_protocol,
        '_set_delete_disposition',
        lambda _raw: (_ for _ in ()).throw(CannotDelete()),
    )

    with pytest.raises(SMBProtocolError) as error:
        smb_protocol._verified_delete(r'\\server\Docs\file.txt')

    assert error.value.public_code == 'CONFLICT'
