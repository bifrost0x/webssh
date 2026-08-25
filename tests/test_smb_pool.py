from dataclasses import dataclass
from threading import Event

import pytest

from app.file_sources import FileCapability
from app.network_policy import ResolvedTarget
from app.smb_pool import SMBConnectionPool, SMBSourceError
from app.smb_protocol import SMBProtocolError


class _Reservation:
    def __init__(self):
        self.released = False

    def release(self):
        self.released = True


class _Quota:
    def __init__(self, events):
        self.events = events
        self.reservations = []

    def reserve(self, kind, user_id):
        self.events.append(('quota', kind.value, str(user_id)))
        reservation = _Reservation()
        self.reservations.append(reservation)
        return reservation


@dataclass
class _Transport:
    connected: bool = True


class _RawConnection:
    def __init__(self):
        self.transport = _Transport()


class _Session:
    def __init__(self):
        self.connection_cache = {}
        self.raw_connection = _RawConnection()
        self.closed = 0
        self.inspect_calls = []
        self.inspect_error = None
        self.access = {
            'list': 'granted',
            'create_file': 'granted',
            'create_directory': 'granted',
            'delete_children': 'granted',
        }

    def inspect_directory_access(self, path):
        self.inspect_calls.append(path)
        if self.inspect_error is not None:
            raise self.inspect_error
        return dict(self.access)

    def close(self):
        self.closed += 1
        self.raw_connection.transport.connected = False
        return self.closed == 1


class _ProtocolClient:
    def __init__(self, events):
        self.events = events
        self.sessions = []
        self.fail = None

    def connect(self, **kwargs):
        self.events.append((
            'connect',
            {key: value for key, value in kwargs.items() if key != 'password'},
        ))
        if self.fail:
            raise self.fail
        session = _Session()
        self.sessions.append(session)
        return session


def _pool():
    events = []
    quota = _Quota(events)
    protocol = _ProtocolClient(events)

    def resolve(host, allowlist):
        events.append(('resolve', host, allowlist))
        return ResolvedTarget('nas.example', 445, '10.0.0.8', 2)

    pool = SMBConnectionPool(
        protocol_client=protocol,
        target_resolver=resolve,
        allowed_targets=('nas.example',),
        quota_manager=quota,
        cleanup_interval=60,
    )
    return pool, protocol, quota, events


VALID_CONNECT = {
    'host': 'nas.example',
    'share': 'Docs',
    'domain': 'DOMAIN',
    'username': 'alice',
    'password': 'Secret-Sentinel-42!',
    'cancel_event': Event(),
}


def test_source_error_rejects_untrusted_diagnostic_metadata():
    error = SMBSourceError(
        'CONNECTION_FAILED',
        diagnostic_phase=['share_access'],
        diagnostic_exception_type='Bad\nType',
        diagnostic_nt_status='secret-status',
    )

    assert error.diagnostic_phase == 'unknown'
    assert error.diagnostic_exception_type is None
    assert error.diagnostic_nt_status is None


def test_quota_is_reserved_before_dns_and_connect():
    pool, _protocol, _quota, events = _pool()

    pool.create_source(user_id='1', **VALID_CONNECT)

    assert [event[0] for event in events][:3] == ['quota', 'resolve', 'connect']


def test_source_owns_distinct_control_and_transfer_sessions_without_password():
    pool, protocol, _quota, events = _pool()

    descriptor = pool.create_source(user_id='1', **VALID_CONNECT)
    source = pool.get_source(descriptor.source_id, '1')

    assert len(protocol.sessions) == 2
    assert source.control_session is protocol.sessions[0]
    assert source.transfer_session is protocol.sessions[1]
    assert source.control_session is not source.transfer_session
    assert source.control_lock is not source.transfer_lock
    assert [event[0] for event in events].count('connect') == 2
    assert 'Secret-Sentinel-42!' not in repr(source)
    assert not hasattr(source, 'password')


def test_second_lane_failure_closes_first_session_and_releases_quota():
    pool, protocol, quota, _events = _pool()
    original_connect = protocol.connect
    calls = 0

    def fail_second(**kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise SMBProtocolError('CONNECTION_FAILED')
        return original_connect(**kwargs)

    protocol.connect = fail_second

    with pytest.raises(SMBSourceError) as exc:
        pool.create_source(user_id='1', **VALID_CONNECT)

    assert exc.value.public_code == 'CONNECTION_FAILED'
    assert protocol.sessions[0].closed == 1
    assert quota.reservations[0].released is True
    assert pool.source_count == 0


def test_normal_close_closes_both_lanes_exactly_once():
    pool, protocol, quota, _events = _pool()
    pool.create_source(user_id='1', **VALID_CONNECT)

    assert pool.close_all_sources() == 1
    assert pool.close_all_sources() == 0
    assert [session.closed for session in protocol.sessions] == [1, 1]
    assert quota.reservations[0].released is True


def test_unexpected_target_resolution_failure_keeps_safe_diagnostic_metadata():
    pool, _protocol, quota, _events = _pool()

    def fail_resolution(_host, _allowlist):
        raise RuntimeError(r'secret \\server\share')

    pool._target_resolver = fail_resolution

    with pytest.raises(SMBSourceError) as exc:
        pool.create_source(user_id='1', **VALID_CONNECT)

    assert exc.value.public_code == 'CONNECTION_FAILED'
    assert exc.value.diagnostic_phase == 'target_resolution'
    assert exc.value.diagnostic_exception_type == 'RuntimeError'
    assert exc.value.diagnostic_nt_status is None
    assert 'secret' not in str(exc.value)
    assert 'server' not in str(exc.value)
    assert quota.reservations[0].released is True


def test_same_target_and_username_never_share_cache_between_webssh_users():
    pool, _protocol, _quota, _events = _pool()

    first = pool.create_source(user_id='1', **VALID_CONNECT)
    second = pool.create_source(user_id='2', **VALID_CONNECT)
    first_source = pool.get_source(first.source_id, '1')
    second_source = pool.get_source(second.source_id, '2')

    assert (
        first_source.control_session.connection_cache
        is not second_source.control_session.connection_cache
    )
    assert (
        first_source.transfer_session.connection_cache
        is not second_source.transfer_session.connection_cache
    )
    assert pool.get_source(first.source_id, '2') is None


def test_descriptor_is_credential_free_and_exposes_verified_capabilities():
    pool, _protocol, _quota, _events = _pool()

    descriptor = pool.create_source(user_id='1', **VALID_CONNECT)

    assert 'Secret-Sentinel-42!' not in repr(descriptor.to_public_dict())
    assert descriptor.security == {
        'encrypted': True,
        'signed': True,
        'secure_negotiate': True,
    }
    assert FileCapability.RECURSIVE in descriptor.capabilities
    assert FileCapability.REMOTE_TRANSFER in descriptor.capabilities
    assert descriptor.access == {
        'list': 'granted',
        'create_file': 'granted',
        'create_directory': 'granted',
        'delete_children': 'granted',
    }


def test_share_root_is_validated_before_descriptor_is_published():
    pool, protocol, _quota, _events = _pool()

    descriptor = pool.create_source(user_id='1', **VALID_CONNECT)

    assert protocol.sessions[0].inspect_calls == [r'\\10.0.0.8\Docs']
    assert pool.get_source(descriptor.source_id, '1') is not None


@pytest.mark.parametrize('code', ('SHARE_UNAVAILABLE', 'PERMISSION_DENIED'))
def test_share_root_failure_closes_session_releases_quota_and_is_not_published(code):
    pool, protocol, quota, _events = _pool()
    original_connect = protocol.connect

    def connect(**kwargs):
        session = original_connect(**kwargs)
        failure = SMBProtocolError(code)
        failure.diagnostic_phase = 'file_operation'
        failure.diagnostic_exception_type = 'SMBOSError'
        failure.diagnostic_nt_status = '0xC0000022'
        session.inspect_error = failure
        return session

    protocol.connect = connect

    with pytest.raises(SMBSourceError) as exc:
        pool.create_source(user_id='1', **VALID_CONNECT)

    assert exc.value.public_code == code
    assert exc.value.diagnostic_phase == 'share_access'
    assert exc.value.diagnostic_exception_type == 'SMBOSError'
    assert exc.value.diagnostic_nt_status == '0xC0000022'
    assert protocol.sessions[0].closed == 1
    assert quota.reservations[0].released is True
    assert pool.source_count == 0


def test_unknown_root_write_access_does_not_reject_readable_share():
    pool, protocol, _quota, _events = _pool()
    original_connect = protocol.connect

    def connect(**kwargs):
        session = original_connect(**kwargs)
        session.access['create_file'] = 'unknown'
        session.access['create_directory'] = 'unknown'
        return session

    protocol.connect = connect

    descriptor = pool.create_source(user_id='1', **VALID_CONNECT)

    assert descriptor.access['list'] == 'granted'
    assert descriptor.access['create_file'] == 'unknown'


def test_failed_connect_releases_quota_without_storing_source():
    pool, protocol, quota, _events = _pool()
    protocol.fail = SMBProtocolError('CONNECTION_FAILED')
    protocol.fail.diagnostic_phase = 'transport_negotiate'
    protocol.fail.diagnostic_exception_type = 'ConnectionResetError'
    protocol.fail.diagnostic_nt_status = None

    with pytest.raises(SMBSourceError) as exc:
        pool.create_source(user_id='1', **VALID_CONNECT)

    assert exc.value.public_code == 'CONNECTION_FAILED'
    assert exc.value.diagnostic_phase == 'transport_negotiate'
    assert exc.value.diagnostic_exception_type == 'ConnectionResetError'
    assert exc.value.diagnostic_nt_status is None
    assert quota.reservations[0].released is True
    assert pool.source_count == 0


def test_dead_source_fails_closed_without_reconnect():
    pool, protocol, quota, events = _pool()
    descriptor = pool.create_source(user_id='1', **VALID_CONNECT)
    protocol.sessions[0].raw_connection.transport.connected = False

    assert pool.get_source(descriptor.source_id, '1') is None
    assert [event[0] for event in events].count('connect') == 2
    assert [session.closed for session in protocol.sessions] == [1, 1]
    assert quota.reservations[0].released is True


def test_close_is_deferred_until_last_hold_releases():
    pool, protocol, quota, _events = _pool()
    descriptor = pool.create_source(user_id='1', **VALID_CONNECT)

    assert pool.acquire_hold(descriptor.source_id, '1') is True
    assert pool.request_close(descriptor.source_id, '1') == 'deferred'
    assert protocol.sessions[0].closed == 0
    assert pool.release_hold(descriptor.source_id, '1') is True
    assert protocol.sessions[0].closed == 1
    assert quota.reservations[0].released is True
    assert pool.release_hold(descriptor.source_id, '1') is False


def test_deferred_close_remains_resolvable_for_held_transfer():
    pool, protocol, _quota, _events = _pool()
    descriptor = pool.create_source(user_id='1', **VALID_CONNECT)

    assert pool.acquire_hold(descriptor.source_id, '1') is True
    assert pool.request_close(descriptor.source_id, '1') == 'deferred'

    source = pool.get_source(descriptor.source_id, '1')

    assert source is not None
    assert source.hold_count == 1
    assert protocol.sessions[0].closed == 0


def test_revocation_closes_held_sources_immediately():
    pool, protocol, _quota, _events = _pool()
    descriptor = pool.create_source(user_id='1', **VALID_CONNECT)
    pool.acquire_hold(descriptor.source_id, '1')

    assert pool.close_all_user_sources('1') == 1
    assert protocol.sessions[0].closed == 1
    assert pool.get_source(descriptor.source_id, '1') is None


def test_cancel_before_pool_work_does_not_reserve_or_resolve():
    pool, _protocol, quota, events = _pool()
    cancelled = Event()
    cancelled.set()

    with pytest.raises(SMBSourceError) as exc:
        pool.create_source(user_id='1', **{**VALID_CONNECT, 'cancel_event': cancelled})

    assert exc.value.public_code == 'CONNECT_CANCELLED'
    assert quota.reservations == []
    assert events == []


def test_close_all_sources_is_idempotent():
    pool, protocol, quota, _events = _pool()
    pool.create_source(user_id='1', **VALID_CONNECT)

    assert pool.close_all_sources() == 1
    assert pool.close_all_sources() == 0
    assert protocol.sessions[0].closed == 1
    assert quota.reservations[0].released is True
