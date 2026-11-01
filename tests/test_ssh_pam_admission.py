"""Ordinary SSH admission must remain independent of file background jobs."""
import threading

import pytest


@pytest.mark.usefixtures('direct_socket_authentication')
@pytest.mark.parametrize('interactive', [False, True])
def test_file_job_does_not_block_ordinary_terminal(app, monkeypatch, interactive):
    from app import socket_events, ssh_manager
    from app.quota_manager import quota_manager, QuotaKind
    from tests.test_command_set_socket_events import create_socket_user, call_socket_handler

    user_id, sid = create_socket_user(app, 'pam_quota_user')
    started, release, finished = threading.Event(), threading.Event(), threading.Event()

    def connect(**kwargs):
        started.set()
        try:
            assert release.wait(3)
            return None, 'Expected test stop'
        finally:
            finished.set()

    monkeypatch.setattr(ssh_manager, 'create_ssh_connection', connect)
    file_job = quota_manager.reserve(QuotaKind.BACKGROUND_JOB, user_id)
    try:
        payload = dict(host='host', username='deploy', password='test-secret',
                       client_request_id='pam-quota-request')
        if interactive:
            payload['ssh_interaction'] = 1
        _, events = call_socket_handler(app, monkeypatch, socket_events.handle_ssh_connect, sid, payload)
        assert started.wait(1), events
    finally:
        release.set()
        if started.is_set():
            assert finished.wait(2)
        file_job.release()


@pytest.fixture
def admission(monkeypatch):
    from app import ssh_connection_attempt, ssh_manager
    from app.quota_manager import QuotaKind, QuotaManager
    from app.ssh_gateway_interaction import GatewayAttempt

    quotas = QuotaManager({kind: {'global': 2, 'per_user': 1} for kind in QuotaKind})
    monkeypatch.setattr(ssh_connection_attempt, 'quota_manager', quotas)
    monkeypatch.setattr(ssh_manager, 'quota_manager', quotas)
    registry = ssh_connection_attempt.SSHAttemptRegistry()
    attempts = []

    def create(user_id=7, sid='sid', request_id='req'):
        attempt = registry.create(
            user_id, sid, request_id, factory=GatewayAttempt,
            emit=lambda *args: None, reserve=True,
            reservation_kind=QuotaKind.SSH_SESSION, require_gateway=False,
        )
        attempts.append(attempt)
        return attempt

    yield quotas, registry, create
    for attempt in attempts:
        registry.finish(attempt)


@pytest.mark.parametrize('reason', ['user', 'disconnected', 'shutdown', 'timeout'])
def test_cancelled_attempt_retains_ssh_capacity_until_finish(admission, reason):
    from app.quota_manager import QuotaExceeded, QuotaKind

    quotas, registry, create = admission
    attempt = create()
    file_job = quotas.reserve(QuotaKind.BACKGROUND_JOB, 7)
    try:
        assert attempt.cancel(reason=reason)
        with pytest.raises(QuotaExceeded):
            quotas.reserve(QuotaKind.SSH_SESSION, 7)
        registry.finish(attempt)
        registry.finish(attempt)
        quotas.reserve(QuotaKind.SSH_SESSION, 7).release()
    finally:
        file_job.release()


def test_pending_attempts_enforce_user_and_global_ssh_limits(admission):
    from app.quota_manager import QuotaExceeded, QuotaKind

    quotas, registry, create = admission
    first = create()
    with pytest.raises(QuotaExceeded) as per_user:
        create(request_id='second')
    assert per_user.value.kind is QuotaKind.SSH_SESSION
    assert per_user.value.scope == 'per_user'
    other = create(user_id=8, sid='other')
    with pytest.raises(QuotaExceeded) as global_limit:
        create(user_id=9, sid='third')
    assert global_limit.value.scope == 'global'
    registry.finish(first)
    create(user_id=9, sid='third')
    assert not other.is_set()


@pytest.mark.parametrize('failure', [False, True])
def test_ssh_reservation_is_transferred_once_or_released(admission, monkeypatch, failure):
    import paramiko
    from app import ssh_manager
    from app.quota_manager import QuotaExceeded, QuotaKind
    from tests.test_ssh_manager import install_ssh_clients, connect_target

    quotas, registry, create = admission
    attempt = create()
    install_ssh_clients(monkeypatch, paramiko.AuthenticationException() if failure else None)
    session_id = None
    try:
        session_id, error = connect_target(password='test-secret', gateway_attempt=attempt)
        if failure:
            assert session_id is None and error
            with pytest.raises(QuotaExceeded):
                quotas.reserve(QuotaKind.SSH_SESSION, 7)
            registry.finish(attempt)
            quotas.reserve(QuotaKind.SSH_SESSION, 7).release()
        else:
            assert error is None and session_id
            assert attempt.reservation is None
            registry.finish(attempt)
            with pytest.raises(QuotaExceeded):
                quotas.reserve(QuotaKind.SSH_SESSION, 7)
            ssh_manager.close_session(session_id)
            quotas.reserve(QuotaKind.SSH_SESSION, 7).release()
    finally:
        if session_id:
            ssh_manager.close_session(session_id)


@pytest.mark.parametrize('invalid', ['other_user', 'released'])
def test_invalid_session_reservation_never_opens_network(admission, monkeypatch, invalid):
    from tests.test_ssh_manager import install_ssh_clients, connect_target

    _quotas, _registry, create = admission
    attempt = create(user_id=8 if invalid == 'other_user' else 7)
    if invalid == 'released':
        attempt.reservation.release()
    clients = install_ssh_clients(monkeypatch)
    session_id, error = connect_target(password='test-secret', gateway_attempt=attempt)
    assert session_id is None and error == 'Invalid SSH session reservation'
    assert clients == [] and clients.opened_sockets == []


def test_cancel_before_session_handoff_retains_capacity_until_cleanup(admission, monkeypatch):
    from app.quota_manager import QuotaExceeded, QuotaKind
    from tests.test_ssh_manager import install_ssh_clients, connect_target

    quotas, registry, create = admission
    attempt = create()
    clients = install_ssh_clients(monkeypatch)
    handoff = attempt.handoff

    def cancel_then_handoff(*resources, **kwargs):
        attempt.cancel()
        handoff(*resources, **kwargs)

    monkeypatch.setattr(attempt, 'handoff', cancel_then_handoff)
    session_id, error = connect_target(password='test-secret', gateway_attempt=attempt)
    assert session_id is None and error
    assert clients[0].closed and clients.opened_sockets[0].closed
    with pytest.raises(QuotaExceeded):
        quotas.reserve(QuotaKind.SSH_SESSION, 7)
    registry.finish(attempt)
    quotas.reserve(QuotaKind.SSH_SESSION, 7).release()


def test_attempt_factory_failure_releases_session_admission(admission):
    from app.quota_manager import QuotaKind

    quotas, registry, _create = admission

    def reject(*args, **kwargs):
        raise ValueError('attempt initialization failed')

    with pytest.raises(ValueError, match='attempt initialization failed'):
        registry.create(7, 'sid', 'req', factory=reject, reserve=True,
                        reservation_kind=QuotaKind.SSH_SESSION)
    assert registry.get(7, 'sid', 'req') is None
    quotas.reserve(QuotaKind.SSH_SESSION, 7).release()
