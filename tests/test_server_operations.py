"""Server actions are bounded and cannot turn target names into shell code."""

import pytest

from app.server_operations import OperationError, build_command


@pytest.mark.parametrize('target', ['sshd;id', '-a', '$(id)', 'a\nb', '../../x'])
def test_service_targets_reject_shell_and_option_injection(target):
    with pytest.raises(OperationError):
        build_command('service.restart', {'unit': target})


def test_allowlisted_actions_and_noninteractive_sudo():
    command = build_command('service.restart', {'unit': 'sshd.service'}, use_sudo=True)
    assert command == 'sudo -n -- systemctl restart -- sshd.service'
    with pytest.raises(OperationError):
        build_command('shell', {'command': 'id'})


def test_container_mutations_require_immutable_full_id():
    with pytest.raises(OperationError):
        build_command('container.stop', {'container': 'database'})
    container = 'a' * 64
    assert build_command('container.stop', {'container': container}) == f'docker stop --time 10 -- {container}'


def test_container_inspection_resolves_name_without_allowing_options():
    assert "docker inspect" in build_command('container.inspect', {'name': 'database-1'})
    for name in ['-x', 'db;id', 'a/b']:
        with pytest.raises(OperationError):
            build_command('container.inspect', {'name': name})


def test_process_termination_uses_pidfd_and_checks_start_identity():
    command = build_command('process.terminate', {'pid': 123, 'start_time': '456'})
    assert 'pidfd_open' in command and 'pidfd_send_signal' in command
    assert 'SIGTERM' in command and 'SIGKILL' not in command
    assert '456' in command
    for value in [True, 0, -1, '1;id']:
        with pytest.raises(OperationError):
            build_command('process.terminate', {'pid': value, 'start_time': '456'})


def test_read_only_commands_are_bounded_and_do_not_follow_logs():
    journal = build_command('service.logs', {'unit': 'sshd.service'})
    docker = build_command('container.logs', {'container': 'b' * 64})
    assert '--lines=100' in journal and '--no-pager' in journal
    assert '--tail 100' in docker and '--follow' not in docker


@pytest.fixture
def session(monkeypatch):
    from app import server_operations as operations
    class Transport:
        def is_active(self):
            return True
    class Client:
        def get_transport(self):
            return transport
    transport = Transport()
    connection = {'user_id': 1, 'connected': True, 'host': 'example.com', 'client': Client()}
    monkeypatch.setattr(operations.ssh_manager, 'sessions', {'session': connection})
    monkeypatch.setattr(operations, '_intents', {})
    monkeypatch.setattr(operations, '_active', set())
    return connection


def test_intents_are_owner_auth_session_and_connection_bound_and_single_use(session):
    from app.server_operations import prepare_intent, get_intent
    token, intent = prepare_intent('session', 1, 'auth-a', 'service.restart', {'unit': 'sshd.service'})
    assert intent.command == 'systemctl restart -- sshd.service'
    for user, auth in [(2, 'auth-a'), (1, 'auth-b')]:
        with pytest.raises(OperationError):
            get_intent(token, user, auth)
    assert get_intent(token, 1, 'auth-a', consume=True) is intent
    with pytest.raises(OperationError):
        get_intent(token, 1, 'auth-a', consume=True)


def test_expired_or_replaced_session_intents_cannot_execute(session, monkeypatch):
    from app import server_operations as operations
    token, _ = operations.prepare_intent('session', 1, 'a', 'system.reboot', {})
    monkeypatch.setattr(operations.time, 'monotonic', lambda: float('inf'))
    with pytest.raises(OperationError):
        operations.get_intent(token, 1, 'a')
    monkeypatch.undo()


def test_replaced_transport_invalidates_intent(session):
    from app.server_operations import prepare_intent, get_intent
    token, _ = prepare_intent('session', 1, 'a', 'system.reboot', {})
    session['client'] = object()
    with pytest.raises(OperationError):
        get_intent(token, 1, 'a')


def test_continuous_remote_output_still_observes_deadline(session, monkeypatch):
    from app import server_operations as operations
    class Channel:
        closed = False
        def recv_ready(self): return True
        def recv(self, _size): return b'x'
        def recv_stderr_ready(self): return False
        def recv_stderr(self, _size): return b''
        def exit_status_ready(self): return False
        def close(self): self.closed = True
    channel = Channel()
    monkeypatch.setattr(operations.ssh_manager, '_open_exec_channel', lambda *args, **kwargs: channel)
    times = iter([0, 0, 1, 16])
    monkeypatch.setattr(operations.time, 'monotonic', lambda: next(times))
    with pytest.raises(OperationError) as error:
        operations.execute_command('session', 1, session, 'uptime')
    assert error.value.code == 'timeout'
    assert channel.closed
    assert not operations._active


def test_lost_exec_ack_is_unknown_for_mutation(session, monkeypatch):
    from app import server_operations as operations
    def fail(*args, **kwargs):
        kwargs['before_exec']()
        raise TimeoutError()
    monkeypatch.setattr(operations.ssh_manager, '_open_exec_channel', fail)
    with pytest.raises(OperationError) as error:
        operations.execute_command('session', 1, session, 'systemctl reboot', mutating=True)
    assert error.value.code == 'unknown'


@pytest.mark.parametrize('revoke', ['cancel', 'session'])
def test_revocation_during_channel_open_prevents_dispatch(session, monkeypatch, revoke):
    from app import server_operations as operations
    commands = []
    cancelled = [False]
    class Channel:
        closed = False
        def settimeout(self, timeout): pass
        def exec_command(self, command): commands.append(command)
        def close(self): self.closed = True
    channel = Channel()
    transport = session['client'].get_transport()
    def open_session(**kwargs):
        if revoke == 'cancel':
            cancelled[0] = True
        else:
            session['connected'] = False
        return channel
    monkeypatch.setattr(transport, 'open_session', open_session, raising=False)
    with pytest.raises(OperationError, match='unavailable'):
        operations.execute_command('session', 1, session, 'systemctl reboot',
                                   mutating=True, cancelled=lambda: cancelled[0])
    assert commands == []
    assert channel.closed
    assert not operations._active


def _login(app, client):
    from app.auth import register_user
    with app.app_context():
        user, error = register_user('operations_user', 'password123')
        assert error is None
        user_id = user.id
    assert client.post('/login', data={'username': 'operations_user', 'password': 'password123'}).status_code == 302
    return user_id


def test_operations_default_disabled_and_cross_user_session_denied(app, client, session):
    _login(app, client)
    response = client.post('/api/server-operations/intents', json={
        'session_id': 'session', 'action': 'system.reboot', 'target': {},
    })
    assert response.status_code == 403
    session['user_id'] = 2
    assert client.get('/api/server-operations/session').status_code == 404


def test_mutation_requires_step_up_and_one_use_intent(app, client, session, monkeypatch):
    import config
    from app import server_operations
    from tests.step_up_helpers import account_password_step_up_headers
    _login(app, client)
    monkeypatch.setattr(config, 'SERVER_OPERATIONS_ENABLED', True)
    calls = []
    def execute(*args, **kwargs):
        calls.append((args, kwargs))
        return {'status': 'completed', 'exit_status': 0, 'output': '', 'error_output': ''}
    monkeypatch.setattr(server_operations, 'execute_command', execute)
    prepared = client.post('/api/server-operations/intents', json={
        'session_id': 'session', 'action': 'service.restart',
        'target': {'unit': 'sshd.service'},
    })
    assert prepared.status_code == 200
    token = prepared.json['intent']
    assert client.post('/api/server-operations/execute', json={'intent': token}).status_code == 403
    headers, _ = account_password_step_up_headers(client, 'server.operation', token)
    assert client.post('/api/server-operations/execute', json={'intent': token}, headers=headers).status_code == 200
    assert len(calls) == 1
    assert client.post('/api/server-operations/execute', json={'intent': token}, headers=headers).status_code == 409
    assert len(calls) == 1


def test_reboot_requires_exact_typed_host_and_reports_requested(app, client, session, monkeypatch):
    import config
    from app import server_operations
    from tests.step_up_helpers import account_password_step_up_headers
    _login(app, client)
    monkeypatch.setattr(config, 'SERVER_OPERATIONS_ENABLED', True)
    monkeypatch.setattr(server_operations, 'execute_command', lambda *args, **kwargs: {
        'status': 'completed', 'exit_status': 0, 'output': '', 'error_output': '',
    })
    token = client.post('/api/server-operations/intents', json={
        'session_id': 'session', 'action': 'system.reboot', 'target': {},
    }).json['intent']
    headers, _ = account_password_step_up_headers(client, 'server.operation', token)
    assert client.post('/api/server-operations/execute', json={'intent': token}, headers=headers).status_code == 400
    response = client.post('/api/server-operations/execute', json={'intent': token, 'confirmation': 'example.com'}, headers=headers)
    assert response.json['status'] == 'requested'
