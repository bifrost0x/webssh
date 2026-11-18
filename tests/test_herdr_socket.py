"""The Herdr overview is granted by the server from the switch and the saved host."""

import json
import time
from threading import Lock
from types import SimpleNamespace

import pytest

from app import herdr, socket_events as events, ssh_manager
from tests.test_socks_connection_socket import capture_connections, connect_payload
from tests.test_socks_proxy_socket import call, user_socket

pytestmark = pytest.mark.usefixtures('direct_socket_authentication')

SNAPSHOT = json.dumps({'id': 'cli:api:snapshot', 'result': {
    'type': 'session_snapshot',
    'snapshot': {'agents': [{'pane_id': 'w1:p1', 'agent': 'codex', 'agent_status': 'working',
                             'cwd': '/srv/app'}], 'panes': []},
}}).encode() + b'\n'
NO_SERVER = (b'{"id":"cli:api:snapshot","error":{"code":"server_not_running",'
             b'"message":"no herdr server is running at /home/deploy/.config/herdr/herdr.sock"}}\n')
MISMATCH = (b'{"id":"cli:api:snapshot","error":{"code":"protocol_mismatch",'
            b'"message":"client protocol 22 is newer than server protocol 21"}}\n')


class Channel:
    def __init__(self, output=SNAPSHOT, errors=b'', status=0, finishes=True):
        self.output, self.errors, self.status, self.finishes = output, errors, status, finishes
        self.closed = False
        self.read = 0

    def recv_ready(self):
        return bool(self.output)

    def recv(self, size):
        chunk, self.output = self.output[:size], self.output[size:]
        self.read += len(chunk)
        return chunk

    def recv_stderr_ready(self):
        return bool(self.errors)

    def recv_stderr(self, size):
        chunk, self.errors = self.errors[:size], self.errors[size:]
        return chunk

    def exit_status_ready(self):
        return self.finishes

    def recv_exit_status(self):
        return self.status

    def close(self):
        self.closed = True


def enable(app, value=True):
    from app import app_settings
    with app.app_context():
        assert app_settings.set_herdr_enabled(value) is value


def saved_host(app, owner, **options):
    from app import profile_manager
    with app.app_context():
        profile, error = profile_manager.upsert_profile(owner, {
            'name': 'Agents', 'host': 'target.example', 'port': 22, 'username': 'ops',
            'auth_type': 'password', **options,
        })
        assert error is None
        return profile


def live_session(monkeypatch, owner, profile_id, channel=None, **fields):
    opened = []
    transport = SimpleNamespace(is_active=lambda: True)
    session = {'connected': True, 'user_id': owner, 'profile_id': profile_id, 'herdr': True,
               'client': SimpleNamespace(get_transport=lambda: transport), **fields}
    monkeypatch.setattr(ssh_manager, 'sessions', {'live': session})

    def open_channel(_transport, command, *, timeout, **kwargs):
        opened.append((command, timeout, kwargs))
        return channel if channel is not None else Channel()

    monkeypatch.setattr(ssh_manager, '_open_exec_channel', open_channel)
    monkeypatch.setattr(herdr, '_snapshot_slots', herdr.BoundedSemaphore(herdr.MAX_CONCURRENT_SNAPSHOTS))
    return session, opened


@pytest.fixture
def overview(app, monkeypatch):
    owner, sid = user_socket(app, 'herdr_owner')
    enable(app)
    profile = saved_host(app, owner, herdr=True)
    monkeypatch.setattr(events, 'verify_session_ownership',
                        lambda session_id, user_id: session_id == 'live' and user_id == owner)
    return SimpleNamespace(app=app, owner=owner, sid=sid, profile=profile)


def request_snapshot(overview, monkeypatch, sid=None, session_id='live'):
    result, emitted = call(overview.app, monkeypatch, events.handle_request_herdr_snapshot,
                           sid or overview.sid, {'session_id': session_id})
    assert emitted == []
    return result


def test_commands_share_one_lookup_prefix_and_contain_no_variable_text():
    prefix = 'PATH="$PATH:$HOME/.local/bin:/usr/local/bin:/opt/homebrew/bin"'
    assert herdr.PATH_PREFIX == prefix
    assert herdr.AVAILABLE_COMMAND == f"sh -c '{prefix}; command -v herdr >/dev/null 2>&1'"
    assert herdr.SNAPSHOT_COMMAND == (
        f"sh -c '{prefix}; herdr api snapshot & p=$!; "
        '(sleep 5; kill "$p") >/dev/null 2>&1 & w=$!; '
        'wait "$p"; s=$?; kill "$w" >/dev/null 2>&1; exit "$s"'
        "'"
    )
    assert herdr.SESSION_COMMAND == f"sh -c '{prefix}; exec herdr'"
    for command in (herdr.AVAILABLE_COMMAND, herdr.SNAPSHOT_COMMAND, herdr.SESSION_COMMAND):
        assert command.count("'") == 2 and command.count(prefix) == 1
    # The host limit outlasts the read deadline, and a session that timed out
    # is not asked again before the stuck call has been ended on the host.
    assert herdr.SNAPSHOT_TIMEOUT < 5 < herdr.TIMEOUT_SNAPSHOT_INTERVAL


def test_owned_session_returns_agents(overview, monkeypatch):
    channel = Channel()
    session, opened = live_session(monkeypatch, overview.owner, overview.profile['id'], channel)
    assert request_snapshot(overview, monkeypatch) == {
        'success': True, 'truncated': False, 'reason': None,
        'agents': [{'id': 'w1:p1', 'kind': 'codex', 'label': '', 'cwd': '/srv/app', 'status': 'working'}],
    }
    assert opened == [(herdr.SNAPSHOT_COMMAND, herdr.SNAPSHOT_TIMEOUT, {})]
    assert channel.closed and not session['herdr_snapshot_lock'].locked()


def test_disabled_switch_answers_disabled_without_opening_a_channel(overview, monkeypatch):
    _, opened = live_session(monkeypatch, overview.owner, overview.profile['id'])
    enable(overview.app, False)
    monkeypatch.setattr(events, 'verify_session_ownership', lambda *args: pytest.fail('looked up'))
    assert request_snapshot(overview, monkeypatch) == {
        'success': False, 'agents': [], 'truncated': False, 'reason': 'disabled'}
    assert opened == []


def test_switch_turned_off_between_two_requests_stops_the_second(overview, monkeypatch):
    session, opened = live_session(monkeypatch, overview.owner, overview.profile['id'])
    assert request_snapshot(overview, monkeypatch)['success'] is True
    session['herdr_snapshot_not_before'] = 0
    enable(overview.app, False)
    assert request_snapshot(overview, monkeypatch)['reason'] == 'disabled'
    assert len(opened) == 1


def test_another_users_session_is_unavailable(overview, monkeypatch):
    _, opened = live_session(monkeypatch, overview.owner, overview.profile['id'])
    _, other_sid = user_socket(overview.app, 'herdr_other')
    result = request_snapshot(overview, monkeypatch, sid=other_sid)
    assert result == {'success': False, 'agents': [], 'truncated': False, 'reason': 'unavailable'}
    assert opened == []


@pytest.mark.parametrize('session_id', [None, '', 7, ['live'], {'id': 'live'}, 'x' * 129])
def test_malformed_session_reference_is_unavailable(overview, monkeypatch, session_id):
    _, opened = live_session(monkeypatch, overview.owner, overview.profile['id'])
    assert request_snapshot(overview, monkeypatch, session_id=session_id)['reason'] == 'unavailable'
    assert opened == []


def test_rate_limit_answers_busy_before_the_ownership_lookup(overview, monkeypatch):
    _, opened = live_session(monkeypatch, overview.owner, overview.profile['id'])
    captured = {}
    monkeypatch.setattr(events.config, 'MAX_SOCKET_CONNECTIONS_PER_USER', 5)
    monkeypatch.setattr(events, 'check_socket_rate_limit', lambda user_id, endpoint, limit: captured.update(
        user_id=user_id, endpoint=endpoint, limit=limit) or True)
    monkeypatch.setattr(events, 'verify_session_ownership', lambda *args: pytest.fail('looked up'))
    assert request_snapshot(overview, monkeypatch)['reason'] == 'busy'
    assert captured == {'user_id': overview.owner, 'endpoint': 'herdr_snapshot', 'limit': '60 per minute'}
    assert opened == []


def test_session_without_the_overview_grant_is_not_enabled(overview, monkeypatch):
    _, opened = live_session(monkeypatch, overview.owner, overview.profile['id'], herdr=False)
    assert request_snapshot(overview, monkeypatch)['reason'] == 'not_enabled'
    assert opened == []


@pytest.mark.parametrize('profile_id', [None, 'missing-profile'])
def test_session_without_a_saved_host_is_not_enabled(overview, monkeypatch, profile_id):
    _, opened = live_session(monkeypatch, overview.owner, profile_id)
    assert request_snapshot(overview, monkeypatch)['reason'] == 'not_enabled'
    assert opened == []


def test_option_removed_from_the_saved_host_stops_a_connected_session(overview, monkeypatch):
    _, opened = live_session(monkeypatch, overview.owner, overview.profile['id'])
    saved_host(overview.app, overview.owner, id=overview.profile['id'], herdr=False)
    assert request_snapshot(overview, monkeypatch)['reason'] == 'not_enabled'
    assert opened == []


def test_another_users_saved_host_never_grants_the_overview(overview, monkeypatch):
    other, _ = user_socket(overview.app, 'herdr_other_profile')
    foreign = saved_host(overview.app, other, herdr=True)
    _, opened = live_session(monkeypatch, overview.owner, foreign['id'])
    assert request_snapshot(overview, monkeypatch)['reason'] == 'not_enabled'
    assert opened == []


def test_disconnected_session_is_reported(overview, monkeypatch):
    _, opened = live_session(monkeypatch, overview.owner, overview.profile['id'], connected=False)
    assert request_snapshot(overview, monkeypatch)['reason'] == 'disconnected'
    monkeypatch.setattr(ssh_manager, 'sessions', {})
    assert request_snapshot(overview, monkeypatch)['reason'] == 'disconnected'
    assert opened == []


def test_second_request_within_the_interval_is_busy(overview, monkeypatch):
    session, opened = live_session(monkeypatch, overview.owner, overview.profile['id'])
    assert request_snapshot(overview, monkeypatch)['success'] is True
    assert request_snapshot(overview, monkeypatch)['reason'] == 'busy'
    assert len(opened) == 1
    session['herdr_snapshot_not_before'] = 0
    assert request_snapshot(overview, monkeypatch)['success'] is True
    assert len(opened) == 2


def test_timeout_keeps_the_session_busy_for_the_longer_interval(overview, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(herdr.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(herdr.time, 'sleep', lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    channel = Channel(b'', b'', finishes=False)
    session, opened = live_session(monkeypatch, overview.owner, overview.profile['id'], channel)
    assert herdr.collect_snapshot('live') == (None, 'timeout')
    timed_out_at = clock[0]
    assert timed_out_at - 1000.0 == pytest.approx(herdr.SNAPSHOT_TIMEOUT, abs=0.05)

    channel.finishes, channel.output = True, SNAPSHOT
    clock[0] = timed_out_at + herdr.MIN_SNAPSHOT_INTERVAL + 1
    assert herdr.collect_snapshot('live') == (None, 'busy')
    clock[0] = timed_out_at + herdr.TIMEOUT_SNAPSHOT_INTERVAL - 0.1
    assert herdr.collect_snapshot('live') == (None, 'busy')
    assert len(opened) == 1

    clock[0] = timed_out_at + herdr.TIMEOUT_SNAPSHOT_INTERVAL
    assert herdr.collect_snapshot('live')[1] is None
    # After an answer the normal interval applies again.
    channel.output = SNAPSHOT
    clock[0] += herdr.MIN_SNAPSHOT_INTERVAL - 0.1
    assert herdr.collect_snapshot('live') == (None, 'busy')
    clock[0] += 0.1
    assert herdr.collect_snapshot('live')[1] is None
    assert len(opened) == 3


def test_overlapping_request_for_the_same_session_is_busy(overview, monkeypatch):
    lock = Lock()
    lock.acquire()
    _, opened = live_session(monkeypatch, overview.owner, overview.profile['id'],
                             herdr_snapshot_lock=lock)
    assert herdr.collect_snapshot('live') == (None, 'busy')
    assert opened == [] and lock.locked()


def test_fifth_concurrent_request_in_the_process_is_busy(overview, monkeypatch):
    session, opened = live_session(monkeypatch, overview.owner, overview.profile['id'])
    slots = herdr._snapshot_slots
    for _ in range(herdr.MAX_CONCURRENT_SNAPSHOTS):
        assert slots.acquire(blocking=False)
    assert herdr.collect_snapshot('live') == (None, 'busy')
    assert opened == [] and not session['herdr_snapshot_lock'].locked()
    assert 'herdr_snapshot_not_before' not in session
    slots.release()
    assert herdr.collect_snapshot('live')[1] is None
    # The finished request returned its slot: exactly one is free again.
    assert slots.acquire(blocking=False)
    assert not slots.acquire(blocking=False)


@pytest.mark.parametrize('channel,reason', [
    (Channel(b'', b'bash: line 1: herdr: command not found\n', 127), 'not_installed'),
    (Channel(b'', NO_SERVER, 1), 'no_server'),
    (Channel(b'', MISMATCH, 1), 'incompatible'),
    (Channel(b'', b'warning: something\n' + NO_SERVER, 1), 'no_server'),
    (Channel(b'', b'{"error":{"code":"future_code","message":"x"}}\n', 1), 'unavailable'),
    (Channel(b'', b'plain text failure\n', 1), 'unavailable'),
    (Channel(b'', b'', 1), 'unavailable'),
    (Channel(b'', NO_SERVER, 2), 'unavailable'),
    (Channel(SNAPSHOT, b'', 126), 'unavailable'),
    # Ended by the host-side limit (SIGTERM).
    (Channel(b'', b'', 143), 'unavailable'),
    (Channel(b'not json', b'', 0), 'invalid'),
    (Channel(b'', b'', 0), 'invalid'),
    (Channel(NO_SERVER, b'', 0), 'invalid'),
])
def test_command_outcomes_map_to_public_reasons(overview, monkeypatch, channel, reason):
    session, _ = live_session(monkeypatch, overview.owner, overview.profile['id'], channel)
    result = request_snapshot(overview, monkeypatch)
    assert result == {'success': False, 'agents': [], 'truncated': False, 'reason': reason}
    assert channel.closed and not session['herdr_snapshot_lock'].locked()


def test_error_output_never_reaches_the_browser(overview, monkeypatch):
    secret = b'/home/deploy/.config/herdr/herdr.sock'
    channel = Channel(b'', NO_SERVER + secret * 400, 1)
    live_session(monkeypatch, overview.owner, overview.profile['id'], channel)
    result = request_snapshot(overview, monkeypatch)
    assert result['reason'] == 'no_server'
    assert 'herdr.sock' not in json.dumps(result)
    assert channel.errors == b''


def test_oversized_output_is_invalid_and_stops_reading(overview, monkeypatch):
    channel = Channel(b'x' * (herdr.MAX_SNAPSHOT_BYTES * 3))
    session, _ = live_session(monkeypatch, overview.owner, overview.profile['id'], channel)
    assert request_snapshot(overview, monkeypatch)['reason'] == 'invalid'
    assert channel.read == herdr.MAX_SNAPSHOT_BYTES + 1
    assert channel.closed and not session['herdr_snapshot_lock'].locked()


def test_command_that_never_finishes_times_out_and_frees_the_session(overview, monkeypatch):
    channel = Channel(b'', b'', finishes=False)
    session, opened = live_session(monkeypatch, overview.owner, overview.profile['id'], channel)
    started = time.monotonic()
    assert herdr.collect_snapshot('live', timeout=0.2) == (None, 'timeout')
    assert 0.2 <= time.monotonic() - started < 2
    assert channel.closed and not session['herdr_snapshot_lock'].locked()
    assert herdr._snapshot_slots.acquire(blocking=False)
    herdr._snapshot_slots.release()
    session['herdr_snapshot_not_before'] = 0
    channel.finishes, channel.output, channel.closed = True, SNAPSHOT, False
    assert herdr.collect_snapshot('live')[1] is None


@pytest.mark.parametrize('error,reason', [
    (TimeoutError('deadline'), 'timeout'), (OSError('reset'), 'unavailable'),
    (RuntimeError('boom'), 'unavailable'),
])
def test_channel_failures_release_every_limit(overview, monkeypatch, error, reason):
    session, _ = live_session(monkeypatch, overview.owner, overview.profile['id'])

    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(ssh_manager, '_open_exec_channel', fail)
    assert herdr.collect_snapshot('live') == (None, reason)
    assert not session['herdr_snapshot_lock'].locked()
    for _ in range(herdr.MAX_CONCURRENT_SNAPSHOTS):
        assert herdr._snapshot_slots.acquire(blocking=False)


def test_inactive_transport_is_disconnected(overview, monkeypatch):
    session, opened = live_session(monkeypatch, overview.owner, overview.profile['id'])
    session['client'] = SimpleNamespace(get_transport=lambda: SimpleNamespace(is_active=lambda: False))
    assert herdr.collect_snapshot('live') == (None, 'disconnected')
    assert opened == []


@pytest.mark.parametrize('enabled,options,browser,expected', [
    (True, {'herdr': True}, {}, True),
    (True, {'herdr': True}, {'herdr': False}, True),
    (False, {'herdr': True}, {'herdr': True, 'use_herdr': True}, False),
    (True, {}, {'herdr': True}, False),
    (True, {'herdr': False}, {'herdr': True}, False),
])
def test_connect_grants_the_overview_only_from_switch_and_saved_host(
        app, monkeypatch, enabled, options, browser, expected):
    owner, sid = user_socket(app, 'herdr_connect')
    enable(app, enabled)
    profile = saved_host(app, owner, **options)
    jobs, connections = capture_connections(app, monkeypatch)
    _, emitted = call(app, monkeypatch, events.handle_ssh_connect, sid,
                      connect_payload(profile_id=profile['id'], **browser))
    assert len(jobs) == 1, emitted
    assert jobs[0].join(3)
    assert connections[0].get('herdr', False) is expected


def test_connect_without_a_saved_host_never_grants_the_overview(app, monkeypatch):
    _, sid = user_socket(app, 'herdr_quick')
    enable(app)
    jobs, connections = capture_connections(app, monkeypatch)
    call(app, monkeypatch, events.handle_ssh_connect, sid, connect_payload(herdr=True, use_herdr=True))
    assert len(jobs) == 1 and jobs[0].join(3)
    assert 'herdr' not in connections[0]


def test_connect_with_another_users_saved_host_is_rejected(app, monkeypatch):
    other, _ = user_socket(app, 'herdr_profile_owner')
    _, sid = user_socket(app, 'herdr_profile_thief')
    enable(app)
    foreign = saved_host(app, other, herdr=True)
    jobs, connections = capture_connections(app, monkeypatch)
    _, emitted = call(app, monkeypatch, events.handle_ssh_connect, sid,
                      connect_payload(profile_id=foreign['id']))
    assert not jobs and not connections
    assert any(event == 'ssh_error' for event, _ in emitted)
    assert foreign['id'] not in json.dumps(emitted)

    jobs, connections = capture_connections(app, monkeypatch)
    call(app, monkeypatch, events.handle_ssh_connect, sid,
         connect_payload(profile_id=foreign['id'], profile_context_optional=True))
    assert len(jobs) == 1 and jobs[0].join(3)
    assert 'herdr' not in connections[0] and 'profile_id' not in connections[0]


@pytest.mark.parametrize('enabled,granted,expected', [
    (True, True, True), (False, True, False), (True, False, False),
])
def test_session_data_reports_the_effective_overview_state(app, enabled, granted, expected):
    enable(app, enabled)
    with app.app_context():
        assert herdr.session_flags({'herdr': granted}) == {'herdr': expected, 'use_herdr': False}
        assert herdr.session_flags({'herdr': 'yes', 'use_herdr': 1}) == {'herdr': False, 'use_herdr': False}


def test_runtime_session_info_carries_the_herdr_flags(monkeypatch):
    base = {'host': 'target.example', 'port': 22, 'username': 'ops', 'connected': True}
    monkeypatch.setattr(ssh_manager, 'sessions', {
        'granted': {**base, 'herdr': True, 'use_herdr': False},
        'legacy': dict(base),
    })
    assert ssh_manager.get_session('granted')['herdr'] is True
    assert ssh_manager.get_session('granted')['use_herdr'] is False
    assert ssh_manager.get_session('legacy')['herdr'] is False
    assert ssh_manager.get_session('legacy')['use_herdr'] is False


@pytest.mark.parametrize('use_herdr', [False, True])
@pytest.mark.parametrize('enabled', [True, False])
def test_restored_session_data_follows_the_switch(app, monkeypatch, enabled, use_herdr):
    from app.models import SSHSession, db
    owner, _ = user_socket(app, 'herdr_restore')
    enable(app, enabled)
    with app.app_context():
        db.session.add(SSHSession(session_id='herdr-live', user_id=owner, host='target.example',
                                  port=22, username='ops', connected=True))
        db.session.commit()
    runtime = {'connected': True, 'herdr': True, 'use_herdr': use_herdr}
    monkeypatch.setattr(events.ssh_manager, 'get_session', lambda _id: runtime)
    monkeypatch.setattr(events.ssh_manager, 'get_output_snapshot', lambda _id: ('', 0))
    monkeypatch.setattr(events, '_public_file_source', lambda *_args: None)
    emitted = []
    monkeypatch.setattr(events, 'emit', lambda event, data=None, **kwargs: emitted.append((event, data)))
    with app.test_request_context('/socket.io'):
        events.restore_user_sessions(owner, 'restoring-socket')
    restored = [data for event, data in emitted if event == 'ssh_session_restored']
    assert len(restored) == 1
    # A running Herdr session stays what it is when the switch is turned off.
    assert restored[0]['herdr'] is enabled and restored[0]['use_herdr'] is use_herdr


SESSION_HOST = {'herdr': True, 'use_herdr': True}


def connect_with(app, monkeypatch, sid, **payload):
    jobs, connections = capture_connections(app, monkeypatch)
    _, emitted = call(app, monkeypatch, events.handle_ssh_connect, sid, connect_payload(**payload))
    for job in jobs:
        assert job.join(3)
    return connections, emitted


@pytest.mark.parametrize('enabled,options,browser,expected', [
    (True, SESSION_HOST, {'use_herdr': True}, True),
    # The saved host alone does not switch a connection into the session mode.
    (True, SESSION_HOST, {}, False),
    (True, SESSION_HOST, {'use_herdr': 'true'}, False),
    (True, {'herdr': True}, {'use_herdr': True}, False),
    (True, {}, {'herdr': True, 'use_herdr': True}, False),
    (False, SESSION_HOST, {'use_herdr': True}, False),
])
def test_connect_grants_the_session_mode_only_from_switch_and_saved_host(
        app, monkeypatch, enabled, options, browser, expected):
    owner, sid = user_socket(app, 'herdr_mode')
    enable(app, enabled)
    profile = saved_host(app, owner, **options)
    connections, emitted = connect_with(app, monkeypatch, sid, profile_id=profile['id'], **browser)
    assert len(connections) == 1, emitted
    assert connections[0].get('use_herdr', False) is expected
    if expected:
        assert connections[0]['herdr'] is True and connections[0]['startup_commands'] == ''


def test_quick_connect_never_gets_the_session_mode(app, monkeypatch):
    _, sid = user_socket(app, 'herdr_mode_quick')
    enable(app)
    connections, _ = connect_with(app, monkeypatch, sid, herdr=True, use_herdr=True)
    assert len(connections) == 1
    assert 'use_herdr' not in connections[0] and 'herdr' not in connections[0]


def test_another_users_saved_host_never_grants_the_session_mode(app, monkeypatch):
    other, _ = user_socket(app, 'herdr_mode_owner')
    _, sid = user_socket(app, 'herdr_mode_thief')
    enable(app)
    foreign = saved_host(app, other, **SESSION_HOST)
    connections, _ = connect_with(app, monkeypatch, sid, profile_id=foreign['id'],
                                  profile_context_optional=True, use_herdr=True)
    assert len(connections) == 1 and 'use_herdr' not in connections[0]


@pytest.mark.parametrize('enabled', [True, False])
@pytest.mark.parametrize('payload,message', [
    ({'use_tmux': True}, 'tmux and Herdr cannot be combined'),
    ({'use_tmux': True, 'reconnect_tmux_name': 'webssh_ops_target_22_deadbeef'},
     'tmux and Herdr cannot be combined'),
    ({'startup_commands': 'uptime'}, 'Herdr session mode cannot be combined with startup commands'),
    ({'startup_mode': 'free_text', 'startup_commands': 'uptime'},
     'Herdr session mode cannot be combined with startup commands'),
])
def test_contradictory_session_mode_requests_are_rejected(app, monkeypatch, enabled, payload, message):
    owner, sid = user_socket(app, 'herdr_mode_conflict')
    enable(app, enabled)
    profile = saved_host(app, owner, **SESSION_HOST)
    connections, emitted = connect_with(app, monkeypatch, sid, profile_id=profile['id'],
                                        use_herdr=True, **payload)
    assert connections == []
    assert [(event, data['error']) for event, data in emitted] == [('ssh_error', message)]


def reconnect_payload(profile_id):
    """What the browser sends when the user reconnects a tab."""
    return dict(profile_id=profile_id, profile_context_optional=True, use_herdr=True,
                use_tmux=False, reconnect_tmux_name=None)


def test_reconnect_of_a_tab_attaches_to_herdr_again(app, monkeypatch):
    owner, sid = user_socket(app, 'herdr_mode_reconnect')
    enable(app)
    profile = saved_host(app, owner, **SESSION_HOST)
    connections, _ = connect_with(app, monkeypatch, sid, **reconnect_payload(profile['id']))
    assert connections[0]['use_herdr'] is True and connections[0]['profile_id'] == profile['id']


@pytest.mark.parametrize('change', ['moved', 'deleted', 'mode_off', 'overview_off', 'switch_off'])
def test_reconnect_falls_back_to_a_normal_shell_when_the_grant_is_gone(app, monkeypatch, change):
    from app import profile_manager
    owner, sid = user_socket(app, 'herdr_mode_lost')
    enable(app)
    profile = saved_host(app, owner, **SESSION_HOST)
    with app.app_context():
        if change == 'moved':
            assert profile_manager.upsert_profile(owner, {**profile, 'host': 'moved.example'})[1] is None
        elif change == 'deleted':
            assert profile_manager.delete_profile(owner, profile['id'])
        elif change == 'mode_off':
            assert profile_manager.upsert_profile(owner, {**profile, 'use_herdr': False})[1] is None
        elif change == 'overview_off':
            assert profile_manager.upsert_profile(
                owner, {**profile, 'herdr': False, 'use_herdr': False})[1] is None
    if change == 'switch_off':
        enable(app, False)
    connections, emitted = connect_with(app, monkeypatch, sid, **reconnect_payload(profile['id']))
    assert len(connections) == 1, emitted
    assert 'use_herdr' not in connections[0]


def connected_payload(app, monkeypatch, sid, runtime, **payload):
    from threading import Event
    from flask import request
    from app import host_platform
    from app.models import SSHSession
    emitted = []
    monkeypatch.setattr(events, 'emit', lambda event, data=None, **kw: emitted.append((event, data)))
    monkeypatch.setattr(events, '_validate_ssh_params',
                        lambda host, port, user, **kw: (host, int(port), user, None))
    monkeypatch.setattr(events.ssh_manager, 'create_ssh_connection', lambda **kw: ('herdr-mode', None))
    monkeypatch.setattr(events.ssh_manager, 'get_session', lambda _id: runtime)
    monkeypatch.setattr(events, '_public_file_source', lambda *args: {})
    monkeypatch.setattr(host_platform, 'detect_connected_platform', lambda *args, **kwargs: None)

    def run(name, target, **kwargs):
        target(Event())
        return SimpleNamespace(cancel=lambda: None)
    monkeypatch.setattr(app.extensions['runtime_lifecycle'], 'start_job', run)
    with app.test_request_context('/socket.io'):
        request.sid = sid
        events.handle_ssh_connect(connect_payload(**payload))
    with app.app_context():
        stored = SSHSession.query.filter_by(session_id='herdr-mode').first()
        stored = None if stored is None else (stored.is_persistent, stored.tmux_session_name)
    return [data for event, data in emitted if event == 'ssh_connected'], stored


@pytest.mark.parametrize('actual', [True, False])
def test_session_data_carries_the_actual_session_mode(app, monkeypatch, actual):
    owner, sid = user_socket(app, 'herdr_mode_data')
    enable(app)
    profile = saved_host(app, owner, **SESSION_HOST)
    runtime = {'use_tmux': False, 'herdr': True, 'use_herdr': actual, 'tmux_session_name': None}
    connected, stored = connected_payload(app, monkeypatch, sid, runtime,
                                          profile_id=profile['id'], use_herdr=True,
                                          display_name='Agents')
    assert len(connected) == 1
    assert connected[0]['use_herdr'] is actual and connected[0]['herdr'] is True
    assert connected[0]['use_tmux'] is False and connected[0]['tmux_session_name'] is None
    assert connected[0]['display_name'] is None
    assert stored == (False, None)


class RecordingTransport:
    def __init__(self):
        self.sessions_opened = 0

    def is_active(self):
        return True

    def open_session(self, timeout=None):
        self.sessions_opened += 1
        raise AssertionError('nothing may run on the host')


def herdr_runtime_session(owner, transport, **fields):
    closed = []
    client = SimpleNamespace(get_transport=lambda: transport, close=lambda: closed.append('client'))
    channel = SimpleNamespace(close=lambda: closed.append('channel'))
    session = {'connected': True, 'user_id': owner, 'client': client, 'channel': channel,
               'herdr': True, 'use_herdr': True, 'use_tmux': False, 'tmux_session_name': None,
               'tmux_reconnect': False, **fields}
    return session, closed


@pytest.mark.parametrize('preserve', [False, True])
def test_disconnecting_a_herdr_session_opens_no_channel(app, monkeypatch, preserve):
    owner, sid = user_socket(app, 'herdr_mode_close')
    transport = RecordingTransport()
    session, closed = herdr_runtime_session(owner, transport)
    monkeypatch.setattr(ssh_manager, 'sessions', {'herdr-live': session})
    monkeypatch.setattr(events, 'verify_session_ownership', lambda session_id, user_id: True)
    call(app, monkeypatch, events.handle_ssh_disconnect, sid,
         {'session_id': 'herdr-live', 'preserve_tmux': preserve})
    assert 'herdr-live' not in ssh_manager.sessions
    assert transport.sessions_opened == 0 and closed == ['channel', 'client']


def test_discarding_a_late_herdr_connection_opens_no_channel(app, monkeypatch):
    owner, sid = user_socket(app, 'herdr_mode_discard')
    transport = RecordingTransport()
    session, closed = herdr_runtime_session(
        owner, transport, client_request_id='herdr-request', host='target.example',
        port=22, username='ops')
    monkeypatch.setattr(ssh_manager, 'sessions', {'herdr-late': session})
    monkeypatch.setattr(events, 'verify_session_ownership', lambda session_id, user_id: True)
    result, _ = call(app, monkeypatch, events.handle_ssh_discard_late_connection, sid,
                     {'session_id': 'herdr-late', 'client_request_id': 'herdr-request'})
    assert result == {'success': True}
    assert transport.sessions_opened == 0 and closed == ['channel', 'client']
