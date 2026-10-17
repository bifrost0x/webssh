"""Behavioral contract for link-based terminal sharing."""

import threading

import pytest

import config
from app import ssh_manager
from app.terminal_share import (
    MODE_CONTROL,
    MODE_VIEW,
    ShareError,
    TerminalShareHub,
    hash_secret,
)


class FakeClock:
    def __init__(self, value=1000.0):
        self.value = value

    def __call__(self):
        return self.value


class FakeRuntime:
    """Minimal stand-in for the SSH registry the hub reads from."""

    def __init__(self):
        self.sessions = {}

    def add(self, session_id, owner_id=1, cols=80, rows=24):
        self.sessions[session_id] = {
            'owner_id': owner_id,
            'cols': cols,
            'rows': rows,
            'output': [],
            'seq': 0,
        }

    def record(self, hub, session_id, data):
        session = self.sessions[session_id]
        session['seq'] += 1
        session['output'].append(data)
        hub.publish(session_id, session['seq'], data)
        return session['seq']

    def probe(self, session_id):
        session = self.sessions.get(session_id)
        if session is None:
            return None
        return {
            'owner_id': session['owner_id'],
            'cols': session['cols'],
            'rows': session['rows'],
        }

    def snapshot(self, session_id):
        session = self.sessions.get(session_id)
        if session is None:
            return None
        return (
            ''.join(session['output']),
            session['seq'],
            session['cols'],
            session['rows'],
        )


@pytest.fixture
def runtime():
    return FakeRuntime()


@pytest.fixture
def clocks():
    return FakeClock(1000.0), FakeClock(1_700_000_000.0)


@pytest.fixture
def hub(runtime, clocks):
    monotonic, wall = clocks
    runtime.add('s1', owner_id=1)
    return TerminalShareHub(
        session_probe=runtime.probe,
        snapshot=runtime.snapshot,
        clock=monotonic,
        wall_clock=wall,
    )


def _events(stream, kind=None):
    events, ended = stream.poll(0)
    if kind is not None:
        events = [event for event in events if event['type'] == kind]
    return events, ended


def test_owner_can_only_share_their_own_live_session(hub, runtime):
    with pytest.raises(ShareError) as missing:
        hub.create(1, 'missing')
    assert missing.value.code == 'session_not_found'

    with pytest.raises(ShareError) as foreign:
        hub.create(2, 's1')
    assert foreign.value.code == 'session_not_found'

    share = hub.create(1, 's1', title='Prod debug')
    assert share['title'] == 'Prod debug'
    assert share['mode'] == MODE_VIEW
    assert len(share['token']) >= 40
    assert hub.list_for_session(2, 's1') == []
    assert [item['id'] for item in hub.list_for_session(1, 's1')] == [share['id']]


def test_share_never_exposes_connection_details_to_viewers(hub, runtime):
    share = hub.create(1, 's1', owner_name='alice')
    view, ticket = hub.join(share['token'], 'Bob')

    assert set(view) == {
        'viewer_id', 'name', 'status', 'title', 'owner', 'mode',
        'expires_at', 'expires_in', 'cols', 'rows', 'viewers',
        'chat_enabled', 'chat',
    }
    assert view['owner'] == 'alice'
    assert view['name'] == 'Bob'
    assert ticket != share['token']


def test_links_are_looked_up_by_hash_and_unknown_links_fail_closed(hub):
    share = hub.create(1, 's1')
    assert hash_secret(share['token']) in hub._by_token
    assert share['token'] not in hub._by_token

    for token in ('', 'short', 'x' * 200, share['token'] + 'x', None):
        with pytest.raises(ShareError) as error:
            hub.join(token)
        assert error.value.code == 'link_invalid'


def test_create_validates_mode_ttl_and_viewer_limits(hub, monkeypatch):
    for kwargs, code in (
        ({'mode': 'admin'}, 'invalid_mode'),
        ({'ttl_minutes': 0}, 'invalid_ttl'),
        ({'ttl_minutes': config.TERMINAL_SHARE_MAX_TTL_MINUTES + 1}, 'invalid_ttl'),
        ({'ttl_minutes': '60'}, 'invalid_ttl'),
        ({'max_viewers': 0}, 'invalid_max_viewers'),
        ({'max_viewers': 999}, 'invalid_max_viewers'),
        ({'require_approval': 'yes'}, 'invalid_request'),
    ):
        with pytest.raises(ShareError) as error:
            hub.create(1, 's1', **kwargs)
        assert error.value.code == code

    monkeypatch.setattr(config, 'TERMINAL_SHARE_ALLOW_CONTROL', False)
    with pytest.raises(ShareError) as error:
        hub.create(1, 's1', mode=MODE_CONTROL)
    assert error.value.code == 'control_disabled'

    monkeypatch.setattr(config, 'TERMINAL_SHARE_ENABLED', False)
    with pytest.raises(ShareError) as error:
        hub.create(1, 's1')
    assert error.value.code == 'sharing_disabled'


def test_titles_and_names_are_single_line_printable_and_bounded(hub):
    share = hub.create(1, 's1', title='Ops\x1b[31m\n‮debug' + 'x' * 200)
    assert '\x1b' not in share['title']
    assert '\n' not in share['title']
    assert '‮' not in share['title']
    assert len(share['title']) <= 80

    view, _ticket = hub.join(share['token'], '\x07\x07')
    assert view['name'] == 'Guest 1'


def test_per_link_global_and_per_owner_caps(hub, runtime, monkeypatch):
    share = hub.create(1, 's1', max_viewers=2)
    hub.join(share['token'])
    hub.join(share['token'])
    with pytest.raises(ShareError) as full:
        hub.join(share['token'])
    assert full.value.code == 'share_full'

    monkeypatch.setattr(config, 'TERMINAL_SHARE_MAX_VIEWERS', 3)
    other = hub.create(1, 's1', max_viewers=2)
    hub.join(other['token'])
    with pytest.raises(ShareError) as capacity:
        hub.join(other['token'])
    assert capacity.value.code == 'capacity'

    monkeypatch.setattr(config, 'TERMINAL_SHARE_MAX_LINKS_PER_USER', 2)
    with pytest.raises(ShareError) as too_many:
        hub.create(1, 's1')
    assert too_many.value.code == 'too_many_links'


def test_first_stream_event_is_a_snapshot_then_live_output(hub, runtime):
    runtime.record(hub, 's1', 'before-share ')
    share = hub.create(1, 's1')
    _view, ticket = hub.join(share['token'])
    stream = hub.open_stream(ticket)

    events, ended = stream.poll(0)
    assert ended is None
    assert events == [{
        'type': 'reset',
        'data': 'before-share ',
        'seq': 1,
        'cols': 80,
        'rows': 24,
        'mode': MODE_VIEW,
        'viewers': 1,
        'chat': [],
    }]

    runtime.record(hub, 's1', 'a')
    runtime.record(hub, 's1', 'b')
    events, _ = _events(stream, 'output')
    # Consecutive chunks are coalesced into one event carrying the last id.
    assert events == [{'type': 'output', 'data': 'ab', 'seq': 3}]


def test_output_already_in_the_snapshot_is_not_delivered_twice(hub, runtime):
    share = hub.create(1, 's1')
    _view, ticket = hub.join(share['token'])
    stream = hub.open_stream(ticket)

    # Simulate the reader racing the snapshot: the chunk is recorded (and so
    # included in the replay), then queued for the viewer after the reset.
    session = runtime.sessions['s1']
    session['seq'] += 1
    session['output'].append('raced')
    reset, _ = stream.poll(0)
    assert reset[0]['data'] == 'raced'
    hub.publish('s1', session['seq'], 'raced')
    runtime.record(hub, 's1', 'next')

    events, _ = _events(stream, 'output')
    assert events == [{'type': 'output', 'data': 'next', 'seq': 2}]


def test_a_slow_viewer_is_resynchronised_instead_of_blocking(hub, runtime, monkeypatch):
    monkeypatch.setattr(config, 'TERMINAL_SHARE_VIEWER_QUEUE_BYTES', 64 * 1024)
    share = hub.create(1, 's1')
    _view, ticket = hub.join(share['token'])
    stream = hub.open_stream(ticket)
    stream.poll(0)

    chunk = 'y' * 4096
    done = threading.Event()

    def flood():
        for _ in range(200):
            runtime.record(hub, 's1', chunk)
        done.set()

    worker = threading.Thread(target=flood)
    worker.start()
    assert done.wait(5), 'publish must never wait for a viewer'
    worker.join()

    assert hub.stats()['queued_bytes'] <= 64 * 1024
    assert hub.stats()['resyncs'] >= 1
    events, _ = stream.poll(0)
    assert events[0]['type'] == 'reset'
    assert events[0]['seq'] == 200


def test_publish_for_unshared_sessions_is_a_no_op(hub, runtime):
    runtime.add('quiet', owner_id=1)
    runtime.record(hub, 'quiet', 'nobody is watching')
    assert hub.stats()['queued_bytes'] == 0


def test_view_only_links_reject_input(hub):
    share = hub.create(1, 's1', mode=MODE_VIEW)
    _view, ticket = hub.join(share['token'])
    with pytest.raises(ShareError) as error:
        hub.authorize_input(ticket)
    assert error.value.code == 'view_only'


def test_control_links_grant_input_and_owner_can_take_it_back(hub):
    share = hub.create(1, 's1', mode=MODE_CONTROL)
    _view, ticket = hub.join(share['token'])
    stream = hub.open_stream(ticket)
    stream.poll(0)

    grant = hub.authorize_input(ticket)
    assert (grant.owner_id, grant.session_id, grant.first_use) == (1, 's1', True)
    assert hub.authorize_input(ticket).first_use is False

    updated = hub.set_mode(1, share['id'], MODE_VIEW)
    assert updated['mode'] == MODE_VIEW
    events, _ = _events(stream, 'mode')
    assert events == [{'type': 'mode', 'mode': MODE_VIEW}]
    with pytest.raises(ShareError):
        hub.authorize_input(ticket)

    with pytest.raises(ShareError) as foreign:
        hub.set_mode(2, share['id'], MODE_CONTROL)
    assert foreign.value.code == 'share_not_found'


def test_global_kill_switch_blocks_input_on_existing_control_links(hub, monkeypatch):
    share = hub.create(1, 's1', mode=MODE_CONTROL)
    _view, ticket = hub.join(share['token'])
    monkeypatch.setattr(config, 'TERMINAL_SHARE_ALLOW_CONTROL', False)
    with pytest.raises(ShareError) as error:
        hub.authorize_input(ticket)
    assert error.value.code == 'view_only'


def test_approval_holds_viewers_in_a_lobby_until_admitted(hub, runtime):
    share = hub.create(1, 's1', mode=MODE_CONTROL, require_approval=True)
    view, ticket = hub.join(share['token'], 'Carol')
    assert view['status'] == 'pending'
    stream = hub.open_stream(ticket)

    assert stream.poll(0) == ([{'type': 'pending'}], None)
    runtime.record(hub, 's1', 'secret output')
    assert stream.poll(0) == ([], None)
    with pytest.raises(ShareError) as error:
        hub.authorize_input(ticket)
    assert error.value.code == 'awaiting_approval'

    hub.approve_viewer(1, share['id'], view['viewer_id'])
    events, _ = stream.poll(0)
    assert events[0]['type'] == 'reset'
    assert hub.authorize_input(ticket).session_id == 's1'


def test_owner_can_remove_a_viewer(hub):
    share = hub.create(1, 's1')
    view, ticket = hub.join(share['token'])
    stream = hub.open_stream(ticket)
    stream.poll(0)

    hub.remove_viewer(1, share['id'], view['viewer_id'])
    assert stream.poll(0) == ([{'type': 'end', 'reason': 'removed'}], 'removed')
    with pytest.raises(ShareError):
        hub.open_stream(ticket)


@pytest.mark.parametrize('end', ['revoke', 'session', 'owner'])
def test_ending_a_share_disconnects_every_viewer(hub, end):
    share = hub.create(1, 's1')
    _view, ticket = hub.join(share['token'])
    stream = hub.open_stream(ticket)
    stream.poll(0)

    if end == 'revoke':
        hub.revoke(1, share['id'])
        reason = 'revoked'
    elif end == 'session':
        hub.end_session('s1')
        reason = 'session_closed'
    else:
        hub.end_owner(1)
        reason = 'owner_signed_out'

    assert stream.poll(0) == ([{'type': 'end', 'reason': reason}], reason)
    assert hub.list_for_owner(1) == []
    with pytest.raises(ShareError) as error:
        hub.join(share['token'])
    assert error.value.code == 'link_invalid'
    assert hub.stats()['links'] == 0
    assert hub.stats()['viewers'] == 0


def test_links_expire(hub, clocks):
    _monotonic, wall = clocks
    notices = []
    hub.set_listener(lambda owner, session, event: notices.append(event))
    share = hub.create(1, 's1', ttl_minutes=5)
    _view, ticket = hub.join(share['token'])

    wall.value += 5 * 60 + 1
    with pytest.raises(ShareError) as error:
        hub.open_stream(ticket)
    assert error.value.code == 'expired'
    hub.reap()
    assert hub.list_for_owner(1) == []
    assert {'kind': 'ended', 'reason': 'expired', 'share_id': share['id']} in notices


def test_disconnected_viewers_keep_their_seat_for_a_grace_period(hub, clocks):
    monotonic, _wall = clocks
    share = hub.create(1, 's1', max_viewers=1)
    _view, ticket = hub.join(share['token'])
    hub.open_stream(ticket).close()

    monotonic.value += config.TERMINAL_SHARE_VIEWER_GRACE_SECONDS - 1
    hub.reap()
    with pytest.raises(ShareError) as full:
        hub.join(share['token'])
    assert full.value.code == 'share_full'

    monotonic.value += 2
    hub.reap()
    hub.join(share['token'])


def test_reconnect_resumes_without_a_snapshot_when_nothing_was_lost(hub, runtime):
    share = hub.create(1, 's1')
    _view, ticket = hub.join(share['token'])
    first = hub.open_stream(ticket)
    first.poll(0)
    runtime.record(hub, 's1', 'one')
    events, _ = _events(first, 'output')
    assert events[0]['seq'] == 1
    first.close()

    runtime.record(hub, 's1', 'two')
    resumed = hub.open_stream(ticket, last_event_id='1')
    assert resumed.resumed is True
    events, _ = resumed.poll(0)
    assert [event['type'] for event in events] == ['state', 'output']
    assert events[1]['data'] == 'two'

    resumed.close()
    stale = hub.open_stream(ticket, last_event_id='0')
    assert stale.resumed is False
    events, _ = stale.poll(0)
    assert events[0]['type'] == 'reset'


def test_a_new_stream_supersedes_the_previous_one(hub):
    share = hub.create(1, 's1')
    _view, ticket = hub.join(share['token'])
    first = hub.open_stream(ticket)
    second = hub.open_stream(ticket)
    assert first.poll(0) == ([], 'superseded')
    assert second.poll(0)[0][0]['type'] == 'reset'
    with pytest.raises(ShareError) as error:
        hub.open_stream(ticket)
    assert error.value.code == 'capacity'


def test_stream_slots_are_bounded_globally(hub, monkeypatch):
    monkeypatch.setattr(config, 'TERMINAL_SHARE_MAX_VIEWERS', 2)
    monkeypatch.setattr(config, 'TERMINAL_SHARE_STREAM_SLACK', 0)
    share = hub.create(1, 's1', max_viewers=2)
    tickets = [hub.join(share['token'])[1] for _ in range(2)]
    streams = [hub.open_stream(ticket) for ticket in tickets]
    with pytest.raises(ShareError) as error:
        hub.open_stream(tickets[0])
    assert error.value.code == 'capacity'
    streams[0].close()
    hub.open_stream(tickets[0])


def test_resize_reaches_viewers(hub, runtime):
    share = hub.create(1, 's1')
    _view, ticket = hub.join(share['token'])
    stream = hub.open_stream(ticket)
    stream.poll(0)
    hub.resize('s1', 132, 40)
    events, _ = _events(stream, 'resize')
    assert events == [{'type': 'resize', 'cols': 132, 'rows': 40}]
    assert hub.describe(ticket)['cols'] == 132


def test_owner_is_notified_about_presence(hub):
    notices = []
    hub.set_listener(lambda owner, session, event: notices.append(
        (owner, session, event['kind'])
    ))
    share = hub.create(1, 's1')
    _view, ticket = hub.join(share['token'], 'Dana')
    hub.leave(ticket)
    hub.revoke(1, share['id'])
    kinds = [kind for owner, session, kind in notices if (owner, session) == (1, 's1')]
    assert kinds[0] == 'created'
    assert 'joined' in kinds
    assert 'left' in kinds
    assert kinds[-1] == 'ended'


def test_listener_failures_never_break_share_operations(hub):
    def broken(*_args):
        raise RuntimeError('socket gone')

    hub.set_listener(broken)
    share = hub.create(1, 's1')
    hub.join(share['token'])
    hub.revoke(1, share['id'])


def _live_stream(hub, token, name='Guest'):
    view, ticket = hub.join(token, name)
    stream = hub.open_stream(ticket)
    stream.poll(0)
    return view, ticket, stream


def test_chat_reaches_everyone_in_the_session_but_not_the_sender(hub):
    activity = []
    hub.set_activity_listener(lambda owner, session, kind, payload: activity.append(
        (owner, session, kind, payload['text'])
    ))
    view_link = hub.create(1, 's1', mode=MODE_VIEW)
    control_link = hub.create(1, 's1', mode=MODE_CONTROL)
    alice, alice_ticket, alice_stream = _live_stream(hub, view_link['token'], 'Alice')
    _bob, _bob_ticket, bob_stream = _live_stream(hub, control_link['token'], 'Bob')

    message = hub.guest_chat(alice_ticket, 'can you run uptime?')
    assert message['name'] == 'Alice'
    assert message['role'] == 'guest'
    assert message['sender'] == alice['viewer_id']
    assert _events(alice_stream, 'chat')[0] == []
    assert [event['text'] for event in _events(bob_stream, 'chat')[0]] == ['can you run uptime?']
    assert activity == [(1, 's1', 'chat', 'can you run uptime?')]

    reply = hub.owner_chat(1, 's1', 'sure', name='alice-admin')
    assert reply['role'] == 'owner'
    assert reply['name'] == 'alice-admin'
    assert [event['text'] for event in _events(alice_stream, 'chat')[0]] == ['sure']
    assert [item['text'] for item in hub.chat_history(1, 's1')] == ['can you run uptime?', 'sure']
    assert hub.chat_history(2, 's1') == []
    assert hub.stats()['chat_messages'] == 2


def test_chat_text_is_single_line_printable_and_bounded(hub):
    share = hub.create(1, 's1')
    _view, ticket, _stream = _live_stream(hub, share['token'])
    message = hub.guest_chat(ticket, 'hi\x1b[31m\nthere\u202e' + 'x' * 900)
    assert '\x1b' not in message['text']
    assert '\n' not in message['text']
    assert '\u202e' not in message['text']
    assert len(message['text']) <= 500
    for bad in ('', '   ', '\x07', None, 5):
        with pytest.raises(ShareError) as error:
            hub.guest_chat(ticket, bad)
        assert error.value.code == 'invalid_request'


def test_lobby_guests_neither_read_nor_write_chat(hub):
    share = hub.create(1, 's1', require_approval=True)
    hub.owner_chat(1, 's1', 'private before admission')
    view, ticket = hub.join(share['token'], 'Pat')
    assert view['chat'] == []
    stream = hub.open_stream(ticket)
    assert stream.poll(0) == ([{'type': 'pending'}], None)
    hub.owner_chat(1, 's1', 'still private')
    assert stream.poll(0) == ([], None)
    with pytest.raises(ShareError) as error:
        hub.guest_chat(ticket, 'let me in')
    assert error.value.code == 'awaiting_approval'
    with pytest.raises(ShareError):
        hub.guest_pointer(ticket, 1, 1)

    hub.approve_viewer(1, share['id'], view['viewer_id'])
    events, _ = stream.poll(0)
    assert events[0]['type'] == 'reset'
    assert [item['text'] for item in events[0]['chat']] == [
        'private before admission', 'still private',
    ]


def test_new_and_resynchronised_guests_receive_recent_history(hub, monkeypatch):
    monkeypatch.setattr(config, 'TERMINAL_SHARE_CHAT_HISTORY', 2)
    share = hub.create(1, 's1')
    for text in ('one', 'two', 'three'):
        hub.owner_chat(1, 's1', text)
    view, ticket = hub.join(share['token'])
    assert [item['text'] for item in view['chat']] == ['two', 'three']
    stream = hub.open_stream(ticket)
    events, _ = stream.poll(0)
    assert [item['text'] for item in events[0]['chat']] == ['two', 'three']


def test_owner_chat_requires_an_owned_shared_session(hub, runtime):
    with pytest.raises(ShareError) as unshared:
        hub.owner_chat(1, 's1', 'hello')
    assert unshared.value.code == 'not_shared'
    hub.create(1, 's1')
    runtime.add('s2', owner_id=2)
    hub.create(2, 's2')
    with pytest.raises(ShareError) as foreign:
        hub.owner_chat(1, 's2', 'hello')
    assert foreign.value.code == 'not_shared'
    with pytest.raises(ShareError):
        hub.owner_pointer(1, 's2', 0, 0)


def test_chat_and_pointers_are_rate_limited_per_sender(hub, clocks):
    monotonic, _wall = clocks
    share = hub.create(1, 's1')
    _view, ticket, _stream = _live_stream(hub, share['token'])
    for index in range(5):
        hub.guest_chat(ticket, f'message {index}')
    with pytest.raises(ShareError) as error:
        hub.guest_chat(ticket, 'one too many')
    assert error.value.code == 'rate_limited'
    monotonic.value += 1
    hub.guest_chat(ticket, 'refilled')

    for _ in range(20):
        hub.guest_pointer(ticket, 1, 1)
    with pytest.raises(ShareError):
        hub.guest_pointer(ticket, 1, 1)

    for index in range(5):
        hub.owner_chat(1, 's1', f'owner {index}')
    with pytest.raises(ShareError) as owner_error:
        hub.owner_chat(1, 's1', 'too fast')
    assert owner_error.value.code == 'rate_limited'


def test_pointers_are_bounded_by_the_terminal_grid(hub, runtime):
    share = hub.create(1, 's1')
    hub.resize('s1', 100, 30)
    alice, alice_ticket, alice_stream = _live_stream(hub, share['token'], 'Alice')
    _bob, _bob_ticket, bob_stream = _live_stream(hub, share['token'], 'Bob')
    activity = []
    hub.set_activity_listener(lambda owner, session, kind, payload: activity.append((kind, payload)))

    pointer = hub.guest_pointer(alice_ticket, 99, 29)
    assert pointer == {
        'name': 'Alice', 'role': 'guest', 'sender': alice['viewer_id'], 'col': 99, 'row': 29,
    }
    assert _events(bob_stream, 'pointer')[0][0]['col'] == 99
    assert _events(alice_stream, 'pointer')[0] == []
    assert activity == [('pointer', pointer)]

    hub.owner_pointer(1, 's1', 0, 0, name='owner')
    assert _events(alice_stream, 'pointer')[0][0]['role'] == 'owner'
    assert len(activity) == 1, 'the owner is not echoed their own pointer'

    for col, row in ((100, 0), (0, 30), (-1, 0), (True, 0), ('1', 1), (1.0, 1)):
        with pytest.raises(ShareError) as error:
            hub.guest_pointer(alice_ticket, col, row)
        assert error.value.code == 'invalid_request'


def test_chat_history_disappears_with_the_last_link(hub):
    first = hub.create(1, 's1')
    second = hub.create(1, 's1')
    hub.owner_chat(1, 's1', 'remember me?')
    hub.revoke(1, first['id'])
    assert len(hub.chat_history(1, 's1')) == 1
    hub.revoke(1, second['id'])
    assert hub.chat_history(1, 's1') == []
    hub.create(1, 's1')
    assert hub.chat_history(1, 's1') == []


def test_chat_kill_switch(hub, monkeypatch):
    share = hub.create(1, 's1')
    view, ticket, _stream = _live_stream(hub, share['token'])
    monkeypatch.setattr(config, 'TERMINAL_SHARE_CHAT_ENABLED', False)
    for call in (
        lambda: hub.guest_chat(ticket, 'hi'),
        lambda: hub.guest_pointer(ticket, 0, 0),
        lambda: hub.owner_chat(1, 's1', 'hi'),
        lambda: hub.owner_pointer(1, 's1', 0, 0),
    ):
        with pytest.raises(ShareError) as error:
            call()
        assert error.value.code == 'chat_disabled'
    assert hub.describe(ticket)['chat_enabled'] is False


def test_activity_listener_failures_never_break_chat(hub):
    def broken(*_args):
        raise RuntimeError('socket gone')

    hub.set_activity_listener(broken)
    share = hub.create(1, 's1')
    _view, ticket, _stream = _live_stream(hub, share['token'])
    hub.guest_chat(ticket, 'still delivered')
    assert hub.chat_history(1, 's1')[0]['text'] == 'still delivered'


@pytest.fixture
def live_session():
    session_id = 'share-live-session'
    with ssh_manager.sessions_lock:
        ssh_manager.sessions[session_id] = {
            'client': None,
            'channel': None,
            'user_id': 7,
            'connected': True,
            'output_buffer': [],
            'output_buffer_size': 0,
            'output_buffer_max': 512000,
            'output_sequence': 0,
            'cols': 80,
            'rows': 24,
        }
    yield session_id
    with ssh_manager.sessions_lock:
        ssh_manager.sessions.pop(session_id, None)


def test_ssh_runtime_snapshot_and_probe(live_session):
    ssh_manager.record_output(live_session, 'hello\x1b[?1;2c world', now=1)
    assert ssh_manager.get_share_probe(live_session) == {
        'owner_id': 7, 'cols': 80, 'rows': 24,
    }
    assert ssh_manager.get_share_snapshot(live_session) == (
        'hello world', 1, 80, 24,
    )
    assert ssh_manager.get_share_probe('missing') is None
    assert ssh_manager.get_share_snapshot('missing') is None


def test_closing_an_ssh_session_ends_its_shares(live_session):
    from app.terminal_share import share_hub

    share = share_hub.create(7, live_session)
    _view, ticket = share_hub.join(share['token'])
    stream = share_hub.open_stream(ticket)
    stream.poll(0)

    assert ssh_manager.close_session(live_session) is True
    assert stream.poll(0) == (
        [{'type': 'end', 'reason': 'session_closed'}],
        'session_closed',
    )
    stream.close()
    assert share_hub.list_for_owner(7) == []
