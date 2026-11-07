import pytest
from app import host_platform

@pytest.mark.parametrize('facts, expected', [
    ('ID=ubuntu\nkernel=Linux', 'ubuntu'),
    ('ID=debian\nmarker=proxmox', 'proxmox'),
    ('ID=debian\nmodel=Raspberry Pi 5 Model B', 'raspberrypi'),
    ('ID=haos', 'homeassistant'), ('ID=truenas', 'truenas'),
    ('kernel=FreeBSD\nmarker=opnsense', 'opnsense'),
    ('kernel=Darwin', 'apple'), ('kernel=FreeBSD', 'freebsd'),
    ('ID=unknown\ndocker=yes', 'server'),
    ('ID=ubuntu;$(touch /tmp/bad)', 'server'),
])
def test_platform_uses_fixed_facts(facts, expected):
    assert host_platform.parse_platform(facts) == expected

def test_rejects_duplicate_oversized_and_control_output():
    for text in ['ID=ubuntu\nID=debian', 'x' * 4097, 'ID=ubuntu\x00']:
        with pytest.raises(ValueError):
            host_platform.parse_platform(text)

def test_probe_never_sources_remote_files():
    command = host_platform.PLATFORM_COMMAND
    assert '. /etc/' not in command and 'source ' not in command
    assert 'eval ' not in command and 'sudo' not in command
    assert 'docker' not in command

def test_platform_cache_is_endpoint_scoped_and_override_persists(app):
    from app import profile_manager
    from tests.test_profile_manager import create_user
    user_id = create_user(app)
    with app.app_context():
        payload = dict(name='Docker', host='example.test', port=22, username='deploy', auth_type='password', platform_icon='proxmox')
        profile, error = profile_manager.upsert_profile(user_id, payload)
        assert error is None
        assert profile['platform_icon'] == 'proxmox'
        assert profile_manager.cache_detected_platform(user_id, profile['id'], host_platform.endpoint(profile), 'ubuntu')
        saved = profile_manager.get_profile(user_id, profile['id'])
        assert saved['detected_platform'] == 'ubuntu'
        assert not profile_manager.cache_detected_platform(user_id + 1, profile['id'], host_platform.endpoint(profile), 'debian')
        changed, error = profile_manager.upsert_profile(user_id, dict(payload, id=profile['id'], host='other.test'))
        assert error is None
        assert 'detected_platform' not in changed
        assert changed['platform_icon'] == 'proxmox'
        assert not profile_manager.cache_detected_platform(user_id, profile['id'], host_platform.endpoint(profile), 'debian')


def test_invalid_platform_override_rejected(app):
    from app import profile_manager
    from tests.test_profile_manager import create_user
    user_id = create_user(app)
    with app.app_context():
        profile, error = profile_manager.upsert_profile(user_id, dict(name='a', host='example.test', username='deploy', auth_type='password', platform_icon='../bad'))
        assert profile is None
        assert error == 'Invalid platform icon'


def test_detection_task_checks_session_ownership_and_uses_facts(app, monkeypatch):
    from app import ssh_manager, profile_manager
    from tests.test_profile_manager import create_user
    user_id = create_user(app)
    events = []
    with app.app_context():
        profile, _ = profile_manager.upsert_profile(user_id, dict(name='Proxmox', host='example.test', port=22, username='deploy', auth_type='password'))
        session = dict(profile, connected=True, user_id=user_id, profile_id=profile['id'])
        monkeypatch.setitem(ssh_manager.sessions, 'platform-test', session)
        monkeypatch.setattr(host_platform, 'collect_platform', lambda _, **kwargs: ('ubuntu', None))
        host_platform.detect_connected_platform('platform-test', user_id + 1, events.append)
        assert events == []
        host_platform.detect_connected_platform('platform-test', user_id, events.append)
        assert events[0]['platform'] == 'ubuntu'
        assert profile_manager.get_profile(user_id, profile['id'])['detected_platform'] == 'ubuntu'
        monkeypatch.setattr(host_platform, 'collect_platform', lambda _, **kwargs: (None, 'transient'))
        host_platform.detect_connected_platform('platform-test', user_id, events.append)
        assert len(events) == 1

@pytest.mark.parametrize('saved, live', [('NAS.Example.test', 'nas.example.test'), ('2001:0db8:0000:0000:0000:0000:0000:0001', '2001:db8::1')])
def test_endpoint_compares_canonical_hosts_and_default_port(saved, live):
    assert host_platform.endpoint(dict(host=saved, username='root')) == host_platform.endpoint(dict(host=live, port=22, username='root'))
    assert host_platform.endpoint(dict(host=saved, username='root')) != host_platform.endpoint(dict(host=live, port=22, username='other'))


def test_platform_collector_channel_failure_is_optional(monkeypatch):
    from app import session_insights
    from tests.test_session_insights import install_session
    install_session(monkeypatch)
    def reject(*args, **kwargs):
        raise OSError('channel unavailable')
    monkeypatch.setattr(session_insights.ssh_manager, '_open_exec_channel', reject)
    assert host_platform.collect_platform('owned-session') == (None, 'transient')
    assert session_insights.ssh_manager.sessions['owned-session']['connected']

def test_platform_collector_rejects_partial_output_and_honors_cancellation(monkeypatch):
    from threading import Event
    from app import session_insights
    from tests.test_session_insights import install_session, FakeChannel
    install_session(monkeypatch)
    channel = FakeChannel(b'ID=ubuntu\n')
    monkeypatch.setattr(channel, 'exit_status_ready', lambda: False)
    monkeypatch.setattr(session_insights.ssh_manager, '_open_exec_channel', lambda *args, **kwargs: channel)
    clock = iter([0, 0, 0, 2])
    monkeypatch.setattr(session_insights.time, 'monotonic', lambda: next(clock))
    assert host_platform.collect_platform('owned-session') == (None, 'transient')
    assert channel.closed
    cancelled = Event()
    cancelled.set()
    channel = FakeChannel(b'ID=ubuntu\n')
    monkeypatch.setattr(session_insights.ssh_manager, '_open_exec_channel', lambda *args, **kwargs: channel)
    monkeypatch.setattr(session_insights.time, 'monotonic', lambda: 0)
    assert host_platform.collect_platform('owned-session', cancel_event=cancelled) == (None, 'transient')
    assert channel.closed

@pytest.mark.usefixtures('direct_socket_authentication')
def test_optional_platform_failure_after_success_never_becomes_ssh_error(app, monkeypatch):
    from types import SimpleNamespace
    from flask import request
    from app import socket_events, ssh_manager
    from tests.test_command_set_socket_events import create_socket_user
    _, sid = create_socket_user(app, 'platform_nonfatal')
    emitted = []
    monkeypatch.setattr(socket_events, 'emit', lambda event, payload=None, **kwargs: emitted.append((event, payload)))
    monkeypatch.setattr(socket_events, '_validate_ssh_params', lambda host, port, username, **kwargs: (host, int(port), username, None))
    monkeypatch.setattr(ssh_manager, 'create_ssh_connection', lambda **kwargs: ('platform-success', None))
    monkeypatch.setattr(ssh_manager, 'get_session', lambda _: {'use_tmux': False})
    monkeypatch.setattr(socket_events, '_public_file_source', lambda *args: {})
    def failed_probe(*args, **kwargs):
        assert [name for name, _ in emitted] == ['ssh_connected']
        raise RuntimeError('optional detector failed')
    monkeypatch.setattr(host_platform, 'detect_connected_platform', failed_probe)
    def run(name, target, **kwargs):
        from threading import Event
        target(Event())
        return SimpleNamespace(cancel=lambda: None)
    monkeypatch.setattr(app.extensions['runtime_lifecycle'], 'start_job', run)
    with app.test_request_context('/socket.io'):
        request.sid = sid
        socket_events.handle_ssh_connect({'host': 'example.test', 'port': 22, 'username': 'deploy', 'auth_type': 'password', 'password': 'temporary'})
    assert [name for name, _ in emitted] == ['ssh_connected']

def test_host_exchange_preserves_only_manual_icon():
    import json
    from app.profile_exchange import export_profiles, preview_import, ExchangeError
    profile = dict(name='NAS', host='example.test', username='root', platform_icon='proxmox', detected_platform='ubuntu')
    document = export_profiles([profile], [])
    assert document['hosts'][0]['platform_icon'] == 'proxmox'
    assert 'detected_platform' not in document['hosts'][0]
    assert preview_import(json.dumps(document), 'json')['records'][0]['platform_icon'] == 'proxmox'
    document['hosts'][0]['platform_icon'] = '../invalid'
    assert preview_import(json.dumps(document), 'json')['records'][0]['blocked']
    document['hosts'][0]['detected_platform'] = 'ubuntu'
    with pytest.raises(ExchangeError):
        preview_import(json.dumps(document), 'json')


@pytest.mark.parametrize('stored, probed', [
    ({}, True),
    ({'platform_icon': 'auto'}, True),
    ({'platform_icon': 'proxmox'}, False),
    ({'detected_platform': 'debian'}, False),
])
def test_detection_runs_once_per_saved_host_in_automatic_mode(app, monkeypatch, stored, probed):
    from app import ssh_manager, profile_manager
    from tests.test_profile_manager import create_user
    user_id = create_user(app)
    calls = []
    with app.app_context():
        profile, _ = profile_manager.upsert_profile(user_id, dict(name='Host', host='example.test', port=22, username='deploy', auth_type='password',
                                                                  **{k: v for k, v in stored.items() if k == 'platform_icon'}))
        if 'detected_platform' in stored:
            assert profile_manager.cache_detected_platform(user_id, profile['id'], host_platform.endpoint(profile), stored['detected_platform'])
        monkeypatch.setitem(ssh_manager.sessions, 'platform-once', dict(profile, connected=True, user_id=user_id, profile_id=profile['id']))
        monkeypatch.setattr(host_platform, 'collect_platform', lambda _, **kwargs: (calls.append(1), ('ubuntu', None))[1])
        host_platform.detect_connected_platform('platform-once', user_id, lambda payload: None)
        assert bool(calls) is probed
        # A detected result is reused on the next connection.
        host_platform.detect_connected_platform('platform-once', user_id, lambda payload: None)
        assert len(calls) == (1 if probed else 0)


def test_quick_connections_are_never_probed(app, monkeypatch):
    from app import ssh_manager
    from tests.test_profile_manager import create_user
    user_id = create_user(app)
    calls = []
    with app.app_context():
        monkeypatch.setitem(ssh_manager.sessions, 'platform-quick', dict(host='example.test', port=22, username='deploy', connected=True, user_id=user_id, profile_id=None))
        monkeypatch.setattr(host_platform, 'collect_platform', lambda _, **kwargs: (calls.append(1), ('ubuntu', None))[1])
        host_platform.detect_connected_platform('platform-quick', user_id, lambda payload: None)
    assert calls == []
