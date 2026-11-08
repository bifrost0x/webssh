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


def test_greeting_platform_is_validated_and_follows_the_address(app):
    from app import profile_manager
    from tests.test_profile_manager import create_user
    user_id = create_user(app)
    with app.app_context():
        payload = dict(name='NAS', host='10.0.0.7', port=22, username='ops', auth_type='password', greeting_platform='ubuntu')
        profile, error = profile_manager.upsert_profile(user_id, payload)
        assert error is None
        assert profile['greeting_platform'] == 'ubuntu'
        assert 'detected_platform' not in profile
        # A later edit from the form keeps it while the address and port stay the same.
        edited = {key: value for key, value in payload.items() if key != 'greeting_platform'}
        renamed, error = profile_manager.upsert_profile(user_id, dict(edited, id=profile['id'], name='Storage', username='admin'))
        assert error is None
        assert renamed['greeting_platform'] == 'ubuntu'
        moved, error = profile_manager.upsert_profile(user_id, dict(edited, id=profile['id'], host='10.0.0.8'))
        assert error is None
        assert 'greeting_platform' not in moved
        for invalid in ('windows', 3, None, '<b>'):
            _, error = profile_manager.upsert_profile(user_id, dict(payload, name=f'bad-{invalid}', greeting_platform=invalid))
            assert error == 'Invalid platform icon'


def test_services_map_fixed_facts_and_known_images_only():
    facts = '\n'.join([
        'service=docker', 'service=unit:nginx', 'service=unit:mysql', 'service=wireguard',
        'service=unit:sshd', 'service=evil',
        'image=lscr.io/linuxserver/nextcloud:latest',
        'image=ghcr.io/home-assistant/home-assistant:stable',
        'image=jc21/nginx-proxy-manager:latest',
        'image=postgres:16', 'image=redis:7', 'image=nginx:alpine',
        'image=$(rm -rf /)', 'unrelated=nextcloud',
    ])
    assert host_platform.parse_services(facts) == [
        'docker', 'homeassistant', 'mariadb', 'nextcloud', 'nginx', 'nginxproxymanager', 'postgresql', 'wireguard',
    ]
    assert host_platform.parse_services('') == []
    for text in ['service=docker\x00', 'x' * 7000]:
        with pytest.raises(ValueError):
            host_platform.parse_services(text)


def test_service_probe_is_read_only_and_bounded():
    command = host_platform.SERVICES_COMMAND
    for forbidden in ('sudo', 'eval ', 'source ', '. /etc/', ' rm ', ' exec ', 'docker run', 'docker exec', 'inspect'):
        assert forbidden not in command
    # Containers are listed by image name only, with a time limit and a line limit.
    assert "ps --format '{{.Image}}'" in command and 'timeout 2' in command and 'head -n 30' in command
    assert 'docker' not in host_platform.PLATFORM_COMMAND


def test_services_are_detected_weekly_kept_on_edit_and_off_with_a_manual_icon(app, monkeypatch):
    from app import ssh_manager, profile_manager
    from tests.test_profile_manager import create_user
    user_id = create_user(app)
    events, calls = [], []
    with app.app_context():
        payload = dict(name='NAS', host='nas.example', port=22, username='deploy', auth_type='password')
        profile, _ = profile_manager.upsert_profile(user_id, payload)
        session = dict(profile, connected=True, user_id=user_id, profile_id=profile['id'])
        monkeypatch.setitem(ssh_manager.sessions, 'services-test', session)
        monkeypatch.setattr(host_platform, 'collect_platform', lambda _, **kwargs: ('debian', None))
        monkeypatch.setattr(host_platform, 'collect_services',
                            lambda _, **kwargs: (calls.append(1), (['docker', 'nextcloud'], None))[1])
        host_platform.detect_connected_platform('services-test', user_id, events.append)
        assert events[-1] == {'session_id': 'services-test', 'profile_id': profile['id'],
                              'platform': 'debian', 'services': ['docker', 'nextcloud']}
        saved = profile_manager.get_profile(user_id, profile['id'])
        assert saved['detected_services'] == ['docker', 'nextcloud']
        # A second connection within the week does not probe again.
        host_platform.detect_connected_platform('services-test', user_id, events.append)
        assert len(calls) == 1
        assert host_platform.services_needed(saved, now=saved['services_checked_at'] + host_platform.SERVICE_REFRESH_SECONDS + 1)
        # Editing the name keeps them; moving the host drops them.
        renamed, _ = profile_manager.upsert_profile(user_id, dict(payload, id=profile['id'], name='Storage'))
        assert renamed['detected_services'] == ['docker', 'nextcloud']
        moved, _ = profile_manager.upsert_profile(user_id, dict(payload, id=profile['id'], host='other.example'))
        assert 'detected_services' not in moved
        assert not host_platform.needs_detection(dict(moved, platform_icon='proxmox'))
        # The browser cannot write detection results itself.
        forged, _ = profile_manager.upsert_profile(user_id, dict(payload, id=profile['id'], detected_services=['plex']))
        assert forged.get('detected_services') != ['plex']


@pytest.mark.parametrize('facts, expected', [
    ('reboot=yes\napt=12\naptsecurity=3', {'reboot_required': True, 'updates': 12, 'security_updates': 3}),
    # apt-check is not asked; such a line from a host is ignored.
    ('reboot=yes\naptcheck=12;3', {'reboot_required': True, 'updates': None, 'security_updates': None}),
    ('reboot=no\napt=4\naptsecurity=1', {'reboot_required': False, 'updates': 4, 'security_updates': 1}),
    # The probe does not ask dnf or needs-restarting; such lines from a host are ignored.
    ('dnf=14\ndnfsecurity=6\nrestartcode=1', {'reboot_required': None, 'updates': None, 'security_updates': None}),
    # Without package lists or tools nothing is claimed.
    ('reboot=no', {'reboot_required': False, 'updates': None, 'security_updates': None}),
    ('', {'reboot_required': None, 'updates': None, 'security_updates': None}),
    ('aptcheck=/usr/lib/update-notifier/apt-check: error', {'reboot_required': None, 'updates': None, 'security_updates': None}),
    ('apt=2\naptsecurity=9', {'reboot_required': None, 'updates': 2, 'security_updates': 2}),
    ('apt=9999999\napt=1', {'reboot_required': None, 'updates': None, 'security_updates': None}),
    ('reboot=$(id)\napt=-1', {'reboot_required': None, 'updates': None, 'security_updates': None}),
])
def test_maintenance_facts_are_parsed_conservatively(facts, expected):
    assert host_platform.parse_maintenance(facts) == expected
    assert host_platform.valid_maintenance(expected)


def test_maintenance_parser_rejects_oversized_and_control_output():
    for text in ('x' * 2000, 'apt=1\x1b[2J', None):
        with pytest.raises(ValueError):
            host_platform.parse_maintenance(text)
    assert not host_platform.valid_maintenance({'updates': True})
    assert not host_platform.valid_maintenance({'updates': -1})
    assert not host_platform.valid_maintenance({'reboot_required': 'yes'})
    assert not host_platform.valid_maintenance({'extra': 1})


def test_maintenance_probe_is_read_only_and_bounded():
    command = host_platform.MAINTENANCE_COMMAND
    for forbidden in ('sudo', 'eval ', 'source ', ' rm ', ' exec ', 'apt-get update', 'apt update', 'makecache',
                      'install', 'upgrade -y', 'refresh'):
        assert forbidden not in command
    # Simulation only, under a time limit, without lock, planner log or binary caches, so
    # nothing is written even as root; apt-check and dnf write caches or logs and are not asked.
    assert ('timeout 6 apt-get -s -o Debug::NoLocking=1 -o Dir::Log::Planner=/dev/null'
            ' -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= upgrade') in command
    assert 'dnf' not in command and 'apt-check' not in command


def test_connecting_never_runs_the_maintenance_probe(app, monkeypatch):
    """The probe runs only in workflows a user starts or schedules, never on connect."""
    from app import ssh_manager, profile_manager, session_insights
    from tests.test_profile_manager import create_user
    user_id = create_user(app)
    commands = []
    monkeypatch.setattr(session_insights, 'collect_linux_stats',
                        lambda session_id, **kwargs: (commands.append(kwargs.get('command')), (None, 'unsupported'))[1])
    with app.app_context():
        profile, _ = profile_manager.upsert_profile(user_id, dict(name='Web', host='web.example', port=22,
                                                                  username='deploy', auth_type='password'))
        monkeypatch.setitem(ssh_manager.sessions, 'no-maintenance', dict(profile, connected=True, user_id=user_id,
                                                                         profile_id=profile['id']))
        host_platform.detect_connected_platform('no-maintenance', user_id, lambda payload: None)
    assert commands, 'the existing platform and service probes still run'
    assert host_platform.MAINTENANCE_COMMAND not in commands
    assert not hasattr(host_platform, 'collect_maintenance') and not hasattr(host_platform, 'maintenance_needed')


def test_malformed_maintenance_facts_never_invalidate_the_profiles_document(app):
    from app import profile_manager
    base = {'id': 'x', 'name': 'x', 'host': 'h', 'port': 22, 'username': 'u', 'auth_type': 'password'}
    for value in ({'updates': 1, 'added_later': {'a': 1}}, 'broken', None, [1]):
        assert profile_manager._valid_profile({**base, 'detected_maintenance': value})


def test_automation_runs_of_the_exact_probe_update_the_overview(app):
    from contextlib import nullcontext
    from app import profile_manager
    from app.automation_service import _record_maintenance_facts
    from tests.test_profile_manager import create_user
    user_id = create_user(app)
    with app.app_context():
        profile, _ = profile_manager.upsert_profile(user_id, dict(name='Web', host='web.example', port=22, username='deploy',
                                                                  auth_type='password'))
        step = {'command': host_platform.MAINTENANCE_COMMAND, 'sudo': False}
        result = {'status': 'succeeded', 'exit_code': 0, 'output_truncated': False, 'stdout': 'reboot=yes\napt=4\naptsecurity=1\n'}
        access = nullcontext
        for changed in ({'sudo': True}, {'command': host_platform.MAINTENANCE_COMMAND + ' '}):
            assert not _record_maintenance_facts(user_id, profile, {**step, **changed}, result, access)
        for changed in ({'exit_code': 1}, {'status': 'failed'}, {'output_truncated': True}, {'stdout': 'x' * 5000}):
            assert not _record_maintenance_facts(user_id, profile, step, {**result, **changed}, access)
        assert 'detected_maintenance' not in profile_manager.get_profile(user_id, profile['id'])
        # A host moved since the run was reviewed keeps no foreign facts.
        assert not _record_maintenance_facts(user_id, dict(profile, host='other.example'), step, result, access)
        assert _record_maintenance_facts(user_id, profile, step, result, access)
        saved = profile_manager.get_profile(user_id, profile['id'])['detected_maintenance']
        assert (saved['reboot_required'], saved['updates'], saved['security_updates']) == (True, 4, 1)


def test_an_empty_automation_probe_keeps_the_last_known_facts(app):
    from contextlib import nullcontext
    from app import profile_manager
    from app.automation_service import _record_maintenance_facts
    from tests.test_profile_manager import create_user
    user_id = create_user(app)
    with app.app_context():
        profile, _ = profile_manager.upsert_profile(user_id, dict(name='Pi', host='pi.example', port=22, username='pi',
                                                                  auth_type='password'))
        step = {'command': host_platform.MAINTENANCE_COMMAND, 'sudo': False}
        done = {'status': 'succeeded', 'exit_code': 0, 'output_truncated': False}
        assert _record_maintenance_facts(user_id, profile, step, {**done, 'stdout': 'reboot=yes\n'}, nullcontext)
        assert not _record_maintenance_facts(user_id, profile, step, {**done, 'stdout': ''}, nullcontext)
        assert profile_manager.get_profile(user_id, profile['id'])['detected_maintenance']['reboot_required'] is True
