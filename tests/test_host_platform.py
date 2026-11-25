import re
import shutil
import subprocess

import pytest
from app import host_catalog, host_platform

@pytest.mark.parametrize('facts, expected', [
    ('ID=ubuntu\nkernel=Linux', 'ubuntu'),
    ('ID=debian\nkernel=Linux\nmarker=proxmox', 'proxmox'),
    ('ID=debian\nkernel=Linux\nmodel=Raspberry Pi 5 Model B', 'raspberrypi'),
    ('ID=haos\nkernel=Linux', 'homeassistant'), ('ID=truenas\nkernel=Linux', 'truenas'),
    ('kernel=FreeBSD\nmarker=opnsense', 'opnsense'),
    ('kernel=Darwin', 'apple'), ('kernel=FreeBSD', 'freebsd'),
    ('ID=unknown\nkernel=Linux\ndocker=yes', 'linux'),
    ('ID=ubuntu;$(touch /tmp/bad)\nkernel=Linux', 'linux'),
])
def test_identity_platform_uses_fixed_facts(facts, expected):
    assert host_platform.parse_identity(facts)['platform'] == expected


@pytest.mark.parametrize('facts', ['ID=haos', 'ID=unknown\ndocker=yes', 'ID=ubuntu;$(touch /tmp/bad)'])
def test_identity_without_kernel_line_is_unavailable(facts):
    assert host_platform.parse_identity(facts) == {
        'state': 'unavailable', 'platform': None, 'family': None, 'os_id': None, 'os_version': None,
        'virt': None, 'graphical': None, 'guests': None, 'services': [], 'container_access': None,
    }


def test_identity_rejects_oversized_control_and_non_text_output():
    for text in ['x' * 8193, 'ID=ubuntu\x00\nkernel=Linux', 'kernel=Linux\x1b[31m', b'kernel=Linux', None]:
        with pytest.raises(ValueError):
            host_platform.parse_identity(text)
    with pytest.raises(ValueError):
        host_platform.parse_identity('kernel=Linux\n' + 'x' * 100, max_bytes=64)
    for char in ('\x7f', '\x80', '\x85', '\x9f'):
        with pytest.raises(ValueError):
            host_platform.parse_identity('kernel=Linux' + char + 'marker=proxmox')
    assert host_platform.parse_identity('ID=debian\nkernel=Linux\nmodel=Raspberry Pi 5 \xa0')['state'] == 'detected'


@pytest.mark.parametrize('separator', ['\u2028', '\u2029', '\u2028\u2029'])
def test_identity_splits_lines_on_newline_only(separator):
    result = host_platform.parse_identity('ID=debian' + separator + 'marker=proxmox\nkernel=Linux' + separator + 'guests=7')
    assert result['platform'] is None and result['guests'] is None
    assert host_platform.parse_identity('ID=debian\r\nkernel=Linux\r\n')['platform'] == 'debian'
    assert host_platform.parse_identity('kernel=Linux\t\r\n')['state'] == 'detected'


def test_identity_drops_duplicate_os_release_keys_without_failing():
    result = host_platform.parse_identity('ID=ubuntu\nID=debian\nID_LIKE=arch\nkernel=Linux')
    assert result['state'] == 'detected' and result['platform'] == 'archlinux' and result['os_id'] is None


def test_identity_maps_fixed_service_facts_and_known_images_only():
    facts = '\n'.join([
        'kernel=Linux', 'service=docker', 'unit=nginx', 'unit=mysql', 'service=wireguard',
        'unit=sshd', 'service=evil', 'service=unit:nginx',
        'image=lscr.io/linuxserver/nextcloud:latest',
        'image=ghcr.io/home-assistant/home-assistant:stable',
        'image=jc21/nginx-proxy-manager:latest',
        'image=postgres:16', 'image=redis:7', 'image=nginx:alpine',
        'image=$(rm -rf /)', 'unrelated=nextcloud',
    ])
    assert host_platform.parse_identity(facts)['services'] == [
        'docker', 'homeassistant', 'mariadb', 'nextcloud', 'nginx', 'nginxproxymanager', 'postgresql', 'redis', 'wireguard',
    ]
    assert host_platform.parse_identity('kernel=Linux')['services'] == []


def test_identity_caps_services_and_ignores_overlong_values():
    units = sorted(host_catalog.SERVICE_UNITS)
    result = host_platform.parse_identity('kernel=Linux\n' + '\n'.join('unit=' + unit for unit in units))
    assert len(result['services']) == host_catalog.MAX_SERVICES
    assert result['services'] == sorted(set(host_catalog.SERVICE_UNITS.values()))[:host_catalog.MAX_SERVICES]
    assert host_platform.parse_identity('kernel=Linux\nimage=nginx:' + 'a' * 200)['services'] == []


@pytest.mark.parametrize('facts, expected', [
    ('', None),
    ('service=docker', None),
    ('service=podman', None),
    ('engine=docker:ok', 'ok'),
    ('engine=docker:denied', 'denied'),
    ('engine=podman:denied\nengine=docker:denied', 'denied'),
    ('engine=podman:ok\nengine=docker:denied', 'ok'),
    ('engine=docker:ok\nengine=podman:denied', 'ok'),
    ('engine=docker:unknown', None),
])
def test_identity_container_access(facts, expected):
    assert host_platform.parse_identity('kernel=Linux\n' + facts)['container_access'] == expected


@pytest.mark.parametrize('facts, expected', [
    ('guests=0', 0), ('guests=9999', 9999), ('guests=10000', None), ('guests=-1', None),
    ('guests= 7', 7), ('guests=7a', None), ('guests=', None),
])
def test_identity_guest_count_is_bounded(facts, expected):
    assert host_platform.parse_identity('kernel=Linux\n' + facts)['guests'] == expected


@pytest.mark.parametrize('facts, expected', [
    ('VERSION_ID="24.04"', '24.04'), ("VERSION_ID='13'", '13'), ('VERSION_ID=rolling', None),
    ('VERSION_ID="1.2.3.4.5.6.7.8.9"', None), ('VERSION_ID="24.04', None), ('VERSION_ID=24.04"', None),
])
def test_identity_os_version_pattern(facts, expected):
    assert host_platform.parse_identity('kernel=Linux\n' + facts)['os_version'] == expected


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


def test_socks_route_change_discards_old_facts_and_rejects_late_probe(app):
    from app import profile_manager, socks_proxy_manager
    from tests.test_profile_manager import create_user
    user_id = create_user(app)
    with app.app_context():
        proxy, error = socks_proxy_manager.add_socks_proxy(user_id, 'Route', 'proxy.example', 1080)
        assert error is None
        payload = dict(name='Target', host='example.test', port=22, username='deploy', auth_type='password')
        profile, error = profile_manager.upsert_profile(user_id, payload)
        assert error is None
        old_endpoint = host_platform.endpoint(profile)
        assert profile_manager.cache_detected_facts(
            user_id, profile['id'], old_endpoint, identity=_identity(platform='ubuntu', services=['docker']),
        )
        changed, error = profile_manager.upsert_profile(
            user_id, dict(payload, id=profile['id'], socks_proxy_id=proxy['id']),
        )
        assert error is None
        assert 'detected_platform' not in changed
        assert 'detected_services' not in changed and 'platform_checked_at' not in changed
        assert not profile_manager.cache_detected_facts(
            user_id, profile['id'], old_endpoint, identity=_identity(services=['nginx']),
        )
        assert profile_manager.cache_detected_facts(
            user_id, profile['id'], host_platform.endpoint(changed), identity=_identity(),
        )


def test_detection_task_checks_session_ownership_and_uses_facts(app, monkeypatch):
    from app import ssh_manager, profile_manager
    from tests.test_profile_manager import create_user
    user_id = create_user(app)
    events = []
    with app.app_context():
        profile, _ = profile_manager.upsert_profile(user_id, dict(name='Proxmox', host='example.test', port=22, username='deploy', auth_type='password'))
        session = dict(profile, connected=True, user_id=user_id, profile_id=profile['id'])
        monkeypatch.setitem(ssh_manager.sessions, 'platform-test', session)
        monkeypatch.setattr(host_platform, 'collect_identity', lambda _, **kwargs: (_identity(platform='ubuntu'), None))
        host_platform.detect_connected_platform('platform-test', user_id + 1, events.append)
        assert events == []
        host_platform.detect_connected_platform('platform-test', user_id, events.append)
        assert events[0]['platform'] == 'ubuntu'
        assert profile_manager.get_profile(user_id, profile['id'])['detected_platform'] == 'ubuntu'
        # A result that is not a parsed identity is never stored or published.
        profile_manager.cache_detected_facts(user_id, profile['id'], host_platform.endpoint(profile), identity=_identity(), now=0)
        for answer in ((None, 'transient'), (_identity(platform='<b>'), None), ({'state': 'detected'}, None)):
            monkeypatch.setattr(host_platform, 'collect_identity', lambda _, answer=answer, **kwargs: answer)
            host_platform.detect_connected_platform('platform-test', user_id, events.append)
        assert len(events) == 1
        assert profile_manager.get_profile(user_id, profile['id'])['platform_checked_at'] == 0

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
    assert host_platform.collect_identity('owned-session') == (None, 'transient')
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
    assert host_platform.collect_identity('owned-session') == (None, 'transient')
    assert channel.closed
    cancelled = Event()
    cancelled.set()
    channel = FakeChannel(b'ID=ubuntu\n')
    monkeypatch.setattr(session_insights.ssh_manager, '_open_exec_channel', lambda *args, **kwargs: channel)
    monkeypatch.setattr(session_insights.time, 'monotonic', lambda: 0)
    assert host_platform.collect_identity('owned-session', cancel_event=cancelled) == (None, 'transient')
    assert channel.closed


@pytest.mark.parametrize('payload, expected', [(b'1) Shell\n2) Exit\nChoice: ', 'unsupported'), (b'', 'transient')])
def test_identity_collector_reports_a_host_that_answers_and_then_waits(monkeypatch, payload, expected):
    """A forced command showing a menu never ends; output before the deadline means it was not the probe."""
    from app import session_insights
    from tests.test_session_insights import install_session, FakeChannel
    install_session(monkeypatch)
    channel = FakeChannel(payload)
    monkeypatch.setattr(channel, 'exit_status_ready', lambda: False)
    monkeypatch.setattr(session_insights.ssh_manager, '_open_exec_channel', lambda *args, **kwargs: channel)
    clock = iter([0] * (3 + len(payload) // 4096) + [5] * 10)
    monkeypatch.setattr(session_insights.time, 'monotonic', lambda: next(clock))
    monkeypatch.setattr(session_insights.time, 'sleep', lambda _: None)
    assert host_platform.collect_identity('owned-session') == (None, expected)
    assert channel.closed
    # Other collectors keep treating every deadline as transient.
    channel = FakeChannel(payload)
    monkeypatch.setattr(channel, 'exit_status_ready', lambda: False)
    monkeypatch.setattr(session_insights.ssh_manager, '_open_exec_channel', lambda *args, **kwargs: channel)
    clock = iter([0] * (3 + len(payload) // 4096) + [5] * 10)
    assert session_insights.collect_linux_stats('owned-session', timeout=1.0, command='true',
                                                parser=lambda text, **kwargs: text, allow_partial=False) == (None, 'transient')

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


def test_host_exchange_carries_a_validated_role_override(app, client):
    import json
    from app import profile_manager
    from app.profile_exchange import export_profiles, preview_import
    from tests.test_profile_exchange import _login
    base = dict(name='NAS', host='nas.example', username='root', auth_type='password')
    document = export_profiles([dict(base, role_override='storage', detected_virt='vm'),
                                dict(base, name='Plain', host='plain.example', role_override='auto')], [])
    assert document['hosts'][0]['role_override'] == 'storage' and 'detected_virt' not in document['hosts'][0]
    # 'auto' is the default; leaving it out keeps the document importable by releases without roles.
    assert 'role_override' not in document['hosts'][1]
    rows = preview_import(json.dumps(document), 'json')['records']
    assert not rows[0]['blocked'] and rows[0]['role_override'] == 'storage'
    for invalid in ('superhero', 3, None, '../x'):
        forged = json.loads(json.dumps(document))
        forged['hosts'][0]['role_override'] = invalid
        assert preview_import(json.dumps(forged), 'json')['records'][0]['blocked']
    user_id = _login(app, client)
    result = client.post('/api/profiles/exchange', json={'format': 'json', 'source': json.dumps(document),
                                                         'selections': [{'index': 0}, {'index': 1}]})
    assert [item['status'] for item in result.json['results']] == ['imported', 'imported']
    with app.app_context():
        stored = {profile['name']: profile for profile in profile_manager.load_profiles(user_id)}
    assert stored['NAS']['role_override'] == 'storage' and 'role_override' not in stored['Plain']


@pytest.mark.parametrize('stored, probed', [
    ({}, True),
    ({'platform_icon': 'auto'}, True),
    ({'platform_icon': 'proxmox'}, False),
    ({'detected_platform': 'debian'}, True),
    ({'identity': True}, False),
])
def test_detection_runs_once_per_saved_host_in_automatic_mode(app, monkeypatch, stored, probed):
    from app import ssh_manager, profile_manager
    from tests.test_profile_manager import create_user
    user_id = create_user(app)
    calls = []
    with app.app_context():
        profile, _ = profile_manager.upsert_profile(user_id, dict(name='Host', host='example.test', port=22, username='deploy', auth_type='password',
                                                                  **{k: v for k, v in stored.items() if k == 'platform_icon'}))
        # A platform from before the identity probe has no check time and is probed once more.
        if 'detected_platform' in stored:
            assert profile_manager.cache_detected_platform(user_id, profile['id'], host_platform.endpoint(profile), stored['detected_platform'])
        if 'identity' in stored:
            assert profile_manager.cache_detected_facts(user_id, profile['id'], host_platform.endpoint(profile), identity=_identity())
        monkeypatch.setitem(ssh_manager.sessions, 'platform-once', dict(profile, connected=True, user_id=user_id, profile_id=profile['id']))
        monkeypatch.setattr(host_platform, 'collect_identity', lambda _, **kwargs: (calls.append(1), (_identity(platform='ubuntu'), None))[1])
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
        monkeypatch.setattr(host_platform, 'collect_identity', lambda _, **kwargs: (calls.append(1), (_identity(), None))[1])
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
        for invalid in ('plan9', 3, None, '<b>'):
            _, error = profile_manager.upsert_profile(user_id, dict(payload, name=f'bad-{invalid}', greeting_platform=invalid))
            assert error == 'Invalid platform icon'


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
    assert commands == [host_platform.IDENTITY_COMMAND]
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


def _restart_hint_session(app, monkeypatch, name, *, checked_at=None, reboot_required=True):
    import time
    from app import ssh_manager, profile_manager
    from tests.test_profile_manager import create_user
    user_id = create_user(app)
    with app.app_context():
        profile, _ = profile_manager.upsert_profile(user_id, dict(name=name, host=f'{name}.example', port=22,
                                                                  username='deploy', auth_type='password'))
        assert profile_manager.cache_detected_facts(
            user_id, profile['id'], host_platform.endpoint(profile),
            maintenance={'reboot_required': reboot_required, 'updates': 3, 'security_updates': 1},
            now=time.time() if checked_at is None else checked_at)
    monkeypatch.setitem(ssh_manager.sessions, name, dict(profile, connected=True, user_id=user_id, profile_id=profile['id']))
    return user_id, profile


def _fake_host(monkeypatch, output, during=None):
    """A host answering output; None means a timeout, 'busy' a held collector."""
    from app import session_insights
    commands = []

    def collect(session_id, **kwargs):
        if output == 'busy':
            return None, 'busy'
        commands.append(kwargs.get('command'))
        if during:
            during()
        if output is None:
            return None, 'transient'
        try:
            return kwargs['parser'](output, max_bytes=kwargs['max_bytes']), None
        except ValueError:
            return None, 'unsupported'

    monkeypatch.setattr(session_insights, 'collect_linux_stats', collect)
    return commands


def _hint(app, user_id, profile):
    from app import profile_manager
    with app.app_context():
        return profile_manager.get_profile(user_id, profile['id'])['detected_maintenance']


def test_the_login_recheck_reads_only_the_restart_marker():
    command = host_platform.REBOOT_HINT_COMMAND
    marker = "if [ -e /var/run/reboot-required ] || [ -e /run/reboot-required ]; then printf 'reboot=yes\\n';"
    # The same marker test as the check the user already runs, nothing else.
    assert marker in host_platform.MAINTENANCE_COMMAND and marker in command
    for forbidden in ('sudo', 'apt', 'dnf', 'timeout', '>', 'rm ', 'touch', 'eval', '. /'):
        assert forbidden not in command


def test_only_the_exact_one_line_answer_counts():
    assert host_platform.parse_reboot_hint('reboot=yes\n') is True
    assert host_platform.parse_reboot_hint('reboot=no\n') is False
    for text in ('', 'reboot=maybe\n', 'Welcome\nreboot=no\n', 'reboot=no\napt=3\n', 'x' * 65, None):
        with pytest.raises(ValueError):
            host_platform.parse_reboot_hint(text)


def test_a_gone_marker_on_login_lowers_only_the_restart_hint(app, monkeypatch):
    user_id, profile = _restart_hint_session(app, monkeypatch, 'rebooted')
    commands = _fake_host(monkeypatch, 'reboot=no\n')
    published = []
    with app.app_context():
        host_platform.recheck_reboot_hint('rebooted', user_id, published.append)
    saved = _hint(app, user_id, profile)
    assert commands == [host_platform.REBOOT_HINT_COMMAND]
    assert published == [{'profile_id': profile['id']}]
    assert saved['reboot_required'] is False
    assert (saved['updates'], saved['security_updates']) == (3, 1)


def test_a_present_marker_keeps_the_hint_and_asks_again_next_login(app, monkeypatch):
    user_id, profile = _restart_hint_session(app, monkeypatch, 'pending')
    commands = _fake_host(monkeypatch, 'reboot=yes\n')
    with app.app_context():
        host_platform.recheck_reboot_hint('pending', user_id, pytest.fail)
        host_platform.recheck_reboot_hint('pending', user_id, pytest.fail)
    assert len(commands) == 2
    saved = _hint(app, user_id, profile)
    assert saved['reboot_required'] is True and 'recheck_stopped' not in saved


@pytest.mark.parametrize('output', [None, '', 'reboot=maybe\n', 'Welcome to the jump box\nreboot=no\n', 'x' * 2000])
def test_an_unclear_answer_keeps_the_hint_and_stops_asking(app, monkeypatch, output):
    """A forced command can answer in place of ours; it must not run again on every login."""
    user_id, profile = _restart_hint_session(app, monkeypatch, 'forced')
    commands = _fake_host(monkeypatch, output)
    with app.app_context():
        host_platform.recheck_reboot_hint('forced', user_id, pytest.fail)
        host_platform.recheck_reboot_hint('forced', user_id, pytest.fail)
    assert len(commands) == 1
    saved = _hint(app, user_id, profile)
    assert saved['reboot_required'] is True and saved['recheck_stopped'] is True


def test_a_new_full_check_starts_the_recheck_over(app, monkeypatch):
    from app import profile_manager
    user_id, profile = _restart_hint_session(app, monkeypatch, 'renewed')
    _fake_host(monkeypatch, '')
    with app.app_context():
        host_platform.recheck_reboot_hint('renewed', user_id, pytest.fail)
        assert profile_manager.cache_detected_facts(user_id, profile['id'], host_platform.endpoint(profile),
                                                    maintenance={'reboot_required': True})
    assert 'recheck_stopped' not in _hint(app, user_id, profile)
    commands = _fake_host(monkeypatch, 'reboot=no\n')
    with app.app_context():
        host_platform.recheck_reboot_hint('renewed', user_id, lambda payload: None)
    assert len(commands) == 1 and _hint(app, user_id, profile)['reboot_required'] is False


def test_a_busy_session_sends_nothing_and_keeps_asking(app, monkeypatch):
    user_id, profile = _restart_hint_session(app, monkeypatch, 'busy')
    _fake_host(monkeypatch, 'busy')
    with app.app_context():
        host_platform.recheck_reboot_hint('busy', user_id, pytest.fail)
    assert 'recheck_stopped' not in _hint(app, user_id, profile)


def test_a_newer_check_during_the_recheck_is_never_overwritten(app, monkeypatch):
    from app import profile_manager
    user_id, profile = _restart_hint_session(app, monkeypatch, 'raced')

    def newer_check():
        later = _hint(app, user_id, profile)['checked_at'] + 5
        with app.app_context():
            assert profile_manager.cache_detected_facts(user_id, profile['id'], host_platform.endpoint(profile),
                                                        maintenance={'reboot_required': True, 'updates': 9}, now=later)

    _fake_host(monkeypatch, 'reboot=no\n', during=newer_check)
    with app.app_context():
        host_platform.recheck_reboot_hint('raced', user_id, pytest.fail)
    saved = _hint(app, user_id, profile)
    assert saved['reboot_required'] is True and saved['updates'] == 9


@pytest.mark.parametrize('change', ['closed', 'replaced', 'moved', 'cancelled'])
def test_a_session_that_changed_during_the_recheck_writes_nothing(app, monkeypatch, change):
    import threading
    from app import ssh_manager
    user_id, profile = _restart_hint_session(app, monkeypatch, 'changing')
    cancel = threading.Event()

    def mutate():
        if change == 'closed':
            ssh_manager.sessions['changing']['connected'] = False
        elif change == 'replaced':
            ssh_manager.sessions['changing'] = dict(ssh_manager.sessions['changing'])
        elif change == 'moved':
            ssh_manager.sessions['changing']['host'] = 'elsewhere.example'
        else:
            cancel.set()

    _fake_host(monkeypatch, 'reboot=no\n', during=mutate)
    with app.app_context():
        host_platform.recheck_reboot_hint('changing', user_id, pytest.fail, cancel_event=cancel)
    saved = _hint(app, user_id, profile)
    assert saved['reboot_required'] is True and 'recheck_stopped' not in saved


@pytest.mark.parametrize('case', ['no-hint', 'stale', 'stopped', 'other-user', 'moved', 'cancelled', 'quick-connection'])
def test_hosts_without_a_current_restart_hint_are_never_asked(app, monkeypatch, case):
    import threading
    from app import ssh_manager, profile_manager
    hint = case != 'no-hint'
    user_id, profile = _restart_hint_session(app, monkeypatch, 'quiet', reboot_required=True if hint else False,
                                             checked_at=1_000 if case == 'stale' else None)
    if case == 'stopped':
        with app.app_context():
            assert profile_manager.settle_reboot_hint(user_id, profile['id'], host_platform.endpoint(profile),
                                                      _hint(app, user_id, profile)['checked_at'], cleared=False)
    session = ssh_manager.sessions['quiet']
    if case == 'moved':
        session['host'] = 'elsewhere.example'
    if case == 'quick-connection':
        session['profile_id'] = None
    cancel = threading.Event()
    if case == 'cancelled':
        cancel.set()
    commands = _fake_host(monkeypatch, 'reboot=no\n')
    with app.app_context():
        host_platform.recheck_reboot_hint('quiet', user_id + 1 if case == 'other-user' else user_id,
                                          lambda payload: None, cancel_event=cancel)
    assert commands == []


def test_identity_probe_is_read_only_bounded_and_posix():
    command = host_platform.IDENTITY_COMMAND
    for forbidden in ('. /etc/', 'source ', 'eval ', 'sudo', '>/etc', 'tee ', 'mkdir', 'rm '):
        assert forbidden not in command
    assert command.count('timeout 2') >= 2            # docker and podman queries
    assert 'head -n 100' in command                   # image lines
    assert 'systemd-detect-virt' in command and 'get-default' in command
    assert '/etc/pve/qemu-server' in command and '/etc/pve/lxc' in command
    assert 'ID_LIKE' in command and 'VERSION_ID' in command
    assert 'marker=ubiquiti' in command


def test_identity_probe_covers_the_catalog():
    command = host_platform.IDENTITY_COMMAND
    for unit in host_catalog.SERVICE_UNITS:
        assert re.search(r"[|(\s]'%s'[|)]" % re.escape(unit), command)
    for path, _ in host_catalog.SERVICE_PATHS:
        assert "'%s'" % path in command
    for snap in host_catalog.SERVICE_SNAPS:
        assert "/snap/%s'" % snap in command


@pytest.mark.parametrize('units, paths, snaps', [
    ({'nginx; rm -rf /': 'nginx'}, (), {}),
    ({'nginx': "x'; id; '"}, (), {}),
    ({}, (('/etc/x y', 'redis'),), {}),
    ({}, (('/etc/$(id)', 'redis'),), {}),
    ({}, (('/etc/x', 'redis\nservice=evil'),), {}),
    ({}, (), {'a`id`': 'plex'}),
    ({}, (), {'plex': 'a|b'}),
])
def test_identity_probe_rejects_unsafe_catalog_values(units, paths, snaps):
    with pytest.raises(ValueError):
        host_platform._identity_command(units, paths, snaps)


def test_identity_probe_accepts_catalog_style_values():
    command = host_platform._identity_command({'wg@x': 'wireguard'}, (('/opt/a-b_c.d+e', 'redis'),), {'a-b': 'plex'})
    assert "'wg@x'" in command and "'/opt/a-b_c.d+e'" in command


def test_identity_probe_runs_under_a_minimal_posix_shell():
    shell = shutil.which('busybox') and ['busybox', 'sh'] or [shutil.which('dash') or 'sh']
    result = subprocess.run([*shell, '-c', host_platform.IDENTITY_COMMAND], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0
    assert re.search(r'^kernel=\S+$', result.stdout, re.M)
    assert all(re.fullmatch(r'[A-Za-z_]+=.*', line) for line in result.stdout.splitlines())
    keys = {line.partition('=')[0] for line in result.stdout.splitlines()}
    assert keys <= {'ID', 'ID_LIKE', 'VERSION_ID', 'VARIANT_ID', 'kernel', 'model', 'marker', 'virt',
                    'target', 'guests', 'service', 'unit', 'snap', 'image', 'engine'}
    assert len([line for line in result.stdout.splitlines() if line.startswith('image=')]) <= 100
    identity = host_platform.parse_identity(result.stdout)
    assert identity['state'] == 'detected' and identity['platform'] not in (None, 'server')


def _module_text_without_comments(module):
    import inspect
    import io
    import tokenize
    source = inspect.getsource(module)
    return ' '.join(token.string for token in tokenize.generate_tokens(io.StringIO(source).readline)
                    if token.type != tokenize.COMMENT)


def test_identity_probe_never_runs_a_plain_podman_query():
    # Every probe in the module, not only the identity probe, may ask podman only through a socket.
    command = _module_text_without_comments(host_platform)
    invocations = re.findall(r'timeout 2 podman\S*(?: \S+)?', command)
    assert invocations and all(item.startswith('timeout 2 podman --remote') for item in invocations)
    # Container listings name their engine literally: docker, or podman behind --remote --url.
    assert set(re.findall(r'(\S+) ps\b', command)) == {'docker', '"unix://$sock"'}
    assert not re.search(r'podman (ps|info|images|version)', command)
    assert 'unix:///run/podman/podman.sock' not in command or '--remote' in command
    assert '$XDG_RUNTIME_DIR/podman/podman.sock' in command and '[ -S ' in command


def test_identity_probe_keeps_docker_presence_without_timeout():
    command = host_platform.IDENTITY_COMMAND
    line = next(line for line in command.splitlines() if line.startswith('if command -v docker') and 'found docker' in line)
    assert '/var/run/docker.sock' in line and 'timeout' not in line


def test_identity_probe_virt_fallbacks_also_cover_none():
    command = host_platform.IDENTITY_COMMAND
    assert '[ -z "$virt" ] || [ "$virt" = none ]' in command


@pytest.mark.parametrize('units, paths, snaps', [
    ({}, (), {}),
    ({}, (('/etc/x', 'redis'),), {'a': 'plex'}),
    ({'nginx': 'nginx'}, (), {}),
])
def test_identity_probe_generates_valid_shell_for_any_mapping(units, paths, snaps, tmp_path):
    script = tmp_path / 'probe.sh'
    script.write_text(host_platform._identity_command(units, paths, snaps))
    for shell in (['sh'], ['bash', '--posix']):
        assert subprocess.run([*shell, '-n', str(script)], capture_output=True).returncode == 0


def test_identity_probe_worst_case_output_fits_the_budget():
    lines = ['ID=' + 'x' * 197, 'ID_LIKE=' + 'x' * 192, 'VERSION_ID=' + 'x' * 189, 'VARIANT_ID=' + 'x' * 189]
    lines += ['kernel=' + 'x' * 32, 'model=' + 'x' * 160, 'virt=' + 'x' * 32, 'target=' + 'x' * 40, 'guests=' + '9' * 6]
    lines += ['marker=' + name for name in host_catalog.MARKER_PLATFORMS]
    lines += ['unit=' + name for name in host_catalog.SERVICE_UNITS]
    lines += ['snap=' + name for name in host_catalog.SERVICE_SNAPS]
    lines += ['service=' + service for _, service in host_catalog.SERVICE_PATHS]
    lines += ['service=docker', 'service=podman', 'service=wireguard', 'engine=docker:denied', 'engine=podman:denied']
    size = sum(len(line) + 1 for line in lines)
    # Images: the probe stops at 3000 bytes whatever the daemon returns.
    assert '> 3000' in host_platform.IDENTITY_COMMAND and 'sort -u' in host_platform.IDENTITY_COMMAND
    assert size + 3000 < 8192


def _identity(**changes):
    return {'state': 'detected', 'platform': 'debian', 'family': None, 'os_id': None, 'os_version': '13',
            'virt': 'vm', 'graphical': False, 'guests': None, 'services': ['docker', 'nextcloud'],
            'container_access': 'ok', **changes}


_UNAVAILABLE = {'state': 'unavailable', 'platform': None, 'family': None, 'os_id': None, 'os_version': None,
                'virt': None, 'graphical': None, 'guests': None, 'services': [], 'container_access': None}


def _identity_session(app, monkeypatch, name, **fields):
    from app import ssh_manager, profile_manager
    from tests.test_profile_manager import create_user
    user_id = create_user(app, f'identity-{name}')
    with app.app_context():
        profile, error = profile_manager.upsert_profile(user_id, dict(name=name, host=f'{name}.example', port=22,
                                                                      username='deploy', auth_type='password', **fields))
        assert error is None
    session = dict(profile, connected=True, user_id=user_id, profile_id=profile['id'])
    monkeypatch.setitem(ssh_manager.sessions, name, session)
    return user_id, profile, session


def _fake_identity(monkeypatch, *results):
    """Answer collect_identity with the given (identity, error) pairs in turn."""
    calls = []
    answers = list(results)

    def collect(session_id, **kwargs):
        calls.append(session_id)
        return answers.pop(0) if len(answers) > 1 else answers[0]

    monkeypatch.setattr(host_platform, 'collect_identity', collect)
    return calls


def _store(app, user_id, profile_id, **fields):
    from app import profile_manager
    with app.app_context():
        profiles = profile_manager.load_profiles(user_id)
        for item in profiles:
            if item['id'] == profile_id:
                item.update(fields)
        assert profile_manager.save_profiles(user_id, profiles, previous_count=len(profiles))


def test_identity_is_stored_and_refreshed_weekly(app, monkeypatch):
    from types import SimpleNamespace
    from app import profile_manager
    user_id, profile, session = _identity_session(app, monkeypatch, 'weekly')
    calls = _fake_identity(monkeypatch, (_identity(), None),
                           (_identity(os_version='14', container_access=None, guests=3), None))
    events = []
    with app.app_context():
        host_platform.detect_connected_platform('weekly', user_id, events.append)
        assert events == [{'session_id': 'weekly', 'profile_id': profile['id'], 'platform': 'debian',
                           'services': ['docker', 'nextcloud'], 'identity': _identity()}]
        saved = profile_manager.get_profile(user_id, profile['id'])
        assert (saved['detected_platform'], saved['detected_os_version'], saved['detected_virt']) == ('debian', '13', 'vm')
        assert saved['detected_services'] == ['docker', 'nextcloud']
        assert saved['detected_container_access'] == 'ok' and saved['detected_graphical'] is False
        assert saved['detection_state'] == 'detected'
        assert isinstance(saved['platform_checked_at'], float)
        assert saved['platform_checked_at'] == saved['services_checked_at']
        for missing in ('detected_family', 'detected_os_id', 'detected_guests'):
            assert missing not in saved
        assert session['detected_platform'] == 'debian'
        checked = saved['platform_checked_at']

        # Within the week the stored facts are used as they are.
        monkeypatch.setattr(host_platform, 'time', SimpleNamespace(time=lambda: checked + 6 * 24 * 3600))
        host_platform.detect_connected_platform('weekly', user_id, events.append)
        assert len(calls) == 1 and len(events) == 1

        monkeypatch.setattr(host_platform, 'time', SimpleNamespace(time=lambda: checked + 7 * 24 * 3600 + 1))
        host_platform.detect_connected_platform('weekly', user_id, events.append)
        assert len(calls) == 2
        refreshed = profile_manager.get_profile(user_id, profile['id'])
        assert refreshed['detected_os_version'] == '14' and refreshed['detected_guests'] == 3
        assert 'detected_container_access' not in refreshed
        assert refreshed['platform_checked_at'] > checked


def test_unavailable_identity_is_remembered_and_not_retried_for_a_week(app, monkeypatch):
    from app import profile_manager
    user_id, profile, _ = _identity_session(app, monkeypatch, 'forced')
    calls = _fake_identity(monkeypatch, (dict(_UNAVAILABLE), None))
    events = []
    with app.app_context():
        host_platform.detect_connected_platform('forced', user_id, events.append)
        saved = profile_manager.get_profile(user_id, profile['id'])
        assert saved['detection_state'] == 'unavailable'
        assert isinstance(saved['platform_checked_at'], float)
        assert 'detected_platform' not in saved and 'detected_services' not in saved
        assert 'services_checked_at' not in saved
        assert events == []
        host_platform.detect_connected_platform('forced', user_id, events.append)
        assert len(calls) == 1

    # Facts from an earlier detection stay when a later probe cannot be read.
    user_id, profile, _ = _identity_session(app, monkeypatch, 'kept')
    with app.app_context():
        assert profile_manager.cache_detected_facts(user_id, profile['id'], host_platform.endpoint(profile),
                                                    identity=_identity(), now=1_000.0)
        host_platform.detect_connected_platform('kept', user_id, events.append)
        saved = profile_manager.get_profile(user_id, profile['id'])
        assert saved['detection_state'] == 'unavailable'
        assert saved['detected_platform'] == 'debian' and saved['detected_services'] == ['docker', 'nextcloud']
        assert saved['services_checked_at'] == 1_000.0 and saved['platform_checked_at'] > 1_000.0
        assert events == []


def test_an_unavailable_identity_drops_a_legacy_server_platform(app, monkeypatch):
    from app import profile_manager
    user_id, profile, _ = _identity_session(app, monkeypatch, 'oldserver')
    _store(app, user_id, profile['id'], detected_platform='server', detected_services=['nginx'], services_checked_at=5)
    _fake_identity(monkeypatch, (dict(_UNAVAILABLE), None))
    with app.app_context():
        host_platform.detect_connected_platform('oldserver', user_id, pytest.fail)
        saved = profile_manager.get_profile(user_id, profile['id'])
    assert 'detected_platform' not in saved
    assert saved['detection_state'] == 'unavailable' and saved['detected_services'] == ['nginx']


def test_unreadable_probe_output_counts_as_unavailable_and_failures_retry(app, monkeypatch):
    from app import profile_manager
    user_id, profile, _ = _identity_session(app, monkeypatch, 'garbled')
    calls = _fake_identity(monkeypatch, (None, 'transient'), (None, 'busy'), (None, 'unsupported'))
    with app.app_context():
        for _ in range(2):
            host_platform.detect_connected_platform('garbled', user_id, pytest.fail)
            assert 'detection_state' not in profile_manager.get_profile(user_id, profile['id'])
        # Output that is not the probe's answer (a forced command, a menu) is not asked for again this week.
        host_platform.detect_connected_platform('garbled', user_id, pytest.fail)
        host_platform.detect_connected_platform('garbled', user_id, pytest.fail)
        assert len(calls) == 3
        assert profile_manager.get_profile(user_id, profile['id'])['detection_state'] == 'unavailable'


@pytest.mark.parametrize('greeting', sorted(host_catalog.NON_POSIX_PLATFORMS))
def test_hosts_announcing_a_non_posix_shell_are_never_probed(app, monkeypatch, greeting):
    from app import profile_manager
    user_id, profile, _ = _identity_session(app, monkeypatch, 'router', greeting_platform=greeting)
    calls = _fake_identity(monkeypatch, (_identity(), None))
    with app.app_context():
        host_platform.detect_connected_platform('router', user_id, pytest.fail)
        assert calls == []
        assert 'detection_state' not in profile_manager.get_profile(user_id, profile['id'])
    assert not host_platform.identity_needed({'greeting_platform': greeting})
    assert host_platform.identity_needed({'greeting_platform': 'ubuntu'})
    assert not host_platform.identity_needed({'platform_icon': 'proxmox'})


def test_a_stored_server_platform_counts_as_not_detected(app, monkeypatch):
    import time
    from app import profile_manager
    user_id, profile, _ = _identity_session(app, monkeypatch, 'legacy')
    now = time.time()
    _store(app, user_id, profile['id'], detected_platform='server', detected_services=['nginx'],
           services_checked_at=now, platform_checked_at=now)
    calls = _fake_identity(monkeypatch, (_identity(platform='fedora'), None))
    with app.app_context():
        host_platform.detect_connected_platform('legacy', user_id, lambda payload: None)
        assert len(calls) == 1
        saved = profile_manager.get_profile(user_id, profile['id'])
        assert saved['detected_platform'] == 'fedora' and saved['detected_services'] == ['docker', 'nextcloud']
    # Once the new probe ran, a kept 'server' does not bring the probe back every login.
    assert not host_platform.identity_needed({'detected_platform': 'server', 'detection_state': 'unavailable',
                                              'platform_checked_at': now}, now=now + 60)
    assert host_platform.identity_needed({'detected_platform': 'server', 'platform_checked_at': now}, now=now + 60)
    assert host_platform.identity_needed({'detected_platform': 'debian', 'services_checked_at': now}, now=now + 60)
    for checked in (None, True, 'yesterday', now + 3600):
        assert host_platform.identity_needed({'detected_platform': 'debian', 'platform_checked_at': checked}, now=now)
