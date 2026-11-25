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


def test_identity_rejects_oversized_and_non_text_output():
    for text in ['x' * 8193, b'kernel=Linux', None]:
        with pytest.raises(ValueError):
            host_platform.parse_identity(text)
    with pytest.raises(ValueError):
        host_platform.parse_identity('kernel=Linux\n' + 'x' * 100, max_bytes=64)
    assert host_platform.parse_identity('ID=debian\nkernel=Linux\nmodel=Raspberry Pi 5 \xa0')['state'] == 'detected'


def test_identity_drops_lines_with_control_characters_only():
    # Shell startup files print coloured greetings; they must not hide the probe's answer.
    motd = '\x1b[1;32mWelcome to node-1\x1b[0m\n\x07\nLast login: today\n'
    result = host_platform.parse_identity(motd + 'ID=ubuntu\nVERSION_ID="24.04"\nkernel=Linux\nunit=nginx\x1b[0m\nunit=caddy\n')
    assert result['state'] == 'detected' and result['platform'] == 'ubuntu' and result['os_version'] == '24.04'
    assert result['services'] == ['caddy']
    assert host_platform.parse_identity('\x1b]0;title\x07ID=debian\nkernel=Linux')['platform'] == 'linux'
    assert host_platform.parse_identity('kernel=Linux\x1b[31m')['state'] == 'unavailable'


@pytest.mark.parametrize('char', ['\x00', '\x0b', '\x0c', '\x1b', '\r', '\x7f', '\x80', '\x85', '\x9f'])
def test_a_control_character_never_splits_a_line_into_a_new_key(char):
    assert host_platform.parse_identity('kernel=Linux' + char + 'marker=proxmox')['state'] == 'unavailable'
    result = host_platform.parse_identity('ID=debian' + char + 'marker=proxmox\nkernel=Linux\nguests=1' + char + 'guests=7')
    assert result['state'] == 'detected' and result['platform'] == 'linux' and result['guests'] is None
    result = host_platform.parse_identity('kernel=Linux\nunit=nginx' + char + 'unit=caddy\nimage=x' + char + '\nimage=redis:7')
    assert result['services'] == ['redis']


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
    assert host_platform.parse_identity('ID=ubuntu\nkernel=Linux\n' + facts)['os_version'] == expected


def test_platform_cache_is_endpoint_scoped_and_override_persists(app):
    from app import profile_manager
    from tests.test_profile_manager import create_user
    user_id = create_user(app)
    with app.app_context():
        payload = dict(name='Docker', host='example.test', port=22, username='deploy', auth_type='password', platform_icon='proxmox')
        profile, error = profile_manager.upsert_profile(user_id, payload)
        assert error is None
        assert profile['platform_icon'] == 'proxmox'
        assert profile_manager.cache_detected_facts(user_id, profile['id'], host_platform.endpoint(profile), identity=_identity(platform='ubuntu'))
        saved = profile_manager.get_profile(user_id, profile['id'])
        assert saved['detected_platform'] == 'ubuntu'
        assert not profile_manager.cache_detected_facts(user_id + 1, profile['id'], host_platform.endpoint(profile), identity=_identity())
        changed, error = profile_manager.upsert_profile(user_id, dict(payload, id=profile['id'], host='other.test'))
        assert error is None
        assert 'detected_platform' not in changed
        assert changed['platform_icon'] == 'proxmox'
        assert not profile_manager.cache_detected_facts(user_id, profile['id'], host_platform.endpoint(profile), identity=_identity())


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


@pytest.mark.parametrize('payload, expected', [(b'1) Shell\n2) Exit\nChoice: ', 'unsupported'), (b'', 'silent')])
def test_identity_collector_reports_a_host_that_answers_and_then_waits(monkeypatch, payload, expected):
    """A forced command showing a menu, or one that prints nothing, never ends.

    The probe prints its first lines within milliseconds, so neither is the probe.
    """
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

def _stalled_identity(monkeypatch, payload):
    from app import session_insights
    from tests.test_session_insights import install_session, FakeChannel
    install_session(monkeypatch)
    channel = FakeChannel(payload)
    monkeypatch.setattr(channel, 'exit_status_ready', lambda: False)
    monkeypatch.setattr(session_insights.ssh_manager, '_open_exec_channel', lambda *args, **kwargs: channel)
    clock = iter([0] * (3 + len(payload) // 4096) + [5] * 10)
    monkeypatch.setattr(session_insights.time, 'monotonic', lambda: next(clock))
    monkeypatch.setattr(session_insights.time, 'sleep', lambda _: None)
    result = host_platform.collect_identity('owned-session')
    assert channel.closed
    return result


def test_a_probe_that_stalls_after_its_kernel_line_is_retried_later(monkeypatch):
    # Our probe ran but hung on a read (pmxcfs, D-Bus, a stale NFS mount): what it
    # printed so far lacks the markers and services after that step.
    assert _stalled_identity(monkeypatch, b'ID=debian\nVERSION_ID="12"\nkernel=Linux\nvirt=kvm\nunit=nginx\n'
                                          b'service=docker\nimage=redis') == (None, 'stalled')


@pytest.mark.parametrize('payload', [b'Welcome\nkernel=Linux\x07\n', b'Welcome to node-1\nkernel=Lin',
                                     b'Last login: today\nIDENT=debian\n', b'ID debian\n'])
def test_a_stalled_answer_without_a_probe_line_is_not_the_probe(monkeypatch, payload):
    assert _stalled_identity(monkeypatch, payload) == (None, 'unsupported')


@pytest.mark.parametrize('payload', [b'ID=debian\nVERSION_ID=12\n', b'ID=debian\nVERSION_ID="12"\n', b'ID=debian\nkernel=Lin',
                                     b'Welcome to node-1\r\nID="ubuntu"\r\n', b'\x1b[1mHi\x1b[0m\nmarker=proxmox\n',
                                     b'Last login: today\nservice=docker\n'])
def test_a_probe_that_stalls_before_its_kernel_line_is_retried_later(monkeypatch, payload):
    # os-release was read, then the probe hung (or a startup file printed first):
    # it is our probe, so stored facts stay and it is asked again after a day.
    assert _stalled_identity(monkeypatch, payload) == (None, 'stalled')


@pytest.mark.parametrize('payload', [b'\x1b[0m\n\n', b'\x1b]0;node-1\x07\r\n\x1b[1;32m', b'\n\n\n',
                                     b'\x1b]2;user@node: ~\x1b\\\x1b[?2004h\x1b[0m \t\n', b'\x07\x1b[H\x1b[2J'])
def test_output_that_holds_only_control_lines_counts_as_silent(monkeypatch, payload):
    # A startup file that only set the title or colours has not shown a menu yet.
    assert _stalled_identity(monkeypatch, payload) == (None, 'silent')


@pytest.mark.parametrize('payload', [b'Choice: ', b'\x1b[1mMenu\x1b[0m\nChoice: ', b'\x1b[0m\nThis account is not available\n',
                                     b'\x1b[1mSelect host:\x1b[0m\n\x1b[32m1) foo\x1b[0m\n\x1b[1m> \x1b[0m', b'\x1b[1mMenu\x1b[0m\n',
                                     b'\x1b]0;menu\x1b\\\x1b[7mPick\x1b[m'])
def test_text_from_a_menu_or_forced_command_stays_unsupported(monkeypatch, payload):
    assert _stalled_identity(monkeypatch, payload) == (None, 'unsupported')


def _stall_detection(app, monkeypatch, name, payload, **stored):
    from app import profile_manager
    from app import session_insights
    from tests.test_session_insights import FakeChannel, FakeClient, FakeTransport
    user_id, profile, session = _identity_session(app, monkeypatch, name)
    if stored:
        _store(app, user_id, profile['id'], **stored)
    session['client'] = FakeClient(FakeTransport())
    channel = FakeChannel(payload)
    monkeypatch.setattr(channel, 'exit_status_ready', lambda: False)
    monkeypatch.setattr(session_insights.ssh_manager, '_open_exec_channel', lambda *args, **kwargs: channel)
    clock = iter([0] * 4 + [5] * 50)
    monkeypatch.setattr(session_insights.time, 'monotonic', lambda: next(clock))
    monkeypatch.setattr(session_insights.time, 'sleep', lambda _: None)
    published = []
    with app.app_context():
        host_platform.detect_connected_platform(name, user_id, published.append)
        saved = profile_manager.get_profile(user_id, profile['id'])
    return saved, published, session


def test_a_stalled_probe_stores_no_facts_and_asks_again_after_a_day(app, monkeypatch):
    # A host that always hangs (a dead NFS mount) must not collect a stuck sh per login.
    from types import SimpleNamespace
    monkeypatch.setattr(host_platform, 'time', SimpleNamespace(time=lambda: 10_000_000.0))
    saved, published, session = _stall_detection(app, monkeypatch, 'slowprobe',
                                                  b'ID=ubuntu\nVERSION_ID="24.04"\nkernel=Linux\nservice=docker\n')
    assert published == [] and 'detected_platform' not in session
    assert 'detection_state' not in saved and 'detected_platform' not in saved and 'detected_services' not in saved
    day, week = 24 * 3600, host_platform.IDENTITY_REFRESH_SECONDS
    assert saved['platform_checked_at'] == 10_000_000.0 - week + day
    assert not host_platform.identity_needed(saved, now=10_000_000.0 + 3600)
    assert host_platform.identity_needed(saved, now=10_000_000.0 + day + 1)


def test_a_silent_channel_is_unavailable_but_asked_again_after_a_day(app, monkeypatch):
    # A forced command that waits, or a login shell that starts slowly (nvm, conda,
    # a loaded host, a long jump chain): only the latter answers on a later try.
    from types import SimpleNamespace
    monkeypatch.setattr(host_platform, 'time', SimpleNamespace(time=lambda: 10_000_000.0))
    saved, published, _ = _stall_detection(app, monkeypatch, 'quiet', b'')
    assert published == [] and saved['detection_state'] == 'unavailable'
    day, week = 24 * 3600, host_platform.IDENTITY_REFRESH_SECONDS
    assert saved['platform_checked_at'] == 10_000_000.0 - week + day
    assert host_platform.identity_needed(saved, now=10_000_000.0 + day + 1)


@pytest.mark.parametrize('stored', [
    dict(detected_platform='debian', detected_services=['nginx'], detection_state='detected',
         platform_checked_at=1_000.0, services_checked_at=1_000.0),
    # A system the catalog has no platform for, such as OpenBSD.
    dict(detected_os_id='openbsd', detected_os_version='7.6', detection_state='detected',
         platform_checked_at=1_000.0, services_checked_at=1_000.0),
])
def test_a_silent_login_keeps_an_earlier_detection(app, monkeypatch, stored):
    from types import SimpleNamespace
    monkeypatch.setattr(host_platform, 'time', SimpleNamespace(time=lambda: 10_000_000.0))
    saved, published, _ = _stall_detection(app, monkeypatch, 'quiet', b'', **stored)
    assert published == [] and saved['detection_state'] == 'detected'
    assert {key: saved.get(key) for key in stored if key != 'platform_checked_at'} == {
        key: value for key, value in stored.items() if key != 'platform_checked_at'}
    assert saved['services_checked_at'] == 1_000.0
    day, week = 24 * 3600, host_platform.IDENTITY_REFRESH_SECONDS
    assert saved['platform_checked_at'] == 10_000_000.0 - week + day
    assert not host_platform.identity_needed(saved, now=10_000_000.0 + day - 60)
    assert host_platform.identity_needed(saved, now=10_000_000.0 + day + 1)


def test_a_waiting_menu_is_not_asked_again_for_a_week(app, monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(host_platform, 'time', SimpleNamespace(time=lambda: 10_000_000.0))
    saved, _, _ = _stall_detection(app, monkeypatch, 'menu', b'1) Shell\n2) Exit\nChoice: ')
    assert saved['detection_state'] == 'unavailable' and saved['platform_checked_at'] == 10_000_000.0


def test_a_stall_that_cuts_off_the_markers_keeps_stored_proxmox_facts(app, monkeypatch):
    stored = dict(detected_platform='proxmox', detected_services=['nginx', 'samba'], detected_guests=4,
                  detection_state='detected', platform_checked_at=1_000.0, services_checked_at=1_000.0)
    from types import SimpleNamespace
    monkeypatch.setattr(host_platform, 'time', SimpleNamespace(time=lambda: 10_000_000.0))
    saved, published, _ = _stall_detection(app, monkeypatch, 'pve', b'ID=debian\nVERSION_ID="12"\nkernel=Linux\n', **stored)
    assert published == []
    day, week = 24 * 3600, host_platform.IDENTITY_REFRESH_SECONDS
    assert {key: saved.get(key) for key in stored} == dict(stored, platform_checked_at=10_000_000.0 - week + day)


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
            _store(app, user_id, profile['id'], detected_platform=stored['detected_platform'])
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
    assert commands == [host_platform.IDENTITY_EXEC]
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
    assert command.count('timeout 1') >= 2            # docker and podman queries
    assert 'head -n 100' in command                   # image lines
    assert 'systemd-detect-virt' in command and 'get-default' in command
    assert '/etc/pve/qemu-server' in command and '/etc/pve/lxc' in command
    assert 'ID_LIKE' in command and 'VERSION_ID' in command
    assert 'marker=ubiquiti' in command


def test_identity_probe_covers_the_catalog():
    command = host_platform.IDENTITY_COMMAND
    for unit in host_catalog.SERVICE_UNITS:
        assert re.search(r"[|(\s]%s[|)]" % re.escape(unit), command), unit
    for path, _ in host_catalog.SERVICE_PATHS:
        assert '[ -e %s ]' % path in command
    for snap in host_catalog.SERVICE_SNAPS:
        assert '[ -d /snap/%s ] && echo snap=%s; ' % (snap, snap) in command
    for prefix, service in host_catalog.SERVICE_UNIT_TEMPLATES.items():
        assert '%s@*) found %s ;;' % (prefix, service) in command


def test_the_wrapped_probe_fits_dropbears_command_limit():
    # Dropbear refuses exec requests longer than MAX_CMD_LEN (9000 bytes), which
    # would leave OpenWrt and other Dropbear hosts undetected and asked on every
    # connection. Keep room below it as the catalog grows.
    size = len(host_platform.IDENTITY_EXEC.encode('utf-8'))
    assert size <= 8192, f'the wrapped identity probe is {size} bytes; Dropbear accepts at most 9000'


def test_the_probe_is_one_line_for_csh_and_tcsh_login_shells(tmp_path):
    # csh and tcsh reject a newline inside single quotes and then run the lines
    # after it on their own; on one line the wrapper is one quoted word there too.
    import shlex
    for text in (host_platform.IDENTITY_COMMAND, host_platform.IDENTITY_EXEC):
        assert '\n' not in text and '\r' not in text
    assert shlex.split(host_platform.IDENTITY_EXEC) == ['exec', '/bin/sh', '-c', host_platform.IDENTITY_COMMAND]
    for name, text in (('probe.sh', host_platform.IDENTITY_COMMAND), ('wrapper.sh', host_platform.IDENTITY_EXEC)):
        script = tmp_path / name
        script.write_text(text + '\n')
        for shell in (['sh'], ['bash', '--posix']):
            result = subprocess.run([*shell, '-n', str(script)], capture_output=True, text=True)
            assert result.returncode == 0, (shell, name, result.stderr)


def test_the_one_line_probe_keeps_every_command_of_the_readable_script():
    script = host_platform.IDENTITY_SCRIPT
    lines = [line.strip() for line in script.splitlines() if line.strip()]
    assert host_platform.IDENTITY_COMMAND.startswith(lines[0] + '; ')
    position = 0
    for line in lines:
        position = host_platform.IDENTITY_COMMAND.index(line, position) + len(line)
    assert not any(line.startswith('#') for line in lines)


@pytest.mark.parametrize('script', ['a="x\ny"', "printf 'a\nb'", 'a\n# note\nb'])
def test_the_one_line_join_refuses_text_it_would_change(script):
    with pytest.raises(ValueError):
        host_platform._one_line(script)


@pytest.mark.parametrize('script, expected', [
    ('a\nb', 'a; b'),
    ('if x; then\n  a\nfi\nb', 'if x; then a; fi; b'),
    ('case $x in\n  y) a ;;\nesac', 'case $x in y) a ;; esac'),
    ('x | {\n  while read -r n; do\n    a\n  done\n} | sort', 'x | { while read -r n; do a; done; } | sort'),
    ('a &&\nb ||\nc', 'a && b || c'),
    ('if x; then a;\nelif y; then b;\nelse\nc\nfi', 'if x; then a; elif y; then b; else c; fi'),
])
def test_the_one_line_join_separates_commands_only_where_sh_allows_it(script, expected):
    assert host_platform._one_line(script) == expected


@pytest.mark.parametrize('units, paths, snaps, templates', [
    ({'nginx; rm -rf /': 'nginx'}, (), {}, {}),
    ({'nginx': "x'; id; '"}, (), {}, {}),
    ({}, (('/etc/x y', 'redis'),), {}, {}),
    ({}, (('/etc/$(id)', 'redis'),), {}, {}),
    ({}, (('/etc/x', 'redis\nservice=evil'),), {}, {}),
    ({}, (), {'a`id`': 'plex'}, {}),
    ({}, (), {'plex': 'a|b'}, {}),
    # Words appear unquoted: no globs, tilde, assignments, options or reserved words.
    ({'ngin*': 'nginx'}, (), {}, {}),
    ({'ngin?x': 'nginx'}, (), {}, {}),
    ({'[a]x': 'nginx'}, (), {}, {}),
    ({'esac': 'nginx'}, (), {}, {}),
    ({'in': 'nginx'}, (), {}, {}),
    ({}, (('~root/x', 'redis'),), {}, {}),
    ({}, (('/etc/*', 'redis'),), {}, {}),
    ({}, (('-o', 'redis'),), {}, {}),
    ({}, (('/etc/x', 'a=b'),), {}, {}),
    ({}, (('/etc/x', '-n'),), {}, {}),
    ({}, (), {'-n': 'plex'}, {}),
    ({}, (), {'a\\b': 'plex'}, {}),
    ({}, (), {}, {'esac': 'syncthing'}),
    ({}, (), {}, {'sync': 'a;b'}),
    ({}, (), {'': 'plex'}, {}),
])
def test_identity_probe_rejects_unsafe_catalog_values(units, paths, snaps, templates):
    with pytest.raises(ValueError):
        host_platform._identity_command(units, paths, snaps, templates)


def test_identity_probe_accepts_catalog_style_values():
    command = host_platform._identity_command({'wg@x': 'wireguard'}, (('/opt/a-b_c.d+e', 'redis'),), {'a-b': 'plex'})
    assert 'wg@x)' in command and '[ -e /opt/a-b_c.d+e ]' in command and 'echo snap=a-b' in command


def test_unquoted_catalog_words_reach_the_shell_literally(short_root):
    (short_root / 'present').mkdir()
    (short_root / 'snap' / 'a-b').mkdir(parents=True)
    command = host_platform._identity_command(
        {}, ((str(short_root / 'missing'), 'redis'), (str(short_root / 'present'), 'nextcloud'),
             (str(short_root / 'gone'), 'plex')), {'a-b': 'plex', 'c.d': 'jellyfin'})
    begin = command.index('\nif [ -e ') + 1
    snippet = command[begin:command.index('\nimages=', begin)]
    lines, _ = _run_probe_part(snippet.replace('/snap/', str(short_root / 'snap') + '/'), short_root)
    assert lines[:-1] == ['service=nextcloud', 'snap=a-b']


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


def _fish_words(command):
    """Split a command line the way fish does for the constructs the wrapper uses.

    Inside single quotes fish knows only the escapes \\\\ and \\'; outside quotes a
    backslash escapes the next character. fish itself is not installed here.
    """
    words, word, quoted, index, started = [], '', False, 0, False
    while index < len(command):
        char = command[index]
        if quoted:
            if char == '\\' and command[index + 1:index + 2] in ('\\', "'"):
                word, index = word + command[index + 1], index + 2
                continue
            if char == "'":
                quoted = False
            else:
                word += char
        elif char == "'":
            quoted = started = True
        elif char == '\\':
            word, index, started = word + command[index + 1], index + 2, True
            continue
        elif char in ' \n':
            if started:
                words.append(word)
            word, started = '', False
        else:
            word, started = word + char, True
        index += 1
    assert not quoted
    if started:
        words.append(word)
    return words


def test_identity_probe_runs_under_posix_sh_whatever_the_login_shell():
    import shlex
    command = host_platform.IDENTITY_EXEC
    expected = ['exec', '/bin/sh', '-c', host_platform.IDENTITY_COMMAND]
    assert shlex.split(command) == expected      # sh, dash, ash, bash, ksh, zsh
    assert _fish_words(command) == expected
    direct = subprocess.run(['sh', '-c', host_platform.IDENTITY_COMMAND], capture_output=True, text=True, timeout=10)
    for login_shell in ('sh', 'bash'):
        wrapped = subprocess.run([shutil.which(login_shell), '-c', command], capture_output=True, text=True, timeout=10)
        assert wrapped.returncode == 0 and wrapped.stdout == direct.stdout


@pytest.mark.parametrize('script', ["printf '\\\\n'", "printf 'a\\'", "printf ''", "'x'", 'x\n\'', 'x\\',
                                    'a\nb', 'a\rb'])
def test_the_login_shell_wrapper_refuses_text_fish_would_read_differently(script):
    with pytest.raises(ValueError):
        host_platform._posix_sh(script)


def test_identity_collector_sends_the_wrapped_probe(monkeypatch):
    from app import session_insights
    from tests.test_session_insights import install_session, FakeChannel
    install_session(monkeypatch)
    sent = []
    def open_channel(transport, command, **kwargs):
        sent.append(command)
        return FakeChannel(b'kernel=Linux\n')
    monkeypatch.setattr(session_insights.ssh_manager, '_open_exec_channel', open_channel)
    host_platform.collect_identity('owned-session')
    assert sent == [host_platform.IDENTITY_EXEC]


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
    invocations = re.findall(r'timeout \d+ podman\S*(?: \S+)?', command)
    assert invocations and all(re.match(r'timeout \d+ podman --remote', item) for item in invocations)
    # Container listings always name a local socket: docker -H, or podman behind --remote --url.
    assert set(re.findall(r'(\S+) ps\b', command)) == {'"unix://$dsock"', '"unix://$sock"'}
    assert not re.search(r'podman (ps|info|images|version)', command)
    assert 'unix:///run/podman/podman.sock' not in command or '--remote' in command
    assert '$XDG_RUNTIME_DIR/podman/podman.sock' in command and '[ -S ' in command


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
    lines += ['service=' + service for service in set(host_catalog.SERVICE_UNIT_TEMPLATES.values())]
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
    assert host_platform.identity_needed({'greeting_platform': 'embedded'})
    assert 'embedded' not in host_catalog.NON_POSIX_PLATFORMS
    assert not host_platform.identity_needed({'platform_icon': 'proxmox'})


_STORED_FACTS = dict(detected_platform='debian', detected_os_version='12', detected_services=['nginx'],
                     detected_virt='vm', detection_state='detected', platform_checked_at=1_000.0,
                     services_checked_at=1_000.0,
                     detected_maintenance={'reboot_required': True, 'updates': 3, 'security_updates': 1,
                                           'checked_at': 1_000.0})


@pytest.mark.parametrize('before', [None, 'debian'])
@pytest.mark.parametrize('greeting', sorted(host_catalog.NON_POSIX_PLATFORMS))
def test_a_non_posix_greeting_replaces_facts_from_an_earlier_system(app, monkeypatch, before, greeting):
    """The address now answers as Windows or a network device; what the probe found belonged to another system."""
    import json
    from app import profile_manager
    fields = {'greeting_platform': before} if before else {}
    user_id, profile, _ = _identity_session(app, monkeypatch, 'reused', **fields)
    _store(app, user_id, profile['id'], **_STORED_FACTS)
    with app.app_context():
        assert profile_manager.cache_greeting_platforms(user_id, {profile['id']: (('reused.example', 22), greeting)}) == 1
        saved = profile_manager.get_profile(user_id, profile['id'])
    assert saved['greeting_platform'] == greeting
    assert not set(_STORED_FACTS) & set(saved), json.dumps(saved)


def test_a_legacy_server_platform_goes_when_the_probe_stalls(app, monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(host_platform, 'time', SimpleNamespace(time=lambda: 10_000_000.0))
    saved, published, _ = _stall_detection(app, monkeypatch, 'oldstall', b'ID=debian\nkernel=Linux\n',
                                           detected_platform='server', detected_services=['nginx'],
                                           services_checked_at=5)
    assert published == [] and 'detected_platform' not in saved and saved['detected_services'] == ['nginx']
    day = 24 * 3600
    assert not host_platform.identity_needed(saved, now=10_000_000.0 + 3600)
    assert host_platform.identity_needed(saved, now=10_000_000.0 + day + 1)


def test_a_changed_posix_greeting_asks_the_probe_again(app, monkeypatch):
    from app import profile_manager
    user_id, profile, _ = _identity_session(app, monkeypatch, 'moved', greeting_platform='ubuntu')
    now = 2_000_000_000.0
    _store(app, user_id, profile['id'], **dict(_STORED_FACTS, platform_checked_at=now))
    with app.app_context():
        assert profile_manager.cache_greeting_platforms(user_id, {profile['id']: (('moved.example', 22), 'debian')}) == 1
        saved = profile_manager.get_profile(user_id, profile['id'])
    assert saved['greeting_platform'] == 'debian' and 'platform_checked_at' not in saved
    assert saved['detected_platform'] == 'debian' and saved['detected_services'] == ['nginx']
    assert host_platform.identity_needed(saved, now=now + 60)


def test_a_first_posix_greeting_keeps_a_recent_detection(app, monkeypatch):
    from app import profile_manager
    user_id, profile, _ = _identity_session(app, monkeypatch, 'first')
    now = 2_000_000_000.0
    _store(app, user_id, profile['id'], **dict(_STORED_FACTS, platform_checked_at=now))
    with app.app_context():
        assert profile_manager.cache_greeting_platforms(user_id, {profile['id']: (('first.example', 22), 'ubuntu')}) == 1
        saved = profile_manager.get_profile(user_id, profile['id'])
    assert saved['platform_checked_at'] == now and saved['detected_platform'] == 'debian'
    assert not host_platform.identity_needed(saved, now=now + 60)


def test_a_dropbear_greeting_does_not_suppress_the_probe(app, monkeypatch):
    user_id, profile, _ = _identity_session(app, monkeypatch, 'alpine', greeting_platform='embedded')
    calls = _fake_identity(monkeypatch, (_identity(platform='alpinelinux'), None))
    with app.app_context():
        host_platform.detect_connected_platform('alpine', user_id, pytest.fail)
    assert len(calls) == 1


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


_PROBE_TOOLS = ('timeout', 'head', 'sort', 'cut', 'sed', 'awk', 'ls', 'wc', 'tr', 'grep')


def _probe_part(start):
    """The probe block that starts with the line ``start`` and ends at its own ``fi``."""
    command = host_platform.IDENTITY_SCRIPT
    begin = command.index(start)
    return command[begin:command.index('\nfi\n', begin) + 4]


def _run_probe_part(snippet, root, *, replace=(), tools=None, system_tools=_PROBE_TOOLS, env=None):
    """Run a probe block with fake tools; paths in ``replace`` point into root."""
    bin_dir = root / 'bin'
    bin_dir.mkdir(exist_ok=True)
    for name in system_tools:
        if shutil.which(name) and not (bin_dir / name).exists():
            (bin_dir / name).symlink_to(shutil.which(name))
    for name, body in (tools or {}).items():
        tool = bin_dir / name
        tool.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "' + str(root / 'calls') + '"\n' + body + '\n')
        tool.chmod(0o755)
    for old, new in replace:
        snippet = snippet.replace(old, new)
    script = "found() { printf 'service=%s\\n' \"$1\"; }\nimages=\n" + snippet + '\nprintf \'images=%s\\n\' "$images"\n'
    busybox = shutil.which('busybox')
    argv = [busybox, 'sh', '-c', script] if busybox else [shutil.which('dash') or shutil.which('sh'), '-c', script]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=10,
                            env={'PATH': str(bin_dir), **(env or {})})
    assert result.returncode == 0, result.stderr
    calls = (root / 'calls').read_text().splitlines() if (root / 'calls').exists() else []
    return result.stdout.splitlines(), calls


@pytest.fixture
def short_root():
    # Unix socket paths are limited to about 100 bytes; pytest's tmp_path can be longer.
    import tempfile
    from pathlib import Path
    directory = tempfile.mkdtemp(prefix='probe-', dir='/tmp')
    yield Path(directory)
    shutil.rmtree(directory, ignore_errors=True)


def _unix_socket(path):
    import socket
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    return server


def _docker_part():
    command = host_platform.IDENTITY_SCRIPT
    begin = command.index('dsock=')
    return command[begin:command.index('\nfi\n', command.index('found docker', begin)) + 4]


_DOCKER_LISTS = {'docker': "[ \"$1\" = -H ] || exit 125\nprintf 'nginx:1.27\\n'"}


def test_docker_is_asked_only_through_the_system_socket(short_root):
    sock = _unix_socket(short_root / 'docker.sock')
    try:
        lines, calls = _run_probe_part(_docker_part(), short_root, tools=_DOCKER_LISTS,
                                       replace=(('/var/run/docker.sock', str(short_root / 'docker.sock')),),
                                       env={'DOCKER_HOST': 'ssh://elsewhere'})
    finally:
        sock.close()
    assert calls == ['-H unix://%s ps --format {{.Image}}' % (short_root / 'docker.sock')]
    assert 'service=docker' in lines and 'engine=docker:ok' in lines
    assert lines[-2:] == ['images=', 'nginx:1.27']


def test_rootless_docker_is_asked_through_its_runtime_socket(short_root):
    (short_root / 'run').mkdir()
    sock = _unix_socket(short_root / 'run' / 'docker.sock')
    try:
        lines, calls = _run_probe_part(_docker_part(), short_root, tools=_DOCKER_LISTS,
                                       replace=(('/var/run/docker.sock', str(short_root / 'missing.sock')),),
                                       env={'XDG_RUNTIME_DIR': str(short_root / 'run')})
    finally:
        sock.close()
    assert calls == ['-H unix://%s ps --format {{.Image}}' % (short_root / 'run' / 'docker.sock')]
    assert 'engine=docker:ok' in lines


def test_docker_without_a_local_socket_is_never_run(short_root):
    # The podman-docker shim, a docker context or DOCKER_HOST would otherwise start
    # rootless podman or reach another host.
    (short_root / 'run').mkdir()
    (short_root / 'run' / 'docker.sock').write_text('')
    lines, calls = _run_probe_part(_docker_part(), short_root, tools=_DOCKER_LISTS,
                                   replace=(('/var/run/docker.sock', str(short_root / 'missing.sock')),),
                                   env={'XDG_RUNTIME_DIR': str(short_root / 'run'), 'DOCKER_HOST': 'tcp://elsewhere:2375'})
    assert calls == [] and lines == ['images=']


def test_a_docker_client_that_fails_ends_as_denied(short_root):
    sock = _unix_socket(short_root / 'docker.sock')
    try:
        lines, calls = _run_probe_part(_docker_part(), short_root, tools={'docker': 'exit 125'},
                                       replace=(('/var/run/docker.sock', str(short_root / 'docker.sock')),))
    finally:
        sock.close()
    assert len(calls) == 1 and lines == ['service=docker', 'engine=docker:denied', 'images=']


def test_a_docker_socket_without_the_client_still_names_docker(short_root):
    sock = _unix_socket(short_root / 'docker.sock')
    try:
        lines, calls = _run_probe_part(_docker_part(), short_root,
                                       replace=(('/var/run/docker.sock', str(short_root / 'docker.sock')),))
    finally:
        sock.close()
    assert calls == [] and lines == ['service=docker', 'images=']


def _engines_part():
    command = host_platform.IDENTITY_SCRIPT
    begin = command.index('dsock=')
    return command[begin:command.index('\nfi\n', command.index('found podman', begin)) + 4]


_PODMAN_LISTS = {'podman': "printf 'quay.io/immich-app/immich-server:release\\n'"}


def test_a_docker_socket_that_links_to_podman_is_reported_as_podman(short_root):
    # podman-docker links /run/docker.sock to the Podman API socket.
    (short_root / 'podman').mkdir()
    sock = _unix_socket(short_root / 'podman' / 'podman.sock')
    (short_root / 'docker.sock').symlink_to(short_root / 'podman' / 'podman.sock')
    try:
        lines, calls = _run_probe_part(_engines_part(), short_root, tools={**_DOCKER_LISTS, **_PODMAN_LISTS},
                                       system_tools=(*_PROBE_TOOLS, 'readlink'),
                                       replace=(('/var/run/docker.sock', str(short_root / 'docker.sock')),
                                                ('/run/podman/podman.sock', str(short_root / 'missing.sock'))))
    finally:
        sock.close()
    assert calls == ['--remote --url unix://%s ps --format {{.Image}}' % (short_root / 'docker.sock')]
    assert 'service=docker' not in lines and 'service=podman' in lines and 'engine=podman:ok' in lines
    assert 'quay.io/immich-app/immich-server:release' in lines


def test_a_docker_socket_link_elsewhere_stays_docker(short_root):
    (short_root / 'real').mkdir()
    sock = _unix_socket(short_root / 'real' / 'docker.sock')
    (short_root / 'docker.sock').symlink_to(short_root / 'real' / 'docker.sock')
    try:
        lines, calls = _run_probe_part(_engines_part(), short_root, tools=_DOCKER_LISTS,
                                       system_tools=(*_PROBE_TOOLS, 'readlink'),
                                       replace=(('/var/run/docker.sock', str(short_root / 'docker.sock')),))
    finally:
        sock.close()
    assert calls == ['-H unix://%s ps --format {{.Image}}' % (short_root / 'docker.sock')]
    assert 'service=docker' in lines and 'engine=docker:ok' in lines and 'service=podman' not in lines


def test_every_docker_query_in_the_module_names_a_unix_socket():
    # Every probe in the module, not only the identity probe.
    command = _module_text_without_comments(host_platform)
    queries = [match for match in re.finditer(r'\bdocker (\S+)', command)
               if not command[:match.start()].endswith(('command -v ', 'found ', 'grep -q -e '))]
    assert queries and all(match.group(1) == '-H' and command.startswith('"unix://', match.end() + 1)
                           for match in queries), [match.group(0) for match in queries]


def test_container_queries_leave_room_within_the_deadline():
    limits = re.findall(r'timeout (\d+) (docker|podman)', host_platform.IDENTITY_COMMAND)
    assert sorted(engine for _, engine in limits) == ['docker', 'podman']
    assert sum(int(limit) for limit, _ in limits) <= 2


def test_podman_with_a_socket_but_no_timeout_still_names_podman(short_root):
    command = host_platform.IDENTITY_COMMAND
    (short_root / 'podman').mkdir()
    sock = _unix_socket(short_root / 'podman' / 'podman.sock')
    try:
        lines, calls = _run_probe_part(_probe_part('if [ -n "$psock" ]'), short_root, tools={'podman': ''},
                                       system_tools=(), env={'XDG_RUNTIME_DIR': str(short_root)})
    finally:
        sock.close()
    assert 'timeout 1 podman --remote' in command
    assert calls == [] and lines == ['service=podman', 'images=']


@pytest.mark.parametrize('vyatta, vyos, version, expected', [
    (True, False, '', ['marker=ubiquiti']),                     # EdgeOS
    (True, True, '', []),                                       # VyOS 1.2 and later
    (True, False, 'Version:      VyOS 1.1.8', []),             # VyOS 1.1
    (False, False, '', []),
])
def test_ubiquiti_marker_skips_vyos(short_root, vyatta, vyos, version, expected):
    if vyatta:
        (short_root / 'vyatta' / 'etc').mkdir(parents=True)
        if version:
            (short_root / 'vyatta' / 'etc' / 'version').write_text(version + '\n')
    if vyos:
        (short_root / 'vyos').mkdir()
    line = next(line for line in host_platform.IDENTITY_SCRIPT.splitlines() if 'marker=ubiquiti' in line)
    lines, _ = _run_probe_part(line, short_root, replace=(
        ('/opt/vyatta', str(short_root / 'vyatta')), ('/usr/libexec/vyos', str(short_root / 'vyos')),
        ('/usr/lib/version', str(short_root / 'version'))))
    assert lines[:-1] == expected


def test_ubiquiti_marker_still_covers_unifi_os(short_root):
    (short_root / 'version').write_text('UDMPRO.al324.v4.0.6\nUniFi OS\n')
    line = next(line for line in host_platform.IDENTITY_SCRIPT.splitlines() if 'marker=ubiquiti' in line)
    lines, _ = _run_probe_part(line, short_root, replace=(
        ('/opt/vyatta', str(short_root / 'vyatta')), ('/usr/libexec/vyos', str(short_root / 'vyos')),
        ('/usr/lib/version', str(short_root / 'version'))))
    assert lines[:-1] == ['marker=ubiquiti']


def _guest_part():
    command = host_platform.IDENTITY_SCRIPT
    begin = command.rindex('\nif ', 0, command.index("'guests=")) + 1
    return command[begin:command.index('\nfi\n', begin) + 4]


@pytest.mark.parametrize('unreadable, expected', [(None, ['guests=3']), ('qemu-server', []), ('lxc', [])])
def test_guest_count_is_printed_only_when_both_config_directories_are_readable(short_root, unreadable, expected):
    import os
    if os.geteuid() == 0:
        pytest.skip('root reads every directory')
    pve = short_root / 'pve'
    for name, count in (('qemu-server', 2), ('lxc', 1)):
        (pve / name).mkdir(parents=True)
        for index in range(count):
            (pve / name / f'{100 + index}.conf').write_text('')
    if unreadable:
        (pve / unreadable).chmod(0)
    try:
        lines, _ = _run_probe_part(_guest_part(), short_root, replace=(('/etc/pve', str(pve)),))
    finally:
        if unreadable:
            (pve / unreadable).chmod(0o755)
    assert lines[:-1] == expected


def _units_part():
    return _probe_part('if command -v systemctl')


def test_templated_units_map_to_their_service_once(short_root):
    units = '\n'.join(f'{name}.service loaded active running Something' for name in (
        'syncthing@alice', 'syncthing@bob', 'openvpn-server@site', 'openvpn-client@home', 'openvpn@legacy',
        'nginx', 'syncthingx', 'wg-quick@wg0', 'evil@syncthing'))
    systemctl = ('case "$1" in get-default) echo multi-user.target ;; *) cat <<"UNITS"\n' + units + '\nUNITS\n;; esac')
    lines, _ = _run_probe_part(_units_part(), short_root, tools={'systemctl': systemctl},
                               system_tools=(*_PROBE_TOOLS, 'cat'))
    assert sorted(lines[:-1]) == ['service=openvpn', 'service=syncthing', 'service=wireguard',
                                  'target=multi-user.target', 'unit=nginx']


def test_templated_unit_catalog_values_are_validated():
    with pytest.raises(ValueError):
        host_platform._identity_command({}, (), {}, {'sync$(id)': 'syncthing'})
    with pytest.raises(ValueError):
        host_platform._identity_command({}, (), {}, {'syncthing': 'a b'})
    command = host_platform._identity_command({}, (), {}, {'syncthing': 'syncthing'})
    assert 'syncthing@*) found syncthing ;;' in command
