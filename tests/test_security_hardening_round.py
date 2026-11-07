"""Regression tests for the security review fixes across accounts, storage and the HTTP surface."""
import logging
import threading
import time

import pyotp
import pytest

import config
from tests.step_up_helpers import account_password_step_up_headers
from tests.test_automation_service import context  # noqa: F401  (fixture)
from tests.test_totp_routes import _activate_totp_feature, _create_user, _login


def _enable_rate_limits(monkeypatch):
    monkeypatch.setattr(config, 'RATELIMIT_ENABLED', True)
    monkeypatch.setattr(config, 'RATELIMIT_LOGIN_LIMIT', '5 per minute')


def test_totp_login_is_limited_per_account_across_source_addresses(app, client, monkeypatch):
    user_id = _create_user(app, 'totp_spray_user')
    _activate_totp_feature(app, monkeypatch)
    _login(client, 'totp_spray_user')
    headers, _ = account_password_step_up_headers(client, 'totp.enroll', user_id)
    started = client.post('/api/totp/enroll', json={}, headers=headers).get_json()
    secret = started['secret']
    assert client.post('/api/totp/enroll/verify', json={
        'token': started['token'], 'code': pyotp.TOTP(secret).now(), 'confirm_enable_mfa': True}).status_code == 200
    client.post('/logout')
    assert client.post('/login', data={'username': 'totp_spray_user', 'password': 'password123'}).status_code == 200
    _enable_rate_limits(monkeypatch)
    for index in range(5):
        wrong = client.post('/api/totp/auth/verify', json={'code': '000000'},
                            environ_base={'REMOTE_ADDR': f'198.51.100.{index + 1}'})
        assert wrong.status_code == 401
    # A fresh source address does not reset the per-account budget, even with the right code.
    blocked = client.post('/api/totp/auth/verify', json={'code': pyotp.TOTP(secret).at(time.time() + 30)},
                          environ_base={'REMOTE_ADDR': '198.51.100.99'})
    assert blocked.status_code == 429


def test_password_change_is_limited_per_account(app, client, monkeypatch):
    _create_user(app, 'password_spray_user')
    _login(client, 'password_spray_user')
    _enable_rate_limits(monkeypatch)
    for index in range(5):
        client.post('/change-password', data={'current_password': 'wrong', 'new_password': 'x' * 16, 'confirm_password': 'x' * 16},
                    environ_base={'REMOTE_ADDR': f'203.0.113.{index + 1}'})
    response = client.post('/change-password', data={
        'current_password': 'password123', 'new_password': 'n' * 16, 'confirm_password': 'n' * 16},
        environ_base={'REMOTE_ADDR': '203.0.113.200'})
    assert b'Too many attempts' in response.data
    from app.models import User, db
    with app.app_context():
        assert db.session.query(User).filter_by(username='password_spray_user').one().check_password('password123')


def test_admin_users_skips_missing_and_locked_accounts(app, caplog):
    from app.auth import register_user, sync_admin_users
    from app.models import User, db
    with app.app_context():
        register_user('first_account_admin', 'password123')  # the first account becomes admin
        locked, error = register_user('locked_listed', 'password123')
        assert error is None
        locked.is_locked = True
        db.session.commit()
        original = config.ADMIN_USERS
        config.ADMIN_USERS = ['locked_listed', 'not_registered_yet']
        try:
            with caplog.at_level(logging.WARNING):
                sync_admin_users()
        finally:
            config.ADMIN_USERS = original
        assert db.session.query(User).filter_by(username='locked_listed').one().is_admin is False
    assert 'ADMIN_USERS lists an account that does not exist' in caplog.text


def test_github_auto_provisioning_without_organizations_is_refused_in_production(app, monkeypatch):
    from app import github_auth_service as service
    monkeypatch.setattr(config, 'DEPLOYMENT_PROFILE', 'production')
    assert service.auto_provision_unrestricted(True, []) is True
    assert service.auto_provision_unrestricted(True, ['acme']) is False
    assert service.auto_provision_unrestricted(False, []) is False
    with app.app_context():
        with pytest.raises(service.GitHubConfigurationError):
            service.update_settings({'auto_provision': True, 'allowed_orgs': []}, admin_id=1)
    monkeypatch.setattr(config, 'DEPLOYMENT_PROFILE', 'homelab')
    assert service.auto_provision_unrestricted(True, []) is False


def test_audit_values_cannot_forge_fields():
    from app.audit_logger import _sanitize_log_value
    value = _sanitize_log_value('report.txt | user=admin | ip=10.0.0.1\nFAKE')
    assert ' | user=' not in value and '\n' not in value
    assert value.startswith('report.txt \\| user=admin')


def test_import_preview_is_rate_limited(app, client, context, monkeypatch):
    from app import profile_exchange_routes
    monkeypatch.setattr(profile_exchange_routes, 'check_reauth_rate_limit', lambda *args, **kwargs: True)
    monkeypatch.setattr(profile_exchange_routes, 'load_key_summaries',
                        lambda user_id: (_ for _ in ()).throw(AssertionError('keys must not be decrypted when throttled')))
    assert client.post('/api/profiles/exchange/preview', json={'source': '', 'format': 'json'}).status_code == 429


def test_dynamic_responses_are_not_cached_and_headers_are_current(app, client, context):
    page = client.get('/')
    assert page.headers['Cache-Control'] == 'no-store'
    assert client.get('/api/overview/status').headers['Cache-Control'] == 'no-store'
    policy = page.headers['Content-Security-Policy']
    assert "base-uri 'self'" in policy and "object-src 'none'" in policy and "frame-ancestors 'none'" in policy
    assert page.headers['X-XSS-Protection'] == '0'
    static = client.get('/static/js/overview-model.js')
    assert 'no-store' not in static.headers.get('Cache-Control', '')


def test_placeholder_secret_key_is_refused(tmp_path):
    import os
    import subprocess
    import sys
    env = {**os.environ, 'SECRET_KEY': '<YOUR-SECRET-KEY>', 'DEBUG': 'false', 'DATA_DIR': str(tmp_path)}
    result = subprocess.run([sys.executable, '-c', 'import config'], cwd=os.path.dirname(os.path.dirname(__file__)),
                            env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode != 0 and 'SECRET_KEY' in result.stderr


@pytest.mark.skipif(__import__('os').name != 'posix', reason='file modes are POSIX-only')
def test_new_data_directory_is_private(tmp_path):
    from app import _prepare_data_dir
    target = tmp_path / 'fresh'
    _prepare_data_dir(target)
    assert target.stat().st_mode & 0o077 == 0


def test_discovery_is_not_offered_when_disabled(app, client, context, monkeypatch):
    monkeypatch.setattr(config, 'HOST_DISCOVERY_ENABLED', False)
    assert client.post('/api/discovery/scans', json={'network': '10.0.0.0/30'}).status_code == 404
    assert b'id="hostDiscoveryDialog"' not in client.get('/').data


def test_discovery_admission_is_atomic(app, client, context, monkeypatch):
    from app import discovery_routes as discovery
    discovery._SCANS.clear()
    release = threading.Event()
    monkeypatch.setattr(discovery, '_probe', lambda address, port: release.wait(2) or {'state': 'closed'})
    monkeypatch.setattr(discovery, '_known_endpoints', lambda user_id: set())
    original = discovery.Scan.__init__
    barrier = threading.Barrier(2)

    def slow_init(self, *args, **kwargs):
        original(self, *args, **kwargs)
        barrier.wait(2)  # both requests are past validation before either registers

    monkeypatch.setattr(discovery.Scan, '__init__', slow_init)
    statuses = []

    def start():
        with app.test_client() as other:
            with client.session_transaction() as source, other.session_transaction() as target:
                target.update(dict(source))
            statuses.append(other.post('/api/discovery/scans', json={'network': '10.6.0.0/30'}).status_code)

    threads = [threading.Thread(target=start, daemon=True) for _ in range(2)]
    [thread.start() for thread in threads]
    [thread.join(10) for thread in threads]
    release.set()
    discovery.cancel_all()
    discovery._SCANS.clear()
    assert sorted(statuses) == [202, 409]


def test_discovery_reports_only_ssh_servers(monkeypatch):
    from app import discovery_routes as discovery, network_policy

    class Connection:
        def settimeout(self, value):
            pass

        def recv(self, size):
            return b'HTTP/1.1 400 Bad Request\r\n'

        def close(self):
            pass

    monkeypatch.setattr(network_policy, 'resolve_allowed_target', lambda *args, **kwargs: object())
    monkeypatch.setattr(network_policy, 'open_validated_socket', lambda target, timeout: Connection())
    assert discovery._probe('10.0.0.1', 80) == {'state': 'closed'}


def test_reachability_allows_one_check_per_account_and_cancels_stale_probes(app, client, context, monkeypatch):
    from app import overview_routes
    overview_routes._CACHE.clear()
    with overview_routes._CACHE_LOCK:
        overview_routes._IN_FLIGHT.add(context[0])
    try:
        assert client.post('/api/overview/reachability', json={}).status_code == 429
    finally:
        with overview_routes._CACHE_LOCK:
            overview_routes._IN_FLIGHT.discard(context[0])
    cancelled = []

    class Future:
        def result(self, timeout=None):
            from concurrent.futures import TimeoutError as FutureTimeout
            raise FutureTimeout()

        def cancel(self):
            cancelled.append(True)
            return True

    monkeypatch.setattr(overview_routes._EXECUTOR, 'submit', lambda *args, **kwargs: Future())
    response = client.post('/api/overview/reachability', json={})
    assert response.status_code == 200 and cancelled
    assert context[0] not in overview_routes._IN_FLIGHT


def test_probe_limits_are_per_account_not_per_source_address(app):
    from app.auth import check_user_rate_limit
    with app.app_context():
        assert not any(check_user_rate_limit(1, 'probe_test', '3 per minute') for _ in range(3))
        assert check_user_rate_limit(1, 'probe_test', '3 per minute') is True
        # Another account behind the same address keeps its own budget.
        assert check_user_rate_limit(2, 'probe_test', '3 per minute') is False
        assert check_user_rate_limit(3, 'probe_cost', '10 per minute', cost=11) is True


def test_revoking_an_account_stops_its_scans(app, context):
    from app import discovery_routes as discovery
    from app.user_lifecycle import revoke_user_access
    discovery._SCANS.clear()
    scan = discovery.Scan(context[0], '10.5.0.0/30', ['10.5.0.1'], [22], set())
    other = discovery.Scan(context[0] + 1000, '10.5.1.0/30', ['10.5.1.1'], [22], set())
    discovery._SCANS.update({scan.id: scan, other.id: other})
    with app.app_context():
        revoke_user_access(context[0])
    assert scan.cancel_event.is_set() and scan.revoked and scan.found == []
    assert not other.cancel_event.is_set() and not other.revoked
    discovery._SCANS.clear()


def test_a_stopping_scan_still_blocks_a_new_one(app, client, context, monkeypatch):
    from app import discovery_routes as discovery
    discovery._SCANS.clear()
    monkeypatch.setattr(discovery, '_known_endpoints', lambda user_id: set())
    scan = discovery.Scan(context[0], '10.4.0.0/30', ['10.4.0.1'], [22], set())
    scan.state = 'cancelled'  # cancelled, but run() has not finished yet
    discovery._SCANS[scan.id] = scan
    assert client.post('/api/discovery/scans', json={'network': '10.4.1.0/30'}).status_code == 409
    discovery._SCANS.clear()


@pytest.mark.parametrize('origin,host,accepted', [
    ('http://192.168.1.10:5000', '192.168.1.10:5000', True),
    ('https://ssh.example.com', 'ssh.example.com', True),
    ('https://ssh.example.com:443', 'ssh.example.com', True),
    ('http://SSH.example.com:8080', 'ssh.example.com:8080', True),
    ('https://ssh.example.com', 'ssh.example.com:443', True),
    ('http://192.168.1.10:8080', '192.168.1.10:5000', False),   # another service on the same host
    ('https://grafana.example.com', 'ssh.example.com', False),  # sibling subdomain
    ('http://192.168.1.11:5000', '192.168.1.10:5000', False),
    ('null', '192.168.1.10:5000', False),
    ('file://', '192.168.1.10:5000', False),
    ('http://user:pw@192.168.1.10:5000', '192.168.1.10:5000', False),
    ('http://192.168.1.10:5000', '', False),
])
def test_wildcard_socket_origin_means_same_origin(origin, host, accepted):
    from app import same_origin_socket_check
    assert same_origin_socket_check(origin, {'HTTP_HOST': host, 'wsgi.url_scheme': 'http'}) is accepted


def test_wildcard_cors_installs_the_same_origin_check(monkeypatch):
    from app import create_app, same_origin_socket_check, socketio
    monkeypatch.setattr(config, 'CORS_ORIGINS', '*')
    monkeypatch.setattr(config, 'SOCKETIO_ALLOW_ANY_ORIGIN', False)
    create_app(start_runtime=False)
    assert socketio.server.eio.cors_allowed_origins is same_origin_socket_check
    monkeypatch.setattr(config, 'SOCKETIO_ALLOW_ANY_ORIGIN', True)
    create_app(start_runtime=False)
    assert socketio.server.eio.cors_allowed_origins == '*'


def test_discovery_defaults_off_in_production_only(tmp_path):
    import os
    import subprocess
    import sys
    base = {**os.environ, 'SECRET_KEY': 'x' * 64, 'DEBUG': 'false', 'DATA_DIR': str(tmp_path)}
    base.pop('HOST_DISCOVERY_ENABLED', None)
    root = os.path.dirname(os.path.dirname(__file__))
    homelab = subprocess.run([sys.executable, '-c', 'import config; print(config.HOST_DISCOVERY_ENABLED)'], cwd=root,
                             env={**base, 'DEPLOYMENT_PROFILE': 'homelab'}, capture_output=True, text=True, timeout=60)
    assert homelab.stdout.strip().splitlines()[-1] == 'True'


def test_reachability_reports_late_probes_as_unchecked_and_caps_concurrent_checks(app, client, context, monkeypatch):
    from app import overview_routes
    overview_routes._CACHE.clear()

    class Late:
        def result(self, timeout=None):
            from concurrent.futures import TimeoutError as FutureTimeout
            raise FutureTimeout()

        def cancel(self):
            return True

    monkeypatch.setattr(overview_routes._EXECUTOR, 'submit', lambda *args, **kwargs: Late())
    results = client.post('/api/overview/reachability', json={}).json['results']
    assert results and all(item['state'] == 'unchecked' for item in results.values())
    overview_routes._CACHE.clear()
    with overview_routes._CACHE_LOCK:
        overview_routes._IN_FLIGHT.update({-1, -2, -3})
    try:
        assert client.post('/api/overview/reachability', json={}).status_code == 429
    finally:
        with overview_routes._CACHE_LOCK:
            overview_routes._IN_FLIGHT.difference_update({-1, -2, -3})


def test_overview_values_from_a_newer_version_do_not_corrupt_settings(app, context):
    import json
    from app.models import User, db
    from app.storage_migrations import CURRENT_STORAGE_VERSIONS
    from app.user_settings import get_user_settings, save_user_settings
    uid = context[0]
    with app.app_context():
        path = db.session.get(User, uid).get_data_dir() / 'settings.json'
        path.write_text(json.dumps({
            'schema_version': CURRENT_STORAGE_VERSIONS['settings'], 'theme': 'paper',
            'overview_panels': [{'id': 'future-panel', 'w': 6, 'h': None, 'hidden': False}, {'id': 'hosts', 'w': 6, 'h': None, 'hidden': False}],
            'overview_dismissed': ['future-kind:abc', 'run-failed:r1'],
        }), encoding='utf-8')
        settings = get_user_settings(uid)
        assert settings['theme'] == 'paper'
        assert settings['overview_panels'] == [{'id': 'hosts', 'w': 6, 'h': None, 'hidden': False}]
        assert settings['overview_dismissed'] == ['run-failed:r1']
        # New values are still validated strictly.
        assert save_user_settings(uid, {'overview_dismissed': ['future-kind:abc']}) is False


def test_expired_form_is_refused_with_a_way_back_to_the_form(app, client):
    app.config['WTF_CSRF_ENABLED'] = True
    try:
        from app.auth import register_user
        with app.app_context():
            register_user('form_expiry_admin', 'password123')
        response = client.post('/login', data={'username': 'x', 'password': 'y'})
        page = response.get_data(as_text=True)
        assert response.status_code == 400
        assert 'data-i18n="auth.formExpired"' in page and 'href="/login"' in page
        # Unknown paths fall back to the login form instead of echoing the path.
        unknown = client.post('/no-such-form', data={})
        assert unknown.status_code in (400, 404) and 'no-such-form' not in unknown.get_data(as_text=True)
        api = client.post('/api/overview/reachability', json={})
        assert api.status_code in (400, 401, 302)
        if api.status_code == 400:
            assert api.json['code'] == 'csrf_expired'
    finally:
        app.config['WTF_CSRF_ENABLED'] = False


def test_forbidden_and_missing_pages_are_branded_but_apis_unchanged(app, client):
    from app.auth import register_user
    with app.app_context():
        register_user('first_admin_for_errors', 'password123')
        register_user('plain_user_for_errors', 'password123')
    assert client.post('/login', data={'username': 'plain_user_for_errors', 'password': 'password123'}).status_code == 302
    forbidden = client.get('/admin')
    assert forbidden.status_code == 403 and 'data-i18n="errors.forbiddenTitle"' in forbidden.get_data(as_text=True)
    missing = client.get('/no-such-page')
    assert missing.status_code == 404 and 'data-i18n="errors.notFoundTitle"' in missing.get_data(as_text=True)
    api = client.get('/admin/api/users')
    assert api.status_code == 403 and 'errors.forbiddenTitle' not in api.get_data(as_text=True)
