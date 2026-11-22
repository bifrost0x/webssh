"""Warnings for reverse-proxy settings that contradict the observed traffic."""

import pytest


@pytest.fixture
def warnings_seen(monkeypatch):
    import app as app_module

    events = []
    monkeypatch.setattr(app_module, '_config_warnings_logged', set(), raising=False)
    monkeypatch.setattr(
        app_module,
        'log_warning',
        lambda message, **data: events.append((message, data)),
    )
    return events


def _proxy_warnings(events):
    return [event for event in events if 'TRUSTED_PROXIES' in event[0]]


@pytest.fixture
def direct_app(monkeypatch, request):
    monkeypatch.setenv('TRUSTED_PROXIES', '0')
    return request.getfixturevalue('app')


@pytest.fixture
def proxied_app(monkeypatch, request):
    monkeypatch.setenv('TRUSTED_PROXIES', '1')
    return request.getfixturevalue('app')


def test_forwarded_headers_without_trusted_proxies_warn_once(direct_app, warnings_seen):
    client = direct_app.test_client()
    for _ in range(3):
        client.get('/login', headers={'X-Forwarded-For': '203.0.113.7'},
                   environ_base={'REMOTE_ADDR': '172.18.0.2'})

    warnings = _proxy_warnings(warnings_seen)
    assert len(warnings) == 1
    assert 'TRUSTED_PROXIES=0' in warnings[0][0]
    assert warnings[0][1] == {'proxy': '172.18.0.2'}


def test_rfc7239_forwarded_header_also_counts(direct_app, warnings_seen):
    direct_app.test_client().get('/login', headers={'Forwarded': 'for=203.0.113.7'})

    assert len(_proxy_warnings(warnings_seen)) == 1


def test_direct_traffic_without_proxy_headers_stays_quiet(direct_app, warnings_seen):
    direct_app.test_client().get('/login', environ_base={'REMOTE_ADDR': '192.168.1.20'})

    assert _proxy_warnings(warnings_seen) == []


def test_request_bypassing_a_trusted_proxy_warns_once(proxied_app, warnings_seen):
    client = proxied_app.test_client()
    for _ in range(3):
        client.get('/login', environ_base={'REMOTE_ADDR': '192.168.1.20'})

    warnings = _proxy_warnings(warnings_seen)
    assert len(warnings) == 1
    assert 'without X-Forwarded-For' in warnings[0][0]
    assert warnings[0][1] == {'client': '192.168.1.20', 'trusted_proxies': 1}


def test_proxied_and_loopback_health_requests_stay_quiet(proxied_app, warnings_seen):
    client = proxied_app.test_client()
    client.get('/login', headers={'X-Forwarded-For': '203.0.113.7'},
               environ_base={'REMOTE_ADDR': '172.18.0.2'})
    client.get('/ready', environ_base={'REMOTE_ADDR': '127.0.0.1'})
    client.get('/ready', environ_base={'REMOTE_ADDR': '::1'})

    assert _proxy_warnings(warnings_seen) == []
