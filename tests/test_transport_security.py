"""HTTPS detection behind a TLS-terminating proxy without configured proxy trust."""
import pytest

from tests.test_automation_service import context  # noqa: F401  (fixture)

HOST = 'webssh.home.example'


@pytest.mark.parametrize('headers, expected', [
    ({}, False),
    ({'Origin': f'https://{HOST}'}, True),
    ({'Referer': f'https://{HOST}/automation'}, True),
    ({'Origin': f'https://{HOST.upper()}:443'}, True),
    # A page opened over plain HTTP never counts, whatever else it sends.
    ({'Origin': f'http://{HOST}'}, False),
    ({'Referer': f'http://{HOST}/', 'X-Forwarded-Proto': 'https'}, False),
    # Proxy headers are not trusted without TRUSTED_PROXIES.
    ({'X-Forwarded-Proto': 'https'}, False),
    # Another site, another port or a sandboxed page is not this WebSSH page.
    ({'Origin': 'https://evil.example'}, False),
    ({'Origin': f'https://{HOST}.evil.example'}, False),
    ({'Origin': f'https://{HOST}:8443'}, False),
    ({'Origin': 'null'}, False),
    ({'Origin': 'null', 'Referer': f'https://{HOST}/'}, True),
    ({'Referer': f'https://user:pass@{HOST}/'}, False),
    ({'Referer': 'not a url'}, False),
])
def test_https_page_of_the_same_host_counts_as_https(app, headers, expected):
    from app.transport_security import request_reached_over_https
    with app.test_request_context(base_url=f'http://{HOST}', headers=headers):
        assert request_reached_over_https() is expected


def test_direct_tls_still_counts_without_any_page_information(app):
    from app.transport_security import request_reached_over_https
    with app.test_request_context(base_url=f'https://{HOST}'):
        assert request_reached_over_https() is True


def test_saved_passwords_work_behind_a_tls_proxy_with_default_compose_settings(app, client, context, monkeypatch):
    import config
    monkeypatch.setattr(config, 'TRUSTED_PROXIES', 0)
    plain = client.get('/api/credentials/state', base_url='http://localhost')
    assert plain.status_code == 403 and plain.json['code'] == 'https_required'
    proxied = client.get('/api/credentials/state', base_url='http://localhost',
                         headers={'Referer': 'https://localhost/hosts', 'X-Forwarded-Proto': 'https'})
    assert proxied.status_code == 200
    forged = client.get('/api/credentials/state', base_url='http://localhost',
                        headers={'Referer': 'https://elsewhere.example/'})
    assert forged.status_code == 403


def test_automation_accepts_the_https_page_and_keeps_rejecting_plain_http(app, client, context, monkeypatch):
    import config
    monkeypatch.setattr(config, 'AUTOMATION_ENABLED', True)
    monkeypatch.setattr(config, 'TRUSTED_PROXIES', 0)
    from app import app_settings
    monkeypatch.setattr(app_settings, 'is_automation_enabled', lambda: True)
    rejected = client.get('/api/automation/state', base_url='http://localhost',
                          headers={'Referer': 'http://localhost/automation'})
    assert rejected.status_code == 403 and rejected.json['code'] == 'https_required'
    accepted = client.get('/api/automation/state', base_url='http://localhost',
                          headers={'Referer': 'https://localhost/automation'})
    assert accepted.status_code != 403 or accepted.json.get('code') != 'https_required'
