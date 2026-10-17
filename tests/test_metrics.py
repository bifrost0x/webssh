"""Contract for the opt-in Prometheus metrics endpoint."""

import re

import pytest

import config
from app import ssh_manager
from app.terminal_share import share_hub


TOKEN = 'metrics-token-for-tests-1234'


@pytest.fixture
def metrics_on(monkeypatch):
    monkeypatch.setattr(config, 'METRICS_ENABLED', True)
    monkeypatch.setattr(config, 'METRICS_TOKEN', TOKEN)


def _sample(text, name, **labels):
    label_text = ''
    if labels:
        label_text = r'\{' + ','.join(
            f'{key}="{value}"' for key, value in sorted(labels.items())
        ) + r'\}'
    match = re.search(rf'^{name}{label_text} (\S+)$', text, re.MULTILINE)
    assert match, f'{name} {labels} missing'
    return float(match.group(1))


def test_metrics_are_disabled_by_default(client):
    assert client.get('/metrics').status_code == 404


def test_metrics_require_the_bearer_token(client, metrics_on):
    refused = client.get('/metrics')
    assert refused.status_code == 401
    assert refused.headers['WWW-Authenticate'].startswith('Bearer')
    wrong = client.get('/metrics', headers={'Authorization': 'Bearer nope'})
    assert wrong.status_code == 401

    response = client.get('/metrics', headers={'Authorization': f'Bearer {TOKEN}'})
    assert response.status_code == 200
    assert response.content_type.startswith('text/plain; version=0.0.4')
    assert response.headers['Cache-Control'] == 'no-store'


def test_without_a_token_only_loopback_may_scrape(client, monkeypatch):
    monkeypatch.setattr(config, 'METRICS_ENABLED', True)
    monkeypatch.setattr(config, 'METRICS_TOKEN', '')
    assert client.get('/metrics').status_code == 200
    remote = client.get('/metrics', environ_base={'REMOTE_ADDR': '203.0.113.9'})
    assert remote.status_code == 404


def test_exposition_reports_capacity_without_identifiers(client, metrics_on):
    session_id = 'metrics-session-secret-id'
    with ssh_manager.sessions_lock:
        ssh_manager.sessions[session_id] = {
            'client': None,
            'channel': None,
            'user_id': 42,
            'host': 'secret-host.example',
            'username': 'secret-user',
            'connected': True,
            'output_buffer': [],
            'output_buffer_size': 0,
            'output_buffer_max': 512000,
            'output_sequence': 0,
            'cols': 80,
            'rows': 24,
        }
    try:
        share = share_hub.create(42, session_id, title='Secret title')
        share_hub.join(share['token'], 'Secret guest')
        text = client.get(
            '/metrics', headers={'Authorization': f'Bearer {TOKEN}'},
        ).get_data(as_text=True)
    finally:
        share_hub.end_all()
        with ssh_manager.sessions_lock:
            ssh_manager.sessions.pop(session_id, None)

    assert _sample(text, 'webssh_ssh_sessions') >= 1
    assert _sample(text, 'webssh_terminal_share_links') == 1
    assert _sample(text, 'webssh_terminal_share_viewers', state='joined') == 1
    assert _sample(text, 'webssh_terminal_share_chat_messages_total') >= 0
    assert _sample(text, 'webssh_socket_connections_limit') == config.MAX_SOCKET_CONNECTIONS
    assert _sample(text, 'webssh_maintenance_mode') == 0
    assert _sample(text, 'webssh_threads') >= 1
    for secret in (
        session_id, 'secret-host', 'secret-user', 'Secret title',
        'Secret guest', share['token'],
    ):
        assert secret not in text
    for line in text.splitlines():
        assert line.startswith('#') or re.match(r'^[a-z_]+(\{[^}]*\})? -?[\d.e+]+$', line), line
