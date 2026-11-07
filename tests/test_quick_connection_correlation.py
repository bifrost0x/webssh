import pytest


@pytest.mark.usefixtures('direct_socket_authentication')
@pytest.mark.parametrize('outcome', ['success', 'validation', 'connection', 'rate'])
def test_ordinary_quick_connection_echoes_request_id(app, monkeypatch, outcome):
    from app import socket_events
    from tests.test_command_set_socket_events import create_socket_user, call_socket_handler

    _, sid = create_socket_user(app, 'quick_correlation_' + outcome)
    monkeypatch.setattr(socket_events, 'check_socket_rate_limit', lambda *args: outcome == 'rate')
    monkeypatch.setattr(socket_events.connection_pool.temp_connection_pool, 'create_connection',
                        lambda **kwargs: (None, 'Connection failed') if outcome == 'connection'
                        else ('quick-fixture', None))
    monkeypatch.setattr(socket_events, '_public_file_source', lambda *args: {'id': 'quick-fixture'})
    _, events = call_socket_handler(app, monkeypatch, socket_events.handle_quick_connect, sid, {
        'host': '' if outcome == 'validation' else 'host.example.test',
        'username': 'deploy', 'password': 'fixture', 'client_request_id': 'quick-request-1',
    })
    expected = 'quick_connect_success' if outcome == 'success' else 'quick_connect_error'
    replies = [data for name, data in events if name == expected]
    assert len(replies) == 1
    assert replies[0]['client_request_id'] == 'quick-request-1'
