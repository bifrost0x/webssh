from types import SimpleNamespace

from app import socket_events


def _capture(monkeypatch):
    emitted = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, data: emitted.append((event, data)),
    )
    monkeypatch.setattr(
        socket_events,
        'verify_session_ownership',
        lambda _session_id, _user_id: True,
    )
    return emitted, SimpleNamespace(id=7, username='operator')


def test_list_directory_mirrors_request_identity(monkeypatch):
    emitted, user = _capture(monkeypatch)
    monkeypatch.setattr(
        socket_events.sftp_handler,
        'list_directory',
        lambda session_id, path: ([{'name': 'config.yml'}], None),
    )

    socket_events.handle_list_directory.__wrapped__({
        'session_id': 'session-a',
        'remote_path': '/srv/current',
        'request_id': 'left:directory:4',
    }, current_user=user)

    assert emitted == [('directory_listing', {
        'session_id': 'session-a',
        'path': '/srv/current',
        'files': [{'name': 'config.yml'}],
        'request_id': 'left:directory:4',
    })]


def test_list_directory_error_is_correlated(monkeypatch):
    emitted, user = _capture(monkeypatch)
    monkeypatch.setattr(
        socket_events.sftp_handler,
        'list_directory',
        lambda _session_id, _path: (None, 'permission denied'),
    )

    socket_events.handle_list_directory.__wrapped__({
        'session_id': 'session-a',
        'remote_path': '/root',
        'request_id': 'left:directory:5',
    }, current_user=user)

    assert emitted == [('error', {
        'error': 'Failed to list directory: permission denied',
        'operation': 'list_directory',
        'session_id': 'session-a',
        'path': '/root',
        'request_id': 'left:directory:5',
    })]


def test_home_directory_mirrors_request_identity(monkeypatch):
    emitted, user = _capture(monkeypatch)
    monkeypatch.setattr(
        socket_events.sftp_handler,
        'get_home_directory',
        lambda _session_id: ('/home/operator', None),
    )

    socket_events.handle_get_home_directory.__wrapped__({
        'session_id': 'session-a',
        'request_id': 'left:home:3',
    }, current_user=user)

    assert emitted == [('home_directory', {
        'session_id': 'session-a',
        'path': '/home/operator',
        'request_id': 'left:home:3',
    })]


def test_sftp_request_handlers_reject_malformed_payloads(monkeypatch):
    emitted, user = _capture(monkeypatch)

    socket_events.handle_list_directory.__wrapped__(None, current_user=user)
    socket_events.handle_get_home_directory.__wrapped__([], current_user=user)

    assert emitted == [
        ('error', {
            'error': 'Session ID required',
            'operation': 'list_directory',
            'session_id': None,
            'path': '.',
            'request_id': None,
        }),
        ('error', {
            'error': 'Session ID required',
            'operation': 'get_home_directory',
            'session_id': None,
            'request_id': None,
        }),
    ]
