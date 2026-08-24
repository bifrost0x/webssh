from types import SimpleNamespace

import pytest

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
        socket_events.file_service,
        'list_directory',
        lambda source_id, *, user_id, path: ([{'name': 'config.yml'}], None),
    )

    socket_events.handle_list_directory.__wrapped__({
        'source_id': 'sftp-session:session-a',
        'remote_path': '/srv/current',
        'request_id': 'left:directory:4',
    }, current_user=user)

    assert emitted == [('directory_listing', {
        'source_id': 'sftp-session:session-a',
        'path': '/srv/current',
        'files': [{'name': 'config.yml'}],
        'request_id': 'left:directory:4',
    })]


def test_list_directory_error_is_correlated(monkeypatch):
    emitted, user = _capture(monkeypatch)
    monkeypatch.setattr(
        socket_events.file_service,
        'list_directory',
        lambda _source_id, *, user_id, path: (None, 'permission denied'),
    )

    socket_events.handle_list_directory.__wrapped__({
        'source_id': 'sftp-session:session-a',
        'remote_path': '/root',
        'request_id': 'left:directory:5',
    }, current_user=user)

    assert emitted == [('error', {
        'error': 'Failed to list directory: permission denied',
        'operation': 'list_directory',
        'source_id': 'sftp-session:session-a',
        'path': '/root',
        'request_id': 'left:directory:5',
    })]


def test_home_directory_mirrors_request_identity(monkeypatch):
    emitted, user = _capture(monkeypatch)
    monkeypatch.setattr(
        socket_events.file_service,
        'get_home_directory',
        lambda _source_id, *, user_id: ('/home/operator', None),
    )

    socket_events.handle_get_home_directory.__wrapped__({
        'source_id': 'sftp-session:session-a',
        'request_id': 'left:home:3',
    }, current_user=user)

    assert emitted == [('home_directory', {
        'source_id': 'sftp-session:session-a',
        'path': '/home/operator',
        'request_id': 'left:home:3',
    })]


def test_sftp_request_handlers_reject_malformed_payloads(monkeypatch):
    emitted, user = _capture(monkeypatch)

    socket_events.handle_list_directory.__wrapped__(None, current_user=user)
    socket_events.handle_get_home_directory.__wrapped__([], current_user=user)

    assert emitted == [
        ('error', {
            'error': 'Source ID and request ID required',
            'operation': 'list_directory',
            'source_id': None,
            'path': '.',
            'request_id': None,
        }),
        ('error', {
            'error': 'Source ID and request ID required',
            'operation': 'get_home_directory',
            'source_id': None,
            'request_id': None,
        }),
    ]


def test_file_events_reject_the_removed_session_id_contract(monkeypatch):
    emitted, user = _capture(monkeypatch)
    monkeypatch.setattr(
        socket_events.file_service,
        'list_directory',
        lambda *_args, **_kwargs: pytest.fail('legacy identity reached backend'),
    )

    socket_events.handle_list_directory.__wrapped__({
        'session_id': 'session-a',
        'remote_path': '/srv/current',
        'request_id': 'left:directory:legacy',
    }, current_user=user)

    assert emitted == [('error', {
        'error': 'Source ID and request ID required',
        'operation': 'list_directory',
        'source_id': None,
        'request_id': 'left:directory:legacy',
        'path': '/srv/current',
    })]


def test_server_copy_rejects_the_removed_dual_session_contract(monkeypatch):
    emitted, user = _capture(monkeypatch)

    result = socket_events.handle_transfer_server_to_server.__wrapped__({
        'source_session_id': 'source',
        'source_path': '/from.bin',
        'dest_session_id': 'destination',
        'dest_path': '/to.bin',
        'request_id': 's2s:legacy',
    }, current_user=user)

    assert result['success'] is False
    assert result['source_id'] is None
    assert result['destination_source_id'] is None
    assert emitted[0][0] == 's2s_transfer_error'


def test_sftp_capability_probe_returns_only_correlated_availability(monkeypatch):
    emitted, user = _capture(monkeypatch)
    monkeypatch.setattr(socket_events, 'check_socket_rate_limit', lambda *_args: False)
    monkeypatch.setattr(
        socket_events.sftp_handler,
        'probe_sftp_capability',
        lambda _session_id: False,
    )

    socket_events.handle_probe_session_sftp.__wrapped__({
        'session_id': 'session-a',
        'request_id': 'sftp-probe:4',
    }, current_user=user)

    assert emitted == [('session_sftp_capability', {
        'success': True,
        'session_id': 'session-a',
        'request_id': 'sftp-probe:4',
        'available': False,
    })]


def test_sftp_capability_probe_reports_busy_as_retryable_generic_failure(monkeypatch):
    emitted, user = _capture(monkeypatch)
    monkeypatch.setattr(socket_events, 'check_socket_rate_limit', lambda *_args: False)
    monkeypatch.setattr(
        socket_events.sftp_handler,
        'probe_sftp_capability',
        lambda _session_id: None,
    )

    socket_events.handle_probe_session_sftp.__wrapped__({
        'session_id': 'session-a',
        'request_id': 'sftp-probe:busy',
    }, current_user=user)

    assert emitted == [('session_sftp_capability', {
        'success': False,
        'session_id': 'session-a',
        'request_id': 'sftp-probe:busy',
        'available': False,
    })]


def test_sftp_capability_probe_rejects_unowned_session_generically(monkeypatch):
    emitted, user = _capture(monkeypatch)
    monkeypatch.setattr(socket_events, 'check_socket_rate_limit', lambda *_args: False)
    monkeypatch.setattr(
        socket_events,
        'verify_session_ownership',
        lambda _session_id, _user_id: False,
    )
    monkeypatch.setattr(
        socket_events.sftp_handler,
        'probe_sftp_capability',
        lambda _session_id: pytest.fail('unowned session reached SFTP'),
    )

    socket_events.handle_probe_session_sftp.__wrapped__({
        'session_id': 'session-a',
        'request_id': 'sftp-probe:5',
    }, current_user=user)

    assert emitted == [('session_sftp_capability', {
        'success': False,
        'session_id': 'session-a',
        'request_id': 'sftp-probe:5',
        'available': False,
    })]
