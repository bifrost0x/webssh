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
    calls = []
    monkeypatch.setattr(
        socket_events.file_service,
        'list_directory_page',
        lambda source_id, **kwargs: (
            calls.append((source_id, kwargs))
            or ([{'name': 'config.yml'}], None, None)
        ),
    )

    socket_events.handle_list_directory.__wrapped__({
        'source_id': 'sftp-session:session-a',
        'remote_path': '/srv/current',
        'request_id': 'left:directory:4',
    }, current_user=user)

    assert calls == [('sftp-session:session-a', {
        'user_id': 7,
        'path': '/srv/current',
        'cursor': 0,
        'client_id': None,
        'request_id': 'left:directory:4',
    })]
    assert emitted == [('directory_listing', {
        'source_id': 'sftp-session:session-a',
        'path': '/srv/current',
        'files': [{'name': 'config.yml'}],
        'cursor': 0,
        'next_cursor': None,
        'request_id': 'left:directory:4',
    })]


def test_list_directory_error_is_correlated(monkeypatch):
    emitted, user = _capture(monkeypatch)
    monkeypatch.setattr(
        socket_events.file_service,
        'list_directory_page',
        lambda _source_id, *, user_id, path, cursor, client_id, request_id: (
            None, 'permission denied', None
        ),
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


def test_list_directory_continuation_error_echoes_opaque_cursor(monkeypatch):
    emitted, user = _capture(monkeypatch)
    token = f"v1.abcdefghijklmnop.2.{'b' * 32}"
    monkeypatch.setattr(
        socket_events.file_service,
        'list_directory_page',
        lambda _source_id, *, user_id, path, cursor, client_id, request_id: (
            None, 'listing expired', None
        ),
    )

    socket_events.handle_list_directory.__wrapped__({
        'source_id': 'sftp-session:session-a',
        'remote_path': '/srv',
        'request_id': 'move-picker:directory:6',
        'cursor': token,
    }, current_user=user)

    assert emitted == [('error', {
        'error': 'Failed to list directory: listing expired',
        'operation': 'list_directory',
        'source_id': 'sftp-session:session-a',
        'path': '/srv',
        'request_id': 'move-picker:directory:6',
        'cursor': token,
    })]


def test_cancel_directory_listing_is_exactly_socket_scoped_and_silent(
    monkeypatch,
):
    emitted, user = _capture(monkeypatch)
    calls = []
    token = f"v1.abcdefghijklmnop.2.{'b' * 32}"
    monkeypatch.setattr(
        socket_events,
        'request',
        SimpleNamespace(sid='socket-a'),
    )
    monkeypatch.setattr(
        socket_events.file_service,
        'cancel_directory_snapshot',
        lambda cursor, **kwargs: calls.append((cursor, kwargs)) or True,
    )

    result = socket_events.handle_cancel_directory_listing.__wrapped__({
        'source_id': 'sftp-session:session-a',
        'request_id': 'directory:cancel:7',
        'cursor': token,
    }, current_user=user)

    assert result == {'success': True}
    assert emitted == []
    assert calls == [(token, {
        'user_id': 7,
        'source_id': 'sftp-session:session-a',
        'client_id': 'socket-a',
    })]


def test_cancel_page_zero_listing_is_exactly_request_and_socket_scoped(
    monkeypatch,
):
    emitted, user = _capture(monkeypatch)
    calls = []
    monkeypatch.setattr(
        socket_events,
        'request',
        SimpleNamespace(sid='socket-a'),
    )
    monkeypatch.setattr(
        socket_events.file_service,
        'cancel_directory_request',
        lambda request_id, **kwargs: (
            calls.append((request_id, kwargs)) or True
        ),
    )

    result = socket_events.handle_cancel_directory_listing.__wrapped__({
        'source_id': 'sftp-session:session-a',
        'request_id': 'directory:cancel:8',
        'listing_request_id': 'left:directory:7',
    }, current_user=user)

    assert result == {'success': True}
    assert emitted == []
    assert calls == [('left:directory:7', {
        'user_id': 7,
        'source_id': 'sftp-session:session-a',
        'client_id': 'socket-a',
    })]


@pytest.mark.parametrize('listing_request_id', (
    '',
    'invalid request id',
    'x' * 129,
))
def test_cancel_page_zero_listing_rejects_invalid_request_authority(
    monkeypatch,
    listing_request_id,
):
    _emitted, user = _capture(monkeypatch)
    calls = []
    monkeypatch.setattr(
        socket_events.file_service,
        'cancel_directory_request',
        lambda *args, **kwargs: calls.append((args, kwargs)) or True,
    )

    result = socket_events.handle_cancel_directory_listing.__wrapped__({
        'source_id': 'sftp-session:session-a',
        'request_id': 'directory:cancel:9',
        'listing_request_id': listing_request_id,
    }, current_user=user)

    assert result == {'success': True}
    assert calls == []


def test_cancel_directory_listing_does_not_reveal_invalid_or_missing_state(
    monkeypatch,
):
    _emitted, user = _capture(monkeypatch)
    calls = []
    monkeypatch.setattr(
        socket_events.file_service,
        'cancel_directory_snapshot',
        lambda *args, **kwargs: calls.append((args, kwargs)) or False,
    )

    invalid = socket_events.handle_cancel_directory_listing.__wrapped__({
        'source_id': 'sftp-session:session-a',
        'request_id': 'directory:cancel:8',
        'cursor': 0,
    }, current_user=user)
    token = f"v1.abcdefghijklmnop.2.{'c' * 32}"
    missing = socket_events.handle_cancel_directory_listing.__wrapped__({
        'source_id': 'sftp-session:session-a',
        'request_id': 'directory:cancel:9',
        'cursor': token,
    }, current_user=user)

    assert invalid == {'success': True}
    assert missing == {'success': True}
    assert len(calls) == 1


def test_socket_disconnect_discards_only_its_directory_snapshots(monkeypatch):
    discarded = []

    class Query:
        def filter_by(self, **_kwargs):
            return self

        def delete(self):
            return 1

        def count(self):
            return 1

    monkeypatch.setattr(
        socket_events,
        'request',
        SimpleNamespace(sid='socket-a'),
    )
    monkeypatch.setattr(
        socket_events.ssh_output_flow,
        'release_socket',
        lambda _socket_id: None,
    )
    monkeypatch.setattr(
        socket_events,
        '_cancel_ssh_banner_prompts_for_socket',
        lambda _socket_id: None,
    )
    monkeypatch.setattr(
        socket_events.socket_capacity,
        'release',
        lambda _socket_id: 7,
    )
    monkeypatch.setattr(
        socket_events.socket_capacity,
        'count_for_user',
        lambda _user_id: 1,
    )
    monkeypatch.setattr(
        socket_events,
        'get_user_from_socket',
        lambda _socket_id: None,
    )
    monkeypatch.setattr(
        socket_events,
        '_cancel_smb_attempts_for_socket',
        lambda _user_id, _socket_id: None,
    )
    monkeypatch.setattr(
        socket_events.transfer_manager,
        'cancel_all_for_socket',
        lambda _user_id, _socket_id: None,
    )
    monkeypatch.setattr(
        socket_events.file_service,
        'discard_directory_snapshots',
        lambda **kwargs: discarded.append(kwargs),
    )
    monkeypatch.setattr(
        socket_events,
        'SocketSession',
        SimpleNamespace(query=Query()),
    )
    monkeypatch.setattr(
        socket_events,
        'db',
        SimpleNamespace(session=SimpleNamespace(
            commit=lambda: None,
            rollback=lambda: None,
        )),
    )

    socket_events.handle_disconnect()

    assert discarded == [{'user_id': 7, 'client_id': 'socket-a'}]


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


def test_sftp_capability_probe_preserves_remote_resource_shortage(monkeypatch):
    emitted, user = _capture(monkeypatch)
    monkeypatch.setattr(socket_events, 'check_socket_rate_limit', lambda *_args: False)
    monkeypatch.setattr(
        socket_events.sftp_handler,
        'probe_sftp_capability',
        lambda _session_id: (
            socket_events.sftp_handler.CAPABILITY_RESOURCE_SHORTAGE
        ),
    )

    socket_events.handle_probe_session_sftp.__wrapped__({
        'session_id': 'session-a',
        'request_id': 'sftp-probe:capacity',
    }, current_user=user)

    assert emitted == [('session_sftp_capability', {
        'success': False,
        'session_id': 'session-a',
        'request_id': 'sftp-probe:capacity',
        'available': False,
        'reason': 'resource_shortage',
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
