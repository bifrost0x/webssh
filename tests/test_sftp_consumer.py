from app import socket_events


def test_session_panel_consumer_is_correlated_on_sftp_response():
    payload = socket_events._with_sftp_consumer(
        {'consumer': 'session-panel'},
        {'session_id': 'owned', 'path': '/srv/app'},
    )

    assert payload == {
        'session_id': 'owned',
        'path': '/srv/app',
        'consumer': 'session-panel',
    }


def test_legacy_sftp_response_remains_unchanged():
    original = {'session_id': 'owned', 'path': '/srv/app'}

    assert socket_events._with_sftp_consumer({}, original) is original


def test_arbitrary_consumer_value_is_not_reflected():
    payload = socket_events._with_sftp_consumer(
        {'consumer': '<script>'},
        {'path': '/'},
    )

    assert payload == {'path': '/'}


def test_session_panel_errors_keep_the_validated_consumer(monkeypatch):
    emitted = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, payload: emitted.append((event, payload)),
    )

    socket_events._emit_sftp_error(
        {'consumer': 'session-panel', 'session_id': 'owned'},
        'Failed to list directory',
    )

    assert emitted == [('error', {
        'error': 'Failed to list directory',
        'consumer': 'session-panel',
        'session_id': 'owned',
    })]
