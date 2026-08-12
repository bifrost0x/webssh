"""Socket contracts for safe SSH key upload and metadata rename."""

from flask import request


def create_socket_user(app, username):
    from app.auth import register_socket_session, register_user
    from app.models import db

    with app.app_context():
        user, error = register_user(username, 'socket-password-123')
        assert error is None
        sid = f'{username}-socket'
        register_socket_session(user.id, sid)
        db.session.commit()
        return user.id, sid


def call_socket_handler(app, monkeypatch, handler, sid, payload):
    import app.socket_events as socket_events

    emitted = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, data=None, **_kwargs: emitted.append((event, data)),
    )
    with app.test_request_context('/socket.io'):
        request.sid = sid
        acknowledgement = handler(payload)
    return acknowledgement, emitted


def test_key_upload_and_rename_return_safe_acknowledgements(
        app, monkeypatch, rsa_private_key_pem):
    from app import key_manager
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(app, 'key_ack_owner')
    uploaded, emitted = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_upload_key,
        sid,
        {'name': 'Initial', 'key_content': rsa_private_key_pem},
    )

    assert uploaded['success'] is True
    assert uploaded['key']['name'] == 'Initial'
    assert 'key_content' not in repr(uploaded)
    assert rsa_private_key_pem not in repr(uploaded)
    assert rsa_private_key_pem not in repr(emitted)
    assert set(uploaded['key']) == {
        'id', 'name', 'filename', 'key_type', 'encrypted', 'uploaded_at'
    }
    assert any(event == 'keys_list' for event, _payload in emitted)

    renamed, emitted = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_rename_key,
        sid,
        {'key_id': uploaded['key']['id'], 'name': 'Renamed'},
    )

    assert renamed == {
        'success': True,
        'key': {**uploaded['key'], 'name': 'Renamed'},
    }
    assert any(event == 'key_renamed' for event, _payload in emitted)
    assert rsa_private_key_pem not in repr(renamed)
    assert rsa_private_key_pem not in repr(emitted)
    with app.app_context():
        assert key_manager.load_keys(user_id)[0]['name'] == 'Renamed'


def test_key_upload_rejection_never_returns_private_input(
        app, monkeypatch):
    import app.socket_events as socket_events

    _user_id, sid = create_socket_user(app, 'key_ack_rejected')
    rejected, emitted = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_upload_key,
        sid,
        {'name': '', 'key_content': 'private-input-sentinel'},
    )

    assert rejected == {
        'success': False,
        'error': 'Name and key content required',
    }
    assert 'private-input-sentinel' not in repr(rejected)
    assert 'private-input-sentinel' not in repr(emitted)


def test_key_rename_rejects_unknown_and_cross_user_ids(
        app, monkeypatch, rsa_private_key_pem):
    from app import key_manager
    import app.socket_events as socket_events

    _owner_id, owner_sid = create_socket_user(app, 'key_ack_owned')
    foreign_user_id, _foreign_sid = create_socket_user(
        app, 'key_ack_foreign'
    )
    with app.app_context():
        foreign_key, error = key_manager.save_key(
            foreign_user_id,
            'Foreign',
            rsa_private_key_pem,
        )
        assert error is None

    for key_id in ('not-owned', foreign_key['id']):
        acknowledgement, emitted = call_socket_handler(
            app,
            monkeypatch,
            socket_events.handle_rename_key,
            owner_sid,
            {'key_id': key_id, 'name': 'Cross-user'},
        )
        assert acknowledgement == {
            'success': False,
            'error': 'Key not found',
        }
        assert all(event != 'key_renamed' for event, _payload in emitted)

    with app.app_context():
        assert key_manager.load_keys(foreign_user_id)[0]['name'] == 'Foreign'


def test_key_rename_translates_storage_corruption_without_overwriting(
        app, monkeypatch, rsa_private_key_pem):
    from app import key_manager
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(app, 'key_ack_corrupt')
    with app.app_context():
        key, error = key_manager.save_key(
            user_id, 'Initial', rsa_private_key_pem
        )
        assert error is None
        metadata_path = key_manager.get_user_keys_file(user_id)
        metadata_path.write_text('{broken', encoding='utf-8')
        before = metadata_path.read_bytes()

    corrupt, emitted = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_rename_key,
        sid,
        {'key_id': key['id'], 'name': 'After corruption'},
    )

    assert corrupt['success'] is False
    assert corrupt['code'] == 'storage_error'
    assert any(event == 'error' for event, _payload in emitted)
    with app.app_context():
        assert metadata_path.read_bytes() == before


def test_key_rename_audit_sanitizes_names(monkeypatch):
    from app import audit_logger

    messages = []
    monkeypatch.setattr(audit_logger.audit_logger, 'info', messages.append)

    audit_logger.log_key_rename(
        'admin\nforged',
        'before\rsecret',
        'after\nsecret',
        '127.0.0.1\nforged',
    )

    assert len(messages) == 1
    assert messages[0].startswith('KEY_RENAME | ')
    assert '\n' not in messages[0]
    assert '\r' not in messages[0]


def test_key_replace_returns_safe_acknowledgement_event_and_audit(
        app, monkeypatch, rsa_private_key_pem,
        rsa_openssh_private_key_pem):
    from app import key_manager
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(app, 'key_replace_owner')
    with app.app_context():
        key, error = key_manager.save_key(
            user_id, 'Rotating key', rsa_private_key_pem
        )
        assert error is None

    audits = []
    monkeypatch.setattr(
        socket_events,
        'log_key_replace',
        lambda *args: audits.append(args),
    )
    acknowledgement, emitted = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_replace_key,
        sid,
        {
            'key_id': key['id'],
            'key_content': rsa_openssh_private_key_pem,
        },
    )

    assert acknowledgement == {
        'success': True,
        'key': {**key, 'usable': True},
    }
    assert ('key_replaced', acknowledgement) in emitted
    assert any(event == 'keys_list' for event, _payload in emitted)
    assert rsa_openssh_private_key_pem not in repr(acknowledgement)
    assert rsa_openssh_private_key_pem not in repr(emitted)
    assert rsa_openssh_private_key_pem not in repr(audits)
    assert audits == [(
        'key_replace_owner',
        'Rotating key',
        True,
        None,
    )]
    with app.app_context():
        content, error = key_manager.read_key_content(user_id, key['id'])
        assert error is None
        assert content == rsa_openssh_private_key_pem


def test_key_replace_rejects_missing_and_oversized_content_without_secret_echo(
        app, monkeypatch, rsa_private_key_pem):
    from app import key_manager
    import app.socket_events as socket_events

    user_id, sid = create_socket_user(app, 'key_replace_rejected')
    with app.app_context():
        key, error = key_manager.save_key(
            user_id, 'Original', rsa_private_key_pem
        )
        assert error is None

    cases = (
        ({'key_id': key['id']}, 'Key ID and key content required'),
        (
            {'key_id': key['id'], 'key_content': 's' * (64 * 1024 + 1)},
            'Key content too large (max 64KB)',
        ),
    )
    for payload, expected_error in cases:
        acknowledgement, emitted = call_socket_handler(
            app,
            monkeypatch,
            socket_events.handle_replace_key,
            sid,
            payload,
        )
        assert acknowledgement == {
            'success': False,
            'error': expected_error,
        }
        if payload.get('key_content'):
            assert payload['key_content'] not in repr(acknowledgement)
        assert all(event != 'key_replaced' for event, _payload in emitted)


def test_key_replace_manager_error_is_audited_without_private_input(
        app, monkeypatch):
    import app.socket_events as socket_events

    _user_id, sid = create_socket_user(app, 'key_replace_failed')
    private_input = 'private-replacement-sentinel'
    monkeypatch.setattr(
        socket_events.key_manager,
        'replace_key',
        lambda *_args: (None, 'Replacement rejected'),
    )
    audits = []
    monkeypatch.setattr(
        socket_events,
        'log_key_replace',
        lambda *args: audits.append(args),
    )

    acknowledgement, emitted = call_socket_handler(
        app,
        monkeypatch,
        socket_events.handle_replace_key,
        sid,
        {'key_id': 'owned-key', 'key_content': private_input},
    )

    assert acknowledgement == {
        'success': False,
        'error': 'Replacement rejected',
    }
    assert private_input not in repr(acknowledgement)
    assert private_input not in repr(emitted)
    assert private_input not in repr(audits)
    assert audits == [(
        'key_replace_failed',
        'owned-key',
        False,
        None,
    )]


def test_key_replace_audit_sanitizes_values(monkeypatch):
    from app import audit_logger

    messages = []
    monkeypatch.setattr(audit_logger.audit_logger, 'info', messages.append)

    audit_logger.log_key_replace(
        'admin\nforged',
        'key\rsecret',
        False,
        '127.0.0.1\nforged',
    )

    assert len(messages) == 1
    assert messages[0].startswith('KEY_REPLACE_FAILED | ')
    assert '\n' not in messages[0]
    assert '\r' not in messages[0]
