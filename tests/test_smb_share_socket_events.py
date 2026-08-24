"""Authenticated socket contracts for saved SMB share definitions."""

from types import SimpleNamespace

from app import socket_events


def _create_user(app):
    from app.models import User, db

    with app.app_context():
        user = User(username='smb-share-socket-user', password_hash='unused')
        db.session.add(user)
        db.session.commit()
        return SimpleNamespace(id=user.id, username=user.username)


def test_saved_smb_share_socket_lifecycle_never_returns_password(app, monkeypatch):
    emitted = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, data: emitted.append((event, data)),
    )
    user = _create_user(app)
    monkeypatch.setattr(socket_events.config, 'SMB_ENABLED', True)
    monkeypatch.setattr(
        socket_events,
        'check_socket_rate_limit',
        lambda *_args: False,
    )
    clean = {
        'name': 'Team files',
        'host': 'nas.example',
        'share': 'Docs',
        'domain': 'LAB',
        'username': 'alice',
    }

    with app.app_context():
        rejected = socket_events.handle_save_smb_share.__wrapped__(
            {
                **clean,
                'request_id': 'share-save-rejected',
                'password': 'never-store-me',
            },
            current_user=user,
        )
        saved = socket_events.handle_save_smb_share.__wrapped__(
            {**clean, 'request_id': 'share-save-1'},
            current_user=user,
        )
        socket_events.handle_list_smb_shares.__wrapped__(current_user=user)
        deleted = socket_events.handle_delete_smb_share.__wrapped__(
            {
                'request_id': 'share-delete-1',
                'share_id': saved['share']['id'],
            },
            current_user=user,
        )

    assert rejected == {
        'success': False,
        'error': 'Passwords cannot be saved',
        'request_id': 'share-save-rejected',
    }
    assert saved['success'] is True
    assert saved['request_id'] == 'share-save-1'
    assert 'password' not in saved['share']
    assert deleted == {
        'success': True,
        'request_id': 'share-delete-1',
        'share_id': saved['share']['id'],
    }
    assert [event for event, _payload in emitted] == [
        'smb_share_error',
        'smb_share_saved',
        'smb_shares_list',
        'smb_shares_list',
        'smb_share_deleted',
        'smb_shares_list',
    ]
    assert 'never-store-me' not in repr(emitted)
    assert all('password' not in repr(payload).lower() for _, payload in emitted[1:])


def test_saved_smb_share_socket_rejects_missing_delete_id(app, monkeypatch):
    emitted = []
    monkeypatch.setattr(
        socket_events,
        'emit',
        lambda event, data: emitted.append((event, data)),
    )
    user = _create_user(app)
    monkeypatch.setattr(socket_events.config, 'SMB_ENABLED', True)
    monkeypatch.setattr(
        socket_events,
        'check_socket_rate_limit',
        lambda *_args: False,
    )

    result = socket_events.handle_delete_smb_share.__wrapped__(
        {'request_id': 'share-delete-invalid'},
        current_user=user,
    )

    assert result == {
        'success': False,
        'error': 'SMB share ID required',
        'request_id': 'share-delete-invalid',
    }
    assert emitted == [('smb_share_error', {
        'action': 'delete',
        'error': 'SMB share ID required',
        'request_id': 'share-delete-invalid',
    })]


def test_saved_smb_share_events_fail_closed_when_feature_is_disabled(
        app, monkeypatch):
    emitted = []
    monkeypatch.setattr(socket_events, 'emit', lambda event, data: emitted.append(
        (event, data)
    ))
    monkeypatch.setattr(socket_events.config, 'SMB_ENABLED', False)
    user = _create_user(app)

    with app.app_context():
        result = socket_events.handle_save_smb_share.__wrapped__({
            'request_id': 'share-save-disabled',
            'name': 'Team files',
            'host': 'nas.example',
            'share': 'Docs',
            'domain': '',
            'username': 'alice',
        }, current_user=user)

    assert result == {
        'success': False,
        'error': 'SMB is disabled',
        'request_id': 'share-save-disabled',
    }
    assert emitted == [('smb_share_error', {
        'action': 'save',
        'error': 'SMB is disabled',
        'request_id': 'share-save-disabled',
        'code': 'SMB_DISABLED',
    })]


def test_saved_smb_share_mutations_are_rate_limited(app, monkeypatch):
    emitted = []
    checked = []
    monkeypatch.setattr(socket_events, 'emit', lambda event, data: emitted.append(
        (event, data)
    ))
    monkeypatch.setattr(socket_events.config, 'SMB_ENABLED', True)
    monkeypatch.setattr(
        socket_events,
        'check_socket_rate_limit',
        lambda *args: checked.append(args) or True,
    )
    user = _create_user(app)

    result = socket_events.handle_delete_smb_share.__wrapped__({
        'request_id': 'share-delete-limited',
        'share_id': 'share-1',
    }, current_user=user)

    assert result == {
        'success': False,
        'error': 'Too many saved SMB share changes',
        'request_id': 'share-delete-limited',
    }
    assert checked == [(
        user.id,
        'smb_share_mutation',
        socket_events.config.SMB_SHARE_MUTATION_RATELIMIT,
    )]
    assert emitted[0][1]['code'] == 'RATE_LIMITED'
