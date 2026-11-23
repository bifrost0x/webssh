"""Offline recovery of a local password through the container CLI."""

import pytest


def _user(app, username):
    from app.models import User, db

    with app.app_context():
        db.session.expire_all()
        return User.query.filter_by(username=username).first()


@pytest.fixture
def signed_in_admin(app):
    """The only administrator, with a live browser sign-in."""
    from app.auth import register_user

    with app.app_context():
        user, error = register_user('soleadmin', 'forgotten-password')
        assert error is None
        assert user.is_admin is True
    browser = app.test_client()
    assert browser.post('/login', data={
        'username': 'soleadmin', 'password': 'forgotten-password',
    }).status_code == 302
    assert browser.get('/').status_code == 200
    return browser


def test_reset_password_from_prompt_replaces_the_password_and_ends_sign_ins(app, signed_in_admin):
    from app.auth import authenticate_user
    from app.models import AuthenticationSession

    result = app.test_cli_runner().invoke(
        args=['reset-password', '--username', 'soleadmin'],
        input='replacement-password\nreplacement-password\n',
    )

    assert result.exit_code == 0, result.output
    assert 'replacement-password' not in result.output
    with app.app_context():
        assert authenticate_user('soleadmin', 'replacement-password')[0] is not None
        assert authenticate_user('soleadmin', 'forgotten-password')[0] is None
        user = _user(app, 'soleadmin')
        assert user.is_admin is True
        assert AuthenticationSession.query.filter_by(user_id=user.id).count() == 0
    assert signed_in_admin.get('/').status_code == 302


def test_reset_password_reads_a_password_file(app, signed_in_admin, tmp_path):
    password_file = tmp_path / 'new-password'
    password_file.write_text('file-replacement-password\n', encoding='utf-8')

    result = app.test_cli_runner().invoke(
        args=['reset-password', '--username', 'soleadmin', '--password-file', str(password_file)],
    )

    assert result.exit_code == 0, result.output
    assert _user(app, 'soleadmin').check_password('file-replacement-password')


@pytest.mark.parametrize(('password', 'error'), [
    ('short', 'at least 8 characters'),
    ('a' * 73, '72 bytes'),
])
def test_reset_password_rejects_invalid_passwords(app, signed_in_admin, password, error):
    result = app.test_cli_runner().invoke(
        args=['reset-password', '--username', 'soleadmin'],
        input=f'{password}\n{password}\n',
    )

    assert result.exit_code != 0
    assert error in result.output
    assert _user(app, 'soleadmin').check_password('forgotten-password')


def test_reset_password_rejects_unknown_and_directory_managed_accounts(app, signed_in_admin):
    from app.auth import register_user
    from app.models import LDAPIdentity, db

    with app.app_context():
        user, error = register_user('directoryuser', 'directory-password')
        assert error is None
        db.session.add(LDAPIdentity(
            user_id=user.id, provider='default', subject='directory-subject',
            directory_username='directoryuser',
            distinguished_name='uid=directoryuser,dc=example,dc=com',
        ))
        db.session.commit()
    runner = app.test_cli_runner()

    missing = runner.invoke(args=['reset-password', '--username', 'nobody'],
                            input='replacement-password\nreplacement-password\n')
    managed = runner.invoke(args=['reset-password', '--username', 'directoryuser'],
                            input='replacement-password\nreplacement-password\n')

    assert missing.exit_code != 0 and 'Account not found' in missing.output
    assert managed.exit_code != 0 and 'directory' in managed.output
    assert _user(app, 'directoryuser').check_password('directory-password')


def test_reset_password_is_a_maintenance_command():
    import app as app_module

    assert 'reset-password' in app_module._MAINTENANCE_COMMANDS


def _pending():
    from app.access_revocation_queue import pending_user_ids

    return pending_user_ids()


def test_reset_password_schedules_revocation_of_live_access(app, signed_in_admin):
    user_id = _user(app, 'soleadmin').id

    result = app.test_cli_runner().invoke(
        args=['reset-password', '--username', 'soleadmin'],
        input='replacement-password\nreplacement-password\n',
    )

    assert result.exit_code == 0, result.output
    assert 'have ended' not in result.output
    assert 'end within 5 seconds' in result.output
    assert _pending() == [user_id]


def test_reset_password_fails_loudly_when_revocation_cannot_be_scheduled(
    app, signed_in_admin, monkeypatch,
):
    from app import access_revocation_queue

    def unwritable(user_id):
        raise OSError('read-only data directory')

    monkeypatch.setattr(access_revocation_queue, 'request_revocation', unwritable)

    result = app.test_cli_runner().invoke(
        args=['reset-password', '--username', 'soleadmin'],
        input='replacement-password\nreplacement-password\n',
    )

    assert result.exit_code != 0
    assert 'Restart WebSSH' in result.output
    # The password change itself is committed; only the live cleanup is missing.
    assert _user(app, 'soleadmin').check_password('replacement-password')


def test_server_revokes_requested_access_and_removes_the_request(app, signed_in_admin, monkeypatch):
    from app import access_revocation_queue, user_lifecycle

    user_id = _user(app, 'soleadmin').id
    calls = []

    def fake_revoke(revoked_id, socketio_instance=None, **kwargs):
        calls.append((revoked_id, socketio_instance, kwargs))
        return {'sockets': 1, 'ssh_sessions': 1, 'errors': []}

    monkeypatch.setattr(user_lifecycle, 'revoke_user_access', fake_revoke)
    access_revocation_queue.request_revocation(user_id)
    marker = object()

    assert access_revocation_queue.process_pending(app, marker) == 1

    # Default arguments: tmux ends as it does for a password change in the UI.
    assert calls == [(user_id, marker, {})]
    assert _pending() == []


def test_failed_revocation_keeps_the_request_for_the_next_run(app, signed_in_admin, monkeypatch):
    from app import access_revocation_queue, user_lifecycle

    user_id = _user(app, 'soleadmin').id

    def failing_revoke(revoked_id, socketio_instance=None, **kwargs):
        raise RuntimeError('socket server unavailable')

    monkeypatch.setattr(user_lifecycle, 'revoke_user_access', failing_revoke)
    access_revocation_queue.request_revocation(user_id)

    assert access_revocation_queue.process_pending(app) == 0
    assert _pending() == [user_id]


def test_malformed_and_unknown_revocation_requests_are_discarded(app, monkeypatch):
    import config
    from app import access_revocation_queue, user_lifecycle

    calls = []
    monkeypatch.setattr(
        user_lifecycle, 'revoke_user_access',
        lambda *args, **kwargs: calls.append(args) or {},
    )
    directory = config.DATA_DIR / access_revocation_queue.DIRECTORY_NAME
    directory.mkdir(parents=True, exist_ok=True)
    for name in ('0', '-1', 'abc', '12a', '01'):
        (directory / name).write_bytes(b'pending\n')
    access_revocation_queue.request_revocation(987654)

    assert _pending() == [987654]
    assert sorted(path.name for path in directory.iterdir()) == ['987654']
    assert access_revocation_queue.process_pending(app) == 1
    assert calls == []
    assert list(directory.iterdir()) == []


def test_ordinary_sign_out_does_not_request_account_revocation(app, signed_in_admin):
    assert signed_in_admin.post('/logout').status_code in {200, 302}

    assert _pending() == []


class _SocketServer:
    def __init__(self):
        self.disconnected = []

    def disconnect(self, sid, namespace='/'):
        self.disconnected.append((sid, namespace))


def test_reset_then_server_run_disconnects_the_live_socket(app, signed_in_admin):
    """End to end without fakes in the revocation path: a socket that keeps
    receiving output must be disconnected after a reset from the CLI."""
    from types import SimpleNamespace

    from app import access_revocation_queue
    from app.auth import register_socket_session
    from app.models import SocketSession, db

    user_id = _user(app, 'soleadmin').id
    with app.app_context():
        register_socket_session(user_id, 'silent-socket')
    result = app.test_cli_runner().invoke(
        args=['reset-password', '--username', 'soleadmin'],
        input='replacement-password\nreplacement-password\n',
    )
    assert result.exit_code == 0, result.output
    socketio = SimpleNamespace(server=_SocketServer())

    assert access_revocation_queue.process_pending(app, socketio) == 1

    assert socketio.server.disconnected == [('silent-socket', '/')]
    with app.app_context():
        db.session.expire_all()
        assert SocketSession.query.filter_by(user_id=user_id).count() == 0
    assert _pending() == []


def test_an_undeletable_request_is_not_carried_out_again(app, signed_in_admin, monkeypatch):
    from app import access_revocation_queue, user_lifecycle

    user_id = _user(app, 'soleadmin').id
    calls = []
    monkeypatch.setattr(
        user_lifecycle, 'revoke_user_access',
        lambda revoked_id, *args, **kwargs: calls.append(revoked_id) or {},
    )
    monkeypatch.setattr(access_revocation_queue, '_completed', set())

    def undeletable(_path):
        raise PermissionError('read-only')

    monkeypatch.setattr(access_revocation_queue, '_discard', undeletable)
    access_revocation_queue.request_revocation(user_id)

    assert access_revocation_queue.process_pending(app) == 1
    assert access_revocation_queue.process_pending(app) == 0
    assert calls == [user_id]
