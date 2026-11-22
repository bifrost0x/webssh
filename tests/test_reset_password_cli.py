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
