import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _admin(app, username):
    from app.models import User

    with app.app_context():
        return User.query.filter_by(username=username).first()


def test_create_admin_maintenance_cli_initializes_storage_and_exits(tmp_path):
    data_dir = tmp_path / 'new-data'
    password_file = tmp_path / 'admin-password'
    password_file.write_text('standalone-admin-password\n', encoding='utf-8')
    environment = os.environ.copy()
    environment.update({
        'DATA_DIR': str(data_dir),
        'DEBUG': 'True',
        'SECRET_KEY': 'maintenance-cli-test-secret',
    })

    result = subprocess.run(
        [
            sys.executable,
            '-m',
            'flask',
            '--app',
            'start',
            'create-admin',
            '--username',
            'standaloneadmin',
            '--password-file',
            str(password_file),
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr
    assert (data_dir / 'app.db').is_file()


def test_create_admin_interactively_hides_password(app):
    password = 'strong-admin-password'
    runner = app.test_cli_runner()

    result = runner.invoke(
        args=['create-admin', '--username', 'adminuser'],
        input=f'{password}\n{password}\n',
    )

    assert result.exit_code == 0
    assert password not in result.output
    user = _admin(app, 'adminuser')
    assert user is not None
    assert user.is_admin is True
    assert user.check_password(password)


@pytest.mark.parametrize(
    ('password', 'expected_error'),
    (
        pytest.param('short', 'at least 8 characters', id='weak'),
        pytest.param('a' * 73, '72 bytes', id='overlong'),
    ),
)
def test_create_admin_rejects_invalid_interactive_passwords(
    app,
    password,
    expected_error,
):
    runner = app.test_cli_runner()

    result = runner.invoke(
        args=['create-admin', '--username', 'invalidadmin'],
        input=f'{password}\n{password}\n',
    )

    assert result.exit_code != 0
    assert password not in result.output
    assert expected_error in result.output
    assert _admin(app, 'invalidadmin') is None


def test_create_admin_promotes_existing_user_without_resetting_password(app):
    from app.auth import register_user

    password = 'existing-user-password'
    with app.app_context():
        user, error = register_user('existinguser', password)
        assert error is None
        original_hash = user.password_hash

    result = app.test_cli_runner().invoke(
        args=['create-admin', '--username', 'existinguser'],
    )

    assert result.exit_code == 0
    user = _admin(app, 'existinguser')
    assert user.is_admin is True
    assert user.password_hash == original_hash
    assert user.check_password(password)


def test_create_admin_rejects_password_file_for_existing_user(
    app,
    tmp_path,
):
    from app.auth import register_user

    with app.app_context():
        bootstrap, bootstrap_error = register_user(
            'bootstrapadmin',
            'bootstrap-password',
        )
        assert bootstrap_error is None
        assert bootstrap.is_admin is True
        user, error = register_user(
            'existingfileuser',
            'existing-user-password',
        )
        assert error is None
        original_hash = user.password_hash
    password_file = tmp_path / 'replacement-password'
    password_file.write_text('replacement-password\n', encoding='utf-8')

    result = app.test_cli_runner().invoke(
        args=[
            'create-admin',
            '--username',
            'existingfileuser',
            '--password-file',
            str(password_file),
        ],
    )

    assert result.exit_code != 0
    user = _admin(app, 'existingfileuser')
    assert user.is_admin is False
    assert user.password_hash == original_hash


def test_create_admin_reads_password_file_and_strips_one_newline(
    app,
    tmp_path,
):
    password = 'file-admin-password'
    password_file = tmp_path / 'admin-password'
    password_file.write_text(f'{password}\n', encoding='utf-8')

    result = app.test_cli_runner().invoke(
        args=[
            'create-admin',
            '--username',
            'fileadmin',
            '--password-file',
            str(password_file),
        ],
    )

    assert result.exit_code == 0
    assert password not in result.output
    user = _admin(app, 'fileadmin')
    assert user is not None
    assert user.is_admin is True
    assert user.check_password(password)


def test_create_admin_rejects_password_file_symlink(app, tmp_path):
    target = tmp_path / 'password-target'
    target.write_text('strong-admin-password\n', encoding='utf-8')
    link = tmp_path / 'password-link'
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f'symlinks unavailable: {exc}')

    result = app.test_cli_runner().invoke(
        args=[
            'create-admin',
            '--username',
            'linkadmin',
            '--password-file',
            str(link),
        ],
    )

    assert result.exit_code != 0
    assert 'symbolic link' in result.output.lower()
    assert _admin(app, 'linkadmin') is None


def test_create_admin_rejects_password_file_directory(app, tmp_path):
    result = app.test_cli_runner().invoke(
        args=[
            'create-admin',
            '--username',
            'directoryadmin',
            '--password-file',
            str(tmp_path),
        ],
    )

    assert result.exit_code != 0
    assert 'regular file' in result.output.lower()
    assert _admin(app, 'directoryadmin') is None


def test_create_admin_audits_success_without_password_material(app, caplog):
    password = 'audit-admin-password'

    result = app.test_cli_runner().invoke(
        args=['create-admin', '--username', 'auditadmin'],
        input=f'{password}\n{password}\n',
    )

    assert result.exit_code == 0
    records = [
        record
        for record in caplog.records
        if record.name == 'security_audit'
    ]
    assert any(
        record.getMessage() == 'ADMIN_BOOTSTRAP_SUCCESS'
        and record.extra_data == {
            'user': 'auditadmin',
            'action': 'created',
        }
        for record in records
    )
    assert password not in repr(records)


def test_warn_if_no_admin_reports_missing_bootstrap(caplog, app):
    from app.cli import warn_if_no_admin

    caplog.clear()
    with app.app_context():
        warn_if_no_admin()

    assert any(
        'No administrator account exists' in record.getMessage()
        for record in caplog.records
    )


def test_fresh_production_defaults_to_closed_registration():
    env = os.environ.copy()
    env['SECRET_KEY'] = 'admin-cli-config-test'
    env['DEBUG'] = 'False'
    env['CORS_ORIGINS'] = 'http://localhost:5000'
    env['PYTHONIOENCODING'] = 'utf-8'
    env.pop('REGISTRATION_ENABLED', None)

    result = subprocess.run(
        [
            sys.executable,
            '-c',
            (
                'import config; '
                'raise SystemExit(0 if not config.REGISTRATION_ENABLED else 1)'
            ),
        ],
        cwd=os.getcwd(),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_saved_registration_setting_is_not_overwritten(
    app,
    tmp_path,
    monkeypatch,
):
    from app import app_settings
    from app.storage_migrations import CURRENT_STORAGE_VERSIONS

    path = tmp_path / 'app_settings.json'
    original = json.dumps({
        'schema_version': CURRENT_STORAGE_VERSIONS['app_settings'],
        'registration_enabled': True,
    }).encode('utf-8')
    path.write_bytes(original)
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)
    monkeypatch.setattr(
        app_settings.config,
        'REGISTRATION_ENABLED',
        False,
    )

    assert app_settings.is_registration_enabled() is True
    assert path.read_bytes() == original


def test_legacy_role_migration_promotes_only_oldest_existing_user(app):
    from sqlalchemy import text
    from app.models import db, ensure_user_columns

    with app.app_context():
        db.session.execute(text('DROP TABLE users'))
        db.session.execute(text(
            'CREATE TABLE users ('
            'id INTEGER PRIMARY KEY, '
            'username VARCHAR(80) NOT NULL UNIQUE, '
            'password_hash VARCHAR(128) NOT NULL, '
            'created_at DATETIME, '
            'last_login DATETIME'
            ')'
        ))
        db.session.execute(text(
            "INSERT INTO users (id, username, password_hash) VALUES "
            "(2, 'newer', 'unused'), "
            "(1, 'oldest', 'unused')"
        ))
        db.session.commit()

        ensure_user_columns()
        rows = db.session.execute(text(
            'SELECT id, is_admin, is_locked, auth_generation '
            'FROM users ORDER BY id'
        )).all()

        assert rows == [(1, 1, 0, 0), (2, 0, 0, 0)]

        ensure_user_columns()
        repeated = db.session.execute(text(
            'SELECT id, is_admin, is_locked, auth_generation '
            'FROM users ORDER BY id'
        )).all()
        assert repeated == rows
