import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _maintenance_cli(
    data_dir,
    *arguments,
    environment_overrides=None,
    app_target='start',
    flask_module='flask',
):
    environment = os.environ.copy()
    environment.update({
        'DATA_DIR': str(data_dir),
        'DEBUG': 'True',
        'SECRET_KEY': 'maintenance-cli-test-secret',
    })
    if environment_overrides:
        environment.update(environment_overrides)
    return subprocess.run(
        [
            sys.executable,
            '-m',
            flask_module,
            '--app',
            app_target,
            *arguments,
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )


def _missing_ldap_runtime_environment(tmp_path):
    return {
        'LDAP_ENABLED': 'true',
        'LDAP_URL': 'ldaps://directory.example.com:636',
        'LDAP_BASE_DN': 'dc=example,dc=com',
        'LDAP_BIND_DN': 'cn=service,dc=example,dc=com',
        'LDAP_BIND_PASSWORD_FILE': str(tmp_path / 'missing-ldap-password'),
        'LDAP_CA_FILE': str(tmp_path / 'missing-ldap-ca.pem'),
        'LDAP_USER_FILTER': '(&(objectClass=person)(uid={username}))',
        'LDAP_UNIQUE_ID_ATTRIBUTE': 'entryUUID',
    }


@pytest.mark.parametrize(
    'command',
    ('issue-factor-bootstrap', 'connection-store'),
)
def test_security_maintenance_help_exits_without_runtime_or_storage(
    tmp_path,
    command,
):
    data_dir = tmp_path / command

    result = _maintenance_cli(data_dir, command, '--help')

    assert result.returncode == 0, result.stderr
    assert 'Usage:' in result.stdout
    assert not data_dir.exists()


@pytest.mark.parametrize(
    'command',
    ('issue-factor-bootstrap', 'connection-store'),
)
def test_security_maintenance_help_skips_missing_ldap_runtime_files(
    tmp_path,
    command,
):
    data_dir = tmp_path / command

    result = _maintenance_cli(
        data_dir,
        command,
        '--help',
        environment_overrides=_missing_ldap_runtime_environment(tmp_path),
    )

    assert result.returncode == 0, result.stderr
    assert 'Usage:' in result.stdout
    assert not data_dir.exists()


@pytest.mark.parametrize(
    'command',
    ('issue-factor-bootstrap', 'connection-store'),
)
def test_factory_target_maintenance_help_uses_safe_app_construction(
    tmp_path,
    command,
):
    data_dir = tmp_path / command

    result = _maintenance_cli(
        data_dir,
        command,
        '--help',
        app_target='app:create_app',
        environment_overrides=_missing_ldap_runtime_environment(tmp_path),
    )

    assert result.returncode == 0, result.stderr
    assert 'Usage:' in result.stdout
    assert not data_dir.exists()


@pytest.mark.parametrize(
    'command',
    ('issue-factor-bootstrap', 'connection-store'),
)
def test_flask_cli_module_maintenance_help_uses_safe_app_construction(
    tmp_path,
    command,
):
    data_dir = tmp_path / command

    result = _maintenance_cli(
        data_dir,
        command,
        '--help',
        app_target='app:create_app',
        flask_module='flask.cli',
        environment_overrides=_missing_ldap_runtime_environment(tmp_path),
    )

    assert result.returncode == 0, result.stderr
    assert 'Usage:' in result.stdout
    assert not data_dir.exists()


def test_factory_target_connection_store_initializes_inside_command(tmp_path):
    data_dir = tmp_path / 'connection-store-operation'

    result = _maintenance_cli(
        data_dir,
        'connection-store',
        'list',
        '--username',
        'missing-user',
        '--kind',
        'profiles',
        '--confirm-offline',
        app_target='app:create_app',
        environment_overrides=_missing_ldap_runtime_environment(tmp_path),
    )

    assert result.returncode != 0
    assert 'Account not found' in result.stderr
    assert 'LDAP secret file is unavailable' not in result.stderr
    assert (data_dir / 'app.db').is_file()


def test_factory_target_connection_store_locks_before_initialization(
    tmp_path,
    monkeypatch,
):
    import config
    from app.backup_coordination import operation_lock

    data_dir = tmp_path / 'locked-connection-store-operation'
    operation_dir = tmp_path / 'operations'
    monkeypatch.setattr(config, 'DATA_DIR', data_dir)
    monkeypatch.setattr(config, 'BACKUP_TEMP_DIR', operation_dir)
    monkeypatch.setattr(config, 'BACKUP_OPERATION_TIMEOUT', 1)

    with operation_lock():
        result = _maintenance_cli(
            data_dir,
            'connection-store',
            'list',
            '--username',
            'missing-user',
            '--kind',
            'profiles',
            '--confirm-offline',
            app_target='app:create_app',
            environment_overrides={
                **_missing_ldap_runtime_environment(tmp_path),
                'BACKUP_TEMP_DIR': str(operation_dir),
                'BACKUP_OPERATION_TIMEOUT': '1',
            },
        )

    assert result.returncode != 0
    assert 'another backup or restore operation is active' in result.stderr
    assert not data_dir.exists()


def test_factor_bootstrap_missing_user_exits_instead_of_starting_runtime(
    tmp_path,
):
    result = _maintenance_cli(
        tmp_path / 'factor-bootstrap-data',
        'issue-factor-bootstrap',
        '--username',
        'missing-user',
        '--action',
        'passkey.enroll',
    )

    assert result.returncode != 0
    assert 'Eligible account not found' in result.stderr


def test_factor_bootstrap_operation_skips_missing_ldap_runtime_files(tmp_path):
    result = _maintenance_cli(
        tmp_path / 'factor-bootstrap-ldap-data',
        'issue-factor-bootstrap',
        '--username',
        'missing-user',
        '--action',
        'passkey.enroll',
        environment_overrides=_missing_ldap_runtime_environment(tmp_path),
    )

    assert result.returncode != 0
    assert 'Eligible account not found' in result.stderr
    assert 'LDAP secret file is unavailable' not in result.stderr


def test_normal_app_factory_still_requires_ldap_runtime_files(tmp_path):
    environment = os.environ.copy()
    environment.update({
        'DATA_DIR': str(tmp_path / 'normal-start-data'),
        'DEBUG': 'True',
        'SECRET_KEY': 'normal-start-test-secret',
        **_missing_ldap_runtime_environment(tmp_path),
    })

    result = subprocess.run(
        [
            sys.executable,
            '-c',
            (
                'from app import create_app; '
                'create_app(initialize_storage=False, start_runtime=False, '
                'initialize_oidc=False)'
            ),
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )

    assert result.returncode != 0
    assert 'LDAP secret file is unavailable' in result.stderr


@pytest.mark.parametrize('flask_module', ('flask', 'flask.cli'))
def test_factory_target_nonmaintenance_command_keeps_ldap_fail_fast(
    tmp_path,
    flask_module,
):
    data_dir = tmp_path / 'nonmaintenance-data'

    result = _maintenance_cli(
        data_dir,
        'routes',
        app_target='app:create_app',
        flask_module=flask_module,
        environment_overrides=_missing_ldap_runtime_environment(tmp_path),
    )

    assert result.returncode != 0
    assert 'LDAP secret file is unavailable' in result.stderr
    assert not data_dir.exists()


def test_skipped_ldap_runtime_validation_is_not_marked_ready(monkeypatch):
    import app as app_module
    import config

    monkeypatch.setattr(config, 'LDAP_ENABLED', True)
    monkeypatch.setattr(
        app_module,
        '_is_maintenance_cli_invocation',
        lambda: True,
    )

    maintenance_app = app_module.create_app()

    assert maintenance_app.extensions['maintenance_cli_invocation'] is True
    assert maintenance_app.extensions['security_feature_readiness']['ldap'] == (
        False,
        'LDAP runtime validation did not complete.',
    )


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


def test_create_admin_rejects_promoting_ldap_managed_user(app):
    from app.auth import register_user
    from app.models import LDAPIdentity, db

    with app.app_context():
        admin, admin_error = register_user(
            'localadmin',
            'local-admin-password',
        )
        assert admin_error is None
        assert admin.is_admin is True
        user, error = register_user(
            'directoryuser',
            'existing-user-password',
        )
        assert error is None
        db.session.add(LDAPIdentity(
            user_id=user.id,
            provider='default',
            subject='stable-directory-user-id',
            directory_username='directoryuser',
            distinguished_name='uid=directoryuser,dc=example,dc=com',
        ))
        db.session.commit()

    result = app.test_cli_runner().invoke(
        args=['create-admin', '--username', 'directoryuser'],
    )

    assert result.exit_code != 0
    assert 'LDAP-managed accounts cannot be administrators' in result.output
    user = _admin(app, 'directoryuser')
    assert user.is_admin is False


def test_create_admin_rejects_promoting_github_managed_user(app):
    from app.auth import register_user
    from app.models import GitHubIdentity, db

    with app.app_context():
        admin, admin_error = register_user(
            'githubbreakglass',
            'local-admin-password',
        )
        assert admin_error is None
        assert admin.is_admin is True
        user, error = register_user(
            'githubmanageduser',
            'existing-user-password',
        )
        assert error is None
        db.session.add(GitHubIdentity(
            user_id=user.id,
            github_user_id='424242',
            login='github-managed-user',
            provisioned_by_github=True,
        ))
        db.session.commit()

    result = app.test_cli_runner().invoke(
        args=['create-admin', '--username', 'githubmanageduser'],
    )

    assert result.exit_code != 0
    assert 'GitHub-managed accounts cannot be administrators' in result.output
    user = _admin(app, 'githubmanageduser')
    assert user.is_admin is False


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
