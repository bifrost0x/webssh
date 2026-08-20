import os
import secrets
import stat
from datetime import datetime, timezone
from pathlib import Path

import click
from flask import current_app

import config
from .audit_logger import audit_logger, log_warning
from .auth import (
    user_creation_transaction,
    validate_new_user,
)
from .models import User, db


def _audit_operation(event, **details):
    audit_logger.info(
        event,
        extra={'extra_data': details},
    )


def _require_offline_confirmation(confirm_offline):
    if not confirm_offline:
        raise click.ClickException(
            'Stop every WebSSH application process first, then repeat with '
            '--confirm-offline.'
        )


def _audit_admin_bootstrap(username, action):
    audit_logger.info(
        'ADMIN_BOOTSTRAP_SUCCESS',
        extra={
            'extra_data': {
                'user': username,
                'action': action,
            },
        },
    )


def _read_password_file(password_file):
    path = Path(password_file)
    try:
        path_stat = path.lstat()
    except OSError as exc:
        raise click.ClickException(
            'Password file does not exist or is not readable.'
        ) from exc

    if stat.S_ISLNK(path_stat.st_mode):
        raise click.ClickException(
            'Password file must not be a symbolic link.'
        )
    if not stat.S_ISREG(path_stat.st_mode):
        raise click.ClickException('Password file must be a regular file.')

    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0)
    flags |= getattr(os, 'O_NOFOLLOW', 0)
    descriptor = None
    try:
        descriptor = os.open(path, flags)
        opened_stat = os.fstat(descriptor)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise click.ClickException(
                'Password file must be a regular file.'
            )
        if (
            path_stat.st_dev,
            path_stat.st_ino,
        ) != (
            opened_stat.st_dev,
            opened_stat.st_ino,
        ):
            raise click.ClickException(
                'Password file changed while it was being opened.'
            )

        with os.fdopen(descriptor, 'rb') as fh:
            descriptor = None
            data = fh.read(config.MAX_PASSWORD_LENGTH + 3)
            if fh.read(1):
                raise click.ClickException(
                    f'Password must not exceed '
                    f'{config.MAX_PASSWORD_LENGTH} bytes when encoded as '
                    'UTF-8.'
                )
    except click.ClickException:
        raise
    except OSError as exc:
        raise click.ClickException(
            'Password file could not be read.'
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)

    try:
        password = data.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise click.ClickException(
            'Password file must contain valid UTF-8.'
        ) from exc

    if password.endswith('\n'):
        password = password[:-1]
        if password.endswith('\r'):
            password = password[:-1]
    return password


@click.command('create-admin')
@click.option('--username', required=True, metavar='NAME')
@click.option(
    '--password-file',
    type=click.Path(path_type=Path),
    metavar='PATH',
)
def create_admin(username, password_file):
    """Create a new administrator or promote an existing account."""
    from . import _initialize_persistent_storage
    _initialize_persistent_storage(current_app._get_current_object())

    user = User.query.filter_by(username=username).first()
    if user is not None:
        if user.is_ldap_managed:
            raise click.ClickException(
                'LDAP-managed accounts cannot be administrators.'
            )
        if password_file is not None:
            raise click.ClickException(
                '--password-file cannot be used when promoting an existing '
                'user.'
            )
        if not user.is_admin:
            user.is_admin = True
            db.session.commit()
            action = 'promoted'
        else:
            action = 'already_admin'
        _audit_admin_bootstrap(username, action)
        click.echo(f'Administrator ready: {username}')
        return

    if password_file is None:
        password = click.prompt(
            'Password',
            hide_input=True,
            confirmation_prompt=True,
        )
    else:
        password = _read_password_file(password_file)

    with user_creation_transaction():
        error = validate_new_user(username, password)
        if error:
            raise click.ClickException(error)

        user = User(username=username, is_admin=True)
        user.set_password(password)
        db.session.add(user)
        try:
            db.session.flush()
            user.get_data_dir()
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise

    _audit_admin_bootstrap(username, 'created')
    click.echo(f'Administrator created: {username}')


def warn_if_no_admin():
    if User.query.filter_by(is_admin=True).first() is None:
        if config.BOOTSTRAP_REGISTRATION_ENABLED:
            log_warning(
                'No administrator account exists. One-time browser '
                'registration is available until the first account is created. '
                'Do not expose an unclaimed instance to untrusted networks.'
            )
            return
        log_warning(
            'No administrator account exists. Run the Flask create-admin '
            'command from a trusted host.'
        )


@click.group('backup')
def backup_cli():
    """Create, verify, or restore WebSSH data backups."""


@backup_cli.command('create')
@click.option(
    '--destination',
    type=click.Path(path_type=Path),
    metavar='ARCHIVE',
)
@click.option('--confirm-offline', is_flag=True)
def backup_create(destination, confirm_offline):
    """Create and verify a backup while WebSSH is stopped."""
    from .backup_coordination import operation_lock
    from .backup_manager import create_backup

    _require_offline_confirmation(confirm_offline)
    if destination is None:
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        destination = Path(config.DATA_DIR).parent / (
            f'webssh-backup-{timestamp}.zip'
        )
    try:
        with operation_lock():
            manifest = create_backup(config.DATA_DIR, destination)
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    _audit_operation(
        'BACKUP_CREATE_SUCCESS',
        file_count=len(manifest.files),
    )
    click.echo(
        f'Backup created and verified: {destination} '
        f'({len(manifest.files)} files, format v{manifest.format_version}, '
        f'data schema {manifest.data_schema_version})'
    )


@backup_cli.command('verify')
@click.argument(
    'archive',
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
def backup_verify(archive):
    """Verify archive structure and every recorded checksum."""
    from .backup_manager import evaluate_backup_compatibility, verify_backup

    try:
        manifest = verify_backup(archive)
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    _audit_operation(
        'BACKUP_VERIFY_SUCCESS',
        file_count=len(manifest.files),
    )
    compatibility = evaluate_backup_compatibility(manifest)
    restore_status = (
        'restore compatible (legacy)'
        if compatibility.compatible and compatibility.legacy
        else (
            'restore compatible'
            if compatibility.compatible
            else 'restore incompatible'
        )
    )
    click.echo(
        f'Backup verified ({len(manifest.files)} files, '
        f'format v{manifest.format_version}, '
        f'data schema {manifest.data_schema_version}, {restore_status}).'
    )


@backup_cli.command('restore')
@click.argument(
    'archive',
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option('--confirm-offline', is_flag=True)
def backup_restore(archive, confirm_offline):
    """Restore a verified backup while WebSSH is stopped."""
    from .backup_coordination import operation_lock
    from .backup_manager import restore_backup

    _require_offline_confirmation(confirm_offline)
    try:
        with operation_lock():
            db.session.remove()
            db.engine.dispose()
            restore_backup(archive, config.DATA_DIR)
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    from .maintenance_mode import clear_failed_status_after_cli_restore
    clear_failed_status_after_cli_restore()
    _audit_operation('BACKUP_RESTORE_SUCCESS')
    click.echo('Backup restored and verified.')


@click.command('rotate-secret-key')
@click.option('--confirm-offline', is_flag=True)
def rotate_secret_key(confirm_offline):
    """Rotate the persisted SECRET_KEY and every stored SSH key."""
    from .secret_rotation import rotate_secret

    _require_offline_confirmation(confirm_offline)
    new_secret = secrets.token_hex(32)
    try:
        report = rotate_secret(
            config.SECRET_KEY,
            new_secret,
            config.DATA_DIR,
        )
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    _audit_operation(
        'SECRET_ROTATION_SUCCESS',
        rotated_keys=report.rotated_keys,
        rotated_totp_secrets=report.rotated_totp_secrets,
    )
    click.echo(
        f'SECRET_KEY rotated for {report.rotated_keys} stored SSH keys and '
        f'{report.rotated_totp_secrets} TOTP secrets. '
        f'Verified backup: {report.backup_path}'
    )
    click.echo(
        'Restart WebSSH now so every process loads the new persisted secret.'
    )


def register_cli(app):
    app.cli.add_command(create_admin)
    app.cli.add_command(backup_cli)
    app.cli.add_command(rotate_secret_key)
