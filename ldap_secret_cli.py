"""Standalone LDAP secret-volume management.

This file deliberately lives outside the ``app`` package so Python does not
import Flask or project configuration before a broken LDAP setup can be
repaired.
"""

import getpass
import os
import ssl
import sys
import tempfile
from pathlib import Path

import click


_PASSWORD_FILE = 'ldap_bind_password'
_CA_FILE = 'ldap_ca.pem'
_MAX_PASSWORD_BYTES = 16 * 1024
_MAX_CA_BYTES = 1024 * 1024


def _validated_directory(value):
    directory = Path(value)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not directory.is_dir() or directory.is_symlink():
        raise click.ClickException('Secret directory must be a real directory')
    try:
        directory.chmod(0o700)
    except OSError as exc:
        raise click.ClickException('Cannot secure the secret directory') from exc
    return directory


def _atomic_write(directory, filename, content, mode=0o600):
    target = directory / filename
    temporary_name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='wb',
            dir=directory,
            prefix=f'.{filename}.',
            suffix='.tmp',
            delete=False,
        ) as temporary:
            temporary_name = Path(temporary.name)
            os.chmod(temporary.name, mode)
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, target)
        os.chmod(target, mode)
        if os.name != 'nt':
            directory_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except OSError as exc:
        if temporary_name is not None:
            try:
                temporary_name.unlink(missing_ok=True)
            except OSError:
                pass
        raise click.ClickException(f'Could not write {filename}') from exc


def _read_stdin(limit):
    data = sys.stdin.buffer.read(limit + 1)
    if len(data) > limit:
        raise click.ClickException('Input exceeds the supported size limit')
    return data


@click.group()
@click.option(
    '--secret-dir',
    type=click.Path(path_type=Path),
    default=Path('/run/webssh-auth'),
    show_default=True,
)
@click.pass_context
def cli(context, secret_dir):
    """Manage LDAP files in WebSSH's dedicated secret volume."""
    context.obj = _validated_directory(secret_dir)


@cli.command('set-password')
@click.option('--stdin', 'from_stdin', is_flag=True, help='Read from standard input.')
@click.pass_obj
def set_password(secret_dir, from_stdin):
    """Set the least-privilege LDAP search-account password."""
    if from_stdin:
        raw = _read_stdin(_MAX_PASSWORD_BYTES).rstrip(b'\r\n')
    else:
        first = getpass.getpass('LDAP bind password: ')
        second = getpass.getpass('Repeat LDAP bind password: ')
        if first != second:
            raise click.ClickException('Passwords do not match')
        try:
            raw = first.encode('utf-8')
        except UnicodeEncodeError as exc:
            raise click.ClickException('Password must be valid UTF-8') from exc
    if not raw or len(raw) > _MAX_PASSWORD_BYTES or b'\x00' in raw:
        raise click.ClickException('Password is empty or invalid')
    try:
        raw.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise click.ClickException('Password must be valid UTF-8') from exc
    _atomic_write(secret_dir, _PASSWORD_FILE, raw)
    click.echo('LDAP bind password stored securely.')


@cli.command('install-ca')
@click.option('--stdin', 'from_stdin', is_flag=True, help='Read PEM from standard input.')
@click.argument('pem_file', required=False, type=click.Path(exists=True, path_type=Path))
@click.pass_obj
def install_ca(secret_dir, from_stdin, pem_file):
    """Validate and install the CA bundle used to verify LDAP TLS."""
    if from_stdin == (pem_file is not None):
        raise click.ClickException('Use exactly one of --stdin or PEM_FILE')
    if from_stdin:
        raw = _read_stdin(_MAX_CA_BYTES)
    else:
        if pem_file.stat().st_size > _MAX_CA_BYTES:
            raise click.ClickException('CA bundle exceeds the supported size limit')
        raw = pem_file.read_bytes()
    try:
        pem = raw.decode('ascii')
        ssl.create_default_context(cadata=pem)
    except (UnicodeDecodeError, ssl.SSLError, ValueError) as exc:
        raise click.ClickException('CA bundle is not valid PEM certificate data') from exc
    _atomic_write(secret_dir, _CA_FILE, raw)
    click.echo('LDAP CA bundle installed securely.')


@cli.command('status')
@click.pass_obj
def status(secret_dir):
    """Show whether the required files exist without reading their content."""
    for filename in (_PASSWORD_FILE, _CA_FILE):
        state = 'present' if (secret_dir / filename).is_file() else 'missing'
        click.echo(f'{filename}: {state}')


@cli.command('remove')
@click.option('--yes', is_flag=True, help='Skip the destructive confirmation.')
@click.pass_obj
def remove(secret_dir, yes):
    """Remove only the two LDAP files from the dedicated volume."""
    if not yes and not click.confirm('Remove LDAP bind password and CA bundle?'):
        raise click.Abort()
    for filename in (_PASSWORD_FILE, _CA_FILE):
        try:
            (secret_dir / filename).unlink(missing_ok=True)
        except OSError as exc:
            raise click.ClickException(f'Could not remove {filename}') from exc
    click.echo('LDAP secret files removed.')


if __name__ == '__main__':
    cli()
