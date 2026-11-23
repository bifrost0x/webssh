"""Durable requests to revoke a user's live access in the running server.

Commands such as ``flask reset-password`` run in their own process. They can
invalidate stored sign-ins, but sockets, SSH sessions and transfers live in
the server process. The command records a request here after its database
change is committed, and a background job of the server revokes the user's
live access and then removes the request.
"""

import logging
import re
from pathlib import Path

import config

from .audit_logger import log_error, log_security_event, log_warning
from .backup_coordination import persistent_write
from .storage_utils import atomic_write_bytes, fsync_parent_directory

DIRECTORY_NAME = '.access-revocations'
POLL_SECONDS = 5

_REQUEST_NAME = re.compile(r'[1-9][0-9]{0,18}')


def _directory():
    return Path(config.DATA_DIR) / DIRECTORY_NAME


def request_revocation(user_id):
    """Record that ``user_id`` must lose all live access. Raises on failure."""
    user_id = int(user_id)
    if user_id < 1:
        raise ValueError('user_id must be positive')
    directory = _directory()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    atomic_write_bytes(directory / str(user_id), b'pending\n', mode=0o600)


def _discard(path):
    with persistent_write():
        try:
            path.unlink()
        except FileNotFoundError:
            return
        fsync_parent_directory(path)


def pending_user_ids():
    """Return requested user ids; malformed entries are removed."""
    try:
        entries = sorted(_directory().iterdir())
    except FileNotFoundError:
        return []
    user_ids = []
    for entry in entries:
        if _REQUEST_NAME.fullmatch(entry.name) and entry.is_file() and not entry.is_symlink():
            user_ids.append(int(entry.name))
            continue
        if entry.name.startswith('.') and entry.name.endswith('.tmp'):
            # An in-flight atomic write; it becomes a request or disappears.
            continue
        log_warning('Ignoring malformed access revocation request', entry=entry.name[:64])
        if entry.is_file() or entry.is_symlink():
            try:
                _discard(entry)
            except OSError as error:
                log_error(
                    'Failed to remove malformed access revocation request',
                    error_type=type(error).__name__,
                )
    return user_ids


def process_pending(app, socketio_instance=None):
    """Revoke live access for every recorded request, then remove it.

    A request stays in place when revocation raises, so the next run retries.
    """
    from . import user_lifecycle
    from .models import User, db

    processed = 0
    with app.app_context():
        for user_id in pending_user_ids():
            user = db.session.get(User, user_id)
            if user is not None:
                try:
                    result = user_lifecycle.revoke_user_access(user_id, socketio_instance)
                except Exception as error:
                    log_error(
                        'Requested access revocation failed',
                        user_id=user_id,
                        error_type=type(error).__name__,
                    )
                    db.session.rollback()
                    continue
                log_security_event(
                    'LIVE_ACCESS_REVOKED',
                    level=logging.WARNING,
                    user=user.username,
                    reason='cli_request',
                    sockets=result.get('sockets', 0),
                    ssh_sessions=result.get('ssh_sessions', 0),
                    incomplete=bool(result.get('errors')),
                )
            _discard(_directory() / str(user_id))
            processed += 1
    return processed
