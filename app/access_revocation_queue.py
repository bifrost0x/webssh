"""Durable requests to revoke a user's live access in the running server.

Commands such as ``flask reset-password`` run in their own process. They can
invalidate stored sign-ins, but sockets, SSH sessions and transfers live in
the server process. The command records a request here after its database
change is committed, and a background job of the server revokes the user's
live access and then removes the request.
"""

import logging
import os
import re
import secrets
from pathlib import Path
from threading import Lock

import config

from .audit_logger import log_error, log_security_event, log_warning
from .backup_coordination import persistent_write
from .storage_utils import atomic_write_bytes, fsync_parent_directory

DIRECTORY_NAME = '.access-revocations'
POLL_SECONDS = 5

# At most 18 digits, so every accepted name fits a 64-bit database id.
_REQUEST_NAME = re.compile(r'[1-9][0-9]{0,17}')
_TOKEN = re.compile(r'[0-9a-f]{32}')

# Requests already carried out whose file could not be removed, keyed by
# (user id, request token). A stuck file is not repeated in this process, so
# it cannot end every new sign-in; a newer request has a new token.
_completed_lock = Lock()
_completed = set()


class RequestNotWritable(RuntimeError):
    """The command runs as an identity the server could not read back."""


def _directory():
    return Path(config.DATA_DIR) / DIRECTORY_NAME


def ensure_server_can_read_requests():
    """Refuse to run as root when the data directory belongs to another user.

    Files root creates there would be unreadable for the unprivileged server,
    and root following a planted symlink could write outside the directory.
    """
    if os.name != 'posix' or os.geteuid() != 0:
        return
    owner = os.stat(config.DATA_DIR).st_uid
    if owner != 0:
        raise RequestNotWritable(
            f'Run this command as the owner of the data directory (uid {owner}), '
            'not as root.'
        )


def request_revocation(user_id):
    """Record that ``user_id`` must lose all live access. Raises on failure."""
    user_id = int(user_id)
    if user_id < 1:
        raise ValueError('user_id must be positive')
    ensure_server_can_read_requests()
    directory = _directory()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    token = secrets.token_hex(16)
    atomic_write_bytes(directory / str(user_id), f'{token}\n'.encode('ascii'), mode=0o600)


def _read_token(path):
    try:
        with open(path, 'rb') as handle:
            content = handle.read(64)
    except FileNotFoundError:
        return None
    token = content.decode('ascii', errors='replace').strip()
    # Requests written before tokens existed read as one shared value.
    return token if _TOKEN.fullmatch(token) else 'legacy'


def _discard(path):
    """Remove ``path``; returns False only when it could not be unlinked."""
    with persistent_write():
        try:
            path.unlink()
        except FileNotFoundError:
            return True
        except OSError as error:
            log_error(
                'Failed to remove an access revocation request',
                error_type=type(error).__name__,
            )
            return False
        try:
            fsync_parent_directory(path)
        except OSError as error:
            # The entry is gone; only its durability on power loss is unsure.
            log_warning(
                'Access revocation request removal not flushed',
                error_type=type(error).__name__,
            )
        return True


def pending_requests():
    """Return ``(user_id, token)`` pairs; malformed entries are removed."""
    try:
        entries = sorted(_directory().iterdir())
    except FileNotFoundError:
        return []
    requests = []
    for entry in entries:
        if _REQUEST_NAME.fullmatch(entry.name) and entry.is_file() and not entry.is_symlink():
            token = _read_token(entry)
            if token is not None:
                requests.append((int(entry.name), token))
            continue
        if entry.name.startswith('.') and entry.name.endswith('.tmp'):
            # An in-flight atomic write; it becomes a request or disappears.
            continue
        log_warning('Ignoring malformed access revocation request', entry=entry.name[:64])
        if entry.is_file() or entry.is_symlink():
            _discard(entry)
    return requests


def pending_user_ids():
    return [user_id for user_id, _token in pending_requests()]


def process_pending(app, socketio_instance=None):
    """Revoke live access for every recorded request, then remove it.

    A request stays in place when revocation raises, so the next run retries.
    One failing request does not hold up the others.
    """
    from . import user_lifecycle
    from .models import User, db

    processed = 0
    with app.app_context():
        for user_id, token in pending_requests():
            with _completed_lock:
                if (user_id, token) in _completed:
                    continue
            try:
                user = db.session.get(User, user_id)
                result = (
                    user_lifecycle.revoke_user_access(user_id, socketio_instance)
                    if user is not None else None
                )
            except Exception as error:
                log_error(
                    'Requested access revocation failed',
                    user_id=user_id,
                    error_type=type(error).__name__,
                )
                db.session.rollback()
                continue
            if user is not None:
                log_security_event(
                    'LIVE_ACCESS_REVOKED',
                    level=logging.WARNING,
                    user=user.username,
                    reason='cli_request',
                    sockets=result.get('sockets', 0),
                    ssh_sessions=result.get('ssh_sessions', 0),
                    incomplete=bool(result.get('errors')),
                )
            request = _directory() / str(user_id)
            # A reset during this run wrote a new token; leave that request
            # for the next run instead of removing it unprocessed.
            if _read_token(request) == token and not _discard(request):
                with _completed_lock:
                    _completed.add((user_id, token))
            processed += 1
    return processed
