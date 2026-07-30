"""Central cleanup helpers for revoking a user's live access."""

from uuid import uuid4

import config

from .audit_logger import log_error, log_info, log_warning
from .models import db, SocketSession, SSHSession
from . import connection_pool, ssh_manager


def revoke_user_access(user_id, socketio_instance=None):
    """Disconnect and remove all live resources owned by ``user_id``.

    Cleanup is deliberately best-effort across resource types: one broken SSH
    connection must not prevent the user's sockets, pooled connections, or
    database session metadata from being revoked.
    """
    user_id = int(user_id)
    result = {
        'transfers': 0,
        'sockets': 0,
        'ssh_sessions': 0,
        'pool_connections': 0,
        'errors': [],
    }

    try:
        from .transfer_routes import transfer_manager

        result['transfers'] = transfer_manager.cancel_all_for_user(user_id)
    except Exception as exc:
        result['errors'].append(f'transfers:{exc}')
        log_warning(
            "Failed to cancel revoked user transfers",
            user_id=user_id,
            error=str(exc),
        )

    socket_sids = [
        row.socket_sid
        for row in SocketSession.query.filter_by(user_id=user_id).all()
    ]
    result['sockets'] = len(socket_sids)

    if socketio_instance is None:
        from . import socketio as socketio_instance

    server = getattr(socketio_instance, 'server', None)
    if server is not None:
        for socket_sid in socket_sids:
            try:
                server.disconnect(socket_sid, namespace='/')
            except Exception as exc:
                result['errors'].append(f'socket:{socket_sid}:{exc}')
                log_warning(
                    "Failed to disconnect revoked Socket.IO session",
                    user_id=user_id,
                    sid=socket_sid,
                    error=str(exc),
                )

    with ssh_manager.sessions_lock:
        ssh_session_ids = [
            session_id
            for session_id, session in ssh_manager.sessions.items()
            if str(session.get('user_id')) == str(user_id)
        ]

    for session_id in ssh_session_ids:
        try:
            if ssh_manager.close_session(session_id, kill_tmux=True):
                result['ssh_sessions'] += 1
            else:
                result['errors'].append(f'ssh:{session_id}:close failed')
        except Exception as exc:
            result['errors'].append(f'ssh:{session_id}:{exc}')
            log_warning(
                "Failed to close revoked SSH session",
                user_id=user_id,
                session_id=session_id,
                error=str(exc),
            )

    try:
        result['pool_connections'] = (
            connection_pool.temp_connection_pool.close_all_user_connections(str(user_id))
        )
    except Exception as exc:
        result['errors'].append(f'pool:{exc}')
        log_warning(
            "Failed to close revoked temporary connections",
            user_id=user_id,
            error=str(exc),
        )

    try:
        SocketSession.query.filter_by(user_id=user_id).delete(synchronize_session=False)
        SSHSession.query.filter_by(user_id=user_id).delete(synchronize_session=False)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        result['errors'].append(f'database:{exc}')
        log_warning(
            "Failed to remove revoked session metadata",
            user_id=user_id,
            error=str(exc),
        )

    log_info(
        "User access revoked",
        user_id=user_id,
        transfers=result['transfers'],
        sockets=result['sockets'],
        ssh_sessions=result['ssh_sessions'],
        pool_connections=result['pool_connections'],
        cleanup_errors=len(result['errors']),
    )
    return result


def quarantine_user_data(user_id):
    """Atomically move a user's files outside the active user namespace."""
    user_id = int(user_id)
    original = config.DATA_DIR / 'users' / f'user_{user_id}'
    if not original.exists():
        return None, None

    quarantine_root = config.DATA_DIR / 'deleted_users'
    quarantine_root.mkdir(parents=True, exist_ok=True)
    quarantined = quarantine_root / f'user_{user_id}_{uuid4().hex}'
    original.replace(quarantined)
    return original, quarantined


def restore_quarantined_user_data(original, quarantined):
    """Restore a quarantined directory after a failed database deletion."""
    if original is None or quarantined is None or not quarantined.exists():
        return
    original.parent.mkdir(parents=True, exist_ok=True)
    quarantined.replace(original)


def delete_user_account(user, socketio_instance=None):
    """Revoke a user and delete their row without exposing retained files."""
    user_id = int(user.id)
    revoke_user_access(user_id, socketio_instance)
    original = quarantined = None

    try:
        original, quarantined = quarantine_user_data(user_id)
        db.session.delete(user)
        db.session.commit()
    except Exception:
        db.session.rollback()
        try:
            restore_quarantined_user_data(original, quarantined)
        except Exception as restore_error:
            log_error(
                "Failed to restore quarantined user data",
                user_id=user_id,
                error=str(restore_error),
            )
        raise

    return quarantined
