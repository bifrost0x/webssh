"""Transactional web restore orchestration and reliable process restart."""

import os
from pathlib import Path
import signal
import threading
import time

import config

from . import connection_pool, ssh_manager
from .audit_logger import log_security_event
from .backup_coordination import operation_lock, require_durable_recovery_storage
from .backup_manager import restore_backup
from .backup_operations import backup_operations
from .online_backup import create_online_backup
from .maintenance_mode import (
    begin_preparing,
    mark_failed,
    mark_in_progress,
    mark_succeeded,
)
from .session_epoch import reset_cache, rotate_epoch
from .restore_sanitizer import sanitize_restored_authentication_state


def _close_active_ssh_sessions():
    with ssh_manager.sessions_lock:
        session_ids = tuple(ssh_manager.sessions)
    for session_id in session_ids:
        ssh_manager.close_session(session_id, kill_tmux=False)


def _disconnect_sockets(socketio):
    server = getattr(socketio, 'server', None)
    manager = getattr(server, 'manager', None)
    if server is None or manager is None:
        return
    try:
        participants = tuple(manager.get_participants('/', None))
    except Exception:
        participants = ()
    from .socket_events import (
        disconnect_engineio_transport,
        disconnect_socket_transport,
    )

    for participant in participants:
        sid = participant[0] if isinstance(participant, tuple) else participant
        try:
            disconnect_socket_transport(server, sid)
        except Exception:
            continue

    engineio_server = getattr(server, 'eio', None)
    capacity = getattr(
        engineio_server,
        '_webssh_socket_capacity',
        None,
    )
    engineio_sids = capacity.sids() if capacity is not None else ()
    for engineio_sid in engineio_sids:
        try:
            disconnect_engineio_transport(
                server,
                engineio_sid,
                drain=False,
            )
        except Exception:
            continue


def _clear_restored_runtime_sessions(database_path: Path):
    """Compatibility wrapper for the complete post-restore sanitizer."""
    return sanitize_restored_authentication_state(database_path)


def request_process_restart(delay=1.0):
    time.sleep(delay)
    if 'gunicorn' in os.environ.get('SERVER_SOFTWARE', '').lower():
        os.kill(os.getppid(), signal.SIGTERM)
    os._exit(0)


def _perform_restore(app, socketio, record, username, source_ip,
                     restart_callback):
    operation_id = record.operation_id
    rollback_archive = record.directory / 'rollback.zip'
    restart_required = False
    runtime_stopped = False
    rollback_available = False
    rollback_failed = False
    try:
        with operation_lock() as token:
            begin_preparing(operation_id)
            lifecycle = app.extensions['runtime_lifecycle']
            shutdown = lifecycle.begin_shutdown(
                config.RUNTIME_SHUTDOWN_GRACE_SECONDS
            )
            runtime_stopped = True
            if shutdown.remaining:
                raise RuntimeError(
                    'runtime activity did not stop before restore'
                )
            _close_active_ssh_sessions()
            connection_pool.temp_connection_pool.close_all_connections()
            _disconnect_sockets(socketio)

            with app.app_context():
                from .models import db
                db.session.remove()
                db.engine.dispose()

            create_online_backup(
                config.DATA_DIR,
                rollback_archive,
                held_token=token,
            )
            rollback_available = True
            relative = rollback_archive.relative_to(
                record.directory.parent
            ).as_posix()
            mark_in_progress(operation_id, relative)

            restore_backup(record.archive_path, config.DATA_DIR)
            _clear_restored_runtime_sessions(Path(config.DATA_DIR) / 'app.db')
            reset_cache()
            rotate_epoch()
            mark_succeeded(operation_id)
            log_security_event(
                'RESTORE_SUCCEEDED', user=username, ip=source_ip
            )
            restart_required = True
    except Exception as restore_error:
        if rollback_available:
            try:
                restore_backup(rollback_archive, config.DATA_DIR)
                _clear_restored_runtime_sessions(
                    Path(config.DATA_DIR) / 'app.db'
                )
                reset_cache()
                rotate_epoch()
                restart_required = True
            except Exception:
                rollback_failed = True
        mark_failed(
            operation_id,
            (
                'Restore failed and emergency rollback failed; use CLI recovery'
                if rollback_failed
                else (
                    'Restore failed; original state was restored'
                    if rollback_available
                    else 'Restore failed before persistent state changed'
                )
            ),
            rollback_failed=rollback_failed,
        )
        log_security_event(
            'RESTORE_FAILED',
            user=username,
            ip=source_ip,
            error_type=type(restore_error).__name__,
            rollback_failed=rollback_failed,
        )
    finally:
        if not rollback_failed:
            backup_operations.remove(operation_id)
        if restart_required or runtime_stopped:
            restart_callback()

def start_restore(app, socketio, record, username, source_ip,
                  restart_callback=request_process_restart):
    require_durable_recovery_storage()
    launched = threading.Event()

    def run_restore():
        launched.set()
        _perform_restore(
            app,
            socketio,
            record,
            username,
            source_ip,
            restart_callback,
        )

    thread = threading.Thread(
        target=run_restore,
        name='webssh-restore',
        daemon=False,
    )
    try:
        thread.start()
    except BaseException as error:
        # A non-Exception interruption can land after the OS thread was
        # created but before Thread.ident or the target's event is observable.
        # That state is inherently ambiguous, so keep the operation restoring
        # and never permit a second worker against the same archive.
        worker_started = (
            not isinstance(error, Exception)
            or launched.is_set()
            or getattr(thread, 'ident', None) is not None
        )
        try:
            error.restore_worker_started = worker_started
        except Exception:
            pass
        raise
    return thread
