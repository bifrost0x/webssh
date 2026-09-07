"""Periodic validation for authenticated LDAP-managed sessions."""

import logging
from pathlib import Path
from threading import RLock

from . import user_lifecycle
from .audit_logger import log_security_event
from .ldap_service import LDAPDirectory, LDAPLookupRejected, LDAPUnavailable
from .models import LDAPIdentity, User, db
from .backup_coordination import persistent_write
from .storage_utils import atomic_write_bytes, fsync_parent_directory


class LDAPRevocationFence:
    """Fail closed across threads and restarts while revocation is pending."""

    def __init__(self, marker_directory):
        self._lock = RLock()
        self._pending = set()
        self._validating = set()
        self._validation_locks = {}
        self._marker_directory = Path(marker_directory)

    def _marker_path(self, user_id):
        return self._marker_directory / str(int(user_id))

    def _marker_exists_locked(self, user_id):
        try:
            self._marker_path(user_id).lstat()
        except FileNotFoundError:
            return False
        except OSError:
            # An unreadable durable fence must deny access, not silently turn
            # into an empty in-memory state after a restart.
            return True
        return True

    def _write_marker_locked(self, user_id):
        self._marker_directory.mkdir(
            parents=True,
            exist_ok=True,
            mode=0o700,
        )
        atomic_write_bytes(
            self._marker_path(user_id),
            b'pending\n',
            mode=0o600,
        )

    def validation_lock(self, user_id):
        user_id = int(user_id)
        with self._lock:
            return self._validation_locks.setdefault(user_id, RLock())

    def begin_validation(self, user_id):
        """Persist uncertainty before consulting the external directory."""
        user_id = int(user_id)
        with self._lock:
            if (
                user_id in self._pending
                or self._marker_exists_locked(user_id)
            ):
                self._pending.add(user_id)
                raise LDAPLookupRejected('LDAP revocation is pending')
            # Other threads in this process may continue using the last known
            # valid result while the lookup runs.  If this process dies, the
            # marker is discovered by the replacement process and fails closed.
            self._validating.add(user_id)
            try:
                self._write_marker_locked(user_id)
            except BaseException:
                self._validating.discard(user_id)
                self._pending.add(user_id)
                raise

    def fail_validation(self, user_id):
        user_id = int(user_id)
        with self._lock:
            self._validating.discard(user_id)
            self._pending.add(user_id)

    def complete_validation(self, user_id):
        self.discard(user_id)

    def mark(self, user_id):
        user_id = int(user_id)
        with self._lock:
            self._validating.discard(user_id)
            self._pending.add(user_id)
            self._write_marker_locked(user_id)

    def discard(self, user_id):
        user_id = int(user_id)
        with self._lock:
            marker = self._marker_path(user_id)
            removed = False
            with persistent_write():
                try:
                    marker.unlink()
                    removed = True
                except FileNotFoundError:
                    pass
                if removed:
                    fsync_parent_directory(marker)
            self._pending.discard(user_id)
            self._validating.discard(user_id)

    def contains(self, user_id):
        user_id = int(user_id)
        with self._lock:
            if user_id in self._pending:
                return True
            if user_id in self._validating:
                return False
            return self._marker_exists_locked(user_id)


def _revocation_fence(app):
    fence = app.extensions.get('ldap_revocation_fence')
    if not isinstance(fence, LDAPRevocationFence):
        raise RuntimeError('LDAP revocation fence is unavailable')
    return fence


def ldap_revocation_pending(app, user_id):
    return _revocation_fence(app).contains(user_id)


def revalidate_user_durably(app, user):
    """Revalidate LDAP while a crash-recoverable uncertainty marker exists."""
    fence = _revocation_fence(app)
    with fence.validation_lock(user.id):
        try:
            fence.begin_validation(user.id)
        except LDAPLookupRejected:
            raise
        except BaseException as error:
            raise LDAPUnavailable('LDAP revocation fence unavailable') from error
        try:
            resolved = revalidate_user(user)
        except BaseException:
            fence.fail_validation(user.id)
            raise
        try:
            fence.complete_validation(user.id)
        except BaseException as error:
            fence.fail_validation(user.id)
            raise LDAPUnavailable('LDAP revocation fence unavailable') from error
        return resolved


def persist_ldap_authentication_invalidation(app, user):
    """Invalidate old credentials or retain a durable deny fence."""
    fence = _revocation_fence(app)
    marker_error = None
    marker_control_flow = None
    try:
        fence.mark(user.id)
    except BaseException as error:
        # The database generation/session boundary is an independent durable
        # fallback. A marker I/O failure must not skip that invalidation.
        marker_error = error
        if not isinstance(error, Exception):
            marker_control_flow = error
    try:
        from .auth_assurance import invalidate_user_authentication

        invalidate_user_authentication(user)
        db.session.commit()
    except Exception as database_error:
        db.session.rollback()
        if marker_control_flow is not None:
            raise marker_control_flow from database_error
        return database_error
    except BaseException:
        db.session.rollback()
        raise
    try:
        fence.discard(user.id)
    except Exception as error:
        if marker_control_flow is not None:
            raise marker_control_flow from error
        return error
    if marker_error is not None and marker_control_flow is None:
        log_security_event(
            'LDAP_REVOCATION_MARKER_WRITE_FAILED',
            level=logging.ERROR,
            user=user.username,
            error=type(marker_error).__name__,
        )
    if marker_control_flow is not None:
        raise marker_control_flow
    return None


def revalidate_user(user):
    mapping = user.ldap_identity
    if mapping is None or user.is_locked or user.is_admin:
        raise LDAPLookupRejected('LDAP account is not eligible')
    resolved = LDAPDirectory().lookup(mapping.directory_username)
    if resolved.provider != mapping.provider or resolved.subject != mapping.subject:
        raise LDAPLookupRejected('Stable LDAP identity no longer matches')
    return resolved


def revalidate_all_linked_users(app, socketio_instance=None):
    """Revoke live access for mappings that no longer validate."""
    with app.app_context():
        user_ids = [
            user_id
            for (user_id,) in (
                db.session.query(LDAPIdentity.user_id)
                .order_by(LDAPIdentity.user_id)
                .all()
            )
        ]
        for user_id in user_ids:
            user = db.session.get(User, user_id)
            if user is None:
                continue
            if ldap_revocation_pending(app, user_id):
                invalidation_error = persist_ldap_authentication_invalidation(
                    app,
                    user,
                )
                if invalidation_error is not None:
                    log_security_event(
                        'LDAP_BACKGROUND_AUTHENTICATION_INVALIDATION_FAILED',
                        level=logging.ERROR,
                        user=user.username,
                        error=type(invalidation_error).__name__,
                    )
                user_lifecycle.revoke_user_access(
                    user_id,
                    socketio_instance,
                )
                continue
            try:
                revalidate_user_durably(app, user)
            except (LDAPLookupRejected, LDAPUnavailable) as exc:
                username = user.username
                log_security_event(
                    'LDAP_BACKGROUND_REVALIDATION_REJECTED',
                    level=logging.WARNING,
                    user=username,
                    error=type(exc).__name__,
                )
                invalidation_error = persist_ldap_authentication_invalidation(
                    app,
                    user,
                )
                if invalidation_error is not None:
                    log_security_event(
                        'LDAP_BACKGROUND_AUTHENTICATION_INVALIDATION_FAILED',
                        level=logging.ERROR,
                        user=username,
                        error=type(invalidation_error).__name__,
                    )
                user_lifecycle.revoke_user_access(
                    user_id,
                    socketio_instance,
                )
