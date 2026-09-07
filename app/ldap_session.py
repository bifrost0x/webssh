"""Periodic validation for authenticated LDAP-managed sessions."""

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from threading import RLock

from . import user_lifecycle
from .audit_logger import log_security_event
from .ldap_service import LDAPDirectory, LDAPLookupRejected, LDAPUnavailable
from .models import LDAPIdentity, User, db
from .backup_coordination import persistent_write
from .storage_utils import atomic_write_bytes, fsync_parent_directory


@dataclass(frozen=True)
class LDAPValidationReceipt:
    """One process-local, identity-bound successful LDAP validation."""

    verified_at_epoch: int
    completed_monotonic: float
    identity_key: tuple


class LDAPValidationInProgress(RuntimeError):
    """A foreground request must retry instead of waiting for LDAP."""


class LDAPRevocationFence:
    """Fail closed across threads and restarts while revocation is pending."""

    def __init__(self, marker_directory, *, clock=None, epoch_clock=None):
        self._lock = RLock()
        self._pending = set()
        self._validating = {}
        self._validation_locks = {}
        self._successful_validations = {}
        self._marker_directory = Path(marker_directory)
        self._clock = clock or time.monotonic
        self._epoch_clock = epoch_clock or time.time

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

    def monotonic_now(self):
        return float(self._clock())

    def recent_validation(
        self,
        user_id,
        identity_key,
        *,
        not_before_monotonic,
    ):
        """Return an eligible trusted success without sliding its timestamp."""
        user_id = int(user_id)
        identity_key = tuple(identity_key)
        with self._lock:
            if user_id in self._pending:
                return None
            if (
                user_id not in self._validating
                and self._marker_exists_locked(user_id)
            ):
                return None
            receipt = self._successful_validations.get(user_id)
            if receipt is None:
                return None
            if receipt.identity_key != identity_key:
                self._successful_validations.pop(user_id, None)
                return None
            if not (
                receipt.completed_monotonic
                > float(not_before_monotonic)
            ):
                return None
            return receipt

    def begin_validation(self, user_id):
        """Persist uncertainty before consulting the external directory."""
        user_id = int(user_id)
        with self._lock:
            if (
                user_id in self._pending
                or self._marker_exists_locked(user_id)
            ):
                self._pending.add(user_id)
                self._successful_validations.pop(user_id, None)
                raise LDAPLookupRejected('LDAP revocation is pending')
            # Other threads in this process may continue using the last known
            # valid result while the lookup runs.  If this process dies, the
            # marker is discovered by the replacement process and fails closed.
            token = object()
            self._validating[user_id] = token
            try:
                self._write_marker_locked(user_id)
            except BaseException:
                self._validating.pop(user_id, None)
                self._pending.add(user_id)
                self._successful_validations.pop(user_id, None)
                raise
            return token

    def fail_validation(self, user_id, token):
        user_id = int(user_id)
        with self._lock:
            if self._validating.get(user_id) is not token:
                return
            self._validating.pop(user_id, None)
            self._pending.add(user_id)
            self._successful_validations.pop(user_id, None)

    def _discard_marker_locked(self, user_id):
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

    def complete_validation(self, user_id, token, identity_key):
        """Publish success only if no newer invalidation replaced this run."""
        user_id = int(user_id)
        identity_key = tuple(identity_key)
        with self._lock:
            if (
                self._validating.get(user_id) is not token
                or user_id in self._pending
            ):
                raise LDAPLookupRejected('LDAP revocation is pending')
            self._discard_marker_locked(user_id)
            self._validating.pop(user_id, None)
            self._pending.discard(user_id)
            receipt = LDAPValidationReceipt(
                verified_at_epoch=int(self._epoch_clock()),
                completed_monotonic=float(self._clock()),
                identity_key=identity_key,
            )
            self._successful_validations[user_id] = receipt
            return receipt

    def mark(self, user_id):
        user_id = int(user_id)
        with self._lock:
            self._validating.pop(user_id, None)
            self._pending.add(user_id)
            self._successful_validations.pop(user_id, None)
            self._write_marker_locked(user_id)

    def discard(self, user_id):
        user_id = int(user_id)
        with self._lock:
            self._discard_marker_locked(user_id)
            self._pending.discard(user_id)
            self._validating.pop(user_id, None)
            self._successful_validations.pop(user_id, None)

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


def _validation_identity_key(user):
    mapping = user.ldap_identity
    if mapping is None or user.is_locked or user.is_admin:
        raise LDAPLookupRejected('LDAP account is not eligible')
    return (
        int(user.auth_generation or 0),
        int(mapping.id),
        str(mapping.provider),
        str(mapping.subject),
        str(mapping.directory_username),
    )


def _perform_durable_validation(fence, user, identity_key):
    token = None
    try:
        token = fence.begin_validation(user.id)
    except LDAPLookupRejected:
        raise
    except BaseException as error:
        raise LDAPUnavailable('LDAP revocation fence unavailable') from error
    try:
        revalidate_user(user)
    except BaseException:
        fence.fail_validation(user.id, token)
        raise
    try:
        return fence.complete_validation(user.id, token, identity_key)
    except LDAPLookupRejected:
        fence.fail_validation(user.id, token)
        raise
    except BaseException as error:
        fence.fail_validation(user.id, token)
        raise LDAPUnavailable('LDAP revocation fence unavailable') from error


def ensure_recent_ldap_validation(app, user, *, max_age_seconds):
    """Reuse or elect one nonblocking foreground LDAP validation."""
    fence = _revocation_fence(app)
    max_age_seconds = float(max_age_seconds)
    if max_age_seconds <= 0:
        raise ValueError('LDAP validation maximum age must be positive')
    identity_key = _validation_identity_key(user)
    not_before = fence.monotonic_now() - max_age_seconds
    receipt = fence.recent_validation(
        user.id,
        identity_key,
        not_before_monotonic=not_before,
    )
    if receipt is not None:
        return receipt

    validation_lock = fence.validation_lock(user.id)
    if not validation_lock.acquire(blocking=False):
        receipt = fence.recent_validation(
            user.id,
            identity_key,
            not_before_monotonic=(
                fence.monotonic_now() - max_age_seconds
            ),
        )
        if receipt is not None:
            return receipt
        raise LDAPValidationInProgress('LDAP validation is in progress')
    try:
        identity_key = _validation_identity_key(user)
        receipt = fence.recent_validation(
            user.id,
            identity_key,
            not_before_monotonic=(
                fence.monotonic_now() - max_age_seconds
            ),
        )
        if receipt is not None:
            return receipt
        return _perform_durable_validation(fence, user, identity_key)
    finally:
        validation_lock.release()


def revalidate_user_durably(
    app,
    user,
    *,
    not_before_monotonic=None,
):
    """Revalidate LDAP while a crash-recoverable uncertainty marker exists."""
    fence = _revocation_fence(app)
    with fence.validation_lock(user.id):
        identity_key = _validation_identity_key(user)
        if not_before_monotonic is not None:
            receipt = fence.recent_validation(
                user.id,
                identity_key,
                not_before_monotonic=not_before_monotonic,
            )
            if receipt is not None:
                return receipt
        return _perform_durable_validation(fence, user, identity_key)


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
        sweep_started = _revocation_fence(app).monotonic_now()
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
                revalidate_user_durably(
                    app,
                    user,
                    not_before_monotonic=sweep_started,
                )
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
