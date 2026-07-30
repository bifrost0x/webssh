"""Atomic in-process resource quotas.

The application deliberately runs as a single worker because SSH connection
state is process-local. These quotas share that lifecycle and make capacity
checks and reservations one atomic operation inside the worker.
"""

from enum import Enum
from threading import Lock

import config


class QuotaKind(Enum):
    SSH_SESSION = 'ssh_session'
    QUICK_CONNECTION = 'quick_connection'
    TRANSFER = 'transfer'
    TEMP_BYTES = 'temp_bytes'
    BACKGROUND_JOB = 'background_job'


class QuotaExceeded(RuntimeError):
    """Raised when a reservation would exceed a configured quota."""

    def __init__(self, kind, limit, scope):
        self.kind = kind
        self.limit = limit
        self.scope = scope
        super().__init__(
            f'{kind.value} quota exceeded ({scope} limit {limit})'
        )


def _positive_integer(value, name):
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f'{name} must be a positive integer')
    return value


class Reservation:
    """A quota reservation that can safely be released more than once."""

    def __init__(self, manager, kind, user_id, amount):
        self._manager = manager
        self.kind = kind
        self.user_id = user_id
        self.amount = amount
        self._released = False

    @property
    def released(self):
        return self._released

    def release(self):
        self._manager._release(self)

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc_value, _traceback):
        self.release()
        return False


class QuotaManager:
    """Track global and per-user resource consumption under one lock."""

    def __init__(self, limits):
        expected = set(QuotaKind)
        if set(limits) != expected:
            raise ValueError('limits must configure every quota kind')

        self._limits = {}
        for kind, kind_limits in limits.items():
            if not isinstance(kind, QuotaKind):
                raise ValueError('quota limit keys must be QuotaKind values')
            if set(kind_limits) != {'global', 'per_user'}:
                raise ValueError(
                    f'{kind.value} requires global and per_user limits'
                )
            global_limit = _positive_integer(
                kind_limits['global'], f'{kind.value} global limit'
            )
            per_user_limit = _positive_integer(
                kind_limits['per_user'], f'{kind.value} per-user limit'
            )
            fair_slot_kinds = {
                QuotaKind.SSH_SESSION,
                QuotaKind.QUICK_CONNECTION,
                QuotaKind.TRANSFER,
            }
            if (
                per_user_limit > global_limit
                or (
                    kind in fair_slot_kinds
                    and per_user_limit == global_limit
                )
            ):
                raise ValueError(
                    f'{kind.value} per-user limit must be below global limit'
                )
            self._limits[kind] = {
                'global': global_limit,
                'per_user': per_user_limit,
            }

        self._lock = Lock()
        self._global_counts = {}
        self._user_counts = {}

    @classmethod
    def from_config(cls):
        return cls({
            QuotaKind.SSH_SESSION: {
                'global': config.QUOTA_SSH_SESSION_GLOBAL,
                'per_user': config.QUOTA_SSH_SESSION_PER_USER,
            },
            QuotaKind.QUICK_CONNECTION: {
                'global': config.QUOTA_QUICK_CONNECTION_GLOBAL,
                'per_user': config.QUOTA_QUICK_CONNECTION_PER_USER,
            },
            QuotaKind.TRANSFER: {
                'global': config.QUOTA_TRANSFER_GLOBAL,
                'per_user': config.QUOTA_TRANSFER_PER_USER,
            },
            QuotaKind.TEMP_BYTES: {
                'global': config.QUOTA_TEMP_BYTES_GLOBAL,
                'per_user': config.QUOTA_TEMP_BYTES_PER_USER,
            },
            QuotaKind.BACKGROUND_JOB: {
                'global': config.QUOTA_BACKGROUND_JOB_GLOBAL,
                'per_user': config.QUOTA_BACKGROUND_JOB_PER_USER,
            },
        })

    def reserve(self, kind, user_id, amount=1):
        if not isinstance(kind, QuotaKind):
            raise ValueError('kind must be a QuotaKind')
        amount = _positive_integer(amount, 'reservation amount')
        if user_id is None or isinstance(user_id, bool):
            raise ValueError('user_id is required')
        user_id = str(user_id)
        user_key = (kind, user_id)

        with self._lock:
            limits = self._limits[kind]
            user_total = self._user_counts.get(user_key, 0)
            if user_total + amount > limits['per_user']:
                raise QuotaExceeded(
                    kind, limits['per_user'], 'per_user'
                )

            global_total = self._global_counts.get(kind, 0)
            if global_total + amount > limits['global']:
                raise QuotaExceeded(kind, limits['global'], 'global')

            self._user_counts[user_key] = user_total + amount
            self._global_counts[kind] = global_total + amount

        return Reservation(self, kind, user_id, amount)

    def _release(self, reservation):
        with self._lock:
            if reservation._released:
                return

            user_key = (reservation.kind, reservation.user_id)
            user_total = self._user_counts[user_key] - reservation.amount
            global_total = (
                self._global_counts[reservation.kind] - reservation.amount
            )

            if user_total:
                self._user_counts[user_key] = user_total
            else:
                del self._user_counts[user_key]
            if global_total:
                self._global_counts[reservation.kind] = global_total
            else:
                del self._global_counts[reservation.kind]
            reservation._released = True


def release_reservation(reservation):
    """Release an optional reservation without disrupting cleanup paths."""
    if reservation is None:
        return
    try:
        reservation.release()
    except Exception as exc:
        from .audit_logger import log_error

        log_error(
            "Quota reservation release failed",
            error_type=type(exc).__name__,
        )


quota_manager = QuotaManager.from_config()
