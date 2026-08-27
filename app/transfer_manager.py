"""Bounded lifecycle records for HTTP-streamed file transfers."""

import copy
import hmac
import math
import secrets
import threading
import time
from dataclasses import dataclass
from enum import Enum
from collections.abc import Mapping

from .file_sources import SourceHoldSet
from .quota_manager import QuotaKind, quota_manager as default_quota_manager
from .runtime_lifecycle import RuntimeShuttingDown


class TransferState(Enum):
    PENDING = 'pending'
    RUNNING = 'running'
    CANCELLING = 'cancelling'
    CANCELLED = 'cancelled'
    FAILED = 'failed'
    COMPLETED = 'completed'


@dataclass(frozen=True, slots=True)
class TransferCancelResult:
    """Authoritative cancellation state without exposing record existence."""

    accepted: bool
    state: str

    def __post_init__(self):
        if not isinstance(self.accepted, bool):
            raise ValueError('accepted must be boolean')
        if self.state not in {
            'cancelling', 'cancelled', 'completed', 'failed', 'unavailable'
        }:
            raise ValueError('invalid cancellation state')


class InvalidTransferToken(LookupError):
    """Opaque token rejection shared by all unavailable-token cases."""

    def __init__(self):
        super().__init__('Transfer token is invalid or unavailable')


def _normalize_id(value, name):
    if (
        value is None
        or isinstance(value, bool)
        or not isinstance(value, (str, int))
    ):
        raise ValueError(f'{name} is required')
    normalized = str(value).strip()
    if not normalized:
        raise ValueError(f'{name} is required')
    return normalized


class TransferRecord:
    """A transfer descriptor whose identity binding cannot be reassigned."""

    __slots__ = (
        '_transfer_id',
        '_token',
        '_user_id',
        '_owner_sid',
        '_source_id',
        '_source_ids',
        '_source_holds',
        '_direction',
        '_metadata',
        '_state',
        '_cancel_event',
        '_request_done_event',
        '_expires_at',
        '_token_consumed',
        '_quota_reservation',
    )

    def __init__(
        self,
        transfer_id,
        token,
        user_id,
        owner_sid,
        source_id,
        source_ids,
        source_holds,
        direction,
        metadata,
        expires_at,
        quota_reservation,
    ):
        self._transfer_id = transfer_id
        self._token = token
        self._user_id = user_id
        self._owner_sid = owner_sid
        self._source_id = source_id
        self._source_ids = source_ids
        self._source_holds = source_holds
        self._direction = direction
        self._metadata = metadata
        self._state = TransferState.PENDING
        self._cancel_event = threading.Event()
        self._request_done_event = threading.Event()
        self._expires_at = expires_at
        self._token_consumed = False
        self._quota_reservation = quota_reservation

    @property
    def transfer_id(self):
        return self._transfer_id

    @property
    def token(self):
        return self._token

    @property
    def user_id(self):
        return self._user_id

    @property
    def owner_sid(self):
        return self._owner_sid

    @property
    def source_id(self):
        return self._source_id

    @property
    def source_ids(self):
        return self._source_ids

    def release_source_holds(self):
        """Release retained source lifetimes exactly once."""
        return self._source_holds.release()

    @property
    def direction(self):
        return self._direction

    @property
    def metadata(self):
        return copy.deepcopy(self._metadata)

    @property
    def state(self):
        return self._state

    @property
    def cancel_event(self):
        return self._cancel_event

    @property
    def request_done_event(self):
        return self._request_done_event

    @property
    def expires_at(self):
        return self._expires_at

    def __repr__(self):
        return (
            'TransferRecord('
            f'transfer_id={self._transfer_id!r}, '
            f'direction={self._direction!r}, '
            f'state={self._state.value!r})'
        )


class TransferManager:
    """Own transfer records, one-use tokens, and transfer quota slots."""

    DIRECTIONS = frozenset({'upload', 'download', 'server_to_server'})
    _DUMMY_TOKEN = 'A' * 43

    def __init__(
        self,
        quota_manager=default_quota_manager,
        token_ttl=300,
        clock=time.monotonic,
    ):
        if quota_manager is None or not hasattr(quota_manager, 'reserve'):
            raise ValueError('quota_manager must support reserve')
        if (
            isinstance(token_ttl, bool)
            or not isinstance(token_ttl, (int, float))
            or not math.isfinite(token_ttl)
            or token_ttl <= 0
        ):
            raise ValueError('token_ttl must be a positive finite number')
        if not callable(clock):
            raise ValueError('clock must be callable')

        self._quota_manager = quota_manager
        self._token_ttl = float(token_ttl)
        self._clock = clock
        self._lock = threading.Lock()
        self._records = {}
        self._terminal_states = {}
        self._runtime_binding = None
        self._accepting = True

    def bind_runtime(self):
        """Open this worker manager for one app-runtime generation."""
        binding = object()
        with self._lock:
            self._runtime_binding = binding
            self._accepting = True
        return binding

    def create(
        self,
        user_id,
        source_id,
        direction,
        metadata,
        owner_sid=None,
        *,
        source_ids=None,
        source_holds=None,
    ):
        user_id = _normalize_id(user_id, 'user_id')
        source_id = _normalize_id(source_id, 'source_id')
        if source_ids is None:
            source_ids = (source_id,)
        elif isinstance(source_ids, (str, bytes)):
            raise ValueError('source_ids must be a sequence')
        else:
            try:
                source_ids = tuple(
                    _normalize_id(value, 'source_id')
                    for value in source_ids
                )
            except TypeError as exc:
                raise ValueError('source_ids must be a sequence') from exc
        if not 1 <= len(source_ids) <= 2 or source_ids[0] != source_id:
            raise ValueError('source_ids are invalid')
        unique_source_ids = tuple(dict.fromkeys(source_ids))
        if source_holds is None:
            source_holds = SourceHoldSet(unique_source_ids)
        elif (
            not isinstance(source_holds, SourceHoldSet)
            or source_holds.source_ids != unique_source_ids
        ):
            raise ValueError('source_holds do not match source_ids')
        if owner_sid is not None:
            owner_sid = _normalize_id(owner_sid, 'owner_sid')
        if not isinstance(direction, str) or direction not in self.DIRECTIONS:
            raise ValueError('direction is invalid')
        if not isinstance(metadata, Mapping):
            raise ValueError('metadata must be a mapping')
        try:
            metadata_copy = copy.deepcopy(dict(metadata))
        except Exception as exc:
            raise ValueError('metadata must be copyable') from exc

        now = self._clock()
        try:
            with self._lock:
                if not self._accepting:
                    raise RuntimeShuttingDown(
                        'runtime lifecycle is shutting down'
                    )
                self._cleanup_expired_locked(now)
                transfer_id = self._unique_transfer_id_locked()
                token = self._unique_token_locked()
                record = TransferRecord(
                    transfer_id=transfer_id,
                    token=token,
                    user_id=user_id,
                    owner_sid=owner_sid,
                    source_id=source_id,
                    source_ids=source_ids,
                    source_holds=source_holds,
                    direction=direction,
                    metadata=metadata_copy,
                    expires_at=now + self._token_ttl,
                    quota_reservation=None,
                )
                reservation = self._quota_manager.reserve(
                    QuotaKind.TRANSFER, user_id
                )
                record._quota_reservation = reservation
                self._records[transfer_id] = record
            return record
        except Exception:
            try:
                source_holds.release()
            except Exception:
                pass
            raise

    def consume_token(self, token, user_id):
        token_is_valid = self._valid_token(token)
        candidate_token = token if token_is_valid else self._DUMMY_TOKEN
        try:
            user_id = _normalize_id(user_id, 'user_id')
            user_is_valid = True
        except ValueError:
            user_id = ''
            user_is_valid = False

        with self._lock:
            if not self._accepting:
                raise RuntimeShuttingDown('runtime lifecycle is shutting down')
            self._cleanup_expired_locked(self._clock())
            record = self._find_token_locked(candidate_token)
            if (
                not token_is_valid
                or not user_is_valid
                or record is None
                or record._token_consumed
                or record._user_id != user_id
                or record._state is not TransferState.PENDING
            ):
                raise InvalidTransferToken()
            record._token_consumed = True
            record._token = None
            record._state = TransferState.RUNNING
            return record

    def cancel(self, transfer_id, user_id):
        return self.cancel_with_result(transfer_id, user_id).accepted

    def cancel_with_result(self, transfer_id, user_id):
        """Request cancellation once without claiming running I/O has stopped."""
        try:
            transfer_id = _normalize_id(transfer_id, 'transfer_id')
            user_id = _normalize_id(user_id, 'user_id')
        except ValueError:
            return TransferCancelResult(False, 'unavailable')

        with self._lock:
            self._cleanup_expired_locked(self._clock())
            record = self._records.get(transfer_id)
            if record is not None and record._user_id == user_id:
                if record._state is TransferState.PENDING:
                    release_error = self._release_for_terminal(
                        record,
                        release_source_holds=True,
                    )
                    self._finalize_record_locked(
                        record,
                        TransferState.CANCELLED,
                        set_cancel_event=True,
                    )
                    if release_error is not None:
                        raise release_error
                    return TransferCancelResult(True, 'cancelled')
                if record._state is TransferState.RUNNING:
                    record._state = TransferState.CANCELLING
                    record._cancel_event.set()
                    return TransferCancelResult(True, 'cancelling')
                if record._state is TransferState.CANCELLING:
                    return TransferCancelResult(False, 'cancelling')

            terminal = self._terminal_states.get(transfer_id)
            if terminal is not None and terminal[0] == user_id:
                return TransferCancelResult(False, terminal[1])
            return TransferCancelResult(False, 'unavailable')

    def cancel_all_for_user(self, user_id):
        """Atomically cancel every pending or running transfer for one user."""
        try:
            user_id = _normalize_id(user_id, 'user_id')
        except ValueError:
            return 0

        with self._lock:
            self._cleanup_expired_locked(self._clock())
            records = [
                record for record in self._records.values()
                if (
                    record._user_id == user_id
                    and record._state in {
                        TransferState.PENDING,
                        TransferState.RUNNING,
                    }
                )
            ]
            return self._cancel_records_locked(records)

    def close_and_cancel(self, binding):
        """Atomically reject new transfers and cancel this runtime generation."""
        with self._lock:
            if binding is not self._runtime_binding:
                return ()
            self._accepting = False
            self._cleanup_expired_locked(self._clock())
            records = [
                record for record in self._records.values()
                if record._state in {
                    TransferState.PENDING,
                    TransferState.RUNNING,
                    TransferState.CANCELLING,
                }
            ]
            waiters = tuple(
                (
                    f'http_{record._direction}',
                    record._transfer_id,
                    record._request_done_event,
                )
                for record in records
                if (
                    record._direction in {'upload', 'download'}
                    and record._state in {
                        TransferState.RUNNING,
                        TransferState.CANCELLING,
                    }
                )
            )
            self._cancel_records_locked(records)
            return waiters

    def cancel_all_for_socket(self, user_id, owner_sid):
        """Atomically cancel pending or running transfers owned by one Socket."""
        try:
            user_id = _normalize_id(user_id, 'user_id')
            owner_sid = _normalize_id(owner_sid, 'owner_sid')
        except ValueError:
            return 0

        with self._lock:
            self._cleanup_expired_locked(self._clock())
            records = [
                record for record in self._records.values()
                if (
                    record._user_id == user_id
                    and record._owner_sid == owner_sid
                    and record._state in {
                        TransferState.PENDING,
                        TransferState.RUNNING,
                    }
                )
            ]
            return self._cancel_records_locked(records)

    def complete(self, transfer_id, user_id):
        return self._transition(
            transfer_id,
            user_id,
            allowed_states={
                TransferState.RUNNING,
                TransferState.CANCELLING,
            },
            target_state=TransferState.COMPLETED,
        )

    def fail(self, transfer_id, user_id):
        return self._transition(
            transfer_id,
            user_id,
            allowed_states={
                TransferState.PENDING,
                TransferState.RUNNING,
                TransferState.CANCELLING,
            },
            target_state=TransferState.FAILED,
        )

    def finish_cancelled(self, transfer_id, user_id):
        """Confirm that a worker observed cancellation and stopped its I/O."""
        return self._transition(
            transfer_id,
            user_id,
            allowed_states={
                TransferState.RUNNING,
                TransferState.CANCELLING,
            },
            target_state=TransferState.CANCELLED,
        )

    def cleanup_expired(self):
        """Expire unused tokens and return the number of released records."""
        with self._lock:
            return self._cleanup_expired_locked(self._clock())

    def cleanup_loop(self, cancel_event):
        """Release unused token holds without requiring later user activity."""
        interval = max(1.0, min(30.0, self._token_ttl / 2.0))
        while not cancel_event.wait(interval):
            self.cleanup_expired()

    def _cancel_records_locked(self, records):
        cancelled = 0
        for record in records:
            if record._state is TransferState.CANCELLING:
                continue
            if record._state is TransferState.RUNNING:
                record._state = TransferState.CANCELLING
                record._cancel_event.set()
                cancelled += 1
                continue
            if record._state is TransferState.PENDING:
                try:
                    self._release_for_terminal(
                        record,
                        release_source_holds=True,
                    )
                except Exception:
                    self._release_for_terminal(
                        record,
                        release_source_holds=True,
                    )
                self._finalize_record_locked(
                    record,
                    TransferState.CANCELLED,
                    set_cancel_event=True,
                )
                cancelled += 1
        return cancelled

    def _transition(
        self,
        transfer_id,
        user_id,
        allowed_states,
        target_state,
    ):
        try:
            transfer_id = _normalize_id(transfer_id, 'transfer_id')
            user_id = _normalize_id(user_id, 'user_id')
        except ValueError:
            return False

        with self._lock:
            self._cleanup_expired_locked(self._clock())
            record = self._records.get(transfer_id)
            if (
                record is None
                or record._user_id != user_id
                or record._state not in allowed_states
            ):
                return False
            release_error = self._release_for_terminal(
                record,
                release_source_holds=not (
                    target_state is TransferState.CANCELLED
                    and record._state in {
                        TransferState.RUNNING,
                        TransferState.CANCELLING,
                    }
                ),
            )
            self._finalize_record_locked(
                record,
                target_state,
                set_cancel_event=target_state is TransferState.CANCELLED,
            )
            if release_error is not None:
                raise release_error
            return True

    def _find_token_locked(self, token):
        match = None
        for record in self._records.values():
            if (
                record._token is not None
                and hmac.compare_digest(token, record._token)
            ):
                match = record
        return match

    @staticmethod
    def _valid_token(token):
        return (
            isinstance(token, str)
            and len(token) == 43
            and token.isascii()
            and all(
                character.isalnum() or character in '-_'
                for character in token
            )
        )

    def _unique_transfer_id_locked(self):
        while True:
            transfer_id = secrets.token_urlsafe(18)
            if (
                transfer_id not in self._records
                and transfer_id not in self._terminal_states
            ):
                return transfer_id

    def _unique_token_locked(self):
        while True:
            token = secrets.token_urlsafe(32)
            if self._find_token_locked(token) is None:
                return token

    @staticmethod
    def _release_for_terminal(record, *, release_source_holds=True):
        release_error = None
        try:
            record._quota_reservation.release()
        except Exception as exc:
            if not record._quota_reservation.released:
                raise
            release_error = exc
        if release_source_holds:
            try:
                record.release_source_holds()
            except Exception as exc:
                if release_error is None:
                    release_error = exc
        return release_error

    def _finalize_record_locked(
        self,
        record,
        target_state,
        set_cancel_event,
    ):
        record._state = target_state
        record._token = None
        record._token_consumed = True
        if set_cancel_event:
            record._cancel_event.set()
        self._records.pop(record._transfer_id, None)
        self._terminal_states[record._transfer_id] = (
            record._user_id,
            target_state.value,
            self._clock() + self._token_ttl,
        )

    def _cleanup_expired_locked(self, now):
        self._terminal_states = {
            transfer_id: terminal
            for transfer_id, terminal in self._terminal_states.items()
            if now < terminal[2]
        }
        expired = [
            transfer_id
            for transfer_id, record in self._records.items()
            if (
                not record._token_consumed
                and record._state is TransferState.PENDING
                and now >= record._expires_at
            )
        ]
        for transfer_id in expired:
            record = self._records[transfer_id]
            release_error = self._release_for_terminal(record)
            self._finalize_record_locked(
                record,
                TransferState.FAILED,
                set_cancel_event=True,
            )
            if release_error is not None:
                raise release_error
        return len(expired)
