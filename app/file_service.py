"""Authorization and capability boundary for all file source operations."""

import hashlib
import hmac
import re
import secrets
import time
from threading import Event, Lock, RLock, Timer

import config

from .file_backend import FileWriteOutcome
from .file_sources import (
    FileCapability,
    FileSourceKind,
    FileSourceUnavailable,
    file_source_resolver,
)
from .sftp_backend import SFTPBackend
from .smb_backend import smb_backend


class FileService:
    """Resolve a source and authorize one named operation before dispatch."""

    def __init__(self, resolver):
        self.resolver = resolver
        self._directory_snapshots = {}
        self._directory_snapshot_lock = Lock()

    def resolve(self, source_id, user_id, capability):
        source = self.resolver.resolve(source_id, user_id)
        required = FileCapability(capability)
        if required not in source.descriptor.capabilities:
            raise FileSourceUnavailable()
        return source

    @staticmethod
    def normalize_preview_options(*, max_bytes, offset, tail_lines):
        from . import sftp_handler

        return sftp_handler.normalize_file_preview_options(
            max_bytes=max_bytes,
            offset=offset,
            tail_lines=tail_lines,
        )

    def list_directory(self, source_id, *, user_id, path):
        source = self.resolve(source_id, user_id, FileCapability.LIST)
        return source.backend.list_directory(source, path)

    def list_directory_page(
        self,
        source_id,
        *,
        user_id,
        path,
        cursor=0,
        client_id=None,
        request_id=None,
    ):
        source = self.resolve(source_id, user_id, FileCapability.LIST)
        if cursor != 0:
            return self._continue_directory_snapshot(
                source,
                user_id=user_id,
                path=path,
                cursor=cursor,
                client_id=client_id,
            )

        opener = getattr(source.backend, 'open_directory_listing', None)
        if not callable(opener):
            return None, 'Directory pagination unavailable', None

        owner_key = str(user_id)
        snapshot_id, state = self._reserve_directory_snapshot(
            source,
            owner_key=owner_key,
            path=path,
            client_id=client_id,
            request_id=request_id,
        )
        if state is None:
            return None, 'Too many active directory listings', None

        try:
            listing, error = opener(source, path)
            with state['lock']:
                state['listing'] = listing
            if error or listing is None:
                self._retire_directory_snapshot(snapshot_id, state)
                return (
                    None,
                    error or 'Directory pagination unavailable',
                    None,
                )
            with self._directory_snapshot_lock:
                cancelled = (
                    self._directory_snapshots.get(snapshot_id) is not state
                    or state['status'] != 'opening'
                )
            if cancelled:
                self._retire_directory_snapshot(snapshot_id, state)
                return None, 'Directory listing cancelled', None

            page_size = state['page_size']
            page, error, has_more = listing.read_page(page_size)
        except Exception:
            self._retire_directory_snapshot(snapshot_id, state)
            raise

        if error:
            self._retire_directory_snapshot(snapshot_id, state)
            return None, error, None
        if not isinstance(page, list) or len(page) > page_size:
            self._retire_directory_snapshot(snapshot_id, state)
            return None, 'Invalid directory response', None
        if not has_more:
            self._retire_directory_snapshot(snapshot_id, state)
            return page, None, None
        if not page:
            self._retire_directory_snapshot(snapshot_id, state)
            return None, 'Invalid directory response', None

        now = time.monotonic()
        with self._directory_snapshot_lock:
            if (
                self._directory_snapshots.get(snapshot_id) is not state
                or state['status'] != 'opening'
            ):
                cancelled = True
            else:
                cancelled = False
                state['status'] = 'active'
                state['next_offset'] = len(page)
                state['last_used'] = now
                self._arm_directory_snapshot_locked(snapshot_id, state)
        if cancelled:
            self._retire_directory_snapshot(snapshot_id, state)
            return None, 'Directory listing cancelled', None

        return (
            page,
            None,
            self._directory_cursor(
                snapshot_id,
                state['next_offset'],
                state['signing_key'],
            ),
        )

    def _reserve_directory_snapshot(
        self,
        source,
        *,
        owner_key,
        path,
        client_id,
        request_id,
    ):
        snapshot_id = secrets.token_urlsafe(18)
        state = {
            'owner': owner_key,
            'source_id': str(source.source_id),
            'path': str(path),
            'handle_id': str(source.handle_id),
            'backend_id': id(source.backend),
            'client_id': '' if client_id is None else str(client_id),
            'request_id': (
                request_id
                if self._valid_directory_request_id(request_id)
                else ''
            ),
            'listing': None,
            'page_size': config.REMOTE_LISTING_PAGE_SIZE,
            'next_offset': 0,
            'signing_key': secrets.token_bytes(32),
            'last_used': time.monotonic(),
            'status': 'opening',
            'cancel_waiter': False,
            'close_started': False,
            'lock': RLock(),
            'closed': Event(),
            'timer': None,
        }

        while True:
            retired = []
            with self._directory_snapshot_lock:
                retired = self._prune_directory_snapshots_locked(
                    time.monotonic()
                )
                if not retired:
                    retired = self._retire_for_directory_capacity_locked(
                        owner_key
                    )
                if not retired:
                    owner_count = sum(
                        candidate['owner'] == owner_key
                        for candidate in self._directory_snapshots.values()
                    )
                    if (
                        owner_count
                        >= config.REMOTE_LISTING_SNAPSHOT_MAX_PER_USER
                        or len(self._directory_snapshots)
                        >= config.REMOTE_LISTING_SNAPSHOT_MAX_STATES
                    ):
                        return None, None
                    while snapshot_id in self._directory_snapshots:
                        snapshot_id = secrets.token_urlsafe(18)
                    self._directory_snapshots[snapshot_id] = state
                    return snapshot_id, state
            self._close_directory_states(retired)

    @staticmethod
    def _directory_cursor(snapshot_id, offset, signing_key):
        message = f'{snapshot_id}:{offset}'.encode('ascii')
        signature = hmac.new(
            signing_key,
            message,
            hashlib.sha256,
        ).hexdigest()[:32]
        return f'v1.{snapshot_id}.{offset}.{signature}'

    @staticmethod
    def _parse_directory_cursor(cursor):
        if (
            not isinstance(cursor, str)
            or not 1 <= len(cursor) <= 160
        ):
            return None
        match = re.fullmatch(
            r'v1\.([A-Za-z0-9_-]{16,64})\.([1-9][0-9]{0,7})\.([0-9a-f]{32})',
            cursor,
        )
        if match is None:
            return None
        return match.group(1), int(match.group(2)), match.group(3)

    @staticmethod
    def _valid_directory_request_id(request_id):
        return (
            isinstance(request_id, str)
            and re.fullmatch(r'[A-Za-z0-9:._-]{1,128}', request_id)
            is not None
        )

    def _continue_directory_snapshot(
        self,
        source,
        *,
        user_id,
        path,
        cursor,
        client_id,
    ):
        parsed = self._parse_directory_cursor(cursor)
        if parsed is None:
            return None, 'Invalid or expired directory cursor', None
        snapshot_id, offset, supplied_signature = parsed
        now = time.monotonic()
        with self._directory_snapshot_lock:
            retired = self._prune_directory_snapshots_locked(now)
        self._close_directory_states(retired)
        with self._directory_snapshot_lock:
            state = self._directory_snapshots.get(snapshot_id)
        if state is None:
            return None, 'Invalid or expired directory cursor', None

        retire_result = None
        with state['lock']:
            with self._directory_snapshot_lock:
                if (
                    self._directory_snapshots.get(snapshot_id) is not state
                    or state['status'] != 'active'
                ):
                    return None, 'Invalid or expired directory cursor', None
            expected_cursor = self._directory_cursor(
                snapshot_id,
                offset,
                state['signing_key'],
            )
            expected_signature = expected_cursor.rsplit('.', 1)[-1]
            if not hmac.compare_digest(
                supplied_signature,
                expected_signature,
            ):
                return None, 'Invalid or expired directory cursor', None
            if (
                state['owner'] != str(user_id)
                or state['source_id'] != str(source.source_id)
                or state['path'] != str(path)
                or state['handle_id'] != str(source.handle_id)
                or state['backend_id'] != id(source.backend)
                or state['client_id'] != (
                    '' if client_id is None else str(client_id)
                )
                or offset != state['next_offset']
            ):
                return None, 'Invalid or expired directory cursor', None

            page, error, has_more = state['listing'].read_page(
                state['page_size']
            )
            if (
                error
                or not isinstance(page, list)
                or len(page) > state['page_size']
                or has_more and not page
            ):
                retire_result = (
                    None,
                    error or 'Invalid directory response',
                    None,
                )
            elif not has_more:
                retire_result = (page, None, None)
            else:
                state['next_offset'] += len(page)
                state['last_used'] = now
                with self._directory_snapshot_lock:
                    if (
                        self._directory_snapshots.get(snapshot_id) is not state
                    ):
                        return (
                            None,
                            'Invalid or expired directory cursor',
                            None,
                        )
                    if state['status'] == 'active':
                        self._arm_directory_snapshot_locked(snapshot_id, state)
                    elif state['status'] != 'closing':
                        return (
                            None,
                            'Invalid or expired directory cursor',
                            None,
                        )
                next_cursor = self._directory_cursor(
                    snapshot_id,
                    state['next_offset'],
                    state['signing_key'],
                )
            if retire_result is not None:
                with self._directory_snapshot_lock:
                    if (
                        self._directory_snapshots.get(snapshot_id) is state
                        and state['status'] == 'active'
                    ):
                        state['status'] = 'closing'
                        # This continuation owns the synchronous close. Cancel
                        # retransmissions should acknowledge it, not compete
                        # for the backend handle or add another waiter.
                        state['cancel_waiter'] = True
        if retire_result is not None:
            # Do not retain the per-state RLock while backend close may block.
            # This lets duplicate authenticated cancellations observe the one
            # elected closer and return immediately.
            self._retire_directory_snapshot(snapshot_id, state)
            return retire_result
        return page, None, next_cursor

    def _prune_directory_snapshots_locked(self, now):
        expiry = float(config.REMOTE_LISTING_SNAPSHOT_TTL_SECONDS)
        retired = []
        for snapshot_id, state in tuple(self._directory_snapshots.items()):
            if (
                state['status'] == 'active'
                and now - state['last_used'] >= expiry
            ):
                state['status'] = 'closing'
                retired.append((snapshot_id, state))
        return retired

    def _retire_for_directory_capacity_locked(self, owner_key):
        per_user = config.REMOTE_LISTING_SNAPSHOT_MAX_PER_USER
        owned_count = sum(
            state['owner'] == owner_key
            for state in self._directory_snapshots.values()
        )
        if owned_count >= per_user:
            owned = [
                (state['last_used'], snapshot_id, state)
                for snapshot_id, state in self._directory_snapshots.items()
                if state['owner'] == owner_key
                and state['status'] == 'active'
            ]
            if owned:
                _last_used, snapshot_id, state = min(owned)
                state['status'] = 'closing'
                return [(snapshot_id, state)]
            return []

        maximum = config.REMOTE_LISTING_SNAPSHOT_MAX_STATES
        if len(self._directory_snapshots) >= maximum:
            candidates = [
                (state['last_used'], snapshot_id, state)
                for snapshot_id, state in self._directory_snapshots.items()
                if state['owner'] == owner_key
                and state['status'] == 'active'
            ]
            if candidates:
                _last_used, snapshot_id, state = min(candidates)
                state['status'] = 'closing'
                return [(snapshot_id, state)]
        return []

    def _arm_directory_snapshot_locked(self, snapshot_id, state):
        timer = state.get('timer')
        if timer is not None:
            timer.cancel()
        expected_last_used = state['last_used']
        timer = Timer(
            config.REMOTE_LISTING_SNAPSHOT_TTL_SECONDS,
            self._expire_directory_snapshot,
            args=(snapshot_id, state, expected_last_used),
        )
        timer.daemon = True
        state['timer'] = timer
        timer.start()

    def _expire_directory_snapshot(
        self,
        snapshot_id,
        state,
        expected_last_used,
    ):
        with self._directory_snapshot_lock:
            if (
                self._directory_snapshots.get(snapshot_id) is not state
                or state['last_used'] != expected_last_used
                or state['status'] != 'active'
            ):
                return
            state['status'] = 'closing'
        self._close_directory_state(snapshot_id, state)

    def _retire_directory_snapshot(self, snapshot_id, state):
        with self._directory_snapshot_lock:
            if self._directory_snapshots.get(snapshot_id) is not state:
                return
            state['status'] = 'closing'
        self._close_directory_state(snapshot_id, state)

    def cancel_directory_snapshot(
        self,
        cursor,
        *,
        user_id,
        source_id,
        client_id,
    ):
        """Close exactly one caller-owned paginated directory snapshot."""
        parsed = self._parse_directory_cursor(cursor)
        if parsed is None:
            return False
        snapshot_id, offset, supplied_signature = parsed
        with self._directory_snapshot_lock:
            state = self._directory_snapshots.get(snapshot_id)
        if state is None:
            return False

        should_close = False
        wait_for_close = False
        # Cursor signing material and ownership are immutable after state
        # publication. Validate and elect the closer under the registry lock,
        # without queueing every duplicate behind a remote read that owns the
        # per-state lock.
        with self._directory_snapshot_lock:
            if self._directory_snapshots.get(snapshot_id) is not state:
                return False
            expected_cursor = self._directory_cursor(
                snapshot_id,
                offset,
                state['signing_key'],
            )
            expected_signature = expected_cursor.rsplit('.', 1)[-1]
            valid = (
                hmac.compare_digest(
                    supplied_signature,
                    expected_signature,
                )
                and state['owner'] == str(user_id)
                and state['source_id'] == str(source_id)
                and state['client_id'] == (
                    '' if client_id is None else str(client_id)
                )
            )
            if not valid:
                return False
            if state['status'] == 'active':
                state['status'] = 'closing'
                if not state['cancel_waiter']:
                    state['cancel_waiter'] = True
                    should_close = True
            elif state['status'] in {'cancelled', 'closing'}:
                # Preserve the synchronous close guarantee for one elected
                # caller only. Duplicate retransmissions acknowledge the
                # already-owned cancellation immediately instead of each
                # retaining an Engine.IO worker until backend I/O returns.
                if not state['cancel_waiter']:
                    state['cancel_waiter'] = True
                    wait_for_close = True
            else:
                return False

        if should_close:
            self._close_directory_state(snapshot_id, state)
        elif wait_for_close:
            state['closed'].wait()
        return True

    def cancel_directory_request(
        self,
        request_id,
        *,
        user_id,
        source_id,
        client_id,
    ):
        """Cancel page zero by its exact caller-owned request identity."""
        if not self._valid_directory_request_id(request_id):
            return False
        owner_key = str(user_id)
        source_key = str(source_id)
        client_key = '' if client_id is None else str(client_id)
        retired = []
        wait_for_close = []
        matched = False
        with self._directory_snapshot_lock:
            for snapshot_id, state in tuple(
                self._directory_snapshots.items()
            ):
                if (
                    state.get('request_id') != request_id
                    or state['owner'] != owner_key
                    or state['source_id'] != source_key
                    or state['client_id'] != client_key
                ):
                    continue
                if state['status'] == 'opening':
                    state['status'] = 'cancelled'
                    matched = True
                    if not state['cancel_waiter']:
                        state['cancel_waiter'] = True
                        wait_for_close.append(state)
                elif state['status'] == 'active':
                    state['status'] = 'closing'
                    retired.append((snapshot_id, state))
                    matched = True
                    state['cancel_waiter'] = True
                elif state['status'] in {'cancelled', 'closing'}:
                    matched = True
                    if not state['cancel_waiter']:
                        state['cancel_waiter'] = True
                        wait_for_close.append(state)
        self._close_directory_states(retired)
        # An opening listing cannot safely be closed while its backend owns
        # open_directory_listing() or the initial read_page(). Wait on only
        # the exactly authorized states so a FIFO replacement cannot acquire
        # another backend channel before retirement has completed.
        for state in wait_for_close:
            state['closed'].wait()
        return matched

    def _close_directory_state(self, snapshot_id, state):
        with state['lock']:
            if state['close_started']:
                return
            state['close_started'] = True
            state['cancel_waiter'] = True
            timer = state.get('timer')
            if timer is not None:
                try:
                    timer.cancel()
                except Exception:
                    pass
                state['timer'] = None
            listing = state.get('listing')
            state['listing'] = None
        try:
            # The status transition happened before this point, so no new page
            # read can start. Close outside the state lock: duplicate cancel
            # requests can now observe the elected closer and return without
            # accumulating blocked worker threads behind slow backend I/O.
            if listing is not None:
                listing.close()
        except Exception:
            pass
        finally:
            with self._directory_snapshot_lock:
                if self._directory_snapshots.get(snapshot_id) is state:
                    self._directory_snapshots.pop(snapshot_id, None)
            state['closed'].set()

    def _close_directory_states(self, states):
        for snapshot_id, state in states:
            self._close_directory_state(snapshot_id, state)

    def discard_directory_snapshots(
        self,
        *,
        user_id=None,
        source_id=None,
        client_id=None,
    ):
        """Drop cached directory metadata after a source lifecycle change."""
        owner_key = None if user_id is None else str(user_id)
        source_key = None if source_id is None else str(source_id)
        client_key = None if client_id is None else str(client_id)
        retired = []
        with self._directory_snapshot_lock:
            for snapshot_id, state in tuple(
                self._directory_snapshots.items()
            ):
                if owner_key is not None and state['owner'] != owner_key:
                    continue
                if source_key is not None and state['source_id'] != source_key:
                    continue
                if client_key is not None and state['client_id'] != client_key:
                    continue
                if state['status'] == 'opening':
                    state['status'] = 'cancelled'
                elif state['status'] == 'active':
                    state['status'] = 'closing'
                    retired.append((snapshot_id, state))
        self._close_directory_states(retired)

    def get_home_directory(self, source_id, *, user_id):
        source = self.resolve(source_id, user_id, FileCapability.LIST)
        return source.backend.get_home_directory(source)

    def check_exists(self, source_id, *, user_id, path):
        source = self.resolve(source_id, user_id, FileCapability.READ)
        return source.backend.check_exists(source, path)

    def get_file_stat(self, source_id, *, user_id, path):
        source = self.resolve(source_id, user_id, FileCapability.READ)
        return source.backend.get_file_stat(source, path)

    def create_directory(self, source_id, *, user_id, path):
        source = self.resolve(source_id, user_id, FileCapability.MKDIR)
        return source.backend.mkdir(source, path)

    def rename(self, source_id, *, user_id, old_path, new_path):
        source = self.resolve(source_id, user_id, FileCapability.RENAME)
        if any(
            not isinstance(path, str)
            or any(segment == '..' for segment in path.split('/'))
            for path in (old_path, new_path)
        ):
            return False, 'Invalid move request'
        safe_old = source.backend.normalize_path(old_path)
        safe_new = source.backend.normalize_path(new_path)
        case_insensitive = source.descriptor.kind == 'smb'
        comparable_old = (
            safe_old.casefold()
            if case_insensitive and isinstance(safe_old, str)
            else safe_old
        )
        comparable_new = (
            safe_new.casefold()
            if case_insensitive and isinstance(safe_new, str)
            else safe_new
        )
        if (
            safe_old is None
            or safe_new is None
            or safe_old in {'', '.', '/'}
            or safe_new in {'', '.'}
            or comparable_old == comparable_new
            or comparable_new.startswith(
                f"{comparable_old.rstrip('/')}/"
            )
        ):
            return False, 'Invalid move request'
        destination, error = source.backend.check_exists(source, safe_new)
        if error:
            return False, error
        if destination and destination.get('exists'):
            return False, 'Destination already exists'
        return source.backend.rename(
            source,
            safe_old,
            safe_new,
            replace=False,
        )

    def delete(self, source_id, *, user_id, path, cancel_event=None):
        self.resolve(source_id, user_id, FileCapability.DELETE)
        source = self.resolve(source_id, user_id, FileCapability.RECURSIVE)
        return source.backend.delete(
            source,
            path,
            recursive=True,
            budget=None,
            cancel_event=cancel_event,
        )

    def read_file_preview(
        self,
        source_id,
        *,
        user_id,
        path,
        max_bytes,
        offset,
        tail_lines,
    ):
        source = self.resolve(source_id, user_id, FileCapability.PREVIEW)
        return source.backend.read_file_preview(
            source,
            path,
            max_bytes=max_bytes,
            offset=offset,
            tail_lines=tail_lines,
        )

    def read_file_for_edit(self, source_id, *, user_id, path):
        source = self.resolve(source_id, user_id, FileCapability.EDIT)
        return source.backend.read_file_for_edit(source, path)

    def read_binary_preview(self, source_id, *, user_id, path, max_size):
        source = self.resolve(source_id, user_id, FileCapability.PREVIEW)
        return source.backend.read_binary_preview(
            source,
            path,
            max_size=max_size,
        )

    def write_file_text(
        self,
        source_id,
        *,
        user_id,
        path,
        content,
        encoding,
        newline,
        allow_non_atomic=False,
        expected_revision=None,
        replace_strategy='atomic',
    ):
        source = self.resolve(source_id, user_id, FileCapability.EDIT)
        result = source.backend.write_file_text(
            source,
            path,
            content,
            encoding=encoding,
            newline=newline,
            allow_non_atomic=allow_non_atomic,
            expected_revision=expected_revision,
            replace_strategy=replace_strategy,
        )
        if isinstance(result, FileWriteOutcome):
            return result
        if (
            isinstance(result, tuple)
            and len(result) == 2
            and isinstance(result[0], bool)
        ):
            success, error = result
            return FileWriteOutcome(
                success=success,
                error=None if success else (error or 'Save failed'),
            )
        return FileWriteOutcome(success=False, error='Save failed')


sftp_backend = SFTPBackend()
file_source_resolver.register_backend(FileSourceKind.SFTP_SESSION, sftp_backend)
file_source_resolver.register_backend(FileSourceKind.SFTP_QUICK, sftp_backend)
file_source_resolver.register_backend(FileSourceKind.SMB_QUICK, smb_backend)
file_service = FileService(file_source_resolver)
