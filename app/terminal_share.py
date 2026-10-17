"""Link-based, credential-free sharing of live terminal sessions.

A share grants the holder of a link access to one live SSH session's terminal
stream and, only while its owner allows it, the session's keyboard input.
Viewers never receive the target host, account names, credentials, keys, file
sources, or any other workspace resource.

State is deliberately process-local. A share can never outlive the in-memory
SSH session it exposes, and the documented runtime is a single worker process,
so persisting shares would only create rows that point at nothing.

Fan-out never blocks the SSH output reader. Every viewer owns a bounded queue;
a viewer that falls behind loses its queue and is resynchronised from the
session's bounded replay buffer instead of applying backpressure to the owner.

Owners and admitted guests can also chat and point at terminal cells. Chat is
scoped to the session, kept in a short in-memory history, and rides the same
bounded viewer queues; pointers are ephemeral and never stored.
"""

from collections import deque
from dataclasses import dataclass
import hashlib
import hmac
import secrets
import threading
import time
import unicodedata

import config

from .audit_logger import log_warning


MODE_VIEW = 'view'
MODE_CONTROL = 'control'
MODES = frozenset({MODE_VIEW, MODE_CONTROL})

VIEWER_PENDING = 'pending'
VIEWER_ACTIVE = 'active'

MAX_TITLE_LENGTH = 80
MAX_VIEWER_NAME_LENGTH = 32
MAX_SECRET_LENGTH = 128
MAX_CHAT_LENGTH = 500
DEFAULT_COLS = 80
DEFAULT_ROWS = 24

# Every queued event carries this much bookkeeping cost in addition to its
# payload, so floods of tiny chunks are bounded as tightly as large ones.
_EVENT_OVERHEAD_BYTES = 64

# Burst size and refill rate (per second) for each chat or pointer sender.
_CHAT_RATE = (5, 1.0)
_POINTER_RATE = (20, 10.0)


class ShareError(Exception):
    """A request that cannot be satisfied, with a stable public code."""

    def __init__(self, code, status=400):
        super().__init__(code)
        self.code = code
        self.status = status


def hash_secret(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def _clean_text(value, limit):
    """Return printable single-line text bounded to ``limit`` characters."""
    if not isinstance(value, str):
        return ''
    cleaned = ''.join(
        char if unicodedata.category(char)[0] != 'C' else ' '
        for char in value
    )
    return ' '.join(cleaned.split())[:limit]


def _chat_text(value):
    if not isinstance(value, str):
        raise ShareError('invalid_request')
    text = _clean_text(value, MAX_CHAT_LENGTH)
    if not text:
        raise ShareError('invalid_request')
    return text


def _valid_secret(value):
    return (
        isinstance(value, str)
        and 16 <= len(value) <= MAX_SECRET_LENGTH
        and value.isascii()
    )


def _iso(epoch_seconds):
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(epoch_seconds))


def _default_session_probe(session_id):
    from . import ssh_manager

    return ssh_manager.get_share_probe(session_id)


def _default_snapshot(session_id):
    from . import ssh_manager

    return ssh_manager.get_share_snapshot(session_id)


@dataclass(frozen=True)
class InputGrant:
    owner_id: int
    session_id: str
    share_id: str
    viewer_id: str
    first_use: bool


class _Bucket:
    """Token bucket for one sender's chat or pointer rate."""

    __slots__ = ('capacity', 'rate', 'tokens', 'updated')

    def __init__(self, capacity, rate, now):
        self.capacity = capacity
        self.rate = rate
        self.tokens = float(capacity)
        self.updated = now

    def take(self, now):
        elapsed = max(0.0, now - self.updated)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.updated = now
        if self.tokens < 1:
            return False
        self.tokens -= 1
        return True


class _Share:
    __slots__ = (
        'share_id', 'token', 'token_hash', 'owner_id', 'owner_name',
        'session_id', 'title', 'mode', 'require_approval', 'max_viewers',
        'created_at', 'expires_at', 'viewers', 'join_count', 'ended',
    )

    def __init__(self, **values):
        for name, value in values.items():
            setattr(self, name, value)
        self.viewers = {}
        self.join_count = 0
        self.ended = None


class _Viewer:
    __slots__ = (
        'share', 'viewer_id', 'ticket_hash', 'name', 'status', 'joined_at',
        'events', 'queued_bytes', 'needs_reset', 'last_seq', 'ended',
        'generation', 'open_streams', 'detached_at', 'wake', 'input_used',
        'pending_announced', 'chat_bucket', 'pointer_bucket',
    )

    def __init__(self, share, viewer_id, ticket_hash, name, status, now):
        self.share = share
        self.viewer_id = viewer_id
        self.ticket_hash = ticket_hash
        self.name = name
        self.status = status
        self.joined_at = time.time()
        self.events = deque()
        self.queued_bytes = 0
        self.needs_reset = True
        self.last_seq = 0
        self.ended = None
        self.generation = 0
        self.open_streams = 0
        self.detached_at = now
        self.wake = threading.Event()
        self.input_used = False
        self.pending_announced = False
        self.chat_bucket = _Bucket(*_CHAT_RATE, now)
        self.pointer_bucket = _Bucket(*_POINTER_RATE, now)

    @property
    def connected(self):
        return self.open_streams > 0


class ViewerStream:
    """One long-lived viewer transport; poll it from a single thread."""

    def __init__(self, hub, viewer, generation, resume):
        self._hub = hub
        self._viewer = viewer
        self._generation = generation
        self._closed = False
        self.resumed = resume

    @property
    def viewer_id(self):
        return self._viewer.viewer_id

    def poll(self, timeout):
        """Wait up to ``timeout`` and return ``(events, ended_reason)``."""
        return self._hub._poll(self._viewer, self._generation, timeout)

    def close(self):
        if self._closed:
            return
        self._closed = True
        self._hub._close_stream(self._viewer, self._generation)


class TerminalShareHub:
    """Thread-safe registry and fan-out for terminal share links."""

    def __init__(
        self,
        *,
        session_probe=None,
        snapshot=None,
        clock=time.monotonic,
        wall_clock=time.time,
    ):
        self._lock = threading.RLock()
        self._shares = {}
        self._by_token = {}
        self._by_ticket = {}
        self._by_session = {}
        self._geometry = {}
        self._session_probe = session_probe or _default_session_probe
        self._snapshot = snapshot or _default_snapshot
        self._clock = clock
        self._wall_clock = wall_clock
        self._listener = None
        self._activity_listener = None
        self._open_streams = 0
        self._resyncs = 0
        self._chat = {}
        self._chat_seq = 0
        self._chat_total = 0
        self._owner_buckets = {}

    # ------------------------------------------------------------------
    # Owner notifications
    # ------------------------------------------------------------------
    def set_listener(self, listener):
        """Register ``listener(owner_id, session_id, event)`` for updates."""
        self._listener = listener

    def set_activity_listener(self, listener):
        """Register ``listener(owner_id, session_id, kind, payload)``.

        ``kind`` is ``chat`` for every message in a shared session and
        ``pointer`` for pointers placed by guests.
        """
        self._activity_listener = listener

    def _notify_activity(self, items):
        listener = self._activity_listener
        if listener is None:
            return
        for owner_id, session_id, kind, payload in items:
            try:
                listener(owner_id, session_id, kind, payload)
            except Exception as error:
                log_warning(
                    'Terminal share activity notification failed',
                    error_type=type(error).__name__,
                )

    def _notify(self, notices):
        listener = self._listener
        if listener is None:
            return
        for owner_id, session_id, event in notices:
            try:
                listener(owner_id, session_id, event)
            except Exception as error:
                log_warning(
                    'Terminal share notification failed',
                    error_type=type(error).__name__,
                )

    # ------------------------------------------------------------------
    # Owner operations
    # ------------------------------------------------------------------
    def create(
        self,
        owner_id,
        session_id,
        *,
        owner_name='',
        title='',
        mode=MODE_VIEW,
        ttl_minutes=None,
        max_viewers=None,
        require_approval=False,
    ):
        """Create a share for a live session owned by ``owner_id``."""
        if not config.TERMINAL_SHARE_ENABLED or config.TERMINAL_SHARE_MAX_VIEWERS <= 0:
            raise ShareError('sharing_disabled', 403)
        if mode not in MODES:
            raise ShareError('invalid_mode')
        if mode == MODE_CONTROL and not config.TERMINAL_SHARE_ALLOW_CONTROL:
            raise ShareError('control_disabled', 403)
        if ttl_minutes is None:
            ttl_minutes = config.TERMINAL_SHARE_DEFAULT_TTL_MINUTES
        if (
            type(ttl_minutes) is not int
            or not 1 <= ttl_minutes <= config.TERMINAL_SHARE_MAX_TTL_MINUTES
        ):
            raise ShareError('invalid_ttl')
        per_link_cap = min(
            config.TERMINAL_SHARE_MAX_VIEWERS_PER_LINK,
            config.TERMINAL_SHARE_MAX_VIEWERS,
        )
        if max_viewers is None:
            max_viewers = per_link_cap
        if type(max_viewers) is not int or not 1 <= max_viewers <= per_link_cap:
            raise ShareError('invalid_max_viewers')
        if type(require_approval) is not bool:
            raise ShareError('invalid_request')

        probe = self._session_probe(session_id)
        if probe is None or int(probe['owner_id']) != int(owner_id):
            raise ShareError('session_not_found', 404)

        title = _clean_text(title, MAX_TITLE_LENGTH) or 'Shared terminal'
        now = self._wall_clock()
        token = secrets.token_urlsafe(32)
        share = _Share(
            share_id=secrets.token_urlsafe(9),
            token=token,
            token_hash=hash_secret(token),
            owner_id=int(owner_id),
            owner_name=_clean_text(owner_name, MAX_VIEWER_NAME_LENGTH),
            session_id=session_id,
            title=title,
            mode=mode,
            require_approval=require_approval,
            max_viewers=max_viewers,
            created_at=now,
            expires_at=now + ttl_minutes * 60,
        )
        with self._lock:
            notices = self._reap_locked()
            active = sum(
                1 for item in self._shares.values()
                if item.owner_id == share.owner_id
            )
            if active >= config.TERMINAL_SHARE_MAX_LINKS_PER_USER:
                raise ShareError('too_many_links', 429)
            self._shares[share.share_id] = share
            self._by_token[share.token_hash] = share.share_id
            self._by_session.setdefault(session_id, set()).add(share.share_id)
            self._geometry[session_id] = (
                int(probe.get('cols', DEFAULT_COLS)),
                int(probe.get('rows', DEFAULT_ROWS)),
            )
            public = self._owner_view_locked(share)
            notices.append((share.owner_id, session_id, {'kind': 'created'}))
        self._notify(notices)
        return public

    def list_for_session(self, owner_id, session_id):
        with self._lock:
            notices = self._reap_locked()
            shares = [
                self._owner_view_locked(self._shares[share_id])
                for share_id in self._by_session.get(session_id, ())
                if self._shares[share_id].owner_id == int(owner_id)
            ]
        self._notify(notices)
        shares.sort(key=lambda item: item['created_at'])
        return shares

    def list_for_owner(self, owner_id):
        with self._lock:
            notices = self._reap_locked()
            shares = [
                self._owner_view_locked(share)
                for share in self._shares.values()
                if share.owner_id == int(owner_id)
            ]
        self._notify(notices)
        shares.sort(key=lambda item: item['created_at'])
        return shares

    def revoke(self, owner_id, share_id, reason='revoked'):
        with self._lock:
            share = self._owned_share_locked(owner_id, share_id)
            notices = self._end_share_locked(share, reason)
        self._notify(notices)
        return True

    def set_mode(self, owner_id, share_id, mode):
        if mode not in MODES:
            raise ShareError('invalid_mode')
        if mode == MODE_CONTROL and not config.TERMINAL_SHARE_ALLOW_CONTROL:
            raise ShareError('control_disabled', 403)
        with self._lock:
            share = self._owned_share_locked(owner_id, share_id)
            if share.mode != mode:
                share.mode = mode
                for viewer in share.viewers.values():
                    self._enqueue_locked(viewer, ('mode', {'mode': mode}, 16))
            public = self._owner_view_locked(share)
            notices = [(share.owner_id, share.session_id, {'kind': 'updated'})]
        self._notify(notices)
        return public

    def approve_viewer(self, owner_id, share_id, viewer_id):
        with self._lock:
            share = self._owned_share_locked(owner_id, share_id)
            viewer = share.viewers.get(viewer_id)
            if viewer is None:
                raise ShareError('viewer_not_found', 404)
            if viewer.status != VIEWER_ACTIVE:
                viewer.status = VIEWER_ACTIVE
                viewer.needs_reset = True
                viewer.wake.set()
                self._broadcast_presence_locked(share)
            notices = [(share.owner_id, share.session_id, {
                'kind': 'approved',
                'viewer': viewer.name,
            })]
        self._notify(notices)
        return True

    def remove_viewer(self, owner_id, share_id, viewer_id, reason='removed'):
        with self._lock:
            share = self._owned_share_locked(owner_id, share_id)
            viewer = share.viewers.get(viewer_id)
            if viewer is None:
                raise ShareError('viewer_not_found', 404)
            self._end_viewer_locked(viewer, reason)
            self._broadcast_presence_locked(share)
            notices = [(share.owner_id, share.session_id, {
                'kind': 'removed',
                'viewer': viewer.name,
            })]
        self._notify(notices)
        return True

    # ------------------------------------------------------------------
    # Viewer operations
    # ------------------------------------------------------------------
    def join(self, token, name=''):
        """Allocate a viewer seat and return ``(viewer_view, ticket)``."""
        if not config.TERMINAL_SHARE_ENABLED:
            raise ShareError('sharing_disabled', 403)
        if not _valid_secret(token):
            raise ShareError('link_invalid', 404)
        token_hash = hash_secret(token)
        ticket = secrets.token_urlsafe(32)
        notices = []
        try:
            with self._lock:
                notices = self._reap_locked()
                view = self._join_locked(token_hash, ticket, name, notices)
        finally:
            self._notify(notices)
        return view, ticket

    def _join_locked(self, token_hash, ticket, name, notices):
        share_id = self._by_token.get(token_hash)
        share = self._shares.get(share_id) if share_id else None
        if share is None:
            raise ShareError('link_invalid', 404)
        if len(share.viewers) >= share.max_viewers:
            raise ShareError('share_full', 409)
        if len(self._by_ticket) >= config.TERMINAL_SHARE_MAX_VIEWERS:
            raise ShareError('capacity', 503)
        share.join_count += 1
        name = (
            _clean_text(name, MAX_VIEWER_NAME_LENGTH)
            or f'Guest {share.join_count}'
        )
        viewer = _Viewer(
            share,
            secrets.token_urlsafe(9),
            hash_secret(ticket),
            name,
            VIEWER_PENDING if share.require_approval else VIEWER_ACTIVE,
            self._clock(),
        )
        share.viewers[viewer.viewer_id] = viewer
        self._by_ticket[viewer.ticket_hash] = viewer
        self._broadcast_presence_locked(share)
        notices.append((share.owner_id, share.session_id, {
            'kind': 'pending' if viewer.status == VIEWER_PENDING else 'joined',
            'viewer': viewer.name,
        }))
        return self._viewer_view_locked(viewer)

    def describe(self, ticket):
        """Return the viewer view for a ticket held by a reloading page."""
        with self._lock:
            viewer = self._viewer_for_ticket_locked(ticket)
            return self._viewer_view_locked(viewer)

    def ticket_matches_link(self, ticket, token):
        """Return whether ``ticket`` holds a seat on the share ``token`` opens."""
        if not _valid_secret(ticket) or not _valid_secret(token):
            return False
        with self._lock:
            viewer = self._by_ticket.get(hash_secret(ticket))
            return viewer is not None and hmac.compare_digest(
                viewer.share.token_hash,
                hash_secret(token),
            )

    def leave(self, ticket):
        with self._lock:
            if not _valid_secret(ticket):
                return False
            viewer = self._by_ticket.get(hash_secret(ticket))
            if viewer is None:
                return False
            share = viewer.share
            self._end_viewer_locked(viewer, 'left')
            self._broadcast_presence_locked(share)
            notices = [(share.owner_id, share.session_id, {
                'kind': 'left',
                'viewer': viewer.name,
            })]
        self._notify(notices)
        return True

    def open_stream(self, ticket, last_event_id=None):
        """Attach a transport to a viewer seat, replacing any previous one."""
        with self._lock:
            viewer = self._viewer_for_ticket_locked(ticket)
            stream_cap = (
                config.TERMINAL_SHARE_MAX_VIEWERS
                + config.TERMINAL_SHARE_STREAM_SLACK
            )
            if self._open_streams >= stream_cap or viewer.open_streams >= 2:
                raise ShareError('capacity', 503)
            resume = (
                not viewer.needs_reset
                and viewer.status == VIEWER_ACTIVE
                and last_event_id is not None
                and str(viewer.last_seq) == str(last_event_id).strip()
            )
            if resume:
                # Control events drained into the dead transport preceded
                # everything still queued; restate them first. They are
                # idempotent on the client.
                share = viewer.share
                cols, rows = self._geometry.get(
                    share.session_id, (DEFAULT_COLS, DEFAULT_ROWS)
                )
                self._enqueue_locked(viewer, ('state', {
                    'mode': share.mode,
                    'viewers': self._active_count_locked(share),
                    'cols': cols,
                    'rows': rows,
                }, _EVENT_OVERHEAD_BYTES), front=True)
            else:
                viewer.needs_reset = True
            viewer.generation += 1
            viewer.open_streams += 1
            viewer.detached_at = None
            self._open_streams += 1
            # A superseded transport exits on its next wake-up.
            viewer.wake.set()
            share = viewer.share
            notices = [(share.owner_id, share.session_id, {'kind': 'updated'})]
            stream = ViewerStream(self, viewer, viewer.generation, resume)
        self._notify(notices)
        return stream

    def _close_stream(self, viewer, generation):
        notices = []
        with self._lock:
            viewer.open_streams = max(0, viewer.open_streams - 1)
            self._open_streams = max(0, self._open_streams - 1)
            if viewer.open_streams == 0 and viewer.ended is None:
                viewer.detached_at = self._clock()
                notices.append((
                    viewer.share.owner_id,
                    viewer.share.session_id,
                    {'kind': 'updated'},
                ))
        self._notify(notices)

    def _poll(self, viewer, generation, timeout):
        viewer.wake.wait(max(0.0, timeout))
        notices = []
        try:
            with self._lock:
                viewer.wake.clear()
                notices = self._reap_locked()
                if viewer.generation != generation:
                    return [], 'superseded'
                if viewer.ended is not None:
                    return (
                        [{'type': 'end', 'reason': viewer.ended}],
                        viewer.ended,
                    )
                if viewer.status == VIEWER_PENDING:
                    if viewer.pending_announced:
                        return [], None
                    viewer.pending_announced = True
                    return [{'type': 'pending'}], None
                if not viewer.needs_reset:
                    return self._drain_locked(viewer), None
                viewer.needs_reset = False
                viewer.events.clear()
                viewer.queued_bytes = 0
                session_id = viewer.share.session_id
        finally:
            self._notify(notices)

        # The replay buffer lives under the SSH registry lock, never ours.
        # Output recorded before this snapshot can still be queued afterwards;
        # draining skips every sequence the snapshot already contains.
        snapshot = self._snapshot(session_id)
        if snapshot is None:
            return (
                [{'type': 'end', 'reason': 'session_closed'}],
                'session_closed',
            )
        data, sequence, cols, rows = snapshot
        with self._lock:
            if viewer.generation != generation:
                return [], 'superseded'
            viewer.last_seq = int(sequence)
            share = viewer.share
            return [{
                'type': 'reset',
                'data': data,
                'seq': int(sequence),
                'cols': int(cols),
                'rows': int(rows),
                'mode': share.mode,
                'viewers': self._active_count_locked(share),
                'chat': self._chat_for_viewer_locked(viewer),
            }], None

    def _drain_locked(self, viewer):
        events = []
        pending_output = []
        pending_seq = None
        while viewer.events:
            kind, payload, size = viewer.events.popleft()
            viewer.queued_bytes -= size
            if kind == 'output':
                sequence, data = payload
                if sequence <= viewer.last_seq:
                    continue
                pending_output.append(data)
                pending_seq = sequence
                viewer.last_seq = sequence
                continue
            if pending_output:
                events.append({
                    'type': 'output',
                    'data': ''.join(pending_output),
                    'seq': pending_seq,
                })
                pending_output = []
            events.append({'type': kind, **payload})
        if pending_output:
            events.append({
                'type': 'output',
                'data': ''.join(pending_output),
                'seq': pending_seq,
            })
        viewer.queued_bytes = max(0, viewer.queued_bytes)
        return events

    def authorize_input(self, ticket):
        """Return an :class:`InputGrant` when the viewer may type now."""
        with self._lock:
            viewer = self._viewer_for_ticket_locked(ticket)
            share = viewer.share
            if viewer.status != VIEWER_ACTIVE:
                raise ShareError('awaiting_approval', 403)
            if share.mode != MODE_CONTROL or not config.TERMINAL_SHARE_ALLOW_CONTROL:
                raise ShareError('view_only', 403)
            first_use = not viewer.input_used
            viewer.input_used = True
            return InputGrant(
                owner_id=share.owner_id,
                session_id=share.session_id,
                share_id=share.share_id,
                viewer_id=viewer.viewer_id,
                first_use=first_use,
            )

    # ------------------------------------------------------------------
    # Chat and pointers
    # ------------------------------------------------------------------
    def chat_history(self, owner_id, session_id):
        """Return the session's recent messages for its owner."""
        with self._lock:
            if not self._owns_session_locked(owner_id, session_id):
                return []
            return list(self._chat.get(session_id, ()))

    def owner_chat(self, owner_id, session_id, text, *, name=''):
        text = _chat_text(text)
        with self._lock:
            self._require_owned_session_locked(owner_id, session_id)
            self._take_owner_locked(session_id, 'chat', _CHAT_RATE)
            message = self._post_chat_locked(
                session_id,
                _clean_text(name, MAX_VIEWER_NAME_LENGTH) or 'Owner',
                'owner',
                'owner',
                text,
                exclude=None,
            )
            items = [(int(owner_id), session_id, 'chat', message)]
        self._notify_activity(items)
        return message

    def guest_chat(self, ticket, text):
        text = _chat_text(text)
        with self._lock:
            viewer = self._collaborator_locked(ticket)
            if not viewer.chat_bucket.take(self._clock()):
                raise ShareError('rate_limited', 429)
            share = viewer.share
            message = self._post_chat_locked(
                share.session_id,
                viewer.name,
                'guest',
                viewer.viewer_id,
                text,
                exclude=viewer,
            )
            items = [(share.owner_id, share.session_id, 'chat', message)]
        self._notify_activity(items)
        return message

    def owner_pointer(self, owner_id, session_id, col, row, *, name=''):
        with self._lock:
            self._require_owned_session_locked(owner_id, session_id)
            col, row = self._pointer_cell_locked(session_id, col, row)
            self._take_owner_locked(session_id, 'pointer', _POINTER_RATE)
            pointer = {
                'name': _clean_text(name, MAX_VIEWER_NAME_LENGTH) or 'Owner',
                'role': 'owner',
                'sender': 'owner',
                'col': col,
                'row': row,
            }
            self._broadcast_session_locked(session_id, 'pointer', pointer, exclude=None)
        return pointer

    def guest_pointer(self, ticket, col, row):
        with self._lock:
            viewer = self._collaborator_locked(ticket)
            share = viewer.share
            col, row = self._pointer_cell_locked(share.session_id, col, row)
            if not viewer.pointer_bucket.take(self._clock()):
                raise ShareError('rate_limited', 429)
            pointer = {
                'name': viewer.name,
                'role': 'guest',
                'sender': viewer.viewer_id,
                'col': col,
                'row': row,
            }
            self._broadcast_session_locked(
                share.session_id, 'pointer', pointer, exclude=viewer,
            )
            items = [(share.owner_id, share.session_id, 'pointer', pointer)]
        self._notify_activity(items)
        return pointer

    # ------------------------------------------------------------------
    # SSH runtime hooks
    # ------------------------------------------------------------------
    def publish(self, session_id, sequence, data):
        """Fan one output chunk out to viewers without ever blocking."""
        # Unlocked membership check keeps unshared sessions on a dict lookup.
        if session_id not in self._by_session:
            return
        try:
            size = len(data) + _EVENT_OVERHEAD_BYTES
            with self._lock:
                for share_id in self._by_session.get(session_id, ()):
                    share = self._shares.get(share_id)
                    if share is None:
                        continue
                    for viewer in share.viewers.values():
                        if viewer.status == VIEWER_ACTIVE:
                            self._enqueue_locked(
                                viewer,
                                ('output', (int(sequence), data), size),
                            )
        except Exception as error:
            log_warning(
                'Terminal share fan-out failed',
                error_type=type(error).__name__,
            )

    def resize(self, session_id, cols, rows):
        if session_id not in self._by_session:
            return
        with self._lock:
            if session_id not in self._by_session:
                return
            self._geometry[session_id] = (int(cols), int(rows))
            for share_id in self._by_session.get(session_id, ()):
                share = self._shares.get(share_id)
                if share is None:
                    continue
                for viewer in share.viewers.values():
                    self._enqueue_locked(viewer, (
                        'resize',
                        {'cols': int(cols), 'rows': int(rows)},
                        _EVENT_OVERHEAD_BYTES,
                    ))

    def end_session(self, session_id, reason='session_closed'):
        if session_id not in self._by_session:
            return 0
        with self._lock:
            notices = []
            share_ids = list(self._by_session.get(session_id, ()))
            for share_id in share_ids:
                share = self._shares.get(share_id)
                if share is not None:
                    notices.extend(self._end_share_locked(share, reason))
        self._notify(notices)
        return len(share_ids)

    def end_owner(self, owner_id, reason='owner_signed_out'):
        with self._lock:
            notices = []
            shares = [
                share for share in self._shares.values()
                if share.owner_id == int(owner_id)
            ]
            for share in shares:
                notices.extend(self._end_share_locked(share, reason))
        self._notify(notices)
        return len(shares)

    def end_all(self, reason='shutdown'):
        with self._lock:
            notices = []
            for share in list(self._shares.values()):
                notices.extend(self._end_share_locked(share, reason))
        self._notify(notices)

    def reap(self):
        with self._lock:
            notices = self._reap_locked()
        self._notify(notices)

    def stats(self):
        with self._lock:
            viewers = list(self._by_ticket.values())
            return {
                'links': len(self._shares),
                'viewers': len(viewers),
                'viewers_connected': sum(1 for item in viewers if item.connected),
                'viewers_pending': sum(
                    1 for item in viewers if item.status == VIEWER_PENDING
                ),
                'streams': self._open_streams,
                'queued_bytes': sum(item.queued_bytes for item in viewers),
                'resyncs': self._resyncs,
                'chat_messages': self._chat_total,
            }

    # ------------------------------------------------------------------
    # Internal helpers (call with self._lock held)
    # ------------------------------------------------------------------
    def _enqueue_locked(self, viewer, event, *, front=False):
        if viewer.ended is not None:
            return
        size = event[2]
        if viewer.needs_reset:
            # A pending snapshot supersedes queued output; keep control events
            # small and bounded, and drop output entirely.
            if event[0] == 'output':
                return
        if front:
            viewer.events.appendleft(event)
        else:
            viewer.events.append(event)
        viewer.queued_bytes += size
        if viewer.queued_bytes > config.TERMINAL_SHARE_VIEWER_QUEUE_BYTES:
            viewer.events.clear()
            viewer.queued_bytes = 0
            viewer.needs_reset = True
            self._resyncs += 1
        viewer.wake.set()

    def _owns_session_locked(self, owner_id, session_id):
        return any(
            self._shares[share_id].owner_id == int(owner_id)
            for share_id in self._by_session.get(session_id, ())
        )

    def _require_owned_session_locked(self, owner_id, session_id):
        if not config.TERMINAL_SHARE_CHAT_ENABLED:
            raise ShareError('chat_disabled', 403)
        if (
            not isinstance(session_id, str)
            or not self._owns_session_locked(owner_id, session_id)
        ):
            raise ShareError('not_shared', 409)

    def _collaborator_locked(self, ticket):
        if not config.TERMINAL_SHARE_CHAT_ENABLED:
            raise ShareError('chat_disabled', 403)
        viewer = self._viewer_for_ticket_locked(ticket)
        if viewer.status != VIEWER_ACTIVE:
            raise ShareError('awaiting_approval', 403)
        return viewer

    def _take_owner_locked(self, session_id, kind, rate):
        now = self._clock()
        bucket = self._owner_buckets.get((session_id, kind))
        if bucket is None:
            bucket = self._owner_buckets[(session_id, kind)] = _Bucket(*rate, now)
        if not bucket.take(now):
            raise ShareError('rate_limited', 429)

    def _pointer_cell_locked(self, session_id, col, row):
        cols, rows = self._geometry.get(
            session_id, (DEFAULT_COLS, DEFAULT_ROWS)
        )
        if (
            type(col) is not int
            or type(row) is not int
            or not 0 <= col < cols
            or not 0 <= row < rows
        ):
            raise ShareError('invalid_request')
        return col, row

    def _post_chat_locked(self, session_id, name, role, sender, text, *, exclude):
        self._chat_seq += 1
        self._chat_total += 1
        message = {
            'id': self._chat_seq,
            'name': name,
            'role': role,
            'sender': sender,
            'text': text,
            'at': _iso(self._wall_clock()),
        }
        limit = config.TERMINAL_SHARE_CHAT_HISTORY
        if limit:
            history = self._chat.get(session_id)
            if history is None or history.maxlen != limit:
                history = deque(history or (), maxlen=limit)
                self._chat[session_id] = history
            history.append(message)
        self._broadcast_session_locked(session_id, 'chat', message, exclude=exclude)
        return message

    def _broadcast_session_locked(self, session_id, kind, payload, *, exclude):
        size = _EVENT_OVERHEAD_BYTES + sum(
            len(str(value)) for value in payload.values()
        )
        for share_id in self._by_session.get(session_id, ()):
            share = self._shares.get(share_id)
            if share is None:
                continue
            for viewer in share.viewers.values():
                if viewer is not exclude and viewer.status == VIEWER_ACTIVE:
                    self._enqueue_locked(viewer, (kind, payload, size))

    def _chat_for_viewer_locked(self, viewer):
        if not config.TERMINAL_SHARE_CHAT_ENABLED or viewer.status != VIEWER_ACTIVE:
            return []
        return list(self._chat.get(viewer.share.session_id, ()))

    def _viewer_for_ticket_locked(self, ticket):
        if not _valid_secret(ticket):
            raise ShareError('ticket_invalid', 404)
        viewer = self._by_ticket.get(hash_secret(ticket))
        if viewer is None:
            raise ShareError('ticket_invalid', 404)
        if viewer.ended is not None:
            raise ShareError(viewer.ended, 410)
        if viewer.share.expires_at <= self._wall_clock():
            # The reaper ends the share and notifies its owner.
            raise ShareError('expired', 410)
        return viewer

    def _owned_share_locked(self, owner_id, share_id):
        share = self._shares.get(share_id) if isinstance(share_id, str) else None
        if share is None or share.owner_id != int(owner_id):
            raise ShareError('share_not_found', 404)
        return share

    def _end_viewer_locked(self, viewer, reason):
        if viewer.ended is None:
            viewer.ended = reason
        viewer.events.clear()
        viewer.queued_bytes = 0
        viewer.share.viewers.pop(viewer.viewer_id, None)
        self._by_ticket.pop(viewer.ticket_hash, None)
        viewer.wake.set()

    def _end_share_locked(self, share, reason):
        if share.share_id not in self._shares:
            return []
        share.ended = reason
        for viewer in list(share.viewers.values()):
            self._end_viewer_locked(viewer, reason)
        self._shares.pop(share.share_id, None)
        self._by_token.pop(share.token_hash, None)
        session_shares = self._by_session.get(share.session_id)
        if session_shares is not None:
            session_shares.discard(share.share_id)
            if not session_shares:
                self._by_session.pop(share.session_id, None)
                self._geometry.pop(share.session_id, None)
                self._chat.pop(share.session_id, None)
                for key in [
                    key for key in self._owner_buckets
                    if key[0] == share.session_id
                ]:
                    del self._owner_buckets[key]
        return [(share.owner_id, share.session_id, {
            'kind': 'ended',
            'reason': reason,
            'share_id': share.share_id,
        })]

    def _reap_locked(self):
        notices = []
        now_wall = self._wall_clock()
        now = self._clock()
        grace = config.TERMINAL_SHARE_VIEWER_GRACE_SECONDS
        for share in list(self._shares.values()):
            if share.expires_at <= now_wall:
                notices.extend(self._end_share_locked(share, 'expired'))
                continue
            dropped = False
            for viewer in list(share.viewers.values()):
                if (
                    viewer.open_streams == 0
                    and viewer.detached_at is not None
                    and now - viewer.detached_at > grace
                ):
                    self._end_viewer_locked(viewer, 'timed_out')
                    dropped = True
            if dropped:
                self._broadcast_presence_locked(share)
                notices.append((share.owner_id, share.session_id, {
                    'kind': 'updated',
                }))
        return notices

    def _active_count_locked(self, share):
        return sum(
            1 for viewer in share.viewers.values()
            if viewer.status == VIEWER_ACTIVE
        )

    def _broadcast_presence_locked(self, share):
        count = self._active_count_locked(share)
        for viewer in share.viewers.values():
            if viewer.status == VIEWER_ACTIVE:
                self._enqueue_locked(viewer, (
                    'presence',
                    {'viewers': count},
                    _EVENT_OVERHEAD_BYTES,
                ))

    def _owner_view_locked(self, share):
        now = self._wall_clock()
        return {
            'id': share.share_id,
            'token': share.token,
            'session_id': share.session_id,
            'title': share.title,
            'mode': share.mode,
            'require_approval': share.require_approval,
            'max_viewers': share.max_viewers,
            'created_at': _iso(share.created_at),
            'expires_at': _iso(share.expires_at),
            'expires_in': max(0, int(share.expires_at - now)),
            'viewers': [
                {
                    'id': viewer.viewer_id,
                    'name': viewer.name,
                    'status': viewer.status,
                    'connected': viewer.connected,
                    'joined_at': _iso(viewer.joined_at),
                    'typed': viewer.input_used,
                }
                for viewer in sorted(
                    share.viewers.values(),
                    key=lambda item: item.joined_at,
                )
            ],
        }

    def _viewer_view_locked(self, viewer):
        share = viewer.share
        cols, rows = self._geometry.get(
            share.session_id, (DEFAULT_COLS, DEFAULT_ROWS)
        )
        now = self._wall_clock()
        return {
            'viewer_id': viewer.viewer_id,
            'name': viewer.name,
            'status': viewer.status,
            'title': share.title,
            'owner': share.owner_name,
            'mode': share.mode,
            'expires_at': _iso(share.expires_at),
            'expires_in': max(0, int(share.expires_at - now)),
            'cols': cols,
            'rows': rows,
            'viewers': self._active_count_locked(share),
            'chat_enabled': config.TERMINAL_SHARE_CHAT_ENABLED,
            'chat': self._chat_for_viewer_locked(viewer),
        }


share_hub = TerminalShareHub()
