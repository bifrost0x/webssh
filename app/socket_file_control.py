"""Bounded Socket.IO file envelopes, byte budgets and editor retry proofs.

State belongs to the process and is keyed by authenticated user. This module
never resolves a remote source or performs a file operation.
"""

import hashlib
import re
import secrets
import threading
import time

from flask import request

import config
from .auth import get_user_from_socket


_FILE_SOURCE_ID_MAX_BYTES = 160
_FILE_CONTROL_SMALL_TEXT_MAX_BYTES = 128
_FILE_CONTROL_PATH_FIELDS = frozenset({
    'parent_path',
    'remote_path',
    'path',
    'old_path',
    'new_path',
    'source_path',
    'dest_path',
})
_FILE_CONTROL_SOURCE_FIELDS = frozenset({
    'source_id',
    'destination_source_id',
})
_FILE_CONTROL_SMALL_FIELDS = frozenset({
    'request_id',
    'listing_request_id',
    'transfer_id',
    'expected_revision',
    'direction',
    'encoding',
    'newline',
    'replace_strategy',
    'save_challenge',
    'conflict_policy',
})
_FILE_CONTROL_CHECKED = object()
_file_control_budgets = {}
_editor_save_budgets = {}
_editor_retry_challenges = {}
_file_control_budget_lock = threading.Lock()
_EDITOR_RETRY_CHALLENGE_TTL_SECONDS = 120.0
_EDITOR_RETRY_CHALLENGE_MAX_STATES = 256
_EDITOR_RETRY_CHALLENGE_MAX_PER_USER = 4


def _file_request_identity(
    payload,
    user_id=None,
    *,
    allow_editor_content=False,
    editor_budget_exempt=False,
    allow_permission_paths=False,
):
    if isinstance(payload, dict) and payload.get(
        '_file_control_checked'
    ) is not _FILE_CONTROL_CHECKED:
        if user_id is None:
            try:
                socket_user = get_user_from_socket(request.sid)
                user_id = socket_user.id if socket_user is not None else None
            except Exception:
                user_id = None
        budget_now = time.monotonic()
        reserved = user_id is not None and _consume_file_control_budget(
            user_id, 256, now=budget_now
        )
        if not reserved:
            _sanitize_file_control_payload(payload)
            valid = False
        else:
            editor_body = (
                allow_editor_content
                and isinstance(payload.get('content'), str)
            )
            editor_reserved = (
                not editor_body
                or editor_budget_exempt
                or _consume_editor_save_budget(
                    user_id,
                    1,
                    now=budget_now,
                )
            )
            if not editor_reserved:
                _sanitize_file_control_payload(payload)
                valid = False
            else:
                byte_count, editor_bytes = _file_control_payload_metrics(
                    payload,
                    allow_editor_content=allow_editor_content,
                    allow_permission_paths=allow_permission_paths,
                )
                valid = _sanitize_file_control_payload(payload)
                remainder = max(0, byte_count - 256)
                if remainder and not _consume_file_control_budget(
                    user_id,
                    remainder,
                    now=budget_now,
                ):
                    valid = False
                if (
                    editor_body
                    and not editor_budget_exempt
                    and editor_bytes is not None
                    and editor_bytes > 1
                    and not _consume_editor_save_budget(
                        user_id,
                        editor_bytes - 1,
                        now=budget_now,
                    )
                ):
                    valid = False
        payload['_file_control_valid'] = valid
        payload['_file_control_checked'] = _FILE_CONTROL_CHECKED
    if isinstance(payload, dict) and not payload.get(
        '_file_control_valid', False
    ):
        payload['source_id'] = None
    request_id = payload.get('request_id')
    if (
        not isinstance(request_id, str)
        or len(request_id) > 128
        or not re.fullmatch(r'[A-Za-z0-9:._-]{1,128}', request_id)
    ):
        request_id = None
    return {
        'source_id': payload.get('source_id'),
        'request_id': request_id,
    }


def _utf8_text_within(value, maximum):
    if not isinstance(value, str) or len(value) > maximum:
        return False
    try:
        return len(value.encode('utf-8')) <= maximum
    except UnicodeEncodeError:
        return False


def _bounded_utf8_size(value, maximum):
    """Measure UTF-8 incrementally and stop before an oversized full copy."""
    if not isinstance(value, str) or len(value) > maximum:
        return None
    size = 0
    for offset in range(0, len(value), 4096):
        try:
            size += len(str(value[offset:offset + 4096]).encode('utf-8'))
        except UnicodeEncodeError:
            return None
        if size > maximum:
            return None
    return size


def _file_control_payload_metrics(payload, *, allow_editor_content=False, allow_permission_paths=False):
    """Bound all control metadata without reserializing the attacker payload.

    Editor content is measured separately so it can retain its larger
    legitimate per-file allowance without weakening the tighter metadata
    bucket. Every other value, including unknown or nested fields, is charged
    here so a caller cannot hide an editor-envelope-sized allocation behind a
    harmless request.
    """
    maximum_charge = config.FILE_CONTROL_BYTES_PER_MINUTE + 1
    cost = 0
    editor_bytes = 0
    stack = [(payload, 0, False)]
    visited = 0
    while stack:
        value, depth, editor_content = stack.pop()
        visited += 1
        if visited > 1024 or depth > 8:
            return maximum_charge, None
        if editor_content:
            size = _bounded_utf8_size(
                value,
                config.MAX_EDITOR_FILE_SIZE,
            )
            if size is None:
                return maximum_charge, None
            editor_bytes += size
            continue
        if isinstance(value, dict):
            if len(value) > 1024:
                return maximum_charge, None
            for key, item in value.items():
                if not isinstance(key, str) or len(key) > 256:
                    return maximum_charge, None
                try:
                    cost += len(key.encode('utf-8'))
                except UnicodeEncodeError:
                    return maximum_charge, None
                if allow_permission_paths and depth == 0 and key == 'paths':
                    if not isinstance(item, list) or not 1 <= len(item) <= 10000:
                        return maximum_charge, None
                    names = 0
                    for path in item:
                        size = _bounded_utf8_size(path, min(4096, config.FILE_CONTROL_MAX_PATH_BYTES))
                        if size is None:
                            return maximum_charge, None
                        names += size
                        cost += max(16, size)
                        if names > 4 * 1024 * 1024 or cost > config.FILE_CONTROL_BYTES_PER_MINUTE:
                            return maximum_charge, None
                    continue
                stack.append((
                    item,
                    depth + 1,
                    allow_editor_content
                    and depth == 0
                    and key == 'content'
                    and isinstance(item, str),
                ))
        elif isinstance(value, (list, tuple)):
            if len(value) > 1024:
                return maximum_charge, None
            for item in value:
                stack.append((item, depth + 1, False))
        elif isinstance(value, str):
            size = _bounded_utf8_size(
                value,
                max(0, config.FILE_CONTROL_BYTES_PER_MINUTE - cost),
            )
            if size is None:
                return maximum_charge, None
            cost += size
        elif isinstance(value, (bytes, bytearray, memoryview)):
            cost += len(value)
        else:
            # JSON scalars and unexpected objects still consume parser and
            # object memory; use a small conservative accounting charge.
            cost += 16
        if cost > config.FILE_CONTROL_BYTES_PER_MINUTE:
            return maximum_charge, None
    # A conservative floor also bounds CPU/event amplification independently
    # of how little metadata a syntactically empty request carries.
    return max(256, cost), editor_bytes


def _file_control_payload_cost(payload, *, allow_editor_content=False):
    """Compatibility wrapper returning the metadata charge only."""
    cost, _editor_bytes = _file_control_payload_metrics(
        payload,
        allow_editor_content=allow_editor_content,
    )
    return cost


def _consume_file_control_budget(user_id, byte_count, now=None):
    """Apply a constant-memory per-user token bucket to control metadata."""
    current = time.monotonic() if now is None else float(now)
    key = int(user_id)
    capacity = config.FILE_CONTROL_BYTES_PER_MINUTE
    with _file_control_budget_lock:
        available, updated_at = _file_control_budgets.get(
            key,
            (float(capacity), current),
        )
        elapsed = max(0.0, current - updated_at)
        available = min(
            float(capacity),
            available + (elapsed * capacity / 60.0),
        )
        if byte_count > capacity or byte_count > available:
            # Oversized attempts exhaust the bucket too; otherwise an attacker
            # could repeat rejected editor-envelope allocations for free.
            _file_control_budgets[key] = (0.0, current)
            return False
        _file_control_budgets[key] = (available - byte_count, current)
        return True


def _consume_editor_save_budget(user_id, byte_count, now=None):
    """Charge accepted editor bodies against an exact per-user byte bucket."""
    current = time.monotonic() if now is None else float(now)
    key = int(user_id)
    capacity = config.EDITOR_SAVE_BYTES_PER_MINUTE
    with _file_control_budget_lock:
        available, updated_at = _editor_save_budgets.get(
            key,
            (float(capacity), current),
        )
        elapsed = max(0.0, current - updated_at)
        available = min(
            float(capacity),
            available + (elapsed * capacity / 60.0),
        )
        if byte_count > capacity or byte_count > available:
            _editor_save_budgets[key] = (0.0, current)
            return False
        _editor_save_budgets[key] = (available - byte_count, current)
        return True


def _current_socket_sid():
    try:
        socket_sid = request.sid
    except (AttributeError, RuntimeError):
        return ''
    return socket_sid if isinstance(socket_sid, str) else ''


def _editor_retry_fingerprint(payload, user_id, socket_sid):
    """Build a bounded identity for one exact editor body and destination."""
    if not isinstance(payload, dict):
        return None
    source_id = payload.get('source_id')
    path = payload.get('path')
    content = payload.get('content')
    encoding = payload.get('encoding', 'utf-8')
    newline = payload.get('newline', 'lf')
    expected_revision = payload.get('expected_revision')
    if (
        not _utf8_text_within(source_id, _FILE_SOURCE_ID_MAX_BYTES)
        or not _utf8_text_within(
            path,
            config.FILE_CONTROL_MAX_PATH_BYTES,
        )
        or not _utf8_text_within(
            encoding,
            _FILE_CONTROL_SMALL_TEXT_MAX_BYTES,
        )
        or not _utf8_text_within(
            newline,
            _FILE_CONTROL_SMALL_TEXT_MAX_BYTES,
        )
        or (
            expected_revision is not None
            and not _utf8_text_within(
                expected_revision,
                _FILE_CONTROL_SMALL_TEXT_MAX_BYTES,
            )
        )
        or not isinstance(content, str)
        or len(content) > config.MAX_EDITOR_FILE_SIZE
    ):
        return None

    digest = hashlib.sha256()
    byte_count = 0
    for offset in range(0, len(content), 4096):
        try:
            encoded = content[offset:offset + 4096].encode('utf-8')
        except UnicodeEncodeError:
            return None
        byte_count += len(encoded)
        if byte_count > config.MAX_EDITOR_FILE_SIZE:
            return None
        digest.update(encoded)
    return (
        int(user_id),
        socket_sid,
        source_id,
        path,
        encoding,
        newline,
        expected_revision,
        byte_count,
        digest.hexdigest(),
    )


def _prune_editor_retry_challenges_locked(now):
    for token, state in tuple(_editor_retry_challenges.items()):
        if state['expires_at'] <= now:
            _editor_retry_challenges.pop(token, None)


def _issue_editor_retry_challenge(payload, user_id, socket_sid=None):
    """Authorize one same-body recoverable retry without a second byte charge."""
    socket_sid = _current_socket_sid() if socket_sid is None else socket_sid
    fingerprint = _editor_retry_fingerprint(payload, user_id, socket_sid)
    if fingerprint is None:
        return None
    now = time.monotonic()
    with _file_control_budget_lock:
        _prune_editor_retry_challenges_locked(now)
        owned = [
            (state['issued_at'], token)
            for token, state in _editor_retry_challenges.items()
            if state['fingerprint'][0] == int(user_id)
        ]
        while len(owned) >= _EDITOR_RETRY_CHALLENGE_MAX_PER_USER:
            _issued_at, oldest = min(owned)
            _editor_retry_challenges.pop(oldest, None)
            owned = [entry for entry in owned if entry[1] != oldest]
        while (
            len(_editor_retry_challenges)
            >= _EDITOR_RETRY_CHALLENGE_MAX_STATES
        ):
            oldest = min(
                _editor_retry_challenges,
                key=lambda token: _editor_retry_challenges[token]['issued_at'],
            )
            _editor_retry_challenges.pop(oldest, None)
        token = secrets.token_urlsafe(32)
        while token in _editor_retry_challenges:
            token = secrets.token_urlsafe(32)
        _editor_retry_challenges[token] = {
            'fingerprint': fingerprint,
            'user_id': int(user_id),
            'socket_sid': socket_sid,
            'issued_at': now,
            'expires_at': now + _EDITOR_RETRY_CHALLENGE_TTL_SECONDS,
        }
        return token


def _consume_editor_retry_challenge(payload, user_id, socket_sid=None):
    """Consume a valid challenge exactly once and bind it to the same save."""
    if (
        not isinstance(payload, dict)
        or payload.get('replace_strategy') != 'recoverable_swap'
    ):
        return False
    token = payload.get('save_challenge')
    if (
        not isinstance(token, str)
        or re.fullmatch(r'[A-Za-z0-9_-]{32,64}', token) is None
    ):
        return False
    socket_sid = _current_socket_sid() if socket_sid is None else socket_sid
    now = time.monotonic()
    with _file_control_budget_lock:
        _prune_editor_retry_challenges_locked(now)
        state = _editor_retry_challenges.get(token)
        if (
            state is None
            or state['expires_at'] <= now
            or state['user_id'] != int(user_id)
            or state['socket_sid'] != socket_sid
        ):
            return False
        # Claim the unguessable, coarsely bound token before doing any
        # body-sized work.  Invalid/replayed tokens therefore reach the normal
        # metadata/editor budget gates without hashing their content first,
        # while concurrent replays cannot both receive an exemption.
        _editor_retry_challenges.pop(token, None)
    fingerprint = _editor_retry_fingerprint(payload, user_id, socket_sid)
    return (
        fingerprint is not None
        and state['fingerprint'] == fingerprint
    )


def _sanitize_file_control_payload(payload):
    """Bound file-control metadata before it is copied, logged, or emitted."""
    if not isinstance(payload, dict):
        return False
    invalid = False
    limits = (
        (_FILE_CONTROL_PATH_FIELDS, config.FILE_CONTROL_MAX_PATH_BYTES),
        (_FILE_CONTROL_SOURCE_FIELDS, _FILE_SOURCE_ID_MAX_BYTES),
        (_FILE_CONTROL_SMALL_FIELDS, _FILE_CONTROL_SMALL_TEXT_MAX_BYTES),
        (('name',), 255),
        (('mode',), 3),
        (('expected_metadata',), 512),
    )
    for fields, maximum in limits:
        for field in fields:
            if field not in payload or payload[field] is None:
                continue
            if not _utf8_text_within(payload[field], maximum):
                payload[field] = None
                invalid = True
    if invalid:
        # Every file handler already rejects a missing source ID before backend
        # resolution. Clearing it also prevents exception paths from reflecting
        # any other invalid control field.
        payload['source_id'] = None
    return not invalid
