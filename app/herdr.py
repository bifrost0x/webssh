"""Read-only view of a remote Herdr session.

Everything Herdr reports is untrusted: agents and any process with access to
its socket choose the names, labels and paths. Only a small, bounded and
cleaned agent list ever leaves this module.
"""
import json
import re
import socket
import time
import unicodedata
from threading import BoundedSemaphore, Lock

MAX_SNAPSHOT_BYTES = 262144
MAX_AGENTS = 64
MAX_PANES = 256
MAX_NAME_LENGTH = 120
MAX_PATH_LENGTH = 512
STATUSES = frozenset({'idle', 'working', 'blocked', 'done', 'unknown'})

_AGENT_ID = re.compile(r'[A-Za-z0-9:_-]{1,64}')
# Control, format (including bidirectional overrides), surrogate, private-use
# and unassigned characters, and the two Unicode line separators.
_REMOVED_CATEGORIES = frozenset({'Cc', 'Cf', 'Cs', 'Co', 'Cn', 'Zl', 'Zp'})


def _text(value, limit):
    if not isinstance(value, str):
        return ''
    # Bound the work before inspecting characters of an oversized value.
    cleaned = ''.join(
        character for character in value[:limit * 4]
        if unicodedata.category(character) not in _REMOVED_CATEGORIES
    )
    return cleaned.strip()[:limit].rstrip()


def _agent_id(value):
    if isinstance(value, str) and _AGENT_ID.fullmatch(value):
        return value
    return None


def _pane_labels(panes):
    labels = {}
    if not isinstance(panes, list):
        return labels
    for pane in panes[:MAX_PANES]:
        if not isinstance(pane, dict):
            continue
        pane_id = _agent_id(pane.get('pane_id'))
        if pane_id is not None and pane_id not in labels:
            labels[pane_id] = _text(pane.get('label'), MAX_NAME_LENGTH)
    return labels


def parse_snapshot(payload):
    """Reduce ``herdr api snapshot`` output to the agents shown in WebSSH.

    Raises ValueError for anything that is not a session snapshot.
    """
    if not isinstance(payload, (bytes, bytearray)) or len(payload) > MAX_SNAPSHOT_BYTES:
        raise ValueError('Unusable Herdr snapshot')
    try:
        document = json.loads(bytes(payload).decode('utf-8'))
    except (ValueError, RecursionError) as error:
        raise ValueError('Unusable Herdr snapshot') from error
    result = document.get('result') if isinstance(document, dict) else None
    if not isinstance(result, dict) or result.get('type') != 'session_snapshot':
        raise ValueError('Unusable Herdr snapshot')
    snapshot = result.get('snapshot')
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get('agents'), list):
        raise ValueError('Unusable Herdr snapshot')

    labels = _pane_labels(snapshot.get('panes'))
    agents = []
    seen = set()
    truncated = False
    for entry in snapshot['agents']:
        if not isinstance(entry, dict):
            continue
        agent_id = _agent_id(entry.get('pane_id'))
        if agent_id is None or agent_id in seen:
            continue
        if len(agents) == MAX_AGENTS:
            truncated = True
            break
        seen.add(agent_id)
        status = entry.get('agent_status')
        agents.append({
            'id': agent_id,
            'kind': (
                _text(entry.get('display_agent'), MAX_NAME_LENGTH)
                or _text(entry.get('agent'), MAX_NAME_LENGTH)
            ),
            'label': (
                _text(entry.get('name'), MAX_NAME_LENGTH)
                or labels.get(agent_id, '')
            ),
            'cwd': _text(entry.get('cwd'), MAX_PATH_LENGTH),
            'status': status if isinstance(status, str) and status in STATUSES else 'unknown',
        })
    return {'agents': agents, 'truncated': truncated}


# One lookup prefix for every Herdr command, so the overview and the session
# mode always resolve the same binary. The official installer places it in
# ~/.local/bin, which a non-login exec channel does not search. The fixed
# candidates are appended, so the account's own PATH keeps priority, and the
# single-quoted script reaches sh unchanged whatever the login shell is.
PATH_PREFIX = 'PATH="$PATH:$HOME/.local/bin:/usr/local/bin:/opt/homebrew/bin"'
AVAILABLE_COMMAND = f"sh -c '{PATH_PREFIX}; command -v herdr >/dev/null 2>&1'"
# The CLI waits for its server without a deadline, and closing an exec
# channel without a PTY does not signal the remote process. A watchdog on the
# host therefore ends a stuck call; it is detached from the channel's output
# so it cannot hold the channel open, and the call's exit status is kept.
SNAPSHOT_COMMAND = (
    f"sh -c '{PATH_PREFIX}; herdr api snapshot & p=$!; "
    '(sleep 5; kill "$p") >/dev/null 2>&1 & w=$!; '
    'wait "$p"; s=$?; kill "$w" >/dev/null 2>&1; exit "$s"'
    "'"
)
SESSION_COMMAND = f"sh -c '{PATH_PREFIX}; exec herdr'"

SNAPSHOT_TIMEOUT = 3.0
MIN_SNAPSHOT_INTERVAL = 4.0
TIMEOUT_SNAPSHOT_INTERVAL = 30.0
MAX_CONCURRENT_SNAPSHOTS = 4
# One account may not take the whole process-wide budget.
MAX_USER_SNAPSHOTS = 2
MAX_ERROR_BYTES = 4096

_snapshot_slots = BoundedSemaphore(MAX_CONCURRENT_SNAPSHOTS)
_user_snapshots = {}
_user_snapshots_lock = Lock()
_ERROR_REASONS = {
    'server_not_running': 'no_server',
    'protocol_mismatch': 'incompatible',
}


def _profile_allows_overview(user_id, profile_id):
    if not profile_id:
        return False
    from . import profile_manager
    profile = profile_manager.get_profile(user_id, profile_id)
    return isinstance(profile, dict) and profile.get('herdr') is True


def overview_allowed(user_id, profile_id):
    """True when the integration is on and the user's own saved host opts in."""
    from .app_settings import is_herdr_enabled
    return is_herdr_enabled() and _profile_allows_overview(user_id, profile_id)


def session_mode_allowed(user_id, profile_id):
    """True when the overview is allowed and the saved host selects Herdr as its session."""
    from . import profile_manager
    from .app_settings import is_herdr_enabled
    if not is_herdr_enabled() or not profile_id:
        return False
    profile = profile_manager.get_profile(user_id, profile_id)
    return (
        isinstance(profile, dict)
        and profile.get('herdr') is True
        and profile.get('use_herdr') is True
    )


def session_flags(session):
    """Herdr fields of the session data sent to the browser."""
    from .app_settings import is_herdr_enabled
    overview = session.get('herdr') is True and is_herdr_enabled()
    return {'herdr': overview, 'use_herdr': session.get('use_herdr') is True}


def _failure_reason(exit_status, error_output):
    """Map the CLI's exit status and JSON error line to a public reason."""
    if exit_status == 127:
        return 'not_installed'
    if exit_status != 1:
        return 'unavailable'
    for line in reversed(bytes(error_output).splitlines()):
        try:
            document = json.loads(line.decode('utf-8'))
        except (ValueError, RecursionError):
            continue
        error = document.get('error') if isinstance(document, dict) else None
        code = error.get('code') if isinstance(error, dict) else None
        if isinstance(code, str):
            return _ERROR_REASONS.get(code, 'unavailable')
    return 'unavailable'


def _read_snapshot(channel, deadline):
    """Read the bounded command output; return (reason, output, errors)."""
    output = bytearray()
    errors = bytearray()
    while True:
        if time.monotonic() >= deadline:
            return 'timeout', output, errors
        progressed = False
        if channel.recv_ready():
            chunk = channel.recv(MAX_SNAPSHOT_BYTES + 1 - len(output))
            if chunk:
                progressed = True
                output.extend(chunk)
                if len(output) > MAX_SNAPSHOT_BYTES:
                    return 'invalid', output, errors
        if channel.recv_stderr_ready():
            # Drain the stream so a noisy command cannot stall on a full
            # window; only the first bytes are kept for classification.
            chunk = channel.recv_stderr(MAX_ERROR_BYTES)
            if chunk:
                progressed = True
                errors.extend(chunk[:MAX_ERROR_BYTES - len(errors)])
        if progressed:
            continue
        if channel.exit_status_ready():
            return None, output, errors
        time.sleep(0.02)


def _take_user_slot(user_id):
    with _user_snapshots_lock:
        running = _user_snapshots.get(user_id, 0)
        if running >= MAX_USER_SNAPSHOTS:
            return False
        _user_snapshots[user_id] = running + 1
        return True


def _release_user_slot(user_id):
    with _user_snapshots_lock:
        running = _user_snapshots.get(user_id, 0) - 1
        if running > 0:
            _user_snapshots[user_id] = running
        else:
            _user_snapshots.pop(user_id, None)


def collect_snapshot(session_id, user_id, timeout=SNAPSHOT_TIMEOUT):
    """Query one connected session's Herdr server without ever starting it.

    Returns (snapshot, None) or (None, reason). Only the session's owner may
    query it, whatever the caller has checked before.
    """
    from . import ssh_manager
    from .app_settings import is_herdr_enabled

    if not is_herdr_enabled():
        return None, 'disabled'
    with ssh_manager.sessions_lock:
        session = ssh_manager.sessions.get(session_id)
        if not session or not session.get('connected'):
            return None, 'disconnected'
        owner = session.get('user_id')
        if user_id is None or type(owner) is not type(user_id) or owner != user_id:
            return None, 'unavailable'
        if session.get('herdr') is not True:
            return None, 'not_enabled'
        profile_id = session.get('profile_id')
        client = session.get('client')
        lock = session.setdefault('herdr_snapshot_lock', Lock())
    # The saved host may have lost the option since the session connected.
    if not _profile_allows_overview(user_id, profile_id):
        return None, 'not_enabled'
    if not lock.acquire(blocking=False):
        return None, 'busy'
    slot_taken = user_slot_taken = False
    channel = None
    try:
        now = time.monotonic()
        if now < session.get('herdr_snapshot_not_before', now):
            return None, 'busy'
        user_slot_taken = _take_user_slot(user_id)
        if not user_slot_taken:
            return None, 'busy'
        slot_taken = _snapshot_slots.acquire(blocking=False)
        if not slot_taken:
            return None, 'busy'
        session['herdr_snapshot_not_before'] = now + MIN_SNAPSHOT_INTERVAL
        deadline = now + timeout
        transport = client.get_transport() if client else None
        if not transport or not transport.is_active():
            return None, 'disconnected'
        channel = ssh_manager._open_exec_channel(
            transport, SNAPSHOT_COMMAND, timeout=timeout,
        )
        reason, output, errors = _read_snapshot(channel, deadline)
        if reason == 'timeout':
            raise TimeoutError('Herdr snapshot exceeded its deadline')
        if reason:
            return None, reason
        exit_status = channel.recv_exit_status()
        if exit_status != 0:
            return None, _failure_reason(exit_status, errors)
        return parse_snapshot(output), None
    except ValueError:
        return None, 'invalid'
    except (socket.timeout, TimeoutError):
        # A host that does not answer is asked again much less often.
        session['herdr_snapshot_not_before'] = time.monotonic() + TIMEOUT_SNAPSHOT_INTERVAL
        return None, 'timeout'
    except Exception:
        return None, 'unavailable'
    finally:
        try:
            if channel is not None:
                channel.close()
        finally:
            if slot_taken:
                _snapshot_slots.release()
            if user_slot_taken:
                _release_user_slot(user_id)
            lock.release()
