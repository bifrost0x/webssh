"""Read-only view of a remote Herdr session.

Everything Herdr reports is untrusted: agents and any process with access to
its socket choose the names, labels and paths. Only a small, bounded and
cleaned agent list ever leaves this module.
"""
import json
import re
import unicodedata

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
