"""Bounded, account-fenced storage for native SSH automation."""
import hashlib
import json
import uuid
from pathlib import Path

from .data_access import user_operation
from .models import User, db
from .storage_utils import atomic_write_json, load_json_strict, storage_lock
from .storage_errors import StorageCorruptionError

MAX_STORE_BYTES = 1024 * 1024

class AutomationError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class AutomationNotDispatched(AutomationError):
    """A run was definitely not started; nothing reached any target."""


INTENTS_PER_USER = 8
INTENTS_GLOBAL = 4096


def remember_intent(intents, key, payload, now):
    """Store a short-lived intent with per-user and global bounds.

    A user at the per-user bound replaces their own oldest intent instead of
    being refused, so one account can neither lock itself out nor, together
    with a few others, fill the shared table for everyone. The global bound
    only limits memory.
    """
    current = {name: value for name, value in intents.items() if value['expires'] > now}
    user_id = payload['user_id']
    own = sorted((value['expires'], name) for name, value in current.items() if value['user_id'] == user_id)
    while len(own) >= INTENTS_PER_USER:
        current.pop(own.pop(0)[1], None)
    if len(current) >= INTENTS_GLOBAL:
        raise AutomationError('busy')
    current[key] = payload
    return current


class AutomationHostKeyRequired(AutomationError):
    """Selected hosts have no verified host key yet."""

    def __init__(self, hosts):
        super().__init__('host_key_required')
        self.hosts = list(hosts)[:50]

def text(value, maximum, *, empty=False):
    try:
        size = len(value.encode('utf-8')) if isinstance(value, str) else maximum + 1
    except UnicodeError as error:
        raise AutomationError('invalid_request') from error
    if (not isinstance(value, str) or '\x00' in value or
            (not empty and not value.strip()) or size > maximum):
        raise AutomationError('invalid_request')
    return value

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def profile_fingerprint(profile):
    fields = {key: profile.get(key) for key in (
        'id', 'host', 'port', 'username', 'auth_type', 'key_id', 'jump_host_id',
    )}
    # Preserve the existing SSH binding for v1 vaults. Namespaced resources have
    # explicit types and their additional security-relevant connection fields.
    if profile.get('socks_proxy_id'):
        fields['socks_proxy_id'] = profile['socks_proxy_id']
    if profile.get('kind') in {'jump', 'smb', 'socks'}:
        fields['kind'] = profile['kind']
    if profile.get('kind') == 'socks':
        fields['remote_dns'] = profile.get('remote_dns', True)
    if profile.get('kind') == 'smb':
        fields.update(domain=profile.get('domain', ''), share=profile.get('share'))
    if profile.get('route_fingerprint'):
        fields['route_fingerprint'] = profile['route_fingerprint']
    return digest(fields)

def normalize_runbook(value):
    if not isinstance(value, dict):
        raise AutomationError('invalid_runbook')
    steps = value.get('steps')
    if not isinstance(steps, list) or not 1 <= len(steps) <= 20:
        raise AutomationError('invalid_runbook')
    normalized = []
    for step in steps:
        if not isinstance(step, dict):
            raise AutomationError('invalid_runbook')
        timeout = step.get('timeout', 30)
        sudo = step.get('sudo', False)
        if type(timeout) is not int or not 1 <= timeout <= 300 or type(sudo) is not bool:
            raise AutomationError('invalid_runbook')
        normalized.append(dict(name=text(step.get('name'), 128),
                               command=text(step.get('command'), 8192), timeout=timeout, sudo=sudo))
    stop = value.get('stop_on_error', True)
    if type(stop) is not bool:
        raise AutomationError('invalid_runbook')
    return dict(id=text(value.get('id', str(uuid.uuid4())), 64),
                name=text(value.get('name'), 128), steps=normalized, stop_on_error=stop)

@user_operation
def user_path(user_id, name):
    user = db.session.get(User, int(user_id))
    if user is None:
        raise AutomationError('unavailable')
    root = Path(user.get_data_dir())
    path = root / name
    if root.is_symlink() or path.is_symlink():
        raise AutomationError('storage_unavailable')
    return path

@user_operation
def incarnation(user_id):
    value = db.session.query(User.created_at).filter_by(id=int(user_id)).first()
    if value is None:
        raise AutomationError('unavailable')
    return value[0].isoformat()

def read_document(path, default, validator):
    if path.exists() and path.stat().st_size > MAX_STORE_BYTES:
        raise AutomationError('storage_limit')
    return load_json_strict(path, lambda: default, validator)

def write_document(path, document):
    if len(json.dumps(document).encode()) > MAX_STORE_BYTES:
        raise AutomationError('storage_limit')
    atomic_write_json(path, document)

def _valid_books(document):
    try:
        return (isinstance(document, dict) and document.get('version') == 1
                and isinstance(document.get('runbooks'), list) and len(document['runbooks']) <= 100
                and all(normalize_runbook(book) == book for book in document['runbooks'])
                and len({book['id'] for book in document['runbooks']}) == len(document['runbooks']))
    except (ValueError, TypeError, KeyError):
        return False

@user_operation
def runbooks(user_id):
    with storage_lock(f'automation:{user_id}'):
        return read_document(user_path(user_id, 'automation.json'),
                             dict(version=1, runbooks=[]), _valid_books)['runbooks']

@user_operation
def save_runbook(user_id, value):
    book = normalize_runbook(value)
    with storage_lock(f'automation:{user_id}'):
        path = user_path(user_id, 'automation.json')
        document = read_document(path, dict(version=1, runbooks=[]), _valid_books)
        books = document['runbooks']
        if value.get('id') and not any(item['id'] == book['id'] for item in books):
            raise AutomationError('not_found')
        document['runbooks'] = [item for item in books if item['id'] != book['id']] + [book]
        if len(document['runbooks']) > 100:
            raise AutomationError('storage_limit')
        write_document(path, document)
    return book

@user_operation
def delete_runbook(user_id, book_id):
    with storage_lock(f'automation:{user_id}'):
        path = user_path(user_id, 'automation.json')
        document = read_document(path, dict(version=1, runbooks=[]), _valid_books)
        if not any(book['id'] == book_id for book in document['runbooks']):
            raise AutomationError('not_found')
        document['runbooks'] = [book for book in document['runbooks'] if book['id'] != book_id]
        write_document(path, document)
