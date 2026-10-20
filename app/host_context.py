"""Revisioned private notes and shortcuts for stable saved-profile identities."""

import copy
import json

from .models import User, db
from .profile_manager import _load_profiles_for_read_with_lock_held
from .storage_utils import atomic_write_bytes, load_json_strict, storage_lock

MAX_STORE_BYTES = 4 * 1024 * 1024
MAX_HOST_CONTEXTS = 2000


class ContextError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def bind_profile(user_id, profile_id, host, port, username, jump_host_id, *, optional=False):
    """Bind only an explicitly selected, owned profile with the actual route."""
    if profile_id is None:
        return None
    from .profile_manager import get_profile
    from .network_policy import canonicalize_hostname
    if not isinstance(profile_id, str) or not profile_id or len(profile_id) > 128:
        raise ContextError('invalid_profile')
    profile = get_profile(user_id, profile_id)
    try:
        matches = profile is not None and (
            canonicalize_hostname(profile['host']) == canonicalize_hostname(host)
            and int(profile.get('port', 22)) == int(port)
            and profile['username'] == username
            and (profile.get('jump_host_id') or None) == (jump_host_id or None)
        )
    except (ValueError, TypeError, KeyError):
        matches = False
    if not matches:
        if optional:
            return None
        raise ContextError('invalid_profile')
    return profile_id


def _empty():
    return {'revision': 0, 'notes': '', 'directories': [], 'command_sets': []}


def _valid_content(value):
    if not isinstance(value, dict) or set(value) != {'notes', 'directories', 'command_sets'}:
        return False
    if not isinstance(value['notes'], str) or len(value['notes']) > 100000:
        return False
    for field in ('directories', 'command_sets'):
        entries = value[field]
        if not isinstance(entries, list) or len(entries) > 20:
            return False
        if any(not isinstance(entry, str) for entry in entries):
            return False
        if len(set(entries)) != len(entries):
            return False
    if any(
        not path.startswith('/') or len(path.encode('utf-8')) > 4096
        or any(not character.isprintable() for character in path)
        for path in value['directories']
    ):
        return False
    return all(0 < len(reference) <= 128 for reference in value['command_sets'])


def _valid_document(document):
    if not isinstance(document, dict) or document.get('version') != 1:
        return False
    hosts = document.get('hosts')
    if not isinstance(hosts, dict) or len(hosts) > MAX_HOST_CONTEXTS:
        return False
    for profile_id, value in hosts.items():
        if not isinstance(profile_id, str) or len(profile_id) > 128 or not isinstance(value, dict):
            return False
        revision = value.get('revision')
        if type(revision) is not int or revision < 1:
            return False
        if not _valid_content({key: item for key, item in value.items() if key != 'revision'}):
            return False
    return True


def _owned_profiles(user_id, profile_id):
    if not isinstance(profile_id, str) or len(profile_id) > 128:
        raise ContextError('not_found')
    with storage_lock(f'profiles:{user_id}'):
        profiles = _load_profiles_for_read_with_lock_held(user_id)
    ids = {profile['id'] for profile in profiles}
    if profile_id not in ids:
        raise ContextError('not_found')
    return ids


def _load(user_id):
    user = db.session.get(User, user_id)
    if user is None:
        raise ContextError('not_found')
    path = user.get_data_dir() / 'host_context.json'
    if path.exists() and path.stat().st_size > MAX_STORE_BYTES:
        raise ContextError('quota')
    document = load_json_strict(path, lambda: {'version': 1, 'hosts': {}}, _valid_document)
    return path, document


def read_context(user_id, profile_id):
    with storage_lock(f'command-config:{user_id}'):
        _owned_profiles(user_id, profile_id)
        with storage_lock(f'host-context:{user_id}'):
            _path, document = _load(user_id)
            return copy.deepcopy(document['hosts'].get(profile_id, _empty()))


def write_context(user_id, profile_id, content, expected_revision):
    try:
        valid = _valid_content(content)
        content_bytes = json.dumps(content, ensure_ascii=False).encode('utf-8')
    except (TypeError, ValueError, UnicodeError):
        valid = False
        content_bytes = b''
    if not valid or len(content_bytes) > 512 * 1024 or type(expected_revision) is not int:
        raise ContextError('invalid')
    with storage_lock(f'command-config:{user_id}'):
        ids = _owned_profiles(user_id, profile_id)
        from .command_set_manager import get_command_set
        for reference in content['command_sets']:
            command_set, error = get_command_set(user_id, reference)
            if error or command_set is None:
                raise ContextError('invalid_reference')
        with storage_lock(f'host-context:{user_id}'):
            path, document = _load(user_id)
            previous = document['hosts'].get(profile_id, _empty())
            if expected_revision != previous['revision']:
                raise ContextError('conflict')
            updated = {**copy.deepcopy(content), 'revision': expected_revision + 1}
            document['hosts'] = {key: value for key, value in document['hosts'].items() if key in ids}
            document['hosts'][profile_id] = updated
            payload = json.dumps(document, ensure_ascii=False).encode('utf-8')
            if len(payload) > MAX_STORE_BYTES or len(document['hosts']) > MAX_HOST_CONTEXTS:
                raise ContextError('quota')
            atomic_write_bytes(path, payload)
            return updated
