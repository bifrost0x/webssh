"""Per-user persistence for non-secret SMB share connection definitions."""

from datetime import datetime, timezone
import re
import uuid

import config

from .network_policy import canonicalize_hostname
from .smb_paths import SMBPathRejected, SMBShareName
from .storage_migrations import CURRENT_STORAGE_VERSIONS
from .storage_utils import atomic_write_json, load_json_migrated, storage_lock


_ID_PATTERN = re.compile(r'[A-Za-z0-9._-]{1,64}')
_KNOWN_FIELDS = {
    'id',
    'name',
    'host',
    'share',
    'domain',
    'username',
    'created_at',
    'updated_at',
}
_SECRET_MARKERS = (
    'password',
    'passwd',
    'passphrase',
    'credential',
    'secret',
    'token',
)
_MAX_SAVED_SHARE_DOCUMENT_ITEMS = 1000


def _is_secret_field(key):
    normalized = re.sub(r'[^a-z0-9]', '', str(key).casefold())
    return any(marker in normalized for marker in _SECRET_MARKERS)


def _contains_secret_field(value):
    return isinstance(value, dict) and any(
        _is_secret_field(key) for key in value
    )


def get_user_smb_shares_file(user_id):
    from .models import User, db

    user = db.session.get(User, user_id)
    if user is None:
        return None
    return user.get_data_dir() / 'smb_shares.json'


def _clean_text(value, *, required, maximum):
    if not isinstance(value, str):
        raise ValueError('Invalid text value')
    value = value.strip()
    if (required and not value) or len(value) > maximum:
        raise ValueError('Invalid text value')
    if any(not character.isprintable() for character in value):
        raise ValueError('Invalid text value')
    return value


def _valid_share(item):
    if not isinstance(item, dict) or _contains_secret_field(item):
        return False
    if not isinstance(item.get('id'), str) or not _ID_PATTERN.fullmatch(
        item['id']
    ):
        return False
    try:
        name = _clean_text(item.get('name'), required=True, maximum=128)
        host = canonicalize_hostname(item.get('host'))
        share = str(SMBShareName.parse(item.get('share')))
        domain = _clean_text(item.get('domain', ''), required=False, maximum=255)
        username = _clean_text(
            item.get('username'), required=True, maximum=256
        )
    except (TypeError, ValueError, SMBPathRejected):
        return False
    if (
        name != item['name']
        or host != item['host']
        or share != item['share']
        or domain != item.get('domain', '')
        or username != item['username']
    ):
        return False
    return all(
        isinstance(item.get(field), str) and bool(item[field])
        for field in ('created_at', 'updated_at')
    )


def _valid_document(value):
    return (
        isinstance(value, dict)
        and value.get('schema_version')
        == CURRENT_STORAGE_VERSIONS['smb_shares']
        and isinstance(value.get('smb_shares'), list)
        and len(value['smb_shares']) <= _MAX_SAVED_SHARE_DOCUMENT_ITEMS
        and all(_valid_share(item) for item in value['smb_shares'])
    )


def _load_with_lock_held(user_id):
    path = get_user_smb_shares_file(user_id)
    if path is None:
        return []
    document = load_json_migrated(
        path,
        'smb_shares',
        lambda: {'smb_shares': []},
        _valid_document,
    )
    return document['smb_shares']


def load_smb_shares(user_id):
    with storage_lock(f'smb-shares:{user_id}'):
        return _load_with_lock_held(user_id)


def _write_with_lock_held(user_id, shares):
    path = get_user_smb_shares_file(user_id)
    if path is None:
        return False
    document = {
        'schema_version': CURRENT_STORAGE_VERSIONS['smb_shares'],
        'smb_shares': shares,
    }
    if not _valid_document(document):
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(path, document)
    return True


def _validate_payload(payload):
    if not isinstance(payload, dict):
        return None, 'Invalid SMB share data'
    if _contains_secret_field(payload):
        return None, 'Passwords cannot be saved'
    try:
        name = _clean_text(payload.get('name'), required=True, maximum=128)
        host = canonicalize_hostname(payload.get('host'))
        share = str(SMBShareName.parse(payload.get('share')))
        domain = _clean_text(
            payload.get('domain', ''), required=False, maximum=255
        )
        username = _clean_text(
            payload.get('username'), required=True, maximum=256
        )
    except (TypeError, ValueError, SMBPathRejected):
        return None, 'Invalid SMB share data'
    share_id = payload.get('id')
    if share_id is not None and (
        not isinstance(share_id, str) or not _ID_PATTERN.fullmatch(share_id)
    ):
        return None, 'Invalid SMB share ID'
    return {
        'name': name,
        'host': host,
        'share': share,
        'domain': domain,
        'username': username,
    }, None


def upsert_smb_share(user_id, payload):
    validated, error = _validate_payload(payload)
    if error:
        return None, error
    with storage_lock(f'smb-shares:{user_id}'):
        path = get_user_smb_shares_file(user_id)
        if path is None:
            return None, 'User not found'
        shares = _load_with_lock_held(user_id)
        share_id = payload.get('id')
        if any(
            item['name'].casefold() == validated['name'].casefold()
            and item['id'] != share_id
            for item in shares
        ):
            return None, 'An SMB share with this name already exists'

        now = datetime.now(timezone.utc).isoformat()
        if share_id is not None:
            for index, existing in enumerate(shares):
                if existing['id'] != share_id:
                    continue
                unknown = {
                    key: value
                    for key, value in existing.items()
                    if key not in _KNOWN_FIELDS and not _is_secret_field(key)
                }
                saved = {
                    **unknown,
                    **validated,
                    'id': share_id,
                    'created_at': existing['created_at'],
                    'updated_at': now,
                }
                shares[index] = saved
                if not _write_with_lock_held(user_id, shares):
                    return None, 'Failed to save SMB share'
                return saved, None
            return None, 'SMB share not found'

        if len(shares) >= config.SMB_MAX_SAVED_SHARES:
            return None, 'Saved SMB share limit reached'

        saved = {
            **validated,
            'id': uuid.uuid4().hex,
            'created_at': now,
            'updated_at': now,
        }
        shares.append(saved)
        if not _write_with_lock_held(user_id, shares):
            return None, 'Failed to save SMB share'
        return saved, None


def delete_smb_share(user_id, share_id):
    if not isinstance(share_id, str) or not _ID_PATTERN.fullmatch(share_id):
        return False, 'SMB share not found'
    with storage_lock(f'smb-shares:{user_id}'):
        path = get_user_smb_shares_file(user_id)
        if path is None:
            return False, 'User not found'
        shares = _load_with_lock_held(user_id)
        remaining = [item for item in shares if item['id'] != share_id]
        if len(remaining) == len(shares):
            return False, 'SMB share not found'
        if not _write_with_lock_held(user_id, remaining):
            return False, 'Failed to delete SMB share'
        return True, None
