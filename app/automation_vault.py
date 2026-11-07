"""Write-only password vault; its key exists only in a bounded browser lease."""
import base64
import json
import os
import secrets
import threading
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .automation_store import (AutomationError, digest, incarnation, profile_fingerprint,
                               read_document, text, user_path, write_document)
from .data_access import user_data_access
from functools import wraps
from .storage_utils import storage_lock

TTL = 900
_KDF = threading.BoundedSemaphore(1)

def _encode(value):
    return base64.b64encode(value).decode('ascii')

def _decode(value, maximum):
    if not isinstance(value, str) or len(value) > maximum:
        raise AutomationError('vault_unreadable')
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as error:
        raise AutomationError('vault_unreadable') from error

def _valid(document):
    return (isinstance(document, dict) and set(document) == {'version', 'kdf', 'salt', 'nonce', 'ciphertext'}
            and type(document['version']) is int and document['version'] in {1, 2}
            and document['kdf'] == 'scrypt-131072-8-1'
            and all(isinstance(document[key], str) for key in ('salt', 'nonce', 'ciphertext')))

def _derive(passphrase, salt):
    text(passphrase, 1024)
    if len(passphrase) < 16 or len(salt) != 16:
        raise AutomationError('invalid_passphrase')
    return Scrypt(salt=salt, length=32, n=131072, r=8, p=1).derive(passphrase.encode('utf-8'))

def kdf_operation(function):
    @wraps(function)
    def guarded(*args, **kwargs):
        if not _KDF.acquire(blocking=False):
            raise AutomationError('busy')
        try:
            return function(*args, **kwargs)
        finally:
            _KDF.release()
    return guarded

def vault_operation(function):
    @wraps(function)
    def wrapped(self, user_id, *args, **kwargs):
        with user_data_access(user_id):
            return function(self, user_id, *args, **kwargs)
    return wrapped

class Vault:
    def __init__(self):
        self._guard = threading.RLock()
        self._leases = {}

    def path(self, user_id):
        return user_path(user_id, 'automation-vault.json')

    def _binding(self, user_id, auth_id):
        if isinstance(auth_id, int) or str(auth_id).isdigit():
            from datetime import datetime, timezone
            from .models import AuthenticationSession, User, as_naive_utc, db
            row = db.session.query(AuthenticationSession.session_hash).join(
                User, User.id == AuthenticationSession.user_id
            ).filter(AuthenticationSession.id == int(auth_id), User.id == int(user_id),
                AuthenticationSession.auth_generation == User.auth_generation,
                AuthenticationSession.expires_at > as_naive_utc(datetime.now(timezone.utc))).first()
            if row is None:
                raise AutomationError('vault_locked')
            return row[0]
        return str(auth_id)

    def _aad(self, user_id, version=1):
        return f'webssh-automation-vault-v{version}:{user_id}:{incarnation(user_id)}'.encode()

    def lock(self, user_id=None):
        with self._guard:
            owners = list(self._leases) if user_id is None else [int(user_id)]
            for owner in owners:
                lease = self._leases.pop(owner, None)
                if lease:
                    lease['key'][:] = b'\x00' * len(lease['key'])

    def lock_session(self, auth_id):
        with self._guard:
            for owner in [owner for owner, lease in self._leases.items() if lease['auth_id'] == str(auth_id)]:
                self.lock(owner)

    def _read(self, user_id):
        path = self.path(user_id)
        if not path.exists():
            raise AutomationError('vault_missing')
        return read_document(path, None, _valid)

    def _lease(self, user_id, auth_id, document):
        lease = self._leases.get(int(user_id))
        if (lease is None or lease['auth_id'] != str(auth_id) or lease['binding'] != self._binding(user_id, auth_id) or lease['expires'] <= time.monotonic()
                or lease['incarnation'] != incarnation(user_id) or lease['generation'] != digest(document)):
            if lease and (lease['expires'] <= time.monotonic() or lease['generation'] != digest(document)
                          or lease['incarnation'] != incarnation(user_id)):
                self.lock(user_id)
            raise AutomationError('vault_locked')
        return lease

    def _decrypt(self, user_id, key, document):
        try:
            nonce = _decode(document['nonce'], 32)
            ciphertext = _decode(document['ciphertext'], 900000)
            if len(nonce) != 12:
                raise AutomationError('vault_unreadable')
            credentials = json.loads(AESGCM(bytes(key)).decrypt(nonce, ciphertext, self._aad(user_id, document['version'])))
            if (not isinstance(credentials, dict) or len(credentials) > 100
                    or not all(isinstance(k, str) and isinstance(v, dict)
                               and set(v) == ({'fingerprint', 'password'} if document['version'] == 1
                                              else {'fingerprint', 'password', 'generation'})
                               and (document['version'] == 1 or isinstance(v['generation'], str)
                                    and len(v['generation']) == 64
                                    and all(c in '0123456789abcdef' for c in v['generation']))
                               and isinstance(v['fingerprint'], str) and len(v['fingerprint']) == 64
                               and isinstance(v['password'], str) and 0 < len(v['password'].encode()) <= 4096
                               for k, v in credentials.items())):
                raise AutomationError('vault_unreadable')
            return credentials
        except (InvalidTag, ValueError, KeyError, UnicodeError) as error:
            raise AutomationError('vault_unlock_failed') from error

    def _write(self, user_id, key, salt, credentials):
        # A v1 unlock is read-only. Its first authorized mutation preserves the
        # in-memory generations of unchanged records in the new encrypted format.
        legacy = self._leases.get(int(user_id), {}).get('record_generations', {})
        credentials = {name: dict(value, generation=value.get('generation')
                       or legacy.get(name) or secrets.token_hex(32)) for name, value in credentials.items()}
        nonce = os.urandom(12)
        payload = json.dumps(credentials, separators=(',', ':')).encode()
        document = dict(version=2, kdf='scrypt-131072-8-1', salt=_encode(salt), nonce=_encode(nonce),
                        ciphertext=_encode(AESGCM(bytes(key)).encrypt(nonce, payload, self._aad(user_id, 2))))
        write_document(self.path(user_id), document)
        return document

    def _remember(self, user_id, auth_id, key, document):
        self.lock(user_id)
        self._leases[int(user_id)] = dict(auth_id=str(auth_id), key=bytearray(key),
            identity=secrets.token_hex(32), record_generations={},
            binding=self._binding(user_id, auth_id), expires=time.monotonic() + TTL, incarnation=incarnation(user_id), generation=digest(document))

    @vault_operation
    @kdf_operation
    def setup(self, user_id, auth_id, passphrase):
        with self._guard, storage_lock(f'automation-vault:{user_id}'):
            if self.path(user_id).exists():
                raise AutomationError('vault_exists')
            salt = os.urandom(16)
            key = _derive(passphrase, salt)
            document = self._write(user_id, key, salt, {})
            self._remember(user_id, auth_id, key, document)
        return self.status(user_id, auth_id)

    @vault_operation
    @kdf_operation
    def unlock(self, user_id, auth_id, passphrase):
        with self._guard, storage_lock(f'automation-vault:{user_id}'):
            document = self._read(user_id)
            key = _derive(passphrase, _decode(document['salt'], 32))
            self._decrypt(user_id, key, document)
            self._remember(user_id, auth_id, key, document)
        return self.status(user_id, auth_id)

    @vault_operation
    def status(self, user_id, auth_id):
        with self._guard:
            exists = self.path(user_id).exists()
            result = dict(exists=exists, unlocked=False, expires_in=0, credentials=[])
            if not exists:
                return result
            document = self._read(user_id)
            try:
                lease = self._lease(user_id, auth_id, document)
            except AutomationError as error:
                if error.code != 'vault_locked':
                    raise
                return result
            records = self._decrypt(user_id, lease['key'], document)
            return dict(exists=True, unlocked=True,
                        expires_in=max(0, int(lease['expires'] - time.monotonic())),
                        credentials=[dict(profile_id=key, fingerprint=value['fingerprint'])
                                     for key, value in records.items()])

    @vault_operation
    def generation(self, user_id, auth_id):
        with self._guard:
            document = self._read(user_id)
            return self._lease(user_id, auth_id, document)['generation']

    @vault_operation
    def generations(self, user_id, auth_id, profiles):
        """Opaque lease and used-record identities, never derived from secrets."""
        with self._guard:
            document = self._read(user_id)
            lease = self._lease(user_id, auth_id, document)
            records = self._decrypt(user_id, lease['key'], document)
            selected = {}
            for profile in profiles:
                record = records.get(profile['id'])
                if record is None or record['fingerprint'] != profile_fingerprint(profile):
                    raise AutomationError('credential_missing')
                selected[profile['id']] = record.get('generation') or lease['record_generations'].setdefault(
                    profile['id'], secrets.token_hex(32))
            return dict(lease=lease['identity'], records=selected)

    @vault_operation
    def put(self, user_id, auth_id, profile, password):
        text(password, 4096)
        with self._guard, storage_lock(f'automation-vault:{user_id}'):
            document = self._read(user_id)
            lease = self._lease(user_id, auth_id, document)
            records = self._decrypt(user_id, lease['key'], document)
            records[profile['id']] = dict(fingerprint=profile_fingerprint(profile), password=password,
                                          generation=secrets.token_hex(32))
            if len(records) > 100:
                raise AutomationError('storage_limit')
            updated = self._write(user_id, lease['key'], _decode(document['salt'], 32), records)
            lease['generation'] = digest(updated)
        return self.status(user_id, auth_id)

    @vault_operation
    def delete(self, user_id, auth_id, profile_id):
        with self._guard, storage_lock(f'automation-vault:{user_id}'):
            document = self._read(user_id)
            lease = self._lease(user_id, auth_id, document)
            records = self._decrypt(user_id, lease['key'], document)
            if profile_id not in records:
                raise AutomationError('not_found')
            del records[profile_id]
            updated = self._write(user_id, lease['key'], _decode(document['salt'], 32), records)
            lease['generation'] = digest(updated)
        return self.status(user_id, auth_id)

    @vault_operation
    def password(self, user_id, auth_id, profile):
        with self._guard:
            document = self._read(user_id)
            lease = self._lease(user_id, auth_id, document)
            record = self._decrypt(user_id, lease['key'], document).get(profile['id'])
            if not record or record['fingerprint'] != profile_fingerprint(profile):
                raise AutomationError('credential_missing')
            return record['password']

    @vault_operation
    @kdf_operation
    def change_passphrase(self, user_id, auth_id, passphrase):
        with self._guard, storage_lock(f'automation-vault:{user_id}'):
            document = self._read(user_id)
            lease = self._lease(user_id, auth_id, document)
            records = self._decrypt(user_id, lease['key'], document)
            salt = os.urandom(16)
            key = _derive(passphrase, salt)
            updated = self._write(user_id, key, salt, records)
            self._remember(user_id, auth_id, key, updated)
        return self.status(user_id, auth_id)

    @vault_operation
    def reset(self, user_id, auth_id):
        with self._guard, storage_lock(f'automation-vault:{user_id}'):
            self.lock(user_id)
            self.path(user_id).unlink(missing_ok=True)
        return self.status(user_id, auth_id)

    def _same_binding(self, owner, lease):
        try:
            return self._binding(owner, lease['auth_id']) == lease['binding']
        except AutomationError:
            return False

    def purge(self, valid_session=lambda _owner, _auth_id: True):
        with self._guard:
            for owner, lease in list(self._leases.items()):
                if lease['expires'] <= time.monotonic() or not valid_session(owner, lease['auth_id']) or not self._same_binding(owner, lease):
                    self.lock(owner)
