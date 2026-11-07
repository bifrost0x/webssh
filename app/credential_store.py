"""Atomic owned password records and explicitly confirmed destination assignments."""
import secrets
from datetime import datetime, timezone
from . import credential_crypto
from .automation_store import AutomationError, read_document, write_document, user_path, text, profile_fingerprint
from .storage_utils import storage_lock


def _valid(doc):
    try:
        return (set(doc) == {'version','credentials','assignments','imports'} and doc['version'] == 1
            and isinstance(doc['credentials'], dict) and len(doc['credentials']) <= 100
            and isinstance(doc['assignments'], dict) and len(doc['assignments']) <= 1000
            and isinstance(doc['imports'], list) and len(doc['imports']) <= 100
            and all(isinstance(k,str) and set(v)=={'id','name','username','version','updated_at','ciphertext'}
                and v['id']==k and text(v['name'],128) and isinstance(v['username'],str)
                and text(v['version'],64) and text(v['ciphertext'],8192) for k,v in doc['credentials'].items())
            and all(isinstance(k,str) and set(v)=={'credential_id','fingerprint','generation'}
                and v['credential_id'] in doc['credentials'] and isinstance(v['fingerprint'],str)
                and isinstance(v['generation'],str) for k,v in doc['assignments'].items()))
    except (ValueError,TypeError,KeyError):
        return False


class NamedStore:
    def path(self, uid):
        return user_path(uid, 'credentials.json')

    def read(self, uid):
        return read_document(self.path(uid),dict(version=1,credentials={},assignments={},imports=[]),_valid)

    def mutate(self, uid, operation):
        with storage_lock(f'named-credentials:{uid}'):
            document = self.read(uid)
            result = operation(document)
            if not _valid(document):
                raise AutomationError('storage_limit')
            write_document(self.path(uid),document)
            return result

    def public(self, doc, record):
        return {**{k:v for k,v in record.items() if k!='ciphertext'},
                'uses':[rid for rid,a in doc['assignments'].items() if a['credential_id']==record['id']]}

    def create(self, uid, doc, data):
        rid = secrets.token_hex(16)
        record = dict(id=rid,name=text(data.get('name'),128),username=text(data.get('username',''),256,empty=True),
                      version=secrets.token_hex(32),updated_at=datetime.now(timezone.utc).isoformat(),
                      ciphertext=credential_crypto.encrypt(uid,rid,text(data.get('password'),4096)))
        doc['credentials'][rid]=record
        return self.public(doc,record)

    def record(self, doc, rid):
        text(rid,128)
        if rid not in doc['credentials']:
            raise AutomationError('not_found')
        return doc['credentials'][rid]

    def assigned(self, uid, profile):
        doc = self.read(uid)
        assignment = doc['assignments'].get(profile['id'])
        if assignment is None:
            raise AutomationError('credential_missing')
        if assignment['fingerprint'] != profile_fingerprint(profile):
            raise AutomationError('credential_target_changed')
        return assignment,self.record(doc,assignment['credential_id'])

def finish_resource_transaction(path, before, record, callback):
    """Called while the resource manager still owns its normal mutation locks."""
    if callback is None:
        return
    from .storage_utils import atomic_write_bytes
    try:
        callback(record)
    except BaseException:
        if before is None: path.unlink(missing_ok=True)
        else: atomic_write_bytes(path,before)
        raise
