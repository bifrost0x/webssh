"""Personal credential boundary, independent of the Automation feature switch."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import secrets
import threading
import time

from flask import has_request_context, request
from .automation_store import AutomationError, profile_fingerprint, text, MAX_STORE_BYTES
from .automation_vault import Vault
from .audit_logger import log_security_event
from .data_access import user_data_access
from .models import AuthenticationSession, User, as_naive_utc, db
from .profile_manager import load_profiles
from .jump_host_manager import load_jump_hosts
from .smb_share_manager import load_smb_shares

def session_identity(user_id, auth_id):
    db.session.expire_all()
    auth = db.session.get(AuthenticationSession, int(auth_id))
    user = db.session.get(User, int(user_id))
    if (user is None or auth is None or auth.user_id != int(user_id)
            or auth.auth_generation != int(user.auth_generation or 0)
            or auth.expires_at <= as_naive_utc(datetime.now(timezone.utc))):
        raise AutomationError('authentication_required')
    return (user.created_at.isoformat(), auth.session_hash, auth.auth_generation)


class CredentialService:
    def __init__(self, app):
        self.app = app
        self.vault = Vault()
        from .credential_store import NamedStore
        self.named = NamedStore()
        self._lock = threading.RLock()
        self._intents = {}
        self._vault_mutations = threading.Lock()

    def resources(self, user_id, *, coordinator_held=False):
        """Current owned non-secret resources with collision-free public IDs."""
        with user_data_access(user_id):
            if coordinator_held:
                from .profile_manager import _load_profiles_for_read_with_lock_held
                from .jump_host_manager import _load_jump_hosts_for_read_with_lock_held
                from .smb_share_manager import _load_with_lock_held
                jumps=_load_jump_hosts_for_read_with_lock_held(user_id)
                profiles=_load_profiles_for_read_with_lock_held(user_id)
                shares=_load_with_lock_held(user_id)
            else:
                jumps=load_jump_hosts(user_id)
                profiles=load_profiles(user_id)
                shares=load_smb_shares(user_id)
            by_id = {item['id']: item for item in jumps}
            result = []
            for item in profiles:
                resource = dict(item, kind='ssh')
                if item.get('jump_host_id'):
                    jump = by_id.get(item['jump_host_id'])
                    resource['route_fingerprint'] = profile_fingerprint(jump or {})
                result.append(resource)
            result.extend(dict(item, id='jump:'+item['id'], kind='jump') for item in jumps)
            result.extend(dict(item, id='smb:'+item['id'], kind='smb', port=445,
                               auth_type='password') for item in shares)
            return result

    def resolve_resource(self, user_id, resource_id):
        text(resource_id, 128)
        matches = [item for item in self.resources(user_id) if item['id'] == resource_id]
        # Imported legacy stores may contain arbitrary or duplicate IDs. Never
        # let list order choose a different resource's credential binding.
        if len(matches) != 1:
            raise AutomationError('invalid_targets')
        return matches[0]

    def vault_status(self, user_id, auth_id):
        """Annotate non-secret records against their current owned bindings."""
        with user_data_access(user_id):
            status = self.vault.status(user_id, auth_id)
            if not status['credentials']:
                return status
            fingerprints = {}
            for resource in self.resources(user_id):
                fingerprints.setdefault(resource['id'], []).append(profile_fingerprint(resource))
            for record in status['credentials']:
                record['valid'] = fingerprints.get(record['profile_id']) == [record['fingerprint']]
            return status

    def _connection_resource(self, user_id, kind, resource_id, connection):
        # Background callers have already admitted the secure browser request.
        if has_request_context() and not request.is_secure:
            raise AutomationError('https_required')
        if not self.app.extensions['runtime_lifecycle'].accepting_work():
            raise AutomationError('unavailable')
        resource = self.resolve_resource(user_id, resource_id)
        if (kind not in {'ssh', 'jump', 'smb'} or resource['kind'] != kind
                or resource.get('auth_type') != 'password' or not isinstance(connection, dict)):
            raise AutomationError('invalid_targets')
        defaults = dict(port=445 if kind == 'smb' else 22, auth_type='password',
                        key_id=None, jump_host_id=None, domain='')
        fields = ('host', 'port', 'username', 'auth_type', 'key_id', 'jump_host_id')
        if kind == 'smb':
            fields += ('domain', 'share')
        if any(connection.get(field, defaults.get(field)) != resource.get(field, defaults.get(field))
               for field in fields):
            raise AutomationError('credential_target_changed')
        return resource

    def connection_password(self, user_id, auth_id, kind, resource_id, connection):
        """Return a secret only to the server's exact, currently owned destination."""
        with user_data_access(user_id):
            resource = self._connection_resource(user_id, kind, resource_id, connection)
            return self.password(user_id, auth_id, resource)

    def connection_generation(self, user_id, auth_id, kind, resource_id, connection):
        """Capture/recheck this token during pending authentication, never cache a secret."""
        with user_data_access(user_id):
            resource = self._connection_resource(user_id, kind, resource_id, connection)
            return self.generations(user_id, auth_id, [resource])

    def revoke(self, user_id):
        with self._lock:
            self.vault.lock(user_id)
            self._intents = {k:v for k,v in self._intents.items() if v['user_id'] != int(user_id)}

    lock = revoke

    def revoke_session(self, auth_id):
        with self._lock:
            self.vault.lock_session(auth_id)
            self._intents = {k:v for k,v in self._intents.items() if v['auth_id'] != int(auth_id)}

    def shutdown(self, deadline=None):
        with self._lock:
            self.vault.lock()
            self._intents.clear()

    def cleanup(self, cancelled):
        while not cancelled.wait(5):
            with self.app.app_context():
                def valid(uid, aid):
                    try:
                        session_identity(uid, aid)
                        return not self.app.extensions['data_access'].closed
                    except Exception:
                        return False
                self.vault.purge(valid)
                with self._lock:
                    self._intents = {k:v for k,v in self._intents.items() if v['expires'] > time.monotonic()}

    def _remember(self, user_id, auth_id, payload):
        now = time.monotonic()
        token = secrets.token_urlsafe(32)
        payload = dict(payload, user_id=int(user_id), auth_id=int(auth_id),
                       identity=session_identity(user_id, auth_id), expires=now+300)
        with self._lock:
            self._intents = {key: value for key, value in self._intents.items() if value['expires'] > now}
            if len(self._intents) >= 256 or sum(value['user_id'] == int(user_id) for value in self._intents.values()) >= 8:
                raise AutomationError('busy')
            self._intents[hashlib.sha256(token.encode()).hexdigest()] = payload
        return token

    def intent(self, token, user_id, auth_id, *, consume=False):
        from .app_settings import credentials_policy_revision
        if not isinstance(token, str) or not 30 <= len(token) <= 128:
            raise AutomationError('invalid_intent')
        key = hashlib.sha256(token.encode()).hexdigest()
        with self._lock:
            value = self._intents.get(key)
            if (value is None or value['user_id'] != int(user_id) or value['auth_id'] != int(auth_id)
                    or value['expires'] <= time.monotonic()
                    or value['identity'] != session_identity(user_id, auth_id)
                    or (value.get('kind') == 'native' and value.get('policy') != credentials_policy_revision())):
                raise AutomationError('invalid_intent')
            if consume:
                del self._intents[key]
            return deepcopy(value)

    def prepare_vault(self, user_id, auth_id, data):
        self._named_enabled()
        if self._vault_mutations.locked():
            raise AutomationError('busy')
        operation = data.get('operation')
        if operation == 'native':
            from .automation_store import digest
            from .app_settings import credentials_policy_revision
            mutation=data.get('mutation')
            if not isinstance(mutation,dict): raise AutomationError('invalid_request')
            frozen=None
            prior=None
            if mutation.get('method') in {'create','assign'} and mutation.get('resource_id'):
                frozen=profile_fingerprint(self.resolve_resource(user_id,mutation['resource_id']))
                prior=deepcopy(self.named.read(user_id)['assignments'].get(mutation['resource_id']))
                if 'expected_assignment' in mutation and mutation['expected_assignment'] != prior:
                    raise AutomationError('preview_changed')
                replacing=prior and (mutation.get('method')=='create' or mutation.get('credential_id') not in (None,prior['credential_id']))
                if replacing and mutation.get('replace_credential_id') != prior['credential_id']:
                    raise AutomationError('replacement_confirmation_required')
            return dict(intent=self._remember(user_id,auth_id,dict(kind='native',mutation_digest=digest(mutation),resource_fingerprint=frozen,prior_assignment=prior,policy=credentials_policy_revision())),expires_in=300)
        if not isinstance(operation, str) or operation not in {'setup', 'unlock', 'put', 'delete', 'change', 'reset'}:
            raise AutomationError('invalid_request')
        profile = None
        if operation == 'put':
            profile = self.resolve_resource(user_id, data.get('profile_id'))
            if profile is None or profile.get('auth_type') != 'password':
                raise AutomationError('invalid_targets')
        if operation == 'delete':
            text(data.get('profile_id'), 128)
        path = self.vault.path(user_id)
        if path.exists() and path.stat().st_size > MAX_STORE_BYTES:
            raise AutomationError('storage_limit')
        revision = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
        token = self._remember(user_id, auth_id, dict(kind='vault', operation=operation,
                                                     profile=profile, profile_id=data.get('profile_id'), revision=revision))
        return dict(intent=token, expires_in=300)

    def apply_vault(self, token, user_id, auth_id, data):
        if not self._vault_mutations.acquire(blocking=False):
            raise AutomationError('busy')
        try:
            return self._apply_vault(token, user_id, auth_id, data)
        finally:
            self._vault_mutations.release()

    def _apply_vault(self, token, user_id, auth_id, data):
        self._named_enabled()
        with user_data_access(user_id):
            # Serialize the revision check with the mutation across browser tabs.
            with self._lock:
                intent = self.intent(token, user_id, auth_id, consume=True)
                if intent['kind'] != 'vault':
                    raise AutomationError('invalid_intent')
                path = self.vault.path(user_id)
                revision = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
                if revision != intent['revision']:
                    raise AutomationError('preview_changed')
                profile = intent['profile']
                if profile is not None:
                    current = self.resolve_resource(user_id, profile['id'])
                    if current is None or profile_fingerprint(current) != profile_fingerprint(profile):
                        raise AutomationError('preview_changed')
                op = intent['operation']
                if op == 'setup':
                    if data.get('acknowledged') is not True:
                        raise AutomationError('acknowledgement_required')
                    self.vault.setup(user_id, auth_id, data.get('passphrase'))
                elif op == 'unlock':
                    self.vault.unlock(user_id, auth_id, data.get('passphrase'))
                elif op == 'put':
                    self.vault.put(user_id, auth_id, profile, data.get('password'))
                elif op == 'delete':
                    self.vault.delete(user_id, auth_id, intent['profile_id'])
                elif op == 'change':
                    self.vault.change_passphrase(user_id, auth_id, data.get('passphrase'))
                else:
                    if data.get('confirmation') != 'DELETE VAULT':
                        raise AutomationError('confirmation_required')
                    self.vault.reset(user_id, auth_id)
        log_security_event('CREDENTIAL_VAULT_CHANGED', user_id=user_id, action=op)
        return self.vault_status(user_id, auth_id)


    def _named_enabled(self):
        from .app_settings import is_credentials_enabled
        if not is_credentials_enabled():
            raise AutomationError('credentials_disabled')
        if has_request_context() and not request.is_secure:
            raise AutomationError('https_required')
        if not self.app.extensions['runtime_lifecycle'].accepting_work():
            raise AutomationError('unavailable')

    def native_state(self, uid, aid):
        from .app_settings import is_credentials_enabled
        with user_data_access(uid):
            doc = self.named.read(uid)
            profiles = self.resources(uid)
            for profile in profiles:
                assignment = doc['assignments'].get(profile['id'])
                profile['credential_id'] = assignment['credential_id'] if assignment else None
                profile['credential_assignment'] = deepcopy(assignment)
                profile['credential_status'] = self.credential_status(uid, profile)
            public=[]
            for record in doc['credentials'].values():
                item=self.named.public(doc,record)
                item['uses']=[dict(resource_id=rid,id=rid,name=next((p.get('name',rid) for p in profiles if p['id']==rid),rid),kind=next((p.get('kind') for p in profiles if p['id']==rid),None),valid=any(p['id']==rid and profile_fingerprint(p)==doc['assignments'][rid]['fingerprint'] for p in profiles)) for rid in item['uses']]
                public.append(item)
            return dict(enabled=is_credentials_enabled(),credentials=public,
                        profiles=profiles, legacy_vault=self.vault.path(uid).exists(),vault=self.vault_status(uid,aid))

    def create_named(self, uid, data):
        self._named_enabled()
        with user_data_access(uid):
            return self.named.mutate(uid,lambda doc:self.named.create(uid,doc,data))

    def update_named(self, uid, rid, data):
        self._named_enabled()
        def update(doc):
            record = self.named.record(doc,rid)
            if 'name' in data: record['name']=text(data['name'],128)
            if 'username' in data: record['username']=text(data['username'],256,empty=True)
            if 'password' in data:
                from .credential_crypto import encrypt
                record['ciphertext']=encrypt(uid,rid,text(data['password'],4096))
                record['version']=secrets.token_hex(32)
            record['updated_at']=datetime.now(timezone.utc).isoformat()
            return self.named.public(doc,record)
        with user_data_access(uid):
            return self.named.mutate(uid,update)

    def delete_named(self, uid, rid):
        self._named_enabled()
        def delete(doc):
            self.named.record(doc,rid)
            if any(a['credential_id']==rid for a in doc['assignments'].values()):
                raise AutomationError('credential_in_use')
            del doc['credentials'][rid]
        with user_data_access(uid):
            self.named.mutate(uid,delete)

    def assign_named(self, uid, resource_id, rid, confirmed):
        self._named_enabled()
        with user_data_access(uid):
            resource=self.resolve_resource(uid,resource_id)
            def assign(doc):
                previous=doc['assignments'].get(resource_id)
                if previous and rid is not None and previous['credential_id']!=rid:
                    raise AutomationError('replacement_confirmation_required')
                if rid is None:
                    doc['assignments'].pop(resource_id,None)
                    return
                if confirmed is not True or resource.get('auth_type')!='password':
                    raise AutomationError('confirmation_required')
                self.named.record(doc,rid)
                if previous and previous['fingerprint']==profile_fingerprint(resource):
                    return
                doc['assignments'][resource_id]=dict(credential_id=rid,fingerprint=profile_fingerprint(resource),generation=secrets.token_hex(32))
            self.named.mutate(uid,assign)

    def credential_status(self, uid, profile):
        from .app_settings import is_credentials_enabled
        if not is_credentials_enabled(): return 'disabled'
        try:
            self.named.assigned(uid,profile)
            return 'ready'
        except AutomationError as error:
            return 'changed' if error.code=='credential_target_changed' else 'missing'

    def schedule_generations(self, uid, profiles):
        from .app_settings import credentials_policy_revision
        from .automation_store import incarnation
        self._named_enabled()
        with user_data_access(uid):
            values={}
            for profile in profiles:
                current=self.resolve_resource(uid,profile['id'])
                if profile_fingerprint(current)!=profile_fingerprint(profile):
                    raise AutomationError('credential_target_changed')
                assignment,record=self.named.assigned(uid,current)
                values[profile['id']]=[assignment['generation'],record['version']]
            return dict(incarnation=incarnation(uid),policy=credentials_policy_revision(),records=values)

    def schedule_password(self, uid, profile):
        from .credential_crypto import decrypt
        with user_data_access(uid):
            self.schedule_generations(uid,[profile])
            _,record=self.named.assigned(uid,profile)
            return decrypt(uid,record['id'],record['ciphertext'])

    def generations(self, uid, aid, profiles):
        session_identity(uid,aid)
        self._named_enabled()
        doc=self.named.read(uid)
        native=[p for p in profiles if p['id'] in doc['assignments']]
        legacy=[p for p in profiles if p['id'] not in doc['assignments']]
        if not native: return self.vault.generations(uid,aid,profiles)
        return dict(session=session_identity(uid,aid),native=self.schedule_generations(uid,native),legacy=self.vault.generations(uid,aid,legacy) if legacy else None)

    def password(self, uid, aid, profile):
        session_identity(uid,aid)
        self._named_enabled()
        if profile['id'] in self.named.read(uid)['assignments']:
            return self.schedule_password(uid,profile)
        return self.vault.password(uid,aid,profile)

    def import_legacy(self, uid, aid, passphrase):
        from .automation_store import digest
        from .automation_vault import _derive, _decode, _KDF
        self._named_enabled()
        with user_data_access(uid), self.vault._guard:
            document=self.vault._read(uid)
            if not _KDF.acquire(blocking=False): raise AutomationError('busy')
            try:
                key=_derive(passphrase,_decode(document['salt'],32))
                records=self.vault._decrypt(uid,key,document)
            finally:
                _KDF.release()
            revision=digest(document)
            def migrate(doc):
                if revision in doc['imports']: return
                for resource_id,legacy in records.items():
                    try: resource=self.resolve_resource(uid,resource_id)
                    except AutomationError: resource=None
                    created=self.named.create(uid,doc,dict(name=(resource.get('name') if resource else resource_id) or 'Imported password',password=legacy['password']))
                    # Preserve the historical fingerprint even when the target changed.
                    if resource_id not in doc['assignments'] and resource is not None:
                        doc['assignments'][resource_id]=dict(credential_id=created['id'],fingerprint=legacy['fingerprint'],generation=secrets.token_hex(32))
                doc['imports'].append(revision)
            self.named.mutate(uid,migrate)

    def create_assigned(self, uid, resource_id, data, confirmed):
        self._named_enabled()
        with user_data_access(uid):
            resource=self.resolve_resource(uid,resource_id)
            if confirmed is not True or resource.get('auth_type')!='password':
                raise AutomationError('confirmation_required')
            def create(doc):
                if resource_id in doc['assignments']:
                    raise AutomationError('replacement_confirmation_required')
                record=self.named.create(uid,doc,data)
                doc['assignments'][resource_id]=dict(credential_id=record['id'],fingerprint=profile_fingerprint(resource),generation=secrets.token_hex(32))
                return self.named.public(doc,doc['credentials'][record['id']])
            return self.named.mutate(uid,create)

    def authorize_target(self, uid, aid, data):
        self._named_enabled()
        target=data.get('target')
        if data.get('confirm_target') is not True or not isinstance(target,dict):
            raise AutomationError('confirmation_required')
        from .automation_store import digest
        # Store only validated connection fields; bind explicit route and SMB scope.
        target=self._normalize_target(target)
        text(target.get('host'),253); text(target.get('username'),256)
        if target.get('auth_type') not in (None,'password'): raise AutomationError('invalid_targets')
        rid=data.get('credential_id')
        record=self.named.record(self.named.read(uid),rid)
        from .app_settings import credentials_policy_revision
        route=self.resolve_resource(uid,'jump:'+target['jump_host_id']) if target.get('jump_host_id') else None
        token=self._remember(uid,aid,dict(kind='target',target=target,credential_id=rid,version=record['version'],policy=credentials_policy_revision(),route_fingerprint=profile_fingerprint(route) if route else None))
        return dict(credential_target_token=token)

    def target_generation(self, uid, aid, rid, connection, token):
        self._named_enabled()
        intent=self.intent(token,uid,aid)
        if intent.get('kind')!='target' or intent.get('credential_id')!=rid:
            raise AutomationError('invalid_intent')
        target=intent['target']
        connection=self._normalize_target(connection)
        if connection != target:
            raise AutomationError('credential_target_changed')
        record=self.named.record(self.named.read(uid),rid)
        if record['version']!=intent['version']: raise AutomationError('credential_target_changed')
        from .app_settings import credentials_policy_revision
        if intent['policy']!=credentials_policy_revision(): raise AutomationError('invalid_intent')
        route=self.resolve_resource(uid,'jump:'+target['jump_host_id']) if target.get('jump_host_id') else None
        if intent['route_fingerprint']!=(profile_fingerprint(route) if route else None):
            raise AutomationError('credential_target_changed')
        return dict(version=record['version'],policy=credentials_policy_revision(),session=session_identity(uid,aid))

    def target_password(self, uid, aid, rid, connection, token):
        self.target_generation(uid,aid,rid,connection,token)
        from .credential_crypto import decrypt
        record=self.named.record(self.named.read(uid),rid)
        return decrypt(uid,rid,record['ciphertext'])

    def create_for_resource(self, uid, data):
        from . import profile_manager, jump_host_manager, smb_share_manager
        self._named_enabled()
        kind=data.get('resource_kind'); payload=data.get('resource')
        if kind not in {'ssh','jump','smb'} or not isinstance(payload,dict) or payload.get('id'):
            raise AutomationError('invalid_request')
        if data.get('confirm_target') is not True: raise AutomationError('confirmation_required')
        if kind!='smb' and payload.get('auth_type')!='password': raise AutomationError('invalid_targets')
        with user_data_access(uid):
            result={}
            callback_error=[]
            route=None
            if kind=='ssh' and payload.get('jump_host_id'):
                route=self.resolve_resource(uid,'jump:'+payload['jump_host_id'])
                route=dict(route,id=payload['jump_host_id'])
                route.pop('kind',None)
            def created(record):
                resource=dict(record,id=('' if kind=='ssh' else kind+':')+record['id'],kind=kind)
                if kind=='smb': resource.update(port=445,auth_type='password')
                if route: resource['route_fingerprint']=profile_fingerprint(route)
                def store(doc):
                    credential=self.named.create(uid,doc,data)
                    doc['assignments'][resource['id']]=dict(credential_id=credential['id'],fingerprint=profile_fingerprint(resource),generation=secrets.token_hex(32))
                    result.update(resource=record,credential=credential)
                try: self.named.mutate(uid,store)
                except BaseException as error:
                    callback_error.append(error)
                    raise
            if kind=='ssh': record,error=profile_manager.upsert_profile(uid,payload,on_created=created)
            elif kind=='smb': record,error=smb_share_manager.upsert_smb_share(uid,payload,on_created=created)
            else:
                fields={key:payload.get(key) for key in ('name','host','port','username','auth_type','key_id','jump_host_id')}
                record,error=jump_host_manager.add_jump_host(uid,**fields,on_created=created)
            if callback_error: raise callback_error[0]
            if error or not record: raise AutomationError('invalid_targets')
            return result

    @staticmethod
    def _normalize_target(target):
        from .credential_connections import _saved_route
        is_smb=bool(target.get('share'))
        jump=target.get('jump_host_id')
        if target.get('proxy_jump'):
            saved=_saved_route(target)
            if jump and jump!=saved: raise AutomationError('credential_target_changed')
            jump=saved
        return dict(host=target.get('host'),port=target.get('port') or (445 if is_smb else 22),
                    username=target.get('username'),auth_type=target.get('auth_type') or 'password',
                    key_id=target.get('key_id'),jump_host_id=jump,domain=(target.get('domain') or '') if is_smb else None,
                    share=target.get('share') if is_smb else None)

    def apply_native_assignment(self, uid, aid, token, mutation):
        """Compare an approved destination while all destination writers are fenced."""
        from .storage_utils import storage_lock
        from .automation_store import digest
        self._named_enabled()
        with user_data_access(uid),storage_lock(f'command-config:{uid}'),storage_lock(f'smb-shares:{uid}'):
            intent=self.intent(token,uid,aid)
            if intent.get('kind')!='native' or intent['mutation_digest']!=digest(mutation):
                raise AutomationError('invalid_intent')
            matches=[p for p in self.resources(uid,coordinator_held=True) if p['id']==mutation.get('resource_id')]
            if len(matches)!=1 or profile_fingerprint(matches[0])!=intent.get('resource_fingerprint'):
                raise AutomationError('preview_changed')
            resource=matches[0]
            if mutation.get('target') is not None:
                if self._normalize_target(mutation['target'])!=self._normalize_target(resource):
                    raise AutomationError('credential_target_changed')
            # Admit once before any persistent side effect, while destination writers are fenced.
            self.intent(token,uid,aid,consume=True)
            def store(doc):
                previous=doc['assignments'].get(resource['id'])
                if previous != intent.get('prior_assignment'):
                    raise AutomationError('preview_changed')
                rid=mutation.get('credential_id')
                if mutation['method']=='create': rid=self.named.create(uid,doc,mutation)['id']
                if rid is None:
                    doc['assignments'].pop(resource['id'],None)
                    return
                if mutation.get('confirm_target') is not True or resource.get('auth_type')!='password':
                    raise AutomationError('confirmation_required')
                self.named.record(doc,rid)
                if previous and previous['credential_id']==rid and previous['fingerprint']==profile_fingerprint(resource):
                    return
                doc['assignments'][resource['id']]=dict(credential_id=rid,fingerprint=profile_fingerprint(resource),generation=secrets.token_hex(32))
            self.named.mutate(uid,store)
