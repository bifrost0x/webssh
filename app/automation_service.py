"""Frozen inventories, one-use authorization intents and bounded run ownership."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import math
import secrets
import threading
import time
import uuid

import config
from .automation_store import (AutomationError, profile_fingerprint,
    runbooks, user_path, read_document, write_document, MAX_STORE_BYTES)
from .credential_service import session_identity
from .automation_transport import (CONNECTION_REASONS, STEP_REASONS, STEP_OUTPUT_BYTES,
    RUN_OUTPUT_BYTES, connect_profile, connection_reason, execute_step)
from .data_access import bind_user_data_access, user_data_access
from .profile_manager import load_profiles
from .key_manager import read_key_content
from .quota_manager import quota_manager, QuotaKind
from .storage_utils import storage_lock
from .audit_logger import log_security_event

TERMINAL = {'succeeded', 'failed', 'unknown', 'cancelled', 'skipped'}

def _now():
    return datetime.now(timezone.utc).isoformat()


class AutomationService:
    def __init__(self, app):
        self.app = app
        self.credentials = app.extensions['credentials']
        self.vault = self.credentials.vault
        self._lock = threading.RLock()
        self._intents = {}
        self._vault_mutations = self.credentials._vault_mutations
        self._active = {}

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
        if not isinstance(token, str) or not 30 <= len(token) <= 128:
            raise AutomationError('invalid_intent')
        key = hashlib.sha256(token.encode()).hexdigest()
        with self._lock:
            value = self._intents.get(key)
            if value is None:
                return self.credentials.intent(token, user_id, auth_id, consume=consume)
            if (value is None or value['user_id'] != int(user_id) or value['auth_id'] != int(auth_id)
                    or value['expires'] <= time.monotonic()
                    or value['identity'] != session_identity(user_id, auth_id)):
                raise AutomationError('invalid_intent')
            if consume:
                del self._intents[key]
            return deepcopy(value)

    def _inventory(self, user_id, data):
        ids, groups = data.get('profile_ids', []), data.get('groups', [])
        if (not isinstance(ids, list) or not isinstance(groups, list) or len(ids)+len(groups) > 100
                or any(not isinstance(value, str) or len(value) > 128 for value in ids+groups)):
            raise AutomationError('invalid_targets')
        profiles = load_profiles(user_id)
        by_id = {profile['id']: profile for profile in profiles}
        available_groups = {profile.get('group') for profile in profiles if profile.get('group')}
        if any(value not in by_id for value in ids) or any(value not in available_groups for value in groups):
            raise AutomationError('invalid_targets')
        selected = set(ids)
        selected.update(profile['id'] for profile in profiles if profile.get('group') in groups)
        if not 1 <= len(selected) <= 50:
            raise AutomationError('invalid_targets')
        targets = [profile for profile in profiles if profile['id'] in selected]
        for profile in targets:
            if (profile.get('jump_host_id') or profile.get('auth_type') not in {'key', 'password'}
                    or not profile.get('username') or ':' in profile['username']):
                raise AutomationError('unsupported_target')
        return targets

    def _key_digests(self, user_id, targets):
        result = {}
        for target in targets:
            if target.get('auth_type') == 'key':
                content, error = read_key_content(user_id, target.get('key_id'))
                if error or not content:
                    raise AutomationError('key_unavailable')
                result[target['id']] = hashlib.sha256(content.encode()).hexdigest()
        return result

    def prepare_run(self, user_id, auth_id, data):
        with user_data_access(user_id):
            book = next((item for item in runbooks(user_id) if item['id'] == data.get('runbook_id')), None)
            if book is None:
                raise AutomationError('not_found')
            targets = self._inventory(user_id, data)
            needs_password = any(target['auth_type'] == 'password' for target in targets)
            generation = self.credentials.generations(user_id, auth_id, [t for t in targets if t['auth_type'] == 'password']) if needs_password else None
            for target in targets:
                if target['auth_type'] == 'password':
                    self.credentials.password(user_id, auth_id, target)
            payload = dict(kind='run', book=book, targets=targets, vault_generation=generation,
                           key_digests=self._key_digests(user_id, targets))
            token = self._remember(user_id, auth_id, payload)
            return dict(intent=token, runbook=book, targets=[self.display_target(t) for t in targets],
                        confirmation=str(len(targets)), expires_in=300)

    @staticmethod
    def display_target(target):
        return dict(id=target['id'], name=target['name'], host=target['host'],
                    port=target.get('port',22), username=target['username'], group=target.get('group'))

    def validate_run(self, intent):
        uid, aid = intent['user_id'], intent['auth_id']
        with user_data_access(uid):
            if intent.get('kind') == 'scheduled':
                self.app.extensions['automation_schedules'].validate(intent)
                return
            if session_identity(uid, aid) != intent['identity']:
                raise AutomationError('preview_changed')
            current = {profile['id']: profile for profile in load_profiles(uid)}
            if intent.get('source_schedule'):
                self.app.extensions['automation_schedules'].validate_manual(intent)
                book_valid = True
            else:
                book_valid = intent['book'] in runbooks(uid)
            if (not book_valid or any(profile_fingerprint(current.get(t['id'], {})) != profile_fingerprint(t)
                                                      for t in intent['targets'])
                    or self._key_digests(uid, intent['targets']) != intent['key_digests']):
                raise AutomationError('preview_changed')
            if intent['vault_generation'] is not None and self.credentials.generations(uid, aid, [t for t in intent['targets'] if t['auth_type'] == 'password']) != intent['vault_generation']:
                raise AutomationError('preview_changed')

    def prepare_vault(self, user_id, auth_id, data):
        return self.credentials.prepare_vault(user_id, auth_id, data)

    def apply_vault(self, token, user_id, auth_id, data):
        return self.credentials.apply_vault(token, user_id, auth_id, data)

    def _persist(self, user_id, record):
        with user_data_access(user_id), storage_lock(f'automation-history:{user_id}'):
            path = user_path(user_id, 'automation-runs.json')
            document = self._read_history(path)
            document['runs'] = [deepcopy(record)] + [r for r in document['runs'] if r['id'] != record['id']]
            document['runs'] = document['runs'][:50]
            while len(document['runs']) > 1 and len(json.dumps(document).encode()) > MAX_STORE_BYTES:
                document['runs'].pop()
            # Never silently evict the current run, even if metadata alone exceeds the limit.
            write_document(path, document)

    @staticmethod
    def _read_history(path):
        def bounded(value, maximum, optional=False):
            return (value is None and optional) or (isinstance(value, str) and len(value.encode('utf-8')) <= maximum)
        def step_valid(step):
            return (isinstance(step, dict) and set(step) in (
                {'name','status','exit_code','duration'},
                {'name','status','exit_code','duration','reason','stdout','stderr','output_truncated'})
                and ('stdout' not in step or (
                    bounded(step['stdout'], STEP_OUTPUT_BYTES) and bounded(step['stderr'], STEP_OUTPUT_BYTES)
                    and len(step['stdout'].encode()) + len(step['stderr'].encode()) <= STEP_OUTPUT_BYTES
                    and type(step['output_truncated']) is bool
                    and (step['reason'] is None or step['reason'] in STEP_REASONS)))
                and bounded(step['name'],128) and step['status'] in TERMINAL | {'queued','running'}
                and (step['exit_code'] is None or type(step['exit_code']) is int and 0 <= step['exit_code'] <= 2**32-1)
                and type(step['duration']) in {int,float} and math.isfinite(step['duration']) and 0 <= step['duration'] <= 1801)
        def target_valid(target):
            return (isinstance(target, dict) and set(target) == {'id','name','host','port','username','group','status','steps','reason'}
                and (target['reason'] is None or target['reason'] in CONNECTION_REASONS)
                and all(bounded(target[key],512,key == 'group') for key in ('id','name','host','username','group'))
                and type(target['port']) is int and 1 <= target['port'] <= 65535
                and target['status'] in TERMINAL | {'queued','running'} and isinstance(target['steps'], list)
                and 1 <= len(target['steps']) <= 20 and all(step_valid(step) for step in target['steps']))
        def run_valid(run):
            return (isinstance(run, dict) and set(run) - {'runbook_id', 'schedule_id', 'claim_id'} in (
                {'id','name','created_at','status','targets'}, {'id','name','created_at','finished_at','status','targets'})
                and ('runbook_id' not in run or bounded(run['runbook_id'],64) and bool(run['runbook_id']))
                and ('schedule_id' not in run or bounded(run['schedule_id'],36) and bool(run['schedule_id']))
                and ('claim_id' not in run or bounded(run['claim_id'],64) and bool(run['claim_id']))
                and bounded(run['id'],64) and bounded(run['name'],128) and bounded(run['created_at'],64)
                and bounded(run.get('finished_at'),64,True) and run['status'] in TERMINAL | {'queued','running'}
                and isinstance(run['targets'],list) and 1 <= len(run['targets']) <= 50
                and all(target_valid(target) for target in run['targets'])
                and sum(len(step.get(stream, '').encode()) for target in run['targets']
                        for step in target['steps'] for stream in ('stdout','stderr')) <= RUN_OUTPUT_BYTES)
        def valid(doc):
            try:
                return (isinstance(doc, dict) and set(doc) == {'version','runs'} and doc['version'] == 1
                    and isinstance(doc['runs'], list) and len(doc['runs']) <= 50 and all(run_valid(run) for run in doc['runs']))
            except (TypeError, ValueError, KeyError):
                return False
        return read_document(path, dict(version=1, runs=[]), valid)

    def history(self, user_id):
        with user_data_access(user_id), storage_lock(f'automation-history:{user_id}'):
            document = self._read_history(user_path(user_id, 'automation-runs.json'))
        with self._lock:
            active = {v['record']['id']: deepcopy(v['record']) for uid, v in self._active.items() if uid == int(user_id)}
        result = []
        for record in document['runs']:
            if record['id'] in active:
                record = active[record['id']]
            elif record['status'] not in TERMINAL:
                record['status'] = 'unknown'
                for target in record['targets']:
                    if target['status'] not in TERMINAL:
                        target['status'] = 'unknown'
                    for step in target['steps']:
                        if step['status'] not in TERMINAL:
                            step['status'] = 'unknown'
                            if 'reason' in step:
                                step['reason'] = 'run_interrupted'
            result.append(record)
        return result

    def start(self, token, user_id, auth_id, confirmation):
        intent = self.intent(token, user_id, auth_id)
        if intent['kind'] != 'run' or confirmation != str(len(intent['targets'])):
            raise AutomationError('confirmation_required')
        self.validate_run(intent)
        return self._start_work(intent, consume=lambda: self.intent(token, user_id, auth_id, consume=True))

    def start_scheduled(self, intent):
        if intent.get('kind') != 'scheduled':
            raise AutomationError('invalid_intent')
        self.validate_run(intent)
        return self._start_work(intent)

    def _start_work(self, intent, consume=None):
        user_id, auth_id = intent['user_id'], intent['auth_id']
        access = bind_user_data_access(user_id)
        record = dict(id=str(uuid.uuid4()), runbook_id=intent['book']['id'], name=intent['book']['name'], created_at=_now(), status='queued',
            targets=[dict(**self.display_target(t), status='queued', reason=None, steps=[dict(name=s['name'], status='queued',
                exit_code=None, duration=0, reason=None, stdout='', stderr='', output_truncated=False)
                for s in intent['book']['steps']]) for t in intent['targets']])
        if intent.get('kind') == 'scheduled':
            record.update(schedule_id=intent['schedule_id'], claim_id=intent['claim_id'])
        # Reserve room for terminal reasons/durations and JSON's worst-case escaping.
        # Reject excessive metadata before dispatch, rather than lose the final result.
        metadata_bytes = len(json.dumps(dict(version=1, runs=[record])).encode())
        output_budget = min(RUN_OUTPUT_BYTES, max(0, (MAX_STORE_BYTES-metadata_bytes-65536)//6))
        if metadata_bytes + 65536 > MAX_STORE_BYTES:
            raise AutomationError('storage_limit')
        with self._lock:
            if int(user_id) in self._active or len(self._active) >= 4:
                raise AutomationError('busy')
            reservation = quota_manager.reserve(QuotaKind.BACKGROUND_JOB, user_id)
            state = dict(record=record, cancel=threading.Event(), resources=[], auth_id=int(auth_id),
                         output_budget=output_budget)
            self._active[int(user_id)] = state
            try:
                if consume is not None:
                    consume()
                self._persist(user_id, record)
                self.app.extensions['runtime_lifecycle'].start_job('automation-run',
                    lambda cancelled: self._work(intent, state, access, cancelled, reservation), owner_id=user_id)
            except BaseException:
                self._active.pop(int(user_id), None)
                reservation.release()
                raise
        log_security_event('AUTOMATION_RUN_STARTED', user_id=user_id)
        return deepcopy(record)

    def _work(self, intent, state, access, runtime_cancel, reservation):
        uid, aid = intent['user_id'], intent['auth_id']
        record = state['record']
        deadline = time.monotonic()+1800
        output_remaining = state.get('output_budget', RUN_OUTPUT_BYTES)
        checked = [0.0, True]
        def cancelled():
            if state['cancel'].is_set() or runtime_cancel.is_set() or time.monotonic() >= deadline:
                return True
            if intent.get('source_schedule'):
                try:
                    with access():
                        self.validate_run(intent)
                except Exception:
                    return True
            from .app_settings import is_automation_enabled
            if not is_automation_enabled():
                return True
            if intent.get('kind') == 'scheduled':
                try:
                    with access():
                        self.app.extensions['automation_schedules'].validate(intent)
                except Exception:
                    return True
            if time.monotonic()-checked[0] > .25:
                checked[0] = time.monotonic()
                try:
                    with access():
                        checked[1] = (is_automation_enabled() and not self.app.extensions['data_access'].closed
                            and self.app.extensions['runtime_lifecycle'].accepting_work())
                        if checked[1]:
                            if intent.get('kind') == 'scheduled':
                                self.app.extensions['automation_schedules'].validate(intent)
                            else:
                                checked[1] = session_identity(uid, aid) == intent['identity']
                except Exception:
                    checked[1] = False
            # Credential revocation must not inherit the account-check throttle:
            # auth and command dispatch may both occur within the same 250 ms.
            if checked[1] and intent['vault_generation'] is not None:
                try:
                    with access():
                        targets = [t for t in intent['targets'] if t['auth_type'] == 'password']
                        generation = (self.credentials.schedule_generations(uid, targets)
                                      if intent.get('kind') == 'scheduled'
                                      else self.credentials.generations(uid, aid, targets))
                        checked[1] = generation == intent['vault_generation']
                except Exception:
                    checked[1] = False
            return not checked[1]
        def persist():
            with access():
                self._persist(uid, record)
        def own(resource):
            with self._lock:
                state['resources'].append(resource)
                if state['cancel'].is_set() or runtime_cancel.is_set():
                    resource.close()
        try:
            with self.app.app_context():
                record['status'] = 'running'
                with access():
                    self.validate_run(intent)
                for index, profile in enumerate(intent['targets']):
                    if cancelled():
                        break
                    with access():
                        self.validate_run(intent)
                        password = ((self.credentials.schedule_password(uid, profile)
                                     if intent.get('kind') == 'scheduled'
                                     else self.credentials.password(uid, aid, profile))
                                    if profile['auth_type'] == 'password' else None)
                    target = record['targets'][index]
                    target['status'] = 'running'
                    persist()
                    try:
                        with connect_profile(uid, profile, password, cancelled, own, access=access,
                                expected_key_digest=intent['key_digests'].get(profile['id']),
                                validate_auth=lambda: self.validate_run(intent)) as transport:
                            for step_index, step in enumerate(intent['book']['steps']):
                                if cancelled():
                                    break
                                checked[0] = 0
                                if cancelled():
                                    break
                                target['steps'][step_index]['status'] = 'running'
                                persist()
                                result = execute_step(transport, step, cancelled,
                                                      (password,) if password else (), output_remaining)
                                output_remaining -= sum(len(result.get(stream, '').encode('utf-8'))
                                                        for stream in ('stdout', 'stderr'))
                                target['steps'][step_index].update(result)
                                persist()
                                if result['status'] != 'succeeded':
                                    break
                        statuses = [s['status'] for s in target['steps']]
                        target['status'] = ('unknown' if 'unknown' in statuses else 'succeeded'
                            if all(s == 'succeeded' for s in statuses) else 'failed' if 'failed' in statuses else 'cancelled')
                    except Exception as error:
                        target['reason'] = ('run_interrupted' if any(step['status'] in {'unknown','running'} for step in target['steps'])
                                            else connection_reason(error))
                        target['status'] = ('unknown' if any(step['status'] in {'unknown','running'} for step in target['steps'])
                                            else 'cancelled' if cancelled() else 'failed')
                    finally:
                        password = None
                    for step in target['steps']:
                        if step['status'] == 'queued':
                            step['status'] = 'skipped'
                    persist()
                    if target['status'] != 'succeeded' and intent['book']['stop_on_error']:
                        break
        except Exception:
            record['status'] = 'unknown'
        finally:
            for target in record['targets']:
                if target['status'] in {'queued', 'running'}:
                    target['status'] = 'unknown' if target['status'] == 'running' else 'skipped'
                for step in target['steps']:
                    if step['status'] in {'queued', 'running'}:
                        if step['status'] == 'running':
                            step['reason'] = 'run_interrupted'
                        step['status'] = 'unknown' if step['status'] == 'running' else 'skipped'
            for target in record['targets']:
                if any(step['status'] == 'unknown' for step in target['steps']):
                    target['status'] = 'unknown'
            statuses = [t['status'] for t in record['targets']]
            if record['status'] != 'unknown':
                record['status'] = ('unknown' if 'unknown' in statuses else 'succeeded' if all(s == 'succeeded' for s in statuses)
                                    else 'cancelled' if state['cancel'].is_set() or runtime_cancel.is_set() else 'failed')
            record['finished_at'] = _now()
            with self.app.app_context():
                try:
                    with access():
                        persist()
                except Exception:
                    pass
                log_security_event('AUTOMATION_RUN_FINISHED', user_id=uid, outcome=record['status'])
                if intent.get('kind') == 'scheduled':
                    try:
                        self.app.extensions['automation_schedules'].finish(intent, record['status'])
                    except Exception:
                        # Persisted claim remains unknown and is never replayed.
                        log_security_event('AUTOMATION_SCHEDULE_FINALIZE_FAILED', user_id=uid)
            with self._lock:
                self._active.pop(uid, None)
            reservation.release()

    def cancel(self, user_id, run_id=None):
        with self._lock:
            state = self._active.get(int(user_id))
            if state is not None and run_id is not None and state['record']['id'] != run_id:
                state = None
            if state is not None:
                state['cancel'].set()
                resources = list(state['resources'])
                record = deepcopy(state['record'])
            else:
                resources, record = [], None
        # Always stop local resources before any fallible persistent lookup/write.
        for resource in resources:
            try:
                resource.close()
            except Exception:
                pass
        if record is None and run_id is not None:
            with user_data_access(user_id):
                records = self._read_history(user_path(user_id, 'automation-runs.json'))['runs']
                record = next((r for r in records if r['id'] == run_id), None)
        if run_id is not None and record and record.get('schedule_id') and record.get('claim_id'):
            self.app.extensions['automation_schedules'].cancel_run(
                user_id, record['schedule_id'], record['claim_id'])
            return
        if state is None and run_id is not None:
            raise AutomationError('not_found')

    def revoke(self, user_id):
        self.credentials.revoke(user_id)
        self.cancel(user_id)
        with self._lock:
            self._intents = {k:v for k,v in self._intents.items() if v['user_id'] != int(user_id)}

    def revoke_session(self, auth_id):
        self.credentials.revoke_session(auth_id)
        with self._lock:
            owners = [uid for uid, state in self._active.items() if state['auth_id'] == int(auth_id)]
            self._intents = {k:v for k,v in self._intents.items() if v['auth_id'] != int(auth_id)}
        for uid in owners:
            self.cancel(uid)

    def shutdown(self, deadline=None):
        self.vault.lock()
        with self._lock:
            owners = list(self._active)
            self._intents.clear()
        for owner in owners:
            self.cancel(owner)

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
                try:
                    self.app.extensions['automation_schedules'].tick()
                except Exception:
                    log_security_event('AUTOMATION_SCHEDULER_UNAVAILABLE')
