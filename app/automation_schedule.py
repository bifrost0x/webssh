"""Durable, explicitly approved schedule grants and at-most-once slot claims."""
from copy import deepcopy
from datetime import datetime, timezone
import secrets
import uuid

from sqlalchemy import update, case, or_

from .automation_cron import next_due
from .automation_store import AutomationError, profile_fingerprint, runbooks
from .data_access import user_data_access
from .models import User, db
from .profile_manager import load_profiles
from .audit_logger import log_security_event


class AutomationSchedule(db.Model):
    __tablename__ = 'automation_schedules'
    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    revision = db.Column(db.Integer, nullable=False, default=1)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    cron = db.Column(db.String(128), nullable=False)
    timezone = db.Column(db.String(128), nullable=False)
    grant = db.Column(db.JSON, nullable=False)
    next_at = db.Column(db.Float, nullable=False, index=True)
    last_status = db.Column(db.String(32), nullable=False, default='waiting')
    claim_id = db.Column(db.String(64))
    claimed_at = db.Column(db.Float)


def _now():
    return datetime.now(timezone.utc)


def _account(user_id):
    from .session_epoch import current_epoch
    db.session.expire_all()
    user = db.session.get(User, int(user_id))
    if user is None or user.is_locked:
        raise AutomationError('authentication_required')
    return [user.created_at.isoformat(), int(user.auth_generation or 0), current_epoch()]


def _policy():
    from .app_settings import is_automation_enabled, get_automation_policy_revision
    if not is_automation_enabled():
        raise AutomationError('disabled')
    return get_automation_policy_revision()


class ScheduleService:
    def __init__(self, app):
        self.app = app
        self.automation = app.extensions['automation']

    @staticmethod
    def public(row):
        return dict(id=row.id, name=row.grant['book']['name'], runbook_id=row.grant['book']['id'],
                    cron=row.cron, timezone=row.timezone, enabled=row.enabled,
                    next_due=datetime.fromtimestamp(row.next_at, timezone.utc).isoformat(),
                    last_status=row.last_status, running=bool(row.claim_id),
                    profile_ids=[p['id'] for p in row.grant['targets']])

    @staticmethod
    def _ownership(user_id):
        user = db.session.get(User, int(user_id))
        incarnation = user.created_at.isoformat() if user is not None else ''
        return (AutomationSchedule.user_id == int(user_id),
                AutomationSchedule.grant['account'][0].as_string() == incarnation)

    def list(self, user_id):
        with user_data_access(user_id):
            return [self.public(row) for row in AutomationSchedule.query.filter(*self._ownership(user_id)).order_by(AutomationSchedule.next_at).all()]

    def _owned(self, user_id, schedule_id):
        if not isinstance(schedule_id, str) or len(schedule_id) > 36:
            raise AutomationError('not_found')
        row = AutomationSchedule.query.filter(AutomationSchedule.id == schedule_id, *self._ownership(user_id)).first()
        if row is None:
            raise AutomationError('not_found')
        return row

    def prepare_run(self, user_id, auth_id, schedule_id):
        """Review the saved workflow for a fresh, session-authorized manual run."""
        with user_data_access(user_id):
            row = self._owned(user_id, schedule_id)
            grant = deepcopy(row.grant)
            source = dict(id=row.id, revision=row.revision,
                          account=grant['account'], policy=grant['policy'])
            targets = grant['targets']
            passwords = [t for t in targets if t['auth_type'] == 'password']
            generation = self.automation.credentials.generations(user_id, auth_id, passwords) if passwords else None
            for target in passwords:
                self.automation.credentials.password(user_id, auth_id, target)
            payload = dict(kind='run', book=grant['book'], targets=targets,
                           key_digests=grant['key_digests'], vault_generation=generation,
                           source_schedule=source)
            token = self.automation._remember(user_id, auth_id, payload)
            try:
                self.automation.validate_run(self.automation.intent(token, user_id, auth_id))
            except Exception:
                self.automation.intent(token, user_id, auth_id, consume=True)
                raise
            return dict(intent=token, runbook=grant['book'],
                        targets=[self.automation.display_target(t) for t in targets],
                        confirmation=str(len(targets)), expires_in=300)

    def validate_manual(self, intent):
        source = intent['source_schedule']
        uid = intent['user_id']
        with user_data_access(uid):
            db.session.expire_all()
            row = self._owned(uid, source['id'])
            if (row.revision != source['revision'] or source['account'] != _account(uid)
                    or source['policy'] != _policy()
                    or row.grant['book'] != intent['book'] or row.grant['targets'] != intent['targets']):
                raise AutomationError('preview_changed')

    def prepare(self, user_id, auth_id, data, *, now=None):
        now = now or _now()
        _policy()
        due = next_due(data.get('cron'), data.get('timezone'), now)
        schedule_id = data.get('schedule_id')
        revision = self._owned(user_id, schedule_id).revision if schedule_id else None
        preview = self.automation.prepare_run(user_id, auth_id, data)
        payload = self.automation.intent(preview['intent'], user_id, auth_id, consume=True)
        passwords = [p for p in payload['targets'] if p['auth_type'] == 'password']
        # Legacy browser leases are deliberately not eligible for unattended use.
        generation = self.automation.credentials.schedule_generations(user_id, passwords) if passwords else None
        payload.update(kind='schedule', cron=data['cron'], timezone=data['timezone'], schedule_id=schedule_id,
                       schedule_revision=revision, account=_account(user_id), policy=_policy(),
                       scheduled_generation=generation)
        preview['intent'] = self.automation._remember(user_id, auth_id, payload)
        preview['next_runs'] = [due.isoformat()]
        for _ in range(2):
            due = next_due(data['cron'], data['timezone'], due)
            preview['next_runs'].append(due.isoformat())
        return preview

    def apply(self, user_id, auth_id, token, confirmation, *, now=None):
        now = now or _now()
        value = self.automation.intent(token, user_id, auth_id)
        if value['kind'] != 'schedule' or confirmation != str(len(value['targets'])):
            raise AutomationError('confirmation_required')
        if value['account'] != _account(user_id) or value['policy'] != _policy():
            raise AutomationError('preview_changed')
        self.automation.validate_run(value)
        with user_data_access(user_id):
            sid = value.get('schedule_id')
            if sid:
                row = self._owned(user_id, sid)
                if row.revision != value['schedule_revision'] or row.claim_id:
                    raise AutomationError('preview_changed')
            elif AutomationSchedule.query.filter(*self._ownership(user_id)).count() >= 50:
                raise AutomationError('storage_limit')
            self.automation.intent(token, user_id, auth_id, consume=True)
            grant = {k: deepcopy(value[k]) for k in ('book', 'targets', 'key_digests', 'vault_generation', 'account', 'policy')}
            grant['vault_generation'] = deepcopy(value['scheduled_generation'])
            values = dict(grant=grant, cron=value['cron'], timezone=value['timezone'],
                          next_at=next_due(value['cron'], value['timezone'], now).timestamp(),
                          enabled=True, last_status='unknown' if sid and row.last_status == 'unknown' else 'waiting',
                          claim_id=None, claimed_at=None)
            if sid:
                result = db.session.execute(update(AutomationSchedule).where(
                    AutomationSchedule.id == sid, AutomationSchedule.user_id == int(user_id),
                    AutomationSchedule.revision == value['schedule_revision'], AutomationSchedule.claim_id.is_(None)
                ).values(**values, revision=value['schedule_revision'] + 1))
                if result.rowcount != 1:
                    db.session.rollback()
                    raise AutomationError('preview_changed')
            else:
                sid = str(uuid.uuid4())
                db.session.add(AutomationSchedule(id=sid, user_id=int(user_id), revision=1, **values))
            db.session.commit()
            log_security_event('AUTOMATION_SCHEDULE_APPROVED', user_id=user_id)
            return self.public(self._owned(user_id, sid))

    def pause(self, user_id, schedule_id, *, delete=False):
        with user_data_access(user_id):
            row = self._owned(user_id, schedule_id)
            conditions = (AutomationSchedule.id == row.id, *self._ownership(user_id))
            if delete:
                from sqlalchemy import delete as delete_rows
                db.session.execute(delete_rows(AutomationSchedule).where(*conditions))
            else:
                db.session.execute(update(AutomationSchedule).where(*conditions).values(
                    enabled=False, revision=AutomationSchedule.revision + 1,
                    last_status=case((AutomationSchedule.last_status == 'unknown', 'unknown'), else_='paused')))
            db.session.commit()
            # Durable revision prevents future dispatch even on another process.
            log_security_event('AUTOMATION_SCHEDULE_PAUSED', user_id=user_id)
            return None if delete else self.public(self._owned(user_id, schedule_id))

    def cancel_run(self, user_id, schedule_id, claim_id):
        """Fence the exact active run without revoking future approved slots."""
        with user_data_access(user_id):
            self._owned(user_id, schedule_id)
            result = db.session.execute(update(AutomationSchedule).where(
                AutomationSchedule.id == schedule_id, *self._ownership(user_id),
                AutomationSchedule.claim_id == claim_id,
                AutomationSchedule.claim_id.is_not(None)
            ).values(revision=AutomationSchedule.revision + 1))
            db.session.commit()
            return result.rowcount == 1

    def _validate_snapshot(self, user_id, grant):
        if grant['account'] != _account(user_id) or grant['policy'] != _policy():
            raise AutomationError('preview_changed')
        current = {p['id']: p for p in load_profiles(user_id)}
        if grant['book'] not in runbooks(user_id) or any(
            profile_fingerprint(current.get(p['id'], {})) != profile_fingerprint(p) for p in grant['targets']
        ) or self.automation._key_digests(user_id, grant['targets']) != grant['key_digests']:
            raise AutomationError('preview_changed')
        passwords = [p for p in grant['targets'] if p['auth_type'] == 'password']
        if passwords and self.automation.credentials.schedule_generations(user_id, passwords) != grant['vault_generation']:
            raise AutomationError('preview_changed')

    def validate(self, intent):
        uid = intent['user_id']
        with user_data_access(uid):
            db.session.expire_all()
            row = self._owned(uid, intent['schedule_id'])
            if not row.enabled or row.revision != intent['schedule_revision'] or row.claim_id != intent['claim_id']:
                raise AutomationError('preview_changed')
            self._validate_snapshot(uid, row.grant)

    def finish(self, intent, status):
        db.session.execute(update(AutomationSchedule).where(
            AutomationSchedule.id == intent['schedule_id'], AutomationSchedule.user_id == intent['user_id'],
            AutomationSchedule.claim_id == intent['claim_id']
        ).values(claim_id=None, claimed_at=None, last_status=case(
            (AutomationSchedule.last_status == 'unknown', 'unknown'),
            (AutomationSchedule.enabled.is_(False), AutomationSchedule.last_status), else_=status)))
        db.session.commit()

    def tick(self, *, now=None):
        now = now or _now()
        # Recover ambiguous claims independently of the next cron occurrence.
        # Revoking the revision fences surviving workers; only fresh approval
        # can resume scheduling and the unknown outcome remains visible.
        db.session.execute(update(AutomationSchedule).where(
            AutomationSchedule.claim_id.is_not(None),
            or_(AutomationSchedule.claimed_at.is_(None),
                AutomationSchedule.claimed_at < now.timestamp() - 1860)
        ).values(enabled=False, last_status='unknown', claim_id=None,
                 claimed_at=None, revision=AutomationSchedule.revision + 1))
        db.session.commit()
        from .app_settings import is_automation_enabled
        if not is_automation_enabled() or not self.app.extensions['runtime_lifecycle'].accepting_work():
            return
        due = AutomationSchedule.query.filter(AutomationSchedule.enabled.is_(True), AutomationSchedule.next_at <= now.timestamp()).limit(200).all()
        for row in due:
            uid, sid, rev, at = row.user_id, row.id, row.revision, row.next_at
            try:
                with user_data_access(uid):
                    self._validate_snapshot(uid, row.grant)
                    future = next_due(row.cron, row.timezone, now).timestamp()
                    status = 'overlap' if row.claim_id else 'missed' if now.timestamp() - at >= 60 else 'running'
                    claim = secrets.token_hex(24) if status == 'running' else row.claim_id
                    values = dict(next_at=future, last_status=status, revision=rev + 1)
                    # An overlap must not invalidate the currently authorized run.
                    if status == 'overlap':
                        values['revision'] = rev
                    if status == 'running':
                        values.update(claim_id=claim, claimed_at=now.timestamp())
                    result = db.session.execute(update(AutomationSchedule).where(
                        AutomationSchedule.id == sid, AutomationSchedule.revision == rev,
                        AutomationSchedule.next_at == at, AutomationSchedule.enabled.is_(True)
                    ).values(**values))
                    db.session.commit()
                    if result.rowcount != 1 or status != 'running':
                        continue
                    grant = deepcopy(row.grant)
                    grant.update(user_id=uid, auth_id=0, kind='scheduled', schedule_id=sid,
                                 schedule_revision=rev + 1, claim_id=claim)
                    try:
                        self.automation.start_scheduled(grant)
                    except Exception:
                        # Never retry an ambiguous dispatch automatically.
                        db.session.execute(update(AutomationSchedule).where(
                            AutomationSchedule.id == sid, AutomationSchedule.claim_id == claim
                        ).values(enabled=False, last_status='unknown'))
                        db.session.commit()
            except Exception:
                db.session.rollback()
                db.session.execute(update(AutomationSchedule).where(
                    AutomationSchedule.id == sid, AutomationSchedule.revision == rev
                ).values(enabled=False, last_status='needs_review', revision=rev + 1))
                db.session.commit()
