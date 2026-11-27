package automation

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"strconv"
	"time"

	"github.com/bifrost0x/webssh/internal/cron"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
)

// ScheduleOptions are the dependencies of the schedules. DB, Accounts and
// Policy are required. Without Workflows the schedules can be listed,
// paused and deleted, but not reviewed or run (unavailable); without
// Passwords a schedule cannot use saved passwords.
type ScheduleOptions struct {
	DB        *store.DB
	Workflows ScheduleWorkflows
	Accounts  ScheduleAccounts
	Policy    SchedulePolicy
	Passwords SchedulePasswords
	StepUp    ScheduleStepUp
	Audit     ScheduleAudit
	// Draining reports that the server takes no new work (shutdown,
	// maintenance); nil means never.
	Draining func() bool
	Now      func() time.Time
}

// Schedules are the approved, recurring runs of runbooks
// (app/automation_schedule.py): each schedule holds the frozen review the
// user approved and runs it at the slots of its cron expression, at most
// once per slot, without a signed-in session. A run happens only while the
// approval still holds (validateApproval).
type Schedules struct {
	o       ScheduleOptions
	intents *scheduleIntents
}

// NewSchedules returns the schedules.
func NewSchedules(o ScheduleOptions) (*Schedules, error) {
	if o.DB == nil || o.Accounts == nil || o.Policy == nil {
		return nil, errors.New("automation: incomplete schedule options")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Draining == nil {
		o.Draining = func() bool { return false }
	}
	if o.Workflows == nil {
		o.Workflows = noWorkflows{}
	}
	return &Schedules{o: o, intents: newScheduleIntents(o.Now)}, nil
}

// Runs reports whether the run side is wired, so that Tick can be
// registered; without it no due slot is touched.
func (s *Schedules) Runs() bool {
	_, none := s.o.Workflows.(noWorkflows)
	return !none
}

// noWorkflows answers while the run side is not wired.
type noWorkflows struct{}

func (noWorkflows) Review(context.Context, principal.Principal, jsontext.Value) (Snapshot, error) {
	return Snapshot{}, fault.New(fault.Unavailable, "")
}

func (noWorkflows) Current(context.Context, int64, Snapshot) error {
	return fault.New(fault.Unavailable, "")
}

func (noWorkflows) PrepareManual(context.Context, principal.Principal, Snapshot, func(context.Context) error) (jsontext.Value, error) {
	return nil, fault.New(fault.Unavailable, "")
}

func (noWorkflows) StartScheduled(context.Context, ScheduledRun) error {
	return &NotDispatchedError{Code: fault.Unavailable}
}

// Revoke drops the intents of an ended session.
func (s *Schedules) Revoke(rev principal.Revocation) { s.intents.revoke(rev) }

// Sweep drops expired intents.
func (s *Schedules) Sweep() { s.intents.sweep() }

func (s *Schedules) audit(event string, userID int64) {
	if s.o.Audit != nil {
		s.o.Audit.Security(event, "user_id", userID)
	}
}

// NextDue is next_due of app/automation_cron.py: the first slot of expr
// in zone strictly after after, as a UTC time.
func NextDue(expr, zone string, after time.Time) (time.Time, error) {
	sched, err := cron.Parse(expr)
	if err != nil {
		return time.Time{}, err
	}
	loc, err := cron.LoadZone(zone)
	if err != nil {
		return time.Time{}, err
	}
	next, err := sched.Next(after, loc)
	return next.UTC(), err
}

// public is a schedule as the page lists it.
func public(r scheduleRow) jsontext.Value {
	ids := make([]jsontext.Value, 0, len(r.Approval.Targets))
	for _, t := range r.Approval.Targets {
		v, _ := pyjson.Get(t, "id")
		ids = append(ids, v)
	}
	field := func(name string) jsontext.Value {
		v, ok := pyjson.Get(r.Approval.Book, name)
		if !ok {
			return jsontext.Value("null")
		}
		return v
	}
	boolean := func(b bool) jsontext.Value { return jsontext.Value(strconv.FormatBool(b)) }
	return pyjson.Object([]pyjson.Member{
		{Name: "id", Value: pyjson.String(r.ID)}, {Name: "name", Value: field("name")},
		{Name: "runbook_id", Value: field("id")}, {Name: "cron", Value: pyjson.String(r.Cron)},
		{Name: "timezone", Value: pyjson.String(r.Zone)}, {Name: "enabled", Value: boolean(r.Enabled)},
		{Name: "next_due", Value: pyjson.String(pythonISO(fromUnixSeconds(r.NextAt)))},
		{Name: "last_status", Value: pyjson.String(r.LastStatus)}, {Name: "running", Value: boolean(r.ClaimID.Valid)},
		{Name: "profile_ids", Value: pyjson.Array(ids)},
	})
}

// owned returns the user's schedules whose approval belongs to the
// account as it is now (not to an earlier account with the same id).
func (s *Schedules) owned(ctx context.Context, tx *store.Tx, userID int64, where string, args ...any) ([]scheduleRow, error) {
	acc, err := s.o.Accounts.ScheduleAccount(ctx, userID)
	if err != nil && fault.CodeOf(err) != fault.NotFound {
		return nil, err
	}
	rows, err := querySchedules(ctx, tx, `WHERE user_id = ? `+where, append([]any{userID}, args...)...)
	if err != nil {
		return nil, err
	}
	out := rows[:0]
	for _, r := range rows {
		if acc.Incarnation != "" && r.Approval.incarnation() == acc.Incarnation {
			out = append(out, r)
		}
	}
	return out, nil
}

func (s *Schedules) ownedOne(ctx context.Context, tx *store.Tx, userID int64, id string) (scheduleRow, error) {
	if id == "" || len(id) > maxScheduleIDBytes {
		return scheduleRow{}, fault.New(fault.NotFound, "")
	}
	rows, err := s.owned(ctx, tx, userID, `AND id = ?`, id)
	if err != nil {
		return scheduleRow{}, err
	}
	if len(rows) != 1 {
		return scheduleRow{}, fault.New(fault.NotFound, "")
	}
	return rows[0], nil
}

// List returns the user's schedules, the next slot first.
func (s *Schedules) List(ctx context.Context, userID int64) ([]jsontext.Value, error) {
	var rows []scheduleRow
	err := s.o.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		rows, err = s.owned(ctx, tx, userID, `ORDER BY next_at, id`)
		return err
	})
	if err != nil {
		return nil, storageFault(err)
	}
	out := make([]jsontext.Value, 0, len(rows))
	for _, r := range rows {
		out = append(out, public(r))
	}
	return out, nil
}

// Prepare reviews a schedule (new, or a replacement of schedule_id) and
// returns the preview with the next three slots. The review is that of a
// manual run; only saved passwords assigned to the targets can be used.
func (s *Schedules) Prepare(ctx context.Context, p principal.Principal, body jsontext.Value) (jsontext.Value, error) {
	now := s.o.Now()
	if _, err := s.policy(ctx); err != nil {
		return nil, err
	}
	expr, _ := jsonText(field(body, "cron"))
	zone, _ := jsonText(field(body, "timezone"))
	if !isText(body, "cron") || !isText(body, "timezone") {
		return nil, fault.New(fault.InvalidSchedule, "")
	}
	due, err := NextDue(expr, zone, now)
	if err != nil {
		return nil, err
	}
	in := scheduleIntent{Cron: expr, Zone: zone}
	if sid, ok := pyjson.Get(body, "schedule_id"); ok && truthyJSON(sid) {
		id, _ := jsonText(sid)
		err := s.o.DB.Read(ctx, func(tx *store.Tx) error {
			r, err := s.ownedOne(ctx, tx, p.UserID, id)
			in.ScheduleID, in.Revision = r.ID, r.Revision
			return err
		})
		if err != nil {
			return nil, storageFault(err)
		}
	}
	snap, err := s.o.Workflows.Review(ctx, p, body)
	if err != nil {
		return nil, err
	}
	in.Snapshot = snap
	if in.Binding, err = s.passwordBinding(ctx, p.UserID, snap.Targets); err != nil {
		return nil, err
	}
	if in.Account, in.Policy, err = s.binding(ctx, p.UserID); err != nil {
		return nil, err
	}
	token, err := s.intents.remember(p, in)
	if err != nil {
		return nil, err
	}
	runs := []jsontext.Value{pyjson.String(pythonISO(due))}
	for range 2 {
		if due, err = NextDue(expr, zone, due); err != nil {
			return nil, err
		}
		runs = append(runs, pyjson.String(pythonISO(due)))
	}
	targets := make([]jsontext.Value, 0, len(snap.Targets))
	for _, t := range snap.Targets {
		targets = append(targets, displayTarget(t))
	}
	return pyjson.Object([]pyjson.Member{
		{Name: "intent", Value: pyjson.String(token)}, {Name: "runbook", Value: snap.Book},
		{Name: "targets", Value: pyjson.Array(targets)},
		{Name: "confirmation", Value: pyjson.String(strconv.Itoa(len(snap.Targets)))},
		{Name: "expires_in", Value: jsontext.Value(strconv.Itoa(int(IntentTTL.Seconds())))},
		{Name: "next_runs", Value: pyjson.Array(runs)},
	}), nil
}

// Approve stores the reviewed schedule of token after the user confirmed
// the number of targets and gave a step-up grant for the intent.
func (s *Schedules) Approve(ctx context.Context, p principal.Principal, token, confirmation, grant string) (jsontext.Value, error) {
	in, err := s.intents.get(p, token, false)
	if err != nil {
		return nil, err
	}
	if confirmation != strconv.Itoa(len(in.Snapshot.Targets)) {
		return nil, fault.New(fault.ConfirmationRequired, "")
	}
	if s.o.StepUp == nil {
		return nil, fault.New(fault.StepUpRequired, "")
	}
	if err := s.o.StepUp.Consume(ctx, p, principal.ActionAutomationSchedule, token, grant); err != nil {
		return nil, fault.New(fault.StepUpRequired, "")
	}
	return s.apply(ctx, p, token, in)
}

func (s *Schedules) apply(ctx context.Context, p principal.Principal, token string, in scheduleIntent) (jsontext.Value, error) {
	now := s.o.Now()
	changed := fault.New(fault.PreviewChanged, "")
	account, policy, err := s.binding(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	if !sameJSON(account, in.Account) || policy != in.Policy {
		return nil, changed
	}
	if err := s.o.Workflows.Current(ctx, p.UserID, in.Snapshot); err != nil {
		return nil, err
	}
	b, err := s.passwordBinding(ctx, p.UserID, in.Snapshot.Targets)
	if err != nil {
		return nil, err
	}
	if !sameJSON(b, in.Binding) {
		return nil, changed
	}
	next, err := NextDue(in.Cron, in.Zone, now)
	if err != nil {
		return nil, err
	}
	row := scheduleRow{UserID: p.UserID, Enabled: true, Cron: in.Cron, Zone: in.Zone, NextAt: unixSeconds(next),
		LastStatus: StatusWaiting, Approval: scheduleApproval{Book: in.Snapshot.Book, Targets: in.Snapshot.Targets,
			KeyDigests: in.Snapshot.KeyDigests, Binding: in.Binding, Account: in.Account, Policy: in.Policy}}
	id := in.ScheduleID
	err = s.o.DB.Write(ctx, func(tx *store.Tx) error {
		if id != "" {
			cur, err := s.ownedOne(ctx, tx, p.UserID, id)
			if err != nil {
				return err
			}
			if cur.Revision != in.Revision || cur.ClaimID.Valid {
				return changed
			}
			if cur.LastStatus == StatusUnknown {
				row.LastStatus = StatusUnknown
			}
		} else {
			all, err := s.owned(ctx, tx, p.UserID, "")
			if err != nil {
				return err
			}
			if len(all) >= MaxSchedules {
				return fault.New(fault.StorageLimit, "")
			}
		}
		if _, err := s.intents.get(p, token, true); err != nil {
			return err
		}
		if id != "" {
			approval := jsonOf(row.Approval)
			ok, err := execOne(ctx, tx, `UPDATE automation_schedules SET approval = ?, cron = ?, timezone = ?, next_at = ?,
				enabled = 1, last_status = ?, claim_id = NULL, claimed_at = NULL, revision = revision + 1
				WHERE id = ? AND user_id = ? AND revision = ? AND claim_id IS NULL`,
				string(approval), row.Cron, row.Zone, row.NextAt, row.LastStatus, id, p.UserID, in.Revision)
			if err == nil && !ok {
				err = changed
			}
			return err
		}
		row.ID, row.Revision = newUUID(), 1
		id = row.ID
		return insertSchedule(ctx, tx, row)
	})
	if err != nil {
		return nil, storageFault(err)
	}
	s.audit("AUTOMATION_SCHEDULE_APPROVED", p.UserID)
	return s.publicOne(ctx, p.UserID, id)
}

func (s *Schedules) publicOne(ctx context.Context, userID int64, id string) (jsontext.Value, error) {
	var r scheduleRow
	err := s.o.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		r, err = s.ownedOne(ctx, tx, userID, id)
		return err
	})
	if err != nil {
		return nil, storageFault(err)
	}
	return public(r), nil
}
