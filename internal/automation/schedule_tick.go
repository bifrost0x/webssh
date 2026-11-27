package automation

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json/jsontext"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// Tick is the scheduler job (registered with internal/jobs, every
// ScheduleTickInterval, singleton). It first pauses every schedule whose
// claim is too old for its run to be alive, with an unknown outcome; only
// a new approval resumes it. Then, while automation is on and the server
// takes work, it dispatches the due slots, oldest first: each slot runs at
// most once, a late slot is recorded as missed and a slot whose previous
// run still holds its claim as an overlap. A schedule whose approval no
// longer holds is paused and needs a new review.
func (s *Schedules) Tick(ctx context.Context) error {
	if !s.Runs() {
		return nil
	}
	now := s.o.Now()
	nowSec := unixSeconds(now)
	err := s.o.DB.Write(ctx, func(tx *store.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE automation_schedules SET enabled = 0, last_status = 'unknown',
			claim_id = NULL, claimed_at = NULL, revision = revision + 1
			WHERE claim_id IS NOT NULL AND (claimed_at IS NULL OR claimed_at < ?)`, nowSec-staleClaim.Seconds())
		return err
	})
	if err != nil {
		return storageFault(err)
	}
	if enabled, _, err := s.o.Policy.AutomationPolicy(ctx); err != nil || !enabled || s.o.Draining() {
		return storageFault(err)
	}
	var due []scheduleRow
	err = s.o.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		due, err = querySchedules(ctx, tx, `WHERE enabled = 1 AND next_at <= ? ORDER BY next_at, id LIMIT ?`, nowSec, scheduleBatch)
		return err
	})
	if err != nil {
		return storageFault(err)
	}
	for _, r := range due {
		if ctx.Err() != nil || s.o.Draining() {
			return nil
		}
		s.dispatch(ctx, r)
	}
	return nil
}

// dispatch handles one due slot.
func (s *Schedules) dispatch(ctx context.Context, r scheduleRow) {
	now := s.o.Now()
	if err := s.validateApproval(ctx, r.UserID, r.Approval); err != nil {
		s.needsReview(ctx, r, r.Revision, 1)
		return
	}
	future, err := NextDue(r.Cron, r.Zone, now)
	if err != nil {
		s.needsReview(ctx, r, r.Revision, 1)
		return
	}
	status := StatusRunning
	switch {
	case r.ClaimID.Valid:
		status = StatusOverlap
	case now.Sub(fromUnixSeconds(r.NextAt)) >= missedAfter:
		status = StatusMissed
	}
	revision := r.Revision + 1
	claim := r.ClaimID
	claimedAt := r.ClaimedAt
	if status == StatusOverlap {
		// An overlap must not fence the run that is still authorised.
		revision = r.Revision
	}
	if status == StatusRunning {
		claim = sql.NullString{String: newClaim(), Valid: true}
		claimedAt = sql.NullFloat64{Float64: unixSeconds(now), Valid: true}
	}
	var ok bool
	err = s.o.DB.Write(ctx, func(tx *store.Tx) error {
		var err error
		ok, err = execOne(ctx, tx, `UPDATE automation_schedules SET next_at = ?, last_status = ?, revision = ?, claim_id = ?, claimed_at = ?
			WHERE id = ? AND revision = ? AND next_at = ? AND enabled = 1`,
			unixSeconds(future), status, revision, claim, claimedAt, r.ID, r.Revision, r.NextAt)
		return err
	})
	if err != nil || !ok || status != StatusRunning {
		return
	}
	run := ScheduledRun{UserID: r.UserID, ScheduleID: r.ID, ClaimID: claim.String, Snapshot: r.Approval.snapshot()}
	run.Check = func(ctx context.Context) error { return s.validateRun(ctx, r.UserID, r.ID, revision, claim.String) }
	run.Password = func(ctx context.Context, hop jsontext.Value) ([]byte, error) {
		if err := run.Check(ctx); err != nil {
			return nil, err
		}
		if s.o.Passwords == nil {
			return nil, fault.New(fault.CredentialsDisabled, "")
		}
		return s.o.Passwords.SchedulePassword(ctx, r.UserID, hop)
	}
	run.Finish = func(ctx context.Context, status string) { s.finish(ctx, r.UserID, r.ID, claim.String, status) }
	err = s.o.Workflows.StartScheduled(ctx, run)
	if err == nil {
		return
	}
	notDispatched, skip := transient(err)
	ctx = context.WithoutCancel(ctx)
	_ = s.o.DB.Write(ctx, func(tx *store.Tx) error {
		var err error
		switch {
		case notDispatched && skip:
			// Capacity only skips this slot.
			_, err = execOne(ctx, tx, `UPDATE automation_schedules SET claim_id = NULL, claimed_at = NULL, last_status = 'skipped'
				WHERE id = ? AND claim_id = ?`, r.ID, claim.String)
		case notDispatched:
			_, err = execOne(ctx, tx, `UPDATE automation_schedules SET claim_id = NULL, claimed_at = NULL, last_status = 'needs_review',
				enabled = 0, revision = ? WHERE id = ? AND claim_id = ?`, r.Revision+2, r.ID, claim.String)
		default:
			// An ambiguous dispatch is never retried; the claim stays until
			// the stale-claim rule clears it.
			_, err = execOne(ctx, tx, `UPDATE automation_schedules SET enabled = 0, last_status = 'unknown'
				WHERE id = ? AND claim_id = ?`, r.ID, claim.String)
		}
		return err
	})
}

// needsReview pauses a schedule whose approval failed.
func (s *Schedules) needsReview(ctx context.Context, r scheduleRow, revision, step int64) {
	ctx = context.WithoutCancel(ctx)
	_ = s.o.DB.Write(ctx, func(tx *store.Tx) error {
		_, err := execOne(ctx, tx, `UPDATE automation_schedules SET enabled = 0, last_status = 'needs_review', revision = ?
			WHERE id = ? AND revision = ?`, revision+step, r.ID, revision)
		return err
	})
}

// validateRun is the check of a dispatched run: the schedule still exists
// for the account, is enabled, has the revision and claim of the dispatch,
// and its approval holds.
func (s *Schedules) validateRun(ctx context.Context, userID int64, id string, revision int64, claim string) error {
	changed := fault.New(fault.PreviewChanged, "")
	var r scheduleRow
	err := s.o.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		r, err = s.ownedOne(ctx, tx, userID, id)
		return err
	})
	if err != nil {
		if fault.CodeOf(err) == fault.NotFound {
			return changed
		}
		return storageFault(err)
	}
	if !r.Enabled || r.Revision != revision || !r.ClaimID.Valid || r.ClaimID.String != claim {
		return changed
	}
	return s.validateApproval(ctx, userID, r.Approval)
}

// finish releases the claim of a run and records its status; a paused
// schedule keeps its status, an unknown outcome stays visible.
func (s *Schedules) finish(ctx context.Context, userID int64, id, claim, status string) {
	ctx = context.WithoutCancel(ctx)
	err := s.o.DB.Write(ctx, func(tx *store.Tx) error {
		_, err := execOne(ctx, tx, `UPDATE automation_schedules SET claim_id = NULL, claimed_at = NULL,
			last_status = CASE WHEN last_status = 'unknown' THEN 'unknown' WHEN enabled = 0 THEN last_status ELSE ? END
			WHERE id = ? AND user_id = ? AND claim_id = ?`, status, id, userID, claim)
		return err
	})
	if err != nil {
		// The claim stays and is never replayed; the stale-claim rule
		// pauses the schedule with an unknown outcome.
		s.audit("AUTOMATION_SCHEDULE_FINALIZE_FAILED", userID)
	}
}

func newClaim() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
