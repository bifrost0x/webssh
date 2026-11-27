package automation

import (
	"context"
	"encoding/json/jsontext"
	"strconv"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
)

// Pause stops a schedule; it runs again only after a new approval. The
// revision changes, so a run in progress stops at its next check. An
// unknown outcome stays visible.
func (s *Schedules) Pause(ctx context.Context, userID int64, id string) (jsontext.Value, error) {
	err := s.o.DB.Write(ctx, func(tx *store.Tx) error {
		r, err := s.ownedOne(ctx, tx, userID, id)
		if err != nil {
			return err
		}
		_, err = execOne(ctx, tx, `UPDATE automation_schedules SET enabled = 0, revision = revision + 1,
			last_status = CASE WHEN last_status = 'unknown' THEN 'unknown' ELSE 'paused' END WHERE id = ? AND user_id = ?`, r.ID, userID)
		return err
	})
	if err != nil {
		return nil, storageFault(err)
	}
	s.audit("AUTOMATION_SCHEDULE_PAUSED", userID)
	return s.publicOne(ctx, userID, id)
}

// Delete removes a schedule. A run in progress stops at its next check,
// because its schedule is gone.
func (s *Schedules) Delete(ctx context.Context, userID int64, id string) error {
	err := s.o.DB.Write(ctx, func(tx *store.Tx) error {
		r, err := s.ownedOne(ctx, tx, userID, id)
		if err != nil {
			return err
		}
		_, err = execOne(ctx, tx, `DELETE FROM automation_schedules WHERE id = ? AND user_id = ?`, r.ID, userID)
		return err
	})
	if err != nil {
		return storageFault(err)
	}
	// The Python release records a deletion as a pause.
	s.audit("AUTOMATION_SCHEDULE_PAUSED", userID)
	return nil
}

// PrepareRun reviews a manual run of a schedule's approved workflow for
// the session (preview-run). The run needs the normal confirmation and
// step-up of a manual run; it holds only while the schedule is unchanged.
func (s *Schedules) PrepareRun(ctx context.Context, p principal.Principal, id string) (jsontext.Value, error) {
	var r scheduleRow
	err := s.o.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		r, err = s.ownedOne(ctx, tx, p.UserID, id)
		return err
	})
	if err != nil {
		return nil, storageFault(err)
	}
	frozen := r
	check := func(ctx context.Context) error { return s.validateManual(ctx, p.UserID, frozen) }
	return s.o.Workflows.PrepareManual(ctx, p, r.Approval.snapshot(), check)
}

// validateManual is validate_manual: the schedule is the one reviewed,
// with the same approval, account and policy.
func (s *Schedules) validateManual(ctx context.Context, userID int64, frozen scheduleRow) error {
	changed := fault.New(fault.PreviewChanged, "")
	var r scheduleRow
	err := s.o.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		r, err = s.ownedOne(ctx, tx, userID, frozen.ID)
		return err
	})
	if err != nil {
		return storageFault(err)
	}
	account, policy, err := s.binding(ctx, userID)
	if err != nil {
		return err
	}
	if r.Revision != frozen.Revision || !sameJSON(account, frozen.Approval.Account) || policy != frozen.Approval.Policy ||
		!sameJSON(r.Approval.Book, frozen.Approval.Book) ||
		!sameJSON(jsonOf(r.Approval.Targets), jsonOf(frozen.Approval.Targets)) {
		return changed
	}
	return nil
}

// CancelRun fences the active run of claimID without revoking the
// schedule's future slots: the revision changes, so the run fails its
// next check. It reports whether the claim was the active one.
func (s *Schedules) CancelRun(ctx context.Context, userID int64, id, claimID string) (bool, error) {
	var ok bool
	err := s.o.DB.Write(ctx, func(tx *store.Tx) error {
		r, err := s.ownedOne(ctx, tx, userID, id)
		if err != nil {
			return err
		}
		ok, err = execOne(ctx, tx, `UPDATE automation_schedules SET revision = revision + 1
			WHERE id = ? AND user_id = ? AND claim_id = ? AND claim_id IS NOT NULL`, r.ID, userID, claimID)
		return err
	})
	return ok, storageFault(err)
}

func field(v jsontext.Value, name string) jsontext.Value {
	m, _ := pyjson.Get(v, name)
	return m
}

func isText(v jsontext.Value, name string) bool {
	m, ok := pyjson.Get(v, name)
	return ok && m.Kind() == '"'
}

func truthyJSON(v jsontext.Value) bool {
	switch v.Kind() {
	case 'n', 'f', 0:
		return false
	case '"':
		return string(v) != `""`
	case '0':
		f, err := strconv.ParseFloat(string(v), 64)
		return err != nil || f != 0
	}
	return pyjson.Len(v) != 0
}
