package automation

import (
	"context"
	"encoding/json/jsontext"
	"fmt"

	"github.com/bifrost0x/webssh/internal/store"
)

// ImportedSchedule is a schedule taken over from the Python release
// (entity E15). The frozen run and the password binding stay as the
// legacy grant holds them; the account binding is re-expressed with the
// sign-out generation of the new database (migration specification 4.3).
// Stale marks a grant that was no longer valid in the Python release.
type ImportedSchedule struct {
	ID         string
	UserID     int64
	Revision   int64
	Enabled    bool
	Cron, Zone string
	NextAt     float64
	LastStatus string
	Book       jsontext.Value
	Targets    []jsontext.Value
	KeyDigests map[string]string
	Binding    jsontext.Value // null without password hops
	Account    AccountBinding
	Policy     string
	Stale      bool
}

// ImportScheduleTx stores an imported schedule without a claim.
func ImportScheduleTx(ctx context.Context, tx *store.Tx, s ImportedSchedule) error {
	if s.ID == "" || s.UserID <= 0 || s.Revision <= 0 {
		return fmt.Errorf("automation: imported schedule %q is incomplete", s.ID)
	}
	binding := s.Binding
	if len(binding) == 0 {
		binding = jsontext.Value("null")
	}
	return insertSchedule(ctx, tx, scheduleRow{ID: s.ID, UserID: s.UserID, Revision: s.Revision, Enabled: s.Enabled,
		Cron: s.Cron, Zone: s.Zone, NextAt: s.NextAt, LastStatus: s.LastStatus,
		Approval: scheduleApproval{Book: s.Book, Targets: s.Targets, KeyDigests: s.KeyDigests, Binding: binding,
			Account: accountTuple(s.Account), Policy: s.Policy, Stale: s.Stale}})
}

// StoredSchedule is a stored schedule as the migration verifies it.
type StoredSchedule struct {
	ImportedSchedule
	Claimed bool
	// AccountTuple is the stored account binding.
	AccountTuple jsontext.Value
}

// SchedulesTx returns every stored schedule ordered by id.
func SchedulesTx(ctx context.Context, tx *store.Tx) ([]StoredSchedule, error) {
	rows, err := querySchedules(ctx, tx, `ORDER BY id`)
	if err != nil {
		return nil, err
	}
	out := make([]StoredSchedule, 0, len(rows))
	for _, r := range rows {
		a := r.Approval
		out = append(out, StoredSchedule{ID: r.ID, UserID: r.UserID, Revision: r.Revision,
			Enabled: r.Enabled, Cron: r.Cron, Zone: r.Zone, NextAt: r.NextAt, LastStatus: r.LastStatus, Book: a.Book,
			Targets: a.Targets, KeyDigests: a.KeyDigests, Binding: a.Binding, Policy: a.Policy, Stale: a.Stale,
			Claimed: r.ClaimID.Valid, AccountTuple: a.Account})
	}
	return out, nil
}

// SameJSON compares two JSON values by meaning, as Python compared dicts.
func SameJSON(a, b jsontext.Value) bool { return sameJSON(a, b) }
