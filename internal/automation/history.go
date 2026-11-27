package automation

import (
	"context"

	"github.com/bifrost0x/webssh/internal/store"
)

// History is history(): the user's runs, the newest first, with running
// records as they are now. A stored record that is not finished and not
// running in this process is recorded as unknown once.
func (s *Service) History(ctx context.Context, userID int64) ([]Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var live *Run
	if a := s.active[userID]; a != nil {
		r := a.snapshot()
		live = &r
	}
	var out []Run
	err := s.o.DB.Write(ctx, func(tx *store.Tx) error {
		stored, err := readRuns(ctx, tx, userID)
		if err != nil {
			return err
		}
		out = out[:0]
		recovered := false
		for _, st := range stored {
			r := st.run
			switch {
			case live != nil && r.ID == live.ID:
				r = *live
			case recoverRun(&r):
				recovered = true
			}
			out = append(out, r)
		}
		if !recovered {
			return nil
		}
		persisted := make([]Run, len(stored))
		for i, st := range stored {
			persisted[i] = st.run
			if live == nil || st.run.ID != live.ID {
				recoverRun(&persisted[i])
			}
		}
		return storeRecovered(ctx, tx, userID, stored, persisted)
	})
	return out, storageErr(err)
}

// run returns one record of the history.
func (s *Service) Run(ctx context.Context, userID int64, runID string) (Run, error) {
	runs, err := s.History(ctx, userID)
	if err != nil {
		return Run{}, err
	}
	for _, r := range runs {
		if r.ID == runID {
			return r, nil
		}
	}
	return Run{}, Fail("not_found")
}

// DeleteRuns is delete_runs: ids nil removes every finished run; a run
// that is still queued or running is never removed, its record is the
// only evidence of what reached the hosts.
func (s *Service) DeleteRuns(ctx context.Context, userID int64, ids []string) (int, error) {
	if ids != nil && (len(ids) < 1 || len(ids) > MaxRuns) {
		return 0, Fail("invalid_request")
	}
	for _, id := range ids {
		if id == "" || len([]rune(id)) > 64 {
			return 0, Fail("invalid_request")
		}
	}
	s.mu.Lock()
	activeID := ""
	if a := s.active[userID]; a != nil {
		activeID = a.snapshot().ID
	}
	s.mu.Unlock()
	for _, id := range ids {
		if id == activeID {
			return 0, Fail("run_active")
		}
	}
	var removed int
	err := s.o.DB.Write(ctx, func(tx *store.Tx) error {
		var err error
		removed, err = deleteRuns(ctx, tx, userID, ids, func(id string) bool { return id == activeID })
		return err
	})
	if err != nil {
		return 0, storageErr(err)
	}
	if removed > 0 {
		s.audit("AUTOMATION_RUNS_DELETED", "user_id", userID, "count", removed)
	}
	return removed, nil
}

// Cancel is cancel(): it stops the user's active run, or the run runID.
// A scheduled run that is not active here is handed to the schedules so
// its claim settles. manualOnly leaves scheduled runs alone.
func (s *Service) Cancel(ctx context.Context, userID int64, runID string, manualOnly bool) error {
	s.mu.Lock()
	a := s.active[userID]
	var record *Run
	if a != nil {
		r := a.snapshot()
		if (runID != "" && r.ID != runID) || (manualOnly && a.scheduleID != "") {
			a = nil
		} else {
			record = &r
			a.stop()
		}
	}
	s.mu.Unlock()
	if record == nil && runID != "" {
		runs, err := s.History(ctx, userID)
		if err != nil {
			return err
		}
		for i := range runs {
			if runs[i].ID == runID {
				record = &runs[i]
			}
		}
	}
	if runID != "" && record != nil && record.ScheduleID != nil && record.ClaimID != nil && s.schedules() != nil {
		return s.schedules().CancelRun(ctx, userID, *record.ScheduleID, *record.ClaimID)
	}
	if record == nil && runID != "" {
		return Fail("not_found")
	}
	return nil
}
