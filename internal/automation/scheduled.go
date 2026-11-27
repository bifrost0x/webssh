package automation

import "context"

// The run interface of the schedules (AU2). A schedule reviews its run
// with Freeze when the user approves it, keeps the Reviewed part with its
// grant, and starts it with StartScheduled when it is due. The run
// engine, the history and the export are the same as for a manual run.

// Scheduled is a due run of a schedule.
type Scheduled struct {
	UserID     int64
	ScheduleID string // at most 36 bytes
	ClaimID    string // at most 64 bytes, unique per firing
	Reviewed   Reviewed
	// Check re-validates the schedule's grant (switch revision, binding
	// to the runbook digest, account); an error stops the run before the
	// next step. It is called at most every 250 ms and before each step.
	Check func(ctx context.Context) error
	// Finish receives the outcome once the record is final.
	Finish func(ctx context.Context, status string) error
}

// ScheduleRuns is what the schedules provide back: a cancel of a
// scheduled run that is not active in this process settles its claim.
type ScheduleRuns interface {
	CancelRun(ctx context.Context, userID int64, scheduleID, claimID string) error
}

// SetSchedules connects the schedules; call before the first run.
func (s *Service) SetSchedules(r ScheduleRuns) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sched = r
}

func (s *Service) schedules() ScheduleRuns {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sched
}

// StartScheduled is start_scheduled: the run is validated against the
// review (the runbook as bound by the schedule's digest), then
// dispatched. Any failure is a *NotDispatched: nothing reached a host.
func (s *Service) StartScheduled(ctx context.Context, sc Scheduled) (Run, error) {
	if sc.UserID <= 0 || sc.ScheduleID == "" || len(sc.ScheduleID) > 36 || sc.ClaimID == "" || len(sc.ClaimID) > 64 {
		return Run{}, &NotDispatched{Code: "invalid_intent"}
	}
	if sc.Check != nil {
		if err := sc.Check(ctx); err != nil {
			return Run{}, notDispatched(err)
		}
	}
	if err := s.validate(ctx, sc.UserID, sc.Reviewed); err != nil {
		return Run{}, notDispatched(err)
	}
	run, err := s.dispatch(ctx, job{userID: sc.UserID, frozen: sc.Reviewed, scheduled: &sc})
	if err != nil {
		return Run{}, notDispatched(err)
	}
	return run, nil
}

// Runbook returns one runbook of the user (not_found).
func (s *Service) Runbook(ctx context.Context, userID int64, id string) (Runbook, error) {
	return s.runbook(ctx, userID, id)
}
