package automation

import "context"

// finish is the finally block of _work: open entries become skipped or
// unknown, the run gets its outcome and end time, the record is stored
// and a scheduled run reports back.
func (s *Service) finish(rs *runState) {
	cancelled := rs.a.isStopped()
	rs.a.update(func(r *Run) {
		for i := range r.Targets {
			t := &r.Targets[i]
			switch t.Status {
			case StatusRunning:
				t.Status = StatusUnknown
			case StatusQueued:
				t.Status = StatusSkipped
			}
			for k := range t.Steps {
				st := &t.Steps[k]
				switch st.Status {
				case StatusRunning:
					st.Status, st.Reason = StatusUnknown, new("run_interrupted")
				case StatusQueued:
					st.Status = StatusSkipped
				}
				if st.Status == StatusUnknown {
					t.Status = StatusUnknown
				}
			}
		}
		all, unknown := true, false
		for _, t := range r.Targets {
			all = all && t.Status == StatusSucceeded
			unknown = unknown || t.Status == StatusUnknown
		}
		if r.Status != StatusUnknown {
			switch {
			case unknown:
				r.Status = StatusUnknown
			case all:
				r.Status = StatusSucceeded
			case cancelled:
				r.Status = StatusCancelled
			default:
				r.Status = StatusFailed
			}
		}
		r.Finished, r.FinishedAt = true, new(pyISOTime(s.o.Now()))
	})
	final := rs.a.snapshot()
	if err := s.persist(context.Background(), rs.j.userID, final); err != nil {
		s.o.Logger.Warn("automation: final run record not stored", "user_id", rs.j.userID, "error", err)
	}
	s.audit("AUTOMATION_RUN_FINISHED", "user_id", rs.j.userID, "outcome", final.Status)
	if sc := rs.j.scheduled; sc != nil && sc.Finish != nil {
		if err := sc.Finish(context.Background(), final.Status); err != nil {
			// The claim stays unknown and is never replayed.
			s.audit("AUTOMATION_SCHEDULE_FINALIZE_FAILED", "user_id", rs.j.userID)
		}
	}
}
