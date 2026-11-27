package automation

import (
	"context"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/store"
)

// Bounds of one run.
const (
	runDeadline    = 30 * time.Minute
	recheckEvery   = 250 * time.Millisecond
	metadataMargin = 64 << 10
)

// active is a run in progress. mu guards record; the run's goroutine is
// the only writer.
type active struct {
	sessionID  string
	scheduleID string
	claimID    string
	ctx        context.Context
	cancel     context.CancelFunc
	stopped    chan struct{}
	once       sync.Once

	mu     sync.Mutex
	record Run
}

func (a *active) stop() { a.once.Do(func() { close(a.stopped); a.cancel() }) }

func (a *active) isStopped() bool {
	select {
	case <-a.stopped:
		return true
	default:
		return false
	}
}

func (a *active) snapshot() Run {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.record.clone()
}

func (a *active) update(fn func(r *Run)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fn(&a.record)
}

// job is everything a run needs; Scheduled carries the schedule's part.
type job struct {
	userID    int64
	sessionID string
	frozen    Reviewed
	scheduled *Scheduled
	// consume removes the review intent once the run is certain to start.
	consume func() error
	// check is the validation of the schedule a manual run comes from.
	check func(context.Context) error
}

func (s *Service) newRecord(j job) Run {
	r := Run{ID: newUUID(), RunbookID: new(j.frozen.Runbook.ID), Name: j.frozen.Runbook.Name,
		CreatedAt: pyISOTime(s.o.Now()), Status: StatusQueued}
	for _, t := range j.frozen.Targets {
		tr := Target{ID: t.ResourceID, Name: t.Name, Host: t.Host, Port: t.Port, Username: t.Username,
			Group: t.Group, Status: StatusQueued}
		for _, st := range j.frozen.Runbook.Steps {
			tr.Steps = append(tr.Steps, StepResult{Name: st.Name, Status: StatusQueued, Duration: "0", Detailed: true})
		}
		r.Targets = append(r.Targets, tr)
	}
	if j.scheduled != nil {
		r.ScheduleID, r.ClaimID = new(j.scheduled.ScheduleID), new(j.scheduled.ClaimID)
	}
	return r
}

func (s *Service) persist(ctx context.Context, userID int64, r Run) error {
	ctx = context.WithoutCancel(ctx)
	return storageErr(s.o.DB.Write(ctx, func(tx *store.Tx) error {
		return persistRun(ctx, tx, userID, r)
	}))
}

// dispatch is _start_work: one run per user and maxActiveRuns in all,
// a background job quota, the queued record stored before anything is
// sent. Every failure here means nothing reached a host.
func (s *Service) dispatch(ctx context.Context, j job) (Run, error) {
	record := s.newRecord(j)
	metadata := historyBytes([]Run{record})
	if metadata+metadataMargin > MaxStoreBytes {
		return Run{}, &NotDispatched{Code: "storage_limit"}
	}
	budget := min(RunOutputBytes, max(0, (MaxStoreBytes-metadata-metadataMargin)/6))
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopping || !s.o.Accepting() {
		return Run{}, &NotDispatched{Code: "unavailable"}
	}
	if _, busy := s.active[j.userID]; busy || len(s.active) >= maxActiveRuns {
		return Run{}, &NotDispatched{Code: "busy"}
	}
	release, err := s.o.Quotas.Reserve(ctx, "background_job", j.userID, 1)
	if err != nil {
		return Run{}, &NotDispatched{Code: "busy"}
	}
	runCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), runDeadline)
	a := &active{sessionID: j.sessionID, ctx: runCtx, cancel: cancel, stopped: make(chan struct{}), record: record.clone()}
	if j.scheduled != nil {
		a.scheduleID, a.claimID = j.scheduled.ScheduleID, j.scheduled.ClaimID
	}
	if j.consume != nil {
		if err := j.consume(); err != nil {
			cancel()
			release()
			return Run{}, notDispatched(err)
		}
	}
	if err := s.persist(ctx, j.userID, record); err != nil {
		cancel()
		release()
		return Run{}, notDispatched(err)
	}
	s.active[j.userID] = a
	s.work.Go(func() {
		defer release()
		s.run(j, a, budget)
	})
	s.audit("AUTOMATION_RUN_STARTED", "user_id", j.userID)
	return record.clone(), nil
}

// Start is start(): the confirmed review of the signed-in session, after
// the route consumed the step-up grant.
func (s *Service) Start(ctx context.Context, userID int64, sessionID, token, confirmation string) (Run, error) {
	r, err := s.intents.get(token, userID, sessionID, s.o.Now(), false)
	if err != nil {
		return Run{}, err
	}
	if confirmation != r.confirmation() {
		return Run{}, Fail("confirmation_required")
	}
	f := Reviewed{Runbook: r.book, Targets: r.targets, KeyDigests: r.keyDigests, Bindings: r.bindings}
	if err := s.validate(ctx, userID, f); err != nil {
		return Run{}, err
	}
	if r.check != nil {
		if err := r.check(ctx); err != nil {
			return Run{}, Fail("preview_changed")
		}
	}
	run, err := s.dispatch(ctx, job{userID: userID, sessionID: sessionID, frozen: f, check: r.check, consume: func() error {
		_, err := s.intents.get(token, userID, sessionID, s.o.Now(), true)
		return err
	}})
	if err != nil {
		return Run{}, err
	}
	return run, nil
}

// pyISOTime is datetime.now(timezone.utc).isoformat().
func pyISOTime(t time.Time) string {
	t = t.UTC()
	if t.Nanosecond()/1000 == 0 {
		return t.Format("2006-01-02T15:04:05+00:00")
	}
	return t.Format("2006-01-02T15:04:05.000000+00:00")
}
