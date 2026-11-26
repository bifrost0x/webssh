package jobs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/cron"
	"github.com/bifrost0x/webssh/internal/fault"
)

// Options configure a registry.
type Options struct {
	// Log receives job failures and the shutdown report; nil discards.
	Log *slog.Logger
	// Grace bounds Shutdown (DefaultShutdownGrace when zero, at most
	// MaxShutdownGrace).
	Grace time.Duration
	// Store keeps the job state across restarts; nil keeps it in memory.
	Store Store
	// Now is the clock (time.Now when nil).
	Now func() time.Time
}

// MaxNameBytes bounds a job name.
const MaxNameBytes = 128

// saveTimeout bounds one write of the job state.
const saveTimeout = 10 * time.Second

// Registry owns the background jobs of the process. Register every job,
// then Start; Shutdown ends them. It is safe for concurrent use.
type Registry struct {
	log   *slog.Logger
	grace time.Duration
	store Store
	now   func() time.Time

	mu        sync.Mutex
	jobs      map[string]*job
	order     []string
	callbacks []callback
	started   bool
	stopping  bool
	stopped   bool
	stop      chan struct{} // closed when Shutdown begins
	// immediate and deferred are the parents of the runs of jobs without
	// and with Spec.Defer; Shutdown cancels them one after the other.
	immediate, deferred          context.Context
	cancelImmediate, cancelDefer context.CancelFunc

	wg       sync.WaitGroup // loops and runs
	shutdown sync.Once
	result   error
	done     chan struct{} // closed when Shutdown has finished
}

// job is one registered job. Its fields after spec are guarded by the
// registry's mu, except saveMu, which orders the writes of its record.
type job struct {
	name     string
	spec     Spec
	fn       Func
	schedule cron.Schedule
	zone     *time.Location
	limit    int
	wake     chan struct{}

	saveMu    sync.Mutex
	rec       Record
	next      time.Time // next periodic run; zero when none is due
	cancels   map[uint64]context.CancelFunc
	cancelled bool // Cancel ended runs that are still returning
	seq       uint64
}

func (j *job) periodic() bool { return j.spec.Every > 0 || j.spec.Cron != "" }

// New returns an empty registry.
func New(o Options) *Registry {
	r := &Registry{log: o.Log, grace: o.Grace, store: o.Store, now: o.Now,
		jobs: map[string]*job{}, stop: make(chan struct{}), done: make(chan struct{})}
	if r.log == nil {
		r.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if r.grace <= 0 {
		r.grace = DefaultShutdownGrace
	}
	r.grace = min(r.grace, MaxShutdownGrace)
	if r.now == nil {
		r.now = time.Now
	}
	return r
}

// Register adds a job before Start. Names are unique.
func (r *Registry) Register(name string, s Spec, fn Func) error {
	if name == "" || len(name) > MaxNameBytes || fn == nil {
		return errors.New("jobs: a job needs a name of at most 128 bytes and a function")
	}
	if s.Every < 0 || s.Timeout < 0 || s.Concurrency < 0 || s.Every > 0 && s.Cron != "" ||
		s.Every > 0 && s.Every < time.Second || s.Singleton && s.Concurrency > 1 || s.Cron == "" && s.Zone != "" {
		return fmt.Errorf("jobs: %s: invalid spec", name)
	}
	j := &job{name: name, spec: s, fn: fn, limit: max(s.Concurrency, 1), wake: make(chan struct{}, 1),
		cancels: map[uint64]context.CancelFunc{}, rec: Record{Name: name}}
	if s.Cron != "" {
		var err error
		if j.schedule, err = cron.Parse(s.Cron); err != nil {
			return fmt.Errorf("jobs: %s: %w", name, err)
		}
		zone := s.Zone
		if zone == "" {
			zone = "UTC"
		}
		if j.zone, err = cron.LoadZone(zone); err != nil {
			return fmt.Errorf("jobs: %s: %w", name, err)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started || r.stopping {
		return fmt.Errorf("jobs: %s: registered after start", name)
	}
	if _, dup := r.jobs[name]; dup {
		return fmt.Errorf("jobs: %s: registered twice", name)
	}
	r.jobs[name] = j
	r.order = append(r.order, name)
	return nil
}

// Start loads the stored state and starts the jobs. Runs that were
// claimed and never ended (a crash) are reported as interrupted and not
// repeated; on-demand runs that never started run now; a periodic job
// whose run fell due while the process was down runs once. When ctx
// ends, every run is cancelled at once; Shutdown is the graceful end.
//
// Without its stored state the registry does not start (fail closed: an
// interrupted run might be repeated); the error is logged and RunNow
// answers unavailable.
func (r *Registry) Start(ctx context.Context) {
	var stored []Record
	if r.store != nil {
		var err error
		if stored, err = r.store.Load(ctx); err != nil {
			r.log.Error("background jobs not started: their state cannot be read", "err", err)
			return
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started || r.stopping {
		r.log.Error("background jobs started twice")
		return
	}
	r.started = true
	base := context.WithoutCancel(ctx)
	r.immediate, r.cancelImmediate = context.WithCancel(base)
	r.deferred, r.cancelDefer = context.WithCancel(base)
	byName := map[string]Record{}
	for _, rec := range stored {
		byName[rec.Name] = rec
	}
	now := r.now()
	var dirty []*job
	for _, name := range r.order {
		j := r.jobs[name]
		if rec, ok := byName[name]; ok {
			j.rec = rec
			if rec.Running > 0 {
				r.log.Warn("background job was interrupted by a restart and is not repeated", "job", name, "runs", rec.Running)
				j.rec.Running, j.rec.LastErr = 0, true
				dirty = append(dirty, j)
			}
		}
		j.next = r.firstRun(j, now)
	}
	for _, j := range dirty {
		r.wg.Go(func() { r.persist(j) })
	}
	for _, name := range r.order {
		j := r.jobs[name]
		r.wg.Go(func() { r.loop(j) })
	}
	context.AfterFunc(ctx, func() {
		r.cancelImmediate()
		r.cancelDefer()
	})
}

// firstRun is the first periodic run after a start: from the stored last
// run, or one period from now for a job that never ran.
func (r *Registry) firstRun(j *job, now time.Time) time.Time {
	switch {
	case j.spec.Every > 0:
		last := j.rec.LastEnd
		if j.rec.LastRun.After(last) {
			last = j.rec.LastRun // interrupted: count from its start
		}
		if last.IsZero() {
			return now.Add(j.spec.Every)
		}
		return last.Add(j.spec.Every)
	case j.spec.Cron != "":
		from := j.rec.LastRun
		if from.IsZero() {
			from = now
		}
		next, err := j.schedule.Next(from, j.zone)
		if err != nil {
			r.log.Warn("background job has no next run", "job", j.name)
			return time.Time{}
		}
		return next
	}
	return time.Time{}
}

// RunNow requests one on-demand run. It waits for a free slot of the job
// and is kept across a restart until it starts. Beyond MaxPending waiting
// runs it fails with busy.
func (r *Registry) RunNow(ctx context.Context, name string) error {
	j, err := r.lookup(name)
	if err != nil {
		return err
	}
	j.saveMu.Lock()
	defer j.saveMu.Unlock()
	r.mu.Lock()
	if !r.started || r.stopping {
		r.mu.Unlock()
		return fault.New(fault.Unavailable, "Background jobs are not running.")
	}
	if j.rec.Pending >= MaxPending {
		r.mu.Unlock()
		return fault.New(fault.Busy, "Too many runs of this job are waiting.")
	}
	rec := j.rec
	r.mu.Unlock()
	rec.Pending++
	if err := r.save(ctx, rec); err != nil {
		return fault.Wrap(fault.Unavailable, err, "The run could not be recorded.")
	}
	r.mu.Lock()
	j.rec.Pending++
	r.mu.Unlock()
	j.signal()
	return nil
}

// Cancel ends the runs of a job in progress and drops its waiting
// on-demand runs; later periodic runs still happen.
func (r *Registry) Cancel(name string) error {
	j, err := r.lookup(name)
	if err != nil {
		return err
	}
	r.mu.Lock()
	for _, cancel := range j.cancels {
		cancel()
	}
	j.cancelled = len(j.cancels) > 0
	dropped := j.rec.Pending > 0
	j.rec.Pending = 0
	r.mu.Unlock()
	if dropped {
		r.persist(j)
	}
	return nil
}

// List returns the jobs in registration order.
func (r *Registry) List() []Info {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Info, 0, len(r.order))
	for _, name := range r.order {
		j := r.jobs[name]
		state := Idle
		switch {
		case r.stopped:
			state = Stopped
		case j.cancelled:
			state = Cancelled
		case len(j.cancels) > 0:
			state = Running
		}
		out = append(out, Info{Name: name, State: state, Runs: len(j.cancels), LastRun: j.rec.LastRun,
			LastErr: j.rec.LastErr, NextRun: j.next, Periodic: j.periodic()})
	}
	return out
}

func (r *Registry) lookup(name string) (*job, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[name]
	if !ok {
		return nil, fault.New(fault.NotFound, "There is no such background job.")
	}
	return j, nil
}

func (j *job) signal() {
	select {
	case j.wake <- struct{}{}:
	default:
	}
}

// save writes one record, bounded in time.
func (r *Registry) save(ctx context.Context, rec Record) error {
	if r.store == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), saveTimeout)
	defer cancel()
	return r.store.Save(ctx, rec)
}

// persist writes the current record of j; a failure is logged, the state
// in memory stays authoritative until the next write.
func (r *Registry) persist(j *job) {
	j.saveMu.Lock()
	defer j.saveMu.Unlock()
	r.mu.Lock()
	rec := j.rec
	r.mu.Unlock()
	if err := r.save(context.Background(), rec); err != nil {
		r.log.Error("background job state not saved", "job", j.name, "err", err)
	}
}
