package jobs

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"
)

// loop is the one owner of a job: it starts its periodic and on-demand
// runs until Shutdown begins.
func (r *Registry) loop(j *job) {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		wait, ok := r.step(j)
		if !ok {
			return
		}
		if wait < 0 {
			continue
		}
		timer.Reset(wait)
		select {
		case <-r.stop:
			return
		case <-j.wake:
		case <-timer.C:
		}
	}
}

// never is the wait of a job with nothing due.
const never = 24 * time.Hour

// step starts what is due. It returns how long to wait before the next
// step (negative: step again at once) and false once Shutdown began.
func (r *Registry) step(j *job) (time.Duration, bool) {
	r.mu.Lock()
	if r.stopping {
		r.mu.Unlock()
		return 0, false
	}
	now := r.now()
	free := len(j.cancels) < j.limit
	switch {
	case j.rec.Pending > 0 && free:
		r.mu.Unlock()
		r.claim(j, false)
		return -1, true
	case !j.next.IsZero() && !now.Before(j.next):
		if !free {
			// Singleton jobs and full slots skip a due run.
			r.log.Info("background job run skipped: the previous run still runs", "job", j.name)
			j.next = r.following(j, now)
			r.mu.Unlock()
			return -1, true
		}
		r.mu.Unlock()
		r.claim(j, true)
		return -1, true
	case !j.next.IsZero():
		wait := j.next.Sub(now)
		r.mu.Unlock()
		return min(wait, never), true
	}
	r.mu.Unlock()
	return never, true
}

// following is the periodic run after one that starts (or is skipped)
// at now. A job with Every has none until the run ends.
func (r *Registry) following(j *job, now time.Time) time.Time {
	if j.spec.Every > 0 {
		if len(j.cancels) > 0 {
			return time.Time{}
		}
		return now.Add(j.spec.Every)
	}
	next, err := j.schedule.Next(now, j.zone)
	if err != nil {
		r.log.Warn("background job has no next run", "job", j.name)
		return time.Time{}
	}
	return next
}

// claim records a run as started before it starts, so that it runs at
// most once; a run whose claim cannot be written does not run.
func (r *Registry) claim(j *job, periodic bool) {
	j.saveMu.Lock()
	r.mu.Lock()
	now := r.now()
	rec := j.rec
	rec.Running++
	rec.LastRun = now
	if !periodic {
		rec.Pending--
	}
	r.mu.Unlock()
	err := r.save(context.Background(), rec)
	r.mu.Lock()
	started := false
	switch {
	case !periodic && j.rec.Pending == 0:
		// Cancel dropped the request meanwhile.
	case err != nil:
		r.log.Error("background job run skipped: its start could not be recorded", "job", j.name, "err", err)
		j.rec.LastErr = true
		if !periodic {
			j.rec.Pending--
		}
	case r.stopping:
	default:
		j.rec.Running++
		j.rec.LastRun = now
		if !periodic {
			j.rec.Pending--
		}
		r.start(j)
		started = true
	}
	if periodic {
		j.next = r.following(j, now)
	}
	r.mu.Unlock()
	j.saveMu.Unlock()
	if !started {
		// The stored claim did not become a run; store what is true.
		r.persist(j)
	}
}

// start runs j in a goroutine of the registry; r.mu is held.
func (r *Registry) start(j *job) {
	parent := r.immediate
	if j.spec.Defer {
		parent = r.deferred
	}
	ctx, cancel := context.WithCancel(parent)
	if j.spec.Timeout > 0 {
		ctx, cancel = context.WithTimeout(parent, j.spec.Timeout)
	}
	j.seq++
	id := j.seq
	j.cancels[id] = cancel
	r.wg.Go(func() {
		err := call(ctx, j.fn)
		cancel()
		r.finish(j, id, err)
	})
}

// call runs fn; a panic ends the run with an error instead of the
// process, and its stack goes to the log.
func call(ctx context.Context, fn Func) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("jobs: run panicked: %T\n%s", p, debug.Stack())
		}
	}()
	return fn(ctx)
}

func (r *Registry) finish(j *job, id uint64, err error) {
	r.mu.Lock()
	now := r.now()
	delete(j.cancels, id)
	if len(j.cancels) == 0 {
		j.cancelled = false
	}
	j.rec.Running = max(j.rec.Running-1, 0)
	j.rec.LastEnd = now
	j.rec.LastErr = err != nil
	if j.spec.Every > 0 && len(j.cancels) == 0 {
		j.next = now.Add(j.spec.Every)
	}
	r.mu.Unlock()
	if err != nil {
		r.log.Warn("background job failed", "job", j.name, "err", err)
	}
	r.persist(j)
	j.signal()
}
