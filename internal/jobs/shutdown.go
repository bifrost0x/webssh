package jobs

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
)

type callback struct {
	name string
	fn   func(ctx context.Context)
}

// OnShutdown registers a shutdown callback: Shutdown calls it after it
// cancelled the jobs without Defer and before it cancels the deferred
// ones, with a context that ends with the grace. Callbacks end the
// connections that deferred jobs clean up after (register_shutdown_callback
// of app/runtime_lifecycle.py). Names are unique.
func (r *Registry) OnShutdown(name string, fn func(ctx context.Context)) error {
	if name == "" || fn == nil {
		return errors.New("jobs: a shutdown callback needs a name and a function")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopping {
		return errors.New("jobs: shutdown began")
	}
	if slices.ContainsFunc(r.callbacks, func(c callback) bool { return c.name == name }) {
		return fmt.Errorf("jobs: shutdown callback %s registered twice", name)
	}
	r.callbacks = append(r.callbacks, callback{name, fn})
	return nil
}

// ErrNotStopped reports jobs or callbacks that did not end within the
// grace; the error text names them.
var ErrNotStopped = errors.New("jobs: not stopped within the shutdown grace")

// Shutdown stops new runs, starts the shutdown callbacks, cancels the jobs
// without Defer, waits for the callbacks, then cancels the deferred jobs
// and waits for every run. All of it is bounded by the grace and by ctx.
// Runs that did not end stay claimed in the store and count as
// interrupted at the next start. Later calls wait for the first one and
// return its result.
func (r *Registry) Shutdown(ctx context.Context) error {
	r.shutdown.Do(func() {
		r.result = r.shutdownOnce(ctx)
		close(r.done)
	})
	select {
	case <-r.done:
		return r.result
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Registry) shutdownOnce(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, r.grace)
	defer cancel()
	r.mu.Lock()
	r.stopping = true
	close(r.stop)
	callbacks := slices.Clone(r.callbacks)
	started := r.started
	r.mu.Unlock()

	var cbs sync.WaitGroup
	var cbMu sync.Mutex
	pending := map[string]bool{}
	for _, c := range callbacks {
		pending[c.name] = true
		cbs.Go(func() {
			c.fn(ctx)
			cbMu.Lock()
			delete(pending, c.name)
			cbMu.Unlock()
		})
	}
	if started {
		r.cancelImmediate()
	}
	wait(ctx, cbs.Wait)
	if started {
		r.cancelDefer()
	}
	wait(ctx, r.wg.Wait)

	r.mu.Lock()
	r.stopped = true
	var left []string
	for _, name := range r.order {
		if n := len(r.jobs[name].cancels); n > 0 {
			left = append(left, fmt.Sprintf("%s (%d)", name, n))
		}
	}
	r.mu.Unlock()
	cbMu.Lock()
	for _, c := range callbacks {
		if pending[c.name] {
			left = append(left, "callback "+c.name)
		}
	}
	cbMu.Unlock()
	if len(left) > 0 {
		r.log.Error("background work did not stop within the shutdown grace", "grace", r.grace, "remaining", left)
		return fmt.Errorf("%w: %s", ErrNotStopped, strings.Join(left, ", "))
	}
	r.log.Info("background jobs stopped")
	return nil
}

// wait runs fn until it returns or ctx ends. A goroutine left by an
// expired wait ends with fn.
func wait(ctx context.Context, fn func()) {
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}
