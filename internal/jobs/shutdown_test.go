package jobs

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// Shutdown cancels plain jobs first, waits for the callbacks, then
// cancels deferred jobs; synctest fails on any goroutine left behind.
func TestShutdownOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := New(Options{Grace: 5 * time.Second})
		var order []string
		var mu sync.Mutex
		mark := func(s string) {
			mu.Lock()
			defer mu.Unlock()
			order = append(order, s)
		}
		plain := func(ctx context.Context) error { <-ctx.Done(); mark("plain"); return nil }
		deferred := func(ctx context.Context) error { <-ctx.Done(); mark("deferred"); return nil }
		mustRegister(t, r, "plain", Spec{}, plain)
		mustRegister(t, r, "deferred", Spec{Defer: true}, deferred)
		if err := r.OnShutdown("close", func(context.Context) { time.Sleep(time.Second); mark("callback") }); err != nil {
			t.Fatal(err)
		}
		if err := r.OnShutdown("close", func(context.Context) {}); err == nil {
			t.Fatal("callback registered twice")
		}
		r.Start(t.Context())
		_ = r.RunNow(t.Context(), "plain")
		_ = r.RunNow(t.Context(), "deferred")
		synctest.Wait()
		shutdown(t, r)
		if strings.Join(order, ",") != "plain,callback,deferred" {
			t.Fatalf("order %v", order)
		}
		// A second call returns the first result.
		shutdown(t, r)
	})
}

func TestShutdownReportsStuckJobs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := New(Options{Grace: 2 * time.Second})
		release := make(chan struct{})
		mustRegister(t, r, "stuck", Spec{}, func(context.Context) error { <-release; return nil })
		_ = r.OnShutdown("slow", func(context.Context) { <-release })
		r.Start(t.Context())
		_ = r.RunNow(t.Context(), "stuck")
		synctest.Wait()
		start := time.Now()
		err := r.Shutdown(context.Background())
		if !errors.Is(err, ErrNotStopped) || !strings.Contains(err.Error(), "stuck (1)") || !strings.Contains(err.Error(), "callback slow") {
			t.Fatalf("shutdown: %v", err)
		}
		if d := time.Since(start); d != 2*time.Second {
			t.Fatalf("shutdown took %s, grace 2s", d)
		}
		close(release)
		synctest.Wait()
	})
}

func TestShutdownBeforeStart(t *testing.T) {
	t.Parallel()
	r := New(Options{Grace: time.Hour})
	if r.grace != MaxShutdownGrace {
		t.Fatalf("grace %s", r.grace)
	}
	shutdown(t, r)
	r.Start(t.Context())
	if err := r.RunNow(t.Context(), "x"); err == nil {
		t.Fatal("RunNow after shutdown")
	}
}

// TestShutdownUnderLoad starts and cancels many runs at once; the race
// detector and synctest check that nothing is left.
func TestShutdownUnderLoad(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := New(Options{Store: newMemStore()})
		for _, name := range []string{"a", "b", "c", "d"} {
			c := &counter{block: make(chan struct{})}
			mustRegister(t, r, name, Spec{Concurrency: 8, Every: time.Second}, c.fn)
		}
		r.Start(t.Context())
		for range 20 {
			for _, name := range []string{"a", "b", "c", "d"} {
				go func() { _ = r.RunNow(context.Background(), name) }()
			}
		}
		time.Sleep(10 * time.Second)
		synctest.Wait()
		go func() { _ = r.Cancel("a") }()
		shutdown(t, r)
		for _, i := range r.List() {
			if i.Runs != 0 || i.State != Stopped {
				t.Fatalf("after shutdown: %+v", i)
			}
		}
	})
}
