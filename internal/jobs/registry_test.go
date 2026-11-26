package jobs

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
)

func TestEveryRunsAfterThePreviousRun(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := New(Options{})
		var c counter
		mustRegister(t, r, "sweep", Spec{Every: time.Minute}, c.fn)
		r.Start(t.Context())
		time.Sleep(59 * time.Second)
		synctest.Wait()
		if c.runs.Load() != 0 {
			t.Fatal("ran before its interval")
		}
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		if n := c.runs.Load(); n != 10 {
			t.Fatalf("%d runs in ten minutes", n)
		}
		if i := info(t, r, "sweep"); !i.Periodic || i.State != Idle || i.NextRun.IsZero() || i.LastRun.IsZero() {
			t.Fatalf("info %+v", i)
		}
		shutdown(t, r)
		if i := info(t, r, "sweep"); i.State != Stopped {
			t.Fatalf("state after shutdown %s", i.State)
		}
	})
}

func TestCronRunsAtItsSlots(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// The bubble starts at midnight UTC on 1 January 2000.
		r := New(Options{})
		var c counter
		mustRegister(t, r, "nightly", Spec{Cron: "30 2 * * *", Zone: "Europe/Berlin"}, c.fn)
		r.Start(t.Context())
		want := time.Date(2000, 1, 1, 1, 30, 0, 0, time.UTC)
		if next := info(t, r, "nightly").NextRun; !next.Equal(want) {
			t.Fatalf("next run %s, want %s", next, want)
		}
		time.Sleep(3 * 24 * time.Hour)
		synctest.Wait()
		if n := c.runs.Load(); n != 3 {
			t.Fatalf("%d runs in three days", n)
		}
		shutdown(t, r)
	})
}

func TestSingletonSkipsDueRuns(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := New(Options{})
		c := counter{block: make(chan struct{})}
		mustRegister(t, r, "scan", Spec{Cron: "* * * * *", Singleton: true}, c.fn)
		r.Start(t.Context())
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		if c.runs.Load() != 1 || c.peak.Load() != 1 {
			t.Fatalf("runs %d, peak %d", c.runs.Load(), c.peak.Load())
		}
		if i := info(t, r, "scan"); i.State != Running || i.Runs != 1 {
			t.Fatalf("info %+v", i)
		}
		close(c.block)
		time.Sleep(2 * time.Minute)
		synctest.Wait()
		if c.runs.Load() != 3 {
			t.Fatalf("runs after release %d", c.runs.Load())
		}
		shutdown(t, r)
	})
}

func TestRunNowIsBoundedAndQueued(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := New(Options{})
		c := counter{block: make(chan struct{})}
		mustRegister(t, r, "copy", Spec{Concurrency: 2}, c.fn)
		if err := r.RunNow(t.Context(), "copy"); !fault.Is(err, fault.Unavailable) {
			t.Fatalf("RunNow before start: %v", err)
		}
		r.Start(t.Context())
		for range 2 + MaxPending {
			if err := r.RunNow(t.Context(), "copy"); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
		}
		if err := r.RunNow(t.Context(), "copy"); !fault.Is(err, fault.Busy) {
			t.Fatalf("RunNow beyond MaxPending: %v", err)
		}
		if c.active.Load() != 2 {
			t.Fatalf("%d runs in parallel", c.active.Load())
		}
		close(c.block)
		synctest.Wait()
		if c.runs.Load() != 2+MaxPending || c.peak.Load() != 2 {
			t.Fatalf("runs %d, peak %d", c.runs.Load(), c.peak.Load())
		}
		if err := r.RunNow(t.Context(), "nope"); !fault.Is(err, fault.NotFound) {
			t.Fatalf("unknown job: %v", err)
		}
		shutdown(t, r)
		if err := r.RunNow(t.Context(), "copy"); !fault.Is(err, fault.Unavailable) {
			t.Fatalf("RunNow after shutdown: %v", err)
		}
	})
}

func TestCancelEndsRunsAndDropsWaiting(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := New(Options{})
		c := counter{block: make(chan struct{})}
		release := make(chan struct{})
		slow := func(ctx context.Context) error {
			err := c.fn(ctx)
			<-release // returns late after its cancellation
			return err
		}
		mustRegister(t, r, "probe", Spec{Singleton: true}, slow)
		r.Start(t.Context())
		for range 3 {
			if err := r.RunNow(t.Context(), "probe"); err != nil {
				t.Fatal(err)
			}
		}
		synctest.Wait()
		if err := r.Cancel("probe"); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if i := info(t, r, "probe"); i.State != Cancelled || c.cancelled.Load() != 1 {
			t.Fatalf("info %+v, cancelled %d", i, c.cancelled.Load())
		}
		close(release)
		synctest.Wait()
		if i := info(t, r, "probe"); i.State != Idle || !i.LastErr || c.runs.Load() != 1 {
			t.Fatalf("info %+v, runs %d", i, c.runs.Load())
		}
		if err := r.Cancel("nope"); !fault.Is(err, fault.NotFound) {
			t.Fatalf("unknown job: %v", err)
		}
		shutdown(t, r)
	})
}

func TestTimeoutEndsARun(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := New(Options{})
		c := counter{block: make(chan struct{})}
		mustRegister(t, r, "fetch", Spec{Timeout: 30 * time.Second}, c.fn)
		r.Start(t.Context())
		_ = r.RunNow(t.Context(), "fetch")
		time.Sleep(31 * time.Second)
		synctest.Wait()
		if c.cancelled.Load() != 1 || !info(t, r, "fetch").LastErr {
			t.Fatal("the run outlived its timeout")
		}
		shutdown(t, r)
	})
}

func TestPanicEndsTheRunOnly(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := New(Options{})
		mustRegister(t, r, "bad", Spec{}, func(context.Context) error { panic("boom") })
		r.Start(t.Context())
		_ = r.RunNow(t.Context(), "bad")
		synctest.Wait()
		if !info(t, r, "bad").LastErr {
			t.Fatal("panic not recorded")
		}
		shutdown(t, r)
	})
}

func TestRegisterRefuses(t *testing.T) {
	t.Parallel()
	r := New(Options{})
	fn := func(context.Context) error { return nil }
	bad := []struct {
		name string
		s    Spec
		fn   Func
	}{
		{"", Spec{}, fn}, {"x", Spec{}, nil}, {"x", Spec{Every: time.Minute, Cron: "* * * * *"}, fn},
		{"x", Spec{Every: time.Millisecond}, fn}, {"x", Spec{Every: -time.Second}, fn}, {"x", Spec{Cron: "61 * * * *"}, fn},
		{"x", Spec{Cron: "* * * * *", Zone: "Local"}, fn}, {"x", Spec{Zone: "UTC"}, fn},
		{"x", Spec{Singleton: true, Concurrency: 2}, fn}, {"x", Spec{Timeout: -1}, fn},
		{string(make([]byte, MaxNameBytes+1)), Spec{}, fn},
	}
	for _, b := range bad {
		if err := r.Register(b.name, b.s, b.fn); err == nil {
			t.Errorf("registered %q %+v", b.name, b.s)
		}
	}
	mustRegister(t, r, "x", Spec{}, fn)
	if err := r.Register("x", Spec{}, fn); err == nil {
		t.Error("registered twice")
	}
	r.Start(t.Context())
	if err := r.Register("y", Spec{}, fn); err == nil {
		t.Error("registered after start")
	}
	shutdown(t, r)
}

func TestStartContextCancelsRuns(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := New(Options{})
		c := counter{block: make(chan struct{})}
		mustRegister(t, r, "a", Spec{Defer: true}, c.fn)
		ctx, cancel := context.WithCancel(t.Context())
		r.Start(ctx)
		_ = r.RunNow(t.Context(), "a")
		synctest.Wait()
		cancel()
		synctest.Wait()
		if c.cancelled.Load() != 1 {
			t.Fatal("run not cancelled with the start context")
		}
		shutdown(t, r)
	})
}
