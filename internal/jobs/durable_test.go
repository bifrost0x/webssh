package jobs

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/bifrost0x/webssh/internal/store/storetest"
)

// A run that was claimed and never ended (a crash) is not repeated; an
// on-demand run that never started runs after the restart.
func TestRestartRunsAtMostOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := newMemStore()
		now := time.Now()
		st.recs["copy"] = Record{Name: "copy", LastRun: now.Add(-time.Minute), Running: 1, Pending: 2}
		r := New(Options{Store: st})
		var c counter
		mustRegister(t, r, "copy", Spec{Singleton: true}, c.fn)
		r.Start(t.Context())
		synctest.Wait()
		if c.runs.Load() != 2 {
			t.Fatalf("%d runs after the restart, want the 2 waiting ones", c.runs.Load())
		}
		if rec := st.get("copy"); rec.Running != 0 || rec.Pending != 0 || rec.LastErr {
			t.Fatalf("stored %+v", rec)
		}
		shutdown(t, r)
	})
}

func TestInterruptedRunIsReported(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := newMemStore()
		st.recs["scan"] = Record{Name: "scan", LastRun: time.Now().Add(-time.Hour), Running: 1}
		r := New(Options{Store: st})
		var c counter
		mustRegister(t, r, "scan", Spec{}, c.fn)
		r.Start(t.Context())
		synctest.Wait()
		if c.runs.Load() != 0 || !info(t, r, "scan").LastErr {
			t.Fatalf("runs %d, info %+v", c.runs.Load(), info(t, r, "scan"))
		}
		if rec := st.get("scan"); rec.Running != 0 || !rec.LastErr {
			t.Fatalf("stored %+v", rec)
		}
		shutdown(t, r)
	})
}

// Periodic jobs continue from the stored last run: a weekly job does not
// run at every start, and a run missed while the process was down runs
// once.
func TestRestartKeepsTheSchedule(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := newMemStore()
		now := time.Now()
		st.recs["weekly"] = Record{Name: "weekly", LastRun: now.Add(-2 * 24 * time.Hour), LastEnd: now.Add(-2 * 24 * time.Hour)}
		st.recs["hourly"] = Record{Name: "hourly", LastRun: now.Add(-5 * time.Hour), LastEnd: now.Add(-5 * time.Hour)}
		st.recs["daily"] = Record{Name: "daily", LastRun: now.Add(-3 * 24 * time.Hour)}
		r := New(Options{Store: st})
		var weekly, hourly, daily counter
		mustRegister(t, r, "weekly", Spec{Every: 7 * 24 * time.Hour}, weekly.fn)
		mustRegister(t, r, "hourly", Spec{Every: time.Hour}, hourly.fn)
		mustRegister(t, r, "daily", Spec{Cron: "0 4 * * *"}, daily.fn)
		r.Start(t.Context())
		synctest.Wait()
		if weekly.runs.Load() != 0 || hourly.runs.Load() != 1 || daily.runs.Load() != 1 {
			t.Fatalf("at start: weekly %d, hourly %d, daily %d", weekly.runs.Load(), hourly.runs.Load(), daily.runs.Load())
		}
		if next := info(t, r, "weekly").NextRun; !next.Equal(now.Add(5 * 24 * time.Hour)) {
			t.Fatalf("weekly next %s", next)
		}
		time.Sleep(4*time.Hour + time.Minute)
		synctest.Wait()
		if hourly.runs.Load() != 5 || daily.runs.Load() != 2 {
			t.Fatalf("after 4 h: hourly %d, daily %d", hourly.runs.Load(), daily.runs.Load())
		}
		shutdown(t, r)
	})
}

// A run whose claim cannot be written does not start.
func TestUnrecordedRunDoesNotStart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := newMemStore()
		r := New(Options{Store: st})
		var c counter
		mustRegister(t, r, "job", Spec{Every: time.Minute}, c.fn)
		r.Start(t.Context())
		st.fail.Store(true)
		time.Sleep(3 * time.Minute)
		synctest.Wait()
		if c.runs.Load() != 0 || !info(t, r, "job").LastErr {
			t.Fatalf("ran %d times without a recorded start", c.runs.Load())
		}
		if err := r.RunNow(t.Context(), "job"); err == nil {
			t.Fatal("RunNow without a recorded request")
		}
		st.fail.Store(false)
		time.Sleep(time.Minute)
		synctest.Wait()
		if c.runs.Load() != 1 {
			t.Fatalf("runs after recovery %d", c.runs.Load())
		}
		shutdown(t, r)
	})
}

func TestUnreadableStateKeepsJobsStopped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := newMemStore()
		st.failLd = true
		r := New(Options{Store: st})
		var c counter
		mustRegister(t, r, "job", Spec{Every: time.Minute}, c.fn)
		r.Start(t.Context())
		time.Sleep(time.Hour)
		synctest.Wait()
		if c.runs.Load() != 0 {
			t.Fatal("ran without its state")
		}
		if err := r.RunNow(t.Context(), "job"); err == nil {
			t.Fatal("RunNow accepted")
		}
		shutdown(t, r)
	})
}

func TestDBStoreRoundTrip(t *testing.T) {
	t.Parallel()
	db := storetest.Open(t, Schema())
	s := DBStore{DB: db}
	ctx := t.Context()
	at := time.Date(2026, 11, 27, 10, 0, 0, 123456000, time.UTC)
	want := []Record{
		{Name: "a", LastRun: at, LastEnd: at.Add(time.Second), LastErr: true, Pending: 3, Running: 1},
		{Name: "b"},
	}
	for _, r := range want {
		if err := s.Save(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	want[0].Pending = 0
	if err := s.Save(ctx, want[0]); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("loaded %+v, want %+v", got, want)
	}
	if err := s.Save(ctx, Record{Name: "c", Pending: -1}); err == nil {
		t.Fatal("negative count saved")
	}
	if err := s.Save(ctx, Record{Name: ""}); err == nil {
		t.Fatal("empty name saved")
	}
}

// The registry state survives a real store across two registries.
func TestDBStoreAcrossRegistries(t *testing.T) {
	t.Parallel()
	db := storetest.Open(t, Schema())
	block := make(chan struct{})
	first := New(Options{Store: DBStore{DB: db}})
	mustRegister(t, first, "copy", Spec{Singleton: true}, func(ctx context.Context) error {
		select {
		case <-block:
		case <-ctx.Done():
		}
		return ctx.Err()
	})
	first.Start(t.Context())
	for range 3 {
		if err := first.RunNow(t.Context(), "copy"); err != nil {
			t.Fatal(err)
		}
	}
	// One run is in progress and two wait when the process ends.
	deadline := time.Now().Add(5 * time.Second)
	for info(t, first, "copy").Runs != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if err := first.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	close(block)
	second := New(Options{Store: DBStore{DB: db}})
	var c counter
	mustRegister(t, second, "copy", Spec{Singleton: true}, c.fn)
	second.Start(t.Context())
	for c.runs.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	shutdown(t, second)
	if c.runs.Load() != 2 {
		t.Fatalf("%d runs after the restart, want the 2 waiting ones", c.runs.Load())
	}
}
