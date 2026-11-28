package automation

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A check that fails because the tick ran out of time or storage failed
// says nothing about the approval. The slot stays due and the next tick
// runs it; the schedule is not paused for a new review.
func TestScheduleTransientCheckFailureKeepsTheSchedule(t *testing.T) {
	t.Parallel()
	for name, fail := range map[string]func(ctx context.Context, cancel context.CancelFunc) error{
		"tick time limit": func(_ context.Context, cancel context.CancelFunc) error {
			cancel()
			return Fail("key_unavailable")
		},
		"storage error": func(context.Context, context.CancelFunc) error {
			return storageErr(errors.New("disk I/O error"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newScheduleEnv(t)
			id := e.approve(t, "0 9 * * *", "UTC")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			e.wf.mu.Lock()
			e.wf.current = func(ctx context.Context) error { return fail(ctx, cancel) }
			e.wf.mu.Unlock()
			e.clock.set(nine.Add(time.Second))
			if err := e.s.Tick(ctx); err != nil {
				t.Fatal(err)
			}
			got := e.one(t, id)
			if jsonMember(got, "last_status") == StatusNeedsReview || !boolMember(got, "enabled") {
				t.Fatalf("a transient failure paused the schedule: %s", got)
			}
			e.wf.mu.Lock()
			e.wf.current = nil
			e.wf.mu.Unlock()
			e.tickAt(t, nine.Add(2*time.Second))
			if len(e.wf.runs()) != 1 {
				t.Fatalf("%d runs after the retry, want one", len(e.wf.runs()))
			}
		})
	}
}
