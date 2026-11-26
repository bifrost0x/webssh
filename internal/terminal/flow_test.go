package terminal

import (
	"context"
	"errors"
	"testing"
	"time"
)

// huge is a limit that never binds in these tests.
const huge = 1 << 30

func limits() FlowLimits {
	return FlowLimits{StreamBytes: huge, StreamFrames: huge, ConnBytes: huge, ConnFrames: huge,
		UserBytes: huge, UserFrames: huge, GlobalBytes: huge, GlobalFrames: huge, AckTimeout: time.Second}
}

// tryAcquire reports whether a frame is admitted without waiting.
func tryAcquire(t *testing.T, l *ledger, c *credit, seq uint64, n int) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	err := l.acquire(ctx, c, seq, n)
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("acquire: %v", err)
	}
	return err == nil
}

// Every level enforces its byte limit on its own (condition K6: removing
// the byte check of any level must fail this test). The other levels and
// all frame limits are out of reach, and a second credit fills the shared
// levels so that the "empty level admits one frame" rule does not apply.
func TestLedgerByteLimitPerLevel(t *testing.T) {
	cases := []struct {
		name string
		set  func(*FlowLimits)
		// other opens the credit that holds the first frame on the level:
		// the same credit for the stream level, another one otherwise.
		other func(l *ledger, c *credit) *credit
	}{
		{"stream", func(f *FlowLimits) { f.StreamBytes = 1000 }, func(_ *ledger, c *credit) *credit { return c }},
		{"connection", func(f *FlowLimits) { f.ConnBytes = 1000 }, func(l *ledger, _ *credit) *credit { return l.open(1, 1) }},
		{"user", func(f *FlowLimits) { f.UserBytes = 1000 }, func(l *ledger, _ *credit) *credit { return l.open(2, 1) }},
		{"global", func(f *FlowLimits) { f.GlobalBytes = 1000 }, func(l *ledger, _ *credit) *credit { return l.open(3, 2) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lim := limits()
			tc.set(&lim)
			l := newLedger(lim)
			c := l.open(1, 1)
			first := tc.other(l, c)
			if !tryAcquire(t, l, first, 1, 600) {
				t.Fatal("first frame refused")
			}
			if !tryAcquire(t, l, c, 2, 400) {
				t.Fatal("frame up to the byte limit refused")
			}
			if tryAcquire(t, l, c, 3, 1) {
				t.Fatalf("%s level admitted a byte above its limit", tc.name)
			}
			l.ack(first, 1)
			if first != c {
				l.ack(c, 2)
			} else {
				l.ack(c, 1)
			}
			if !tryAcquire(t, l, c, 3, 1) {
				t.Fatal("acknowledged bytes were not released")
			}
		})
	}
}

func TestLedgerFrameLimitPerLevel(t *testing.T) {
	sets := map[string]func(*FlowLimits){
		"stream":     func(f *FlowLimits) { f.StreamFrames = 2 },
		"connection": func(f *FlowLimits) { f.ConnFrames = 2 },
		"user":       func(f *FlowLimits) { f.UserFrames = 2 },
		"global":     func(f *FlowLimits) { f.GlobalFrames = 2 },
	}
	for name, set := range sets {
		t.Run(name, func(t *testing.T) {
			lim := limits()
			set(&lim)
			l := newLedger(lim)
			c := l.open(1, 1)
			if !tryAcquire(t, l, c, 1, 1) || !tryAcquire(t, l, c, 2, 1) {
				t.Fatal("frames within the limit refused")
			}
			if tryAcquire(t, l, c, 3, 1) {
				t.Fatalf("%s level admitted a third frame", name)
			}
		})
	}
}

// A frame larger than every byte limit still passes an empty ledger, so
// one large read cannot stall a stream forever.
func TestLedgerEmptyLevelAdmitsOneFrame(t *testing.T) {
	lim := limits()
	lim.StreamBytes, lim.ConnBytes, lim.UserBytes, lim.GlobalBytes = 10, 10, 10, 10
	l := newLedger(lim)
	c := l.open(1, 1)
	if !tryAcquire(t, l, c, 1, 100) {
		t.Fatal("oversized frame on an empty ledger refused")
	}
	if tryAcquire(t, l, c, 2, 1) {
		t.Fatal("second frame admitted above the limit")
	}
}

// A waiting reader wakes when another stream's ack frees a shared level,
// and when its attachment is closed.
func TestLedgerWakeups(t *testing.T) {
	lim := limits()
	lim.ConnBytes = 100
	l := newLedger(lim)
	a, b := l.open(1, 1), l.open(1, 1)
	if !tryAcquire(t, l, a, 1, 100) {
		t.Fatal("first frame")
	}
	got := make(chan error, 1)
	go func() { got <- l.acquire(t.Context(), b, 1, 50) }()
	time.Sleep(20 * time.Millisecond)
	l.ack(a, 1)
	if err := <-got; err != nil {
		t.Fatalf("waiter after ack: %v", err)
	}
	go func() { got <- l.acquire(t.Context(), b, 2, 100) }()
	time.Sleep(20 * time.Millisecond)
	l.close(b)
	if err := <-got; !errors.Is(err, errDetached) {
		t.Fatalf("waiter after close: %v", err)
	}
	if bytes, frames := l.inFlight(); bytes != 0 || frames != 0 {
		t.Fatalf("closed credits still hold %d bytes, %d frames", bytes, frames)
	}
	l.close(a)
	if len(l.conns) != 0 {
		t.Fatalf("connection level kept after its last credit: %v", l.conns)
	}
}

func TestLedgerReplay(t *testing.T) {
	frames := []chunk{{seq: 1, data: make([]byte, 300)}, {seq: 2, data: make([]byte, 300)}, {seq: 3, data: make([]byte, 300)}}
	lim := limits()
	lim.ConnBytes = 700
	l := newLedger(lim)
	c := l.open(1, 1)
	sent, cut, ok := l.reserveReplay(c, frames)
	if !ok || !cut || len(sent) != 2 || sent[0].seq != 2 {
		t.Fatalf("replay above the connection budget: %d frames, cut %v, ok %v", len(sent), cut, ok)
	}
	// The budget is now taken; even one more frame does not fit.
	other := l.open(1, 1)
	if _, _, ok := l.reserveReplay(other, frames[:1]); ok {
		t.Fatal("replay admitted on a full connection")
	}
	l.ack(c, 3)
	sent, cut, ok = l.reserveReplay(other, frames[2:])
	if !ok || cut || len(sent) != 1 {
		t.Fatalf("after ack: %d frames, cut %v, ok %v", len(sent), cut, ok)
	}
	// User and process levels bound a replay too.
	for name, set := range map[string]func(*FlowLimits){
		"user":   func(f *FlowLimits) { f.UserBytes = 500 },
		"global": func(f *FlowLimits) { f.GlobalBytes = 500 },
	} {
		lim := limits()
		set(&lim)
		l := newLedger(lim)
		if sent, cut, ok := l.reserveReplay(l.open(1, 1), frames); !ok || !cut || len(sent) != 1 {
			t.Fatalf("%s: %d frames, cut %v", name, len(sent), cut)
		}
	}
}

func TestLedgerStale(t *testing.T) {
	l := newLedger(limits())
	now := time.Unix(1000, 0)
	l.now = func() time.Time { return now }
	c := l.open(1, 1)
	if l.stale(c, now.Add(time.Hour)) {
		t.Fatal("nothing pending is never stale")
	}
	if !tryAcquire(t, l, c, 1, 1) {
		t.Fatal("acquire")
	}
	if l.stale(c, now.Add(999*time.Millisecond)) || !l.stale(c, now.Add(time.Second)) {
		t.Fatal("ack timeout boundary")
	}
}

func TestFlowDefaults(t *testing.T) {
	var f FlowLimits
	f.defaults()
	if f.ConnBytes != 512<<10 || f.ConnFrames != 128 || f.UserBytes != 4<<20 || f.UserFrames != 1024 ||
		f.GlobalBytes != 32<<20 || f.GlobalFrames != 8192 || f.StreamFrames != 64 || f.AckTimeout != 10*time.Second {
		t.Fatalf("defaults %+v", f)
	}
}
