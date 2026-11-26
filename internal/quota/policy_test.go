package quota

import (
	"context"
	"maps"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
)

func newPolicy(t *testing.T, kind string, l Limit) *Policy {
	t.Helper()
	limits := map[string]Limit{}
	maps.Copy(limits, DefaultLimits)
	limits[kind] = l
	p, err := New(limits)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReserveOrderAndText(t *testing.T) {
	t.Parallel()
	p := newPolicy(t, Transfer, Limit{Global: 3, PerUser: 2})
	ctx := t.Context()
	r1, _ := p.Reserve(ctx, Transfer, 1, 1)
	if _, err := p.Reserve(ctx, Transfer, 1, 1); err != nil {
		t.Fatal(err)
	}
	_, err := p.Reserve(ctx, Transfer, 1, 1)
	if e, ok := fault.From(err); !ok || e.Code != fault.Busy || e.Message != "transfer quota exceeded (per_user limit 2)" {
		t.Fatalf("per-user refusal: %v", err)
	}
	if _, err := p.Reserve(ctx, Transfer, 2, 1); err != nil {
		t.Fatal(err)
	}
	// Per-user is checked first, so user 2 with one slot left still sees
	// the global refusal only when its own limit allows the amount.
	if _, err := p.Reserve(ctx, Transfer, 2, 2); err == nil || err.Error() != "busy: transfer quota exceeded (per_user limit 2)" {
		t.Fatalf("amount over the per-user limit: %v", err)
	}
	_, err = p.Reserve(ctx, Transfer, 3, 1)
	if e, _ := fault.From(err); e == nil || e.Message != "transfer quota exceeded (global limit 3)" {
		t.Fatalf("global refusal: %v", err)
	}
	r1()
	r1() // idempotent
	if u := p.Usage()[Transfer]; u.Used != 2 || u.Users != 2 {
		t.Fatalf("usage %+v", u)
	}
	if _, err := p.Reserve(ctx, Transfer, 3, 1); err != nil {
		t.Fatalf("after release: %v", err)
	}
}

func TestReserveRefusesMisuse(t *testing.T) {
	t.Parallel()
	p := newPolicy(t, Transfer, DefaultLimits[Transfer])
	for _, c := range []struct {
		kind   string
		amount int64
	}{{"nope", 1}, {Transfer, 0}, {Transfer, -1}} {
		if _, err := p.Reserve(t.Context(), c.kind, 1, c.amount); !fault.Is(err, fault.Internal) {
			t.Errorf("%+v: %v", c, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := p.Reserve(ctx, Transfer, 1, 1); err == nil {
		t.Error("cancelled context reserved")
	}
	// Amounts near the int64 range do not overflow the check.
	big := newPolicy(t, TempBytes, Limit{Global: 1<<63 - 1, PerUser: 1<<63 - 1})
	if _, err := big.Reserve(t.Context(), TempBytes, 1, 1<<62); err != nil {
		t.Fatal(err)
	}
	if _, err := big.Reserve(t.Context(), TempBytes, 1, 1<<62-1); err != nil {
		t.Fatal(err)
	}
	if _, err := big.Reserve(t.Context(), TempBytes, 1, 1); !fault.Is(err, fault.Busy) {
		t.Fatalf("overflowing reservation: %v", err)
	}
}

func TestNewRefusesIncompleteLimits(t *testing.T) {
	t.Parallel()
	limits := map[string]Limit{}
	maps.Copy(limits, DefaultLimits)
	limits["other"] = Limit{1, 1}
	if _, err := New(limits); err == nil {
		t.Error("unknown kind accepted")
	}
	delete(limits, "other")
	delete(limits, Transfer)
	if _, err := New(limits); err == nil {
		t.Error("missing kind accepted")
	}
}

// TestReserveRace reserves and releases from many goroutines; the limits
// hold at every moment and everything is given back.
func TestReserveRace(t *testing.T) {
	t.Parallel()
	const global, perUser = 7, 3
	p := newPolicy(t, SSHSession, Limit{Global: global, PerUser: perUser})
	var held atomic.Int64
	var perUserHeld [5]atomic.Int64
	var wg sync.WaitGroup
	for g := range 40 {
		wg.Go(func() {
			user := int64(g % 5)
			for range 500 {
				release, err := p.Reserve(context.Background(), SSHSession, user, 1)
				if err != nil {
					if !fault.Is(err, fault.Busy) {
						t.Error(err)
					}
					continue
				}
				if n := held.Add(1); n > global {
					t.Errorf("%d held, global limit %d", n, global)
				}
				if n := perUserHeld[user].Add(1); n > perUser {
					t.Errorf("user %d holds %d", user, n)
				}
				perUserHeld[user].Add(-1)
				held.Add(-1)
				release()
				release()
			}
		})
	}
	wg.Wait()
	if u := p.Usage()[SSHSession]; u.Used != 0 || u.Users != 0 {
		t.Fatalf("left over: %+v", u)
	}
}
