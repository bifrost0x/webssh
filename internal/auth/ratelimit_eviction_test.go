package auth

import (
	"strconv"
	"testing"
	"time"
)

// Filling the limiter with fresh source keys must not evict the
// per-name ceiling of a user, so its attempts do not start over within
// the same window (RS2-03).
func TestLimiterSourceFloodKeepsNameCeiling(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	l := NewLimiter()
	l.Now = func() time.Time { return now }
	key := "login:username:victim"
	for range DefaultGlobalRule.Limit {
		if ok, _ := l.AllowAccount(key, DefaultGlobalRule); !ok {
			t.Fatal("ceiling reached early")
		}
	}
	if ok, _ := l.AllowAccount(key, DefaultGlobalRule); ok {
		t.Fatal("ceiling not enforced")
	}
	now = now.Add(time.Second)
	for i := range 2 * maxBuckets {
		l.Allow("login:2001:db8::"+strconv.Itoa(i), DefaultRule)
	}
	if ok, _ := l.AllowAccount(key, DefaultGlobalRule); ok {
		t.Fatal("per-name ceiling was evicted by a flood of fresh source keys within its window")
	}
	if n := len(l.sources.buckets); n > maxBuckets {
		t.Fatalf("source pool holds %d buckets", n)
	}
}

// A flood of fresh account keys keeps a ceiling that is reached; room is
// made from buckets below their limit, and the pool stays bounded.
func TestLimiterAccountFloodKeepsReachedCeiling(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	l := NewLimiter()
	l.Now = func() time.Time { return now }
	key := "login:username:victim"
	for range DefaultGlobalRule.Limit {
		l.AllowAccount(key, DefaultGlobalRule)
	}
	now = now.Add(time.Second)
	for i := range 2 * maxBuckets {
		l.AllowAccount("login:username:fresh"+strconv.Itoa(i), DefaultGlobalRule)
	}
	if ok, _ := l.AllowAccount(key, DefaultGlobalRule); ok {
		t.Fatal("reached ceiling evicted by fresh names")
	}
	if n := len(l.accounts.buckets); n > maxBuckets {
		t.Fatalf("account pool holds %d buckets", n)
	}
}

// When every account bucket near the eviction end is at its limit, a new
// account key is refused instead of dropping a reached ceiling.
func TestLimiterAccountPoolFullOfReachedCeilingsRefuses(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	l := NewLimiter()
	l.Now = func() time.Time { return now }
	one := Rule{Limit: 1, Window: time.Minute}
	for i := range maxBuckets {
		l.AllowAccount("a"+strconv.Itoa(i), one)
	}
	if ok, after := l.AllowAccount("new", one); ok || after <= 0 {
		t.Fatalf("new key admitted into a pool of reached ceilings: %v %v", ok, after)
	}
	if ok, _ := l.AllowAccount("a0", one); ok {
		t.Fatal("reached ceiling dropped")
	}
	now = now.Add(time.Minute)
	if ok, _ := l.AllowAccount("new", one); !ok {
		t.Fatal("expired buckets did not make room")
	}
}

func TestLimiterReleaseAccount(t *testing.T) {
	t.Parallel()
	l := NewLimiter()
	one := Rule{Limit: 1, Window: time.Minute}
	res, ok, _ := l.ReserveAccount("k", one)
	if !ok {
		t.Fatal("refused")
	}
	if ok, _ := l.Allow("k", one); !ok {
		t.Fatal("source and account buckets share a key")
	}
	l.Release(res)
	if _, kept := l.accounts.buckets["k"]; kept {
		t.Fatal("released bucket kept")
	}
	if ok, _ := l.AllowAccount("k", one); !ok {
		t.Fatal("release did not return the event")
	}
}

// Every call at capacity does constant work (RS2-03: it scanned all
// buckets twice under the one mutex).
func BenchmarkLimiterAtCapacity(b *testing.B) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	l := NewLimiter()
	l.Now = func() time.Time { return now }
	for i := range maxBuckets {
		l.Allow("fill:"+strconv.Itoa(i), DefaultRule)
	}
	i := 0
	for b.Loop() {
		i++
		l.Allow("new:"+strconv.Itoa(i), DefaultRule)
	}
}

func BenchmarkLimiterBelowCapacity(b *testing.B) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	l := NewLimiter()
	l.Now = func() time.Time { return now }
	i := 0
	for b.Loop() {
		i++
		l.Allow("new:"+strconv.Itoa(i%1000), DefaultRule)
	}
}
