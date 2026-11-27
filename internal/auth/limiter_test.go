package auth

import (
	json "encoding/json/v2"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestParseRule(t *testing.T) {
	t.Parallel()
	def := Rule{Limit: 7, Window: time.Second}
	for in, want := range map[string]Rule{
		"5 per minute":    {5, time.Minute},
		"200 per hour":    {200, time.Hour},
		"10 per seconds":  {10, time.Second},
		" 3 PER MINUTES ": {3, time.Minute},
		"3 per day":       def,
		"x per minute":    def,
		"":                def,
		"5":               def,
		"0 per minute":    {0, time.Minute},
	} {
		if got := ParseRule(in, def); got != want {
			t.Errorf("%q: %+v, want %+v", in, got, want)
		}
	}
}

func TestSourceBucket(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		in     string
		prefix int
		want   string
	}{
		{"10.0.0.1", 64, "10.0.0.1"},
		{"::ffff:10.0.0.1", 64, "10.0.0.1"},
		{"2001:db8::1", 128, "2001:db8::1"},
		{"2001:db8::1", 64, "2001:db8::/64"},
		{"2001:db8:0:0:ffff::1", 48, "2001:db8::/48"},
		{"2001:db8::1", 12, "2001:db8::1"},
		{"not-an-ip", 64, "not-an-ip"},
		{"", 64, "unknown"},
	} {
		if got := SourceBucket(c.in, c.prefix); got != c.want {
			t.Errorf("%s/%d: %s, want %s", c.in, c.prefix, got, c.want)
		}
	}
}

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestLimiterWindowAndRelease(t *testing.T) {
	t.Parallel()
	c := &testClock{t: time.Unix(1000, 0)}
	l := NewLimiter()
	l.Now = c.now
	r := Rule{Limit: 2, Window: time.Minute}
	a, ok, _ := l.Reserve("k", r)
	if !ok {
		t.Fatal("first refused")
	}
	c.add(10 * time.Second)
	if _, ok, _ := l.Reserve("k", r); !ok {
		t.Fatal("second refused")
	}
	_, ok, after := l.Reserve("k", r)
	if ok || after != 50*time.Second {
		t.Fatalf("third: ok=%v after=%v", ok, after)
	}
	// A refused attempt is not recorded; a release frees one slot.
	l.Release(a)
	if _, ok, _ := l.Reserve("k", r); !ok {
		t.Fatal("released slot not free")
	}
	c.add(61 * time.Second)
	if ok, _ := l.Allow("k", r); !ok {
		t.Fatal("window did not slide")
	}
	if ok, _ := l.Allow("z", Rule{Limit: 0, Window: time.Minute}); ok {
		t.Fatal("limit 0 allowed")
	}
	l.Release(Reservation{key: "missing", id: 99}) // no panic
}

func TestLimiterBoundedMemory(t *testing.T) {
	t.Parallel()
	c := &testClock{t: time.Unix(1000, 0)}
	l := NewLimiter()
	l.Now = c.now
	r := Rule{Limit: 1, Window: time.Second}
	for i := range maxBuckets {
		l.Allow(strconv.Itoa(i), r)
		c.add(time.Microsecond)
	}
	c.add(time.Millisecond)
	if ok, _ := l.Allow("new", r); !ok {
		t.Fatal("a full limiter refused a new key")
	}
	if _, kept := l.sources.buckets["0"]; kept {
		t.Fatal("least recently used bucket kept")
	}
	if ok, _ := l.Allow("new", r); ok {
		t.Fatal("new key not limited")
	}
	c.add(2 * time.Second)
	if ok, _ := l.Allow("new", r); !ok {
		t.Fatal("window did not slide")
	}
	if len(l.sources.buckets) > maxBuckets {
		t.Fatalf("%d buckets", len(l.sources.buckets))
	}
}

func TestRealtimeLimiter(t *testing.T) {
	t.Parallel()
	l := NewLimiter()
	l.Realtime = map[string]Rule{"ssh_connect": {Limit: 1, Window: time.Minute}}
	rt := Realtime{L: l}
	if ok, _ := rt.Allow(1, "ssh_connect"); !ok {
		t.Fatal("first refused")
	}
	if ok, after := rt.Allow(1, "ssh_connect"); ok || after <= 0 {
		t.Fatal("second allowed")
	}
	if ok, _ := rt.Allow(2, "ssh_connect"); !ok {
		t.Fatal("limit shared between users")
	}
	l.RealtimeDefault = Rule{Limit: 1, Window: time.Hour}
	rt.Allow(1, "unknown_key")
	if ok, _ := rt.Allow(1, "unknown_key"); ok {
		t.Fatal("unknown key unlimited")
	}
}

func TestLimiterConcurrent(t *testing.T) {
	t.Parallel()
	l := NewLimiter()
	r := Rule{Limit: 10, Window: time.Hour}
	var wg sync.WaitGroup
	var mu sync.Mutex
	granted := 0
	for range 50 {
		wg.Go(func() {
			if ok, _ := l.Allow("k", r); ok {
				mu.Lock()
				granted++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if granted != 10 {
		t.Fatalf("granted %d", granted)
	}
}

// SafeContinuation and PublicContinuation agree with the Python release.
func TestContinuationMatchesPython(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/python_continuation.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		In     string `json:"in"`
		Root   string `json:"root"`
		Safe   string `json:"safe"`
		Public string `json:"public"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	// Go refuses two values Python lets through: an invalid percent
	// escape and an empty fragment. Both become "/" (fix, stricter).
	stricter := map[string]bool{"/%zz": true, "/x?y#": true}
	for _, c := range cases {
		wantSafe, wantPublic := c.Safe, c.Public
		if stricter[c.In] {
			wantSafe, wantPublic = "/", PublicContinuation(c.Root, "/")
		}
		if got := SafeContinuation(c.In); got != wantSafe {
			t.Errorf("safe %q: %q, want %q", c.In, got, wantSafe)
		}
		if got := PublicContinuation(c.Root, c.In); got != wantPublic {
			t.Errorf("public %q root %q: %q, want %q", c.In, c.Root, got, wantPublic)
		}
	}
}

func FuzzSafeContinuation(f *testing.F) {
	for _, s := range []string{"/", "//x", "/\\x", "/a?b", "http://x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := SafeContinuation(s)
		if got != "/" && got != s {
			t.Fatalf("rewrote %q to %q", s, got)
		}
		if len(got) > 1 && (got[1] == '/' || got[1] == '\\' || got[0] != '/') {
			t.Fatalf("unsafe %q", got)
		}
		pub := PublicContinuation("/root", s)
		if len(pub) < 5 || pub[:5] != "/root" {
			t.Fatalf("public %q leaves the root", pub)
		}
	})
}
