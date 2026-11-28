package auth

import (
	"strconv"
	"testing"
	"time"
)

// A full store makes room for a new browser by dropping the oldest entry,
// so anonymous page requests cannot lock other browsers out of their
// messages.
func TestFlashStoreFullEvictsOldest(t *testing.T) {
	t.Parallel()
	var f flashes
	now := time.Unix(1_700_000_000, 0)
	for i := range maxFlashBrowsers {
		f.add(now.Add(time.Duration(i)*time.Millisecond), "flood-"+strconv.Itoa(i), Flash{Category: "error", Message: "Please log in to access this page."})
	}
	later := now.Add(time.Minute)
	f.add(later, "victim", Flash{Category: "error", Message: "partial logout"})
	if got := f.take(later, "victim"); len(got) != 1 || got[0].Message != "partial logout" {
		t.Fatalf("victim messages = %v", got)
	}
	if got := f.take(later, "flood-0"); got != nil {
		t.Fatalf("oldest entry kept: %v", got)
	}
	if got := f.take(later, "flood-1"); len(got) != 1 {
		t.Fatalf("second oldest entry dropped: %v", got)
	}
	f.mu.Lock()
	n := len(f.m)
	f.mu.Unlock()
	if n > maxFlashBrowsers {
		t.Fatalf("store holds %d browsers", n)
	}
}
