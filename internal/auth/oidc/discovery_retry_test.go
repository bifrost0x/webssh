package oidc

import (
	"sync"
	"testing"
	"time"
)

// An old discovery document whose refresh failed is served without a
// network attempt for metadataRetry, so sign-ins do not each wait for an
// unreachable provider (RS2-10).
func TestDiscoveryRetryAfterFailedRefresh(t *testing.T) {
	t.Parallel()
	f := newFakeIdP(t)
	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	r := newRemote(f.settings(clock))
	if _, _, err := r.metadata(t.Context()); err != nil {
		t.Fatal(err)
	}
	advance(metadataMaxAge)
	f.mu.Lock()
	f.discovery["issuer"] = "https://other.example" // the refresh fails
	f.mu.Unlock()
	if _, _, err := r.metadata(t.Context()); err != nil {
		t.Fatalf("old document not served after a failed refresh: %v", err)
	}
	hits := f.discoveryHits.Load()
	for range 5 {
		if _, _, err := r.metadata(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.discoveryHits.Load(); n != hits {
		t.Fatalf("%d discovery attempts within the retry interval", n-hits)
	}
	advance(metadataRetry)
	if _, _, err := r.metadata(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := f.discoveryHits.Load(); n != hits+1 {
		t.Fatalf("no new attempt after the retry interval: %d", n-hits)
	}
}
