package oidc

import (
	"context"
	"errors"
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

// Before the first document has been fetched, a failed discovery is also
// remembered for metadataRetry: a provider that is down at start does not
// get one request per sign-in, and callers do not queue for it.
func TestDiscoveryRetryAfterFailedFirstFetch(t *testing.T) {
	t.Parallel()
	f := newFakeIdP(t)
	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	f.mu.Lock()
	f.discovery["issuer"] = "https://other.example"
	f.mu.Unlock()
	r := newRemote(f.settings(clock))
	if _, _, err := r.metadata(t.Context()); !errors.Is(err, errProvider) {
		t.Fatalf("first fetch: %v", err)
	}
	for range 5 {
		if _, _, err := r.metadata(t.Context()); !errors.Is(err, errProvider) {
			t.Fatalf("within the retry interval: %v", err)
		}
	}
	if n := f.discoveryHits.Load(); n != 1 {
		t.Fatalf("%d discovery attempts within the retry interval", n)
	}
	f.mu.Lock()
	f.discovery["issuer"] = f.srv.URL
	f.mu.Unlock()
	advance(metadataRetry)
	if _, _, err := r.metadata(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := f.discoveryHits.Load(); n != 2 {
		t.Fatalf("no new attempt after the retry interval: %d", n)
	}
}

// A caller waiting for another caller's fetch gives up with its context.
func TestDiscoveryWaitFollowsContext(t *testing.T) {
	t.Parallel()
	f := newFakeIdP(t)
	r := newRemote(f.settings(time.Now))
	if err := r.lockFetch(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer r.unlockFetch()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := r.metadata(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting caller: %v", err)
	}
}
