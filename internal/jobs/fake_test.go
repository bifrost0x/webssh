package jobs

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

// memStore is a Store in memory that can fail on demand.
type memStore struct {
	mu     sync.Mutex
	recs   map[string]Record
	fail   atomic.Bool
	failLd bool
	saves  atomic.Int64
}

func newMemStore() *memStore { return &memStore{recs: map[string]Record{}} }

var errStore = errors.New("store down")

func (m *memStore) Load(context.Context) ([]Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failLd {
		return nil, errStore
	}
	var out []Record
	for _, r := range m.recs {
		out = append(out, r)
	}
	return out, nil
}

func (m *memStore) Save(_ context.Context, r Record) error {
	if m.fail.Load() {
		return errStore
	}
	m.saves.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recs[r.Name] = r
	return nil
}

func (m *memStore) get(name string) Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.recs[name]
}

// counter is a job function that counts its runs and can block until
// released or cancelled.
type counter struct {
	runs, active, peak atomic.Int64
	block              chan struct{} // nil: return at once
	cancelled          atomic.Int64
}

func (c *counter) fn(ctx context.Context) error {
	c.runs.Add(1)
	n := c.active.Add(1)
	defer c.active.Add(-1)
	for {
		p := c.peak.Load()
		if n <= p || c.peak.CompareAndSwap(p, n) {
			break
		}
	}
	if c.block == nil {
		return nil
	}
	select {
	case <-c.block:
		return nil
	case <-ctx.Done():
		c.cancelled.Add(1)
		return ctx.Err()
	}
}

func mustRegister(t *testing.T, r *Registry, name string, s Spec, fn Func) {
	t.Helper()
	if err := r.Register(name, s, fn); err != nil {
		t.Fatal(err)
	}
}

func shutdown(t *testing.T, r *Registry) {
	t.Helper()
	if err := r.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

func info(t *testing.T, r *Registry, name string) Info {
	t.Helper()
	for _, i := range r.List() {
		if i.Name == name {
			return i
		}
	}
	t.Fatalf("no job %s", name)
	return Info{}
}
