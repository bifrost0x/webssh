package quota

import (
	"context"
	"fmt"
	"maps"
	"sync"

	"github.com/bifrost0x/webssh/internal/fault"
)

// Policy tracks the global and per-user use of every quota kind under one
// lock, so a check and its reservation are one step (QuotaManager of
// app/quota_manager.py). It is safe for concurrent use.
type Policy struct {
	limits map[string]Limit

	mu     sync.Mutex
	global map[string]int64
	users  map[userKey]int64
}

type userKey struct {
	kind string
	user int64
}

// Usage is the use of one kind for the admin page.
type Usage struct {
	Used            int64 // reserved across all users
	Users           int   // users holding a reservation
	Global, PerUser int64 // the limits
}

// New validates the limits and returns a policy without reservations.
// Every kind of Kinds must be configured, and no other.
func New(limits map[string]Limit) (*Policy, error) {
	if len(limits) != len(Kinds()) {
		return nil, fmt.Errorf("quota: limits must configure every quota kind")
	}
	for _, kind := range Kinds() {
		l, ok := limits[kind]
		if !ok {
			return nil, fmt.Errorf("quota: no limits for %s", kind)
		}
		if err := l.Check(kind); err != nil {
			return nil, fmt.Errorf("%s: %w", kind, err)
		}
	}
	return &Policy{limits: maps.Clone(limits), global: map[string]int64{}, users: map[userKey]int64{}}, nil
}

// Reserve takes amount units of kind for userID. The per-user limit is
// checked before the global one; a refusal is busy with the plain text of
// the Python release ("transfer quota exceeded (per_user limit 2)"). The
// returned release gives the units back and may be called more than
// once. An unknown kind or an amount below 1 is a programming error.
func (p *Policy) Reserve(ctx context.Context, kind string, userID, amount int64) (release func(), err error) {
	limit, ok := p.limits[kind]
	if !ok || amount < 1 {
		return nil, fault.Wrap(fault.Internal, fmt.Errorf("quota: reservation of %d units of kind %q", amount, kind), "")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := userKey{kind, userID}
	p.mu.Lock()
	defer p.mu.Unlock()
	if amount > limit.PerUser-p.users[key] {
		return nil, exceeded(kind, "per_user", limit.PerUser)
	}
	if amount > limit.Global-p.global[kind] {
		return nil, exceeded(kind, "global", limit.Global)
	}
	p.users[key] += amount
	p.global[kind] += amount
	released := false
	return func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if released {
			return
		}
		released = true
		if p.users[key] -= amount; p.users[key] <= 0 {
			delete(p.users, key)
		}
		if p.global[kind] -= amount; p.global[kind] <= 0 {
			delete(p.global, kind)
		}
	}, nil
}

func exceeded(kind, scope string, limit int64) error {
	return fault.New(fault.Busy, fmt.Sprintf("%s quota exceeded (%s limit %d)", kind, scope, limit))
}

// Usage returns the current use of every kind.
func (p *Policy) Usage() map[string]Usage {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]Usage, len(p.limits))
	for kind, l := range p.limits {
		out[kind] = Usage{Used: p.global[kind], Global: l.Global, PerUser: l.PerUser}
	}
	for key := range p.users {
		u := out[key.kind]
		u.Users++
		out[key.kind] = u
	}
	return out
}
