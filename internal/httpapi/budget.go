package httpapi

import (
	"context"
	"sync"
	"time"
)

// Request bodies are buffered whole before the CSRF check, so their sum
// is bounded across all requests in flight: signed-in requests share
// signedInBodyBudget, requests without a session (the sign-in routes)
// share the smaller anonymousBodyBudget, so a flood of sign-in attempts
// cannot hold the memory signed-in users need. Within the signed-in
// budget one account holds at most userBodyShare, so a user who sends
// slow bodies over many connections cannot occupy the whole budget until
// the read deadline. A request waits at most bodyBudgetWait for both
// shares and is then answered 503.
const (
	signedInBodyBudget  = 64 << 20
	anonymousBodyBudget = 16 << 20
	userBodyShare       = 8 << 20
	bodyBudgetWait      = 5 * time.Second
)

// bodyBudget is a counting semaphore over bytes. Waiters are woken on
// every release and retry; the number of waiters is bounded by the
// connection limit of the listener.
type bodyBudget struct {
	mu      sync.Mutex
	free    int64
	changed chan struct{}
}

func newBodyBudget(size int64) *bodyBudget {
	return &bodyBudget{free: size, changed: make(chan struct{})}
}

// acquire reserves n bytes. It returns false when ctx ends or wait passes
// before the bytes are free. n must not exceed the budget's size.
func (b *bodyBudget) acquire(ctx context.Context, n int64, wait time.Duration) bool {
	if n <= 0 {
		return true
	}
	changed, ok := b.take(n)
	if ok {
		return true
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		select {
		case <-changed:
		case <-timer.C:
			return false
		case <-ctx.Done():
			return false
		}
		if changed, ok = b.take(n); ok {
			return true
		}
	}
}

// take reserves n bytes if they are free; otherwise it returns the
// channel that is closed on the next release.
func (b *bodyBudget) take(n int64) (<-chan struct{}, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.free >= n {
		b.free -= n
		return nil, true
	}
	return b.changed, false
}

// release returns n bytes and wakes the waiters.
func (b *bodyBudget) release(n int64) {
	if n <= 0 {
		return
	}
	b.mu.Lock()
	b.free += n
	close(b.changed)
	b.changed = make(chan struct{})
	b.mu.Unlock()
}

// userBudgets gives every signed-in account its own budget of share
// bytes. An account's entry exists only while it has a body in flight.
// A single reservation larger than the share takes the whole share.
type userBudgets struct {
	mu    sync.Mutex
	share int64
	users map[int64]*userBudget
}

type userBudget struct {
	budget *bodyBudget
	refs   int
}

func newUserBudgets(share int64) *userBudgets {
	return &userBudgets{share: share, users: map[int64]*userBudget{}}
}

// acquire reserves n bytes of the account's share, waiting like
// bodyBudget.acquire. Every successful acquire needs one release with the
// same n.
func (u *userBudgets) acquire(ctx context.Context, user, n int64, wait time.Duration) bool {
	if n <= 0 {
		return true
	}
	u.mu.Lock()
	e := u.users[user]
	if e == nil {
		e = &userBudget{budget: newBodyBudget(u.share)}
		u.users[user] = e
	}
	e.refs++
	u.mu.Unlock()
	if e.budget.acquire(ctx, min(n, u.share), wait) {
		return true
	}
	u.drop(user, e)
	return false
}

// release returns n bytes to the account's share.
func (u *userBudgets) release(user, n int64) {
	if n <= 0 {
		return
	}
	u.mu.Lock()
	e := u.users[user]
	u.mu.Unlock()
	if e == nil {
		return
	}
	e.budget.release(min(n, u.share))
	u.drop(user, e)
}

func (u *userBudgets) drop(user int64, e *userBudget) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if e.refs--; e.refs == 0 {
		delete(u.users, user)
	}
}
