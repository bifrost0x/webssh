// Package principaltest provides test doubles for the contracts built on
// internal/principal: a step-up service and a revocation feed. Only test
// files import it (architecture tests).
package principaltest

import (
	"context"
	"strconv"
	"sync"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// User returns a valid ordinary principal for tests.
func User(id int64) principal.Principal {
	return principal.Principal{UserID: id, SessionID: "session-" + strconv.FormatInt(id, 10), Username: "user" + strconv.FormatInt(id, 10)}
}

// Admin returns a valid administrator principal for tests.
func Admin(id int64) principal.Principal {
	p := User(id)
	p.IsAdmin = true
	return p
}

// grantKey binds a grant like the real service: user, session, action,
// target and the grant value itself.
type grantKey struct {
	userID    int64
	sessionID string
	action    principal.Action
	target    string
	grant     string
}

// Consumed records one call of StepUp.Consume.
type Consumed struct {
	Principal principal.Principal
	Action    principal.Action
	Target    string
	Grant     string
	Err       error
}

// StepUp is an in-memory step-up service with the method set every
// consumer declares:
//
//	Consume(ctx, p principal.Principal, action principal.Action, target, grant string) error
//
// A grant is accepted once, only for the principal, action and target it
// was issued for; everything else fails with fault.StepUpRequired, as the
// real service does. The zero value is ready to use.
type StepUp struct {
	mu     sync.Mutex
	grants map[grantKey]bool
	calls  []Consumed
}

// Issue makes grant valid once for p, action and target.
func (s *StepUp) Issue(p principal.Principal, action principal.Action, target, grant string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.grants == nil {
		s.grants = map[grantKey]bool{}
	}
	s.grants[grantKey{p.UserID, p.SessionID, action, target, grant}] = true
}

// Consume implements the step-up contract.
func (s *StepUp) Consume(ctx context.Context, p principal.Principal, action principal.Action, target, grant string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := ctx.Err()
	if err == nil {
		key := grantKey{p.UserID, p.SessionID, action, target, grant}
		switch {
		case !action.Known():
			err = fault.New(fault.InvalidRequest, "unknown step-up action")
		case grant == "" || !s.grants[key]:
			err = fault.New(fault.StepUpRequired, "")
		default:
			delete(s.grants, key)
		}
	}
	s.calls = append(s.calls, Consumed{Principal: p, Action: action, Target: target, Grant: grant, Err: err})
	return err
}

// Calls returns every Consume call so far.
func (s *StepUp) Calls() []Consumed {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Consumed(nil), s.calls...)
}

// Revocations is an in-memory revocation feed with the method set of the
// realtime contract. Revoke delivers synchronously to every subscriber
// before it returns, which is the guarantee the session package gives.
// The zero value is ready to use.
type Revocations struct {
	mu   sync.Mutex
	next int
	subs map[int]func(principal.Revocation)
}

// Subscribe registers fn and returns a function that removes it.
func (r *Revocations) Subscribe(fn func(principal.Revocation)) (cancel func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.subs == nil {
		r.subs = map[int]func(principal.Revocation){}
	}
	id := r.next
	r.next++
	r.subs[id] = fn
	return func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		delete(r.subs, id)
	}
}

// Revoke announces rev to every subscriber.
func (r *Revocations) Revoke(rev principal.Revocation) {
	r.mu.Lock()
	subs := make([]func(principal.Revocation), 0, len(r.subs))
	for _, fn := range r.subs {
		subs = append(subs, fn)
	}
	r.mu.Unlock()
	for _, fn := range subs {
		fn(rev)
	}
}
