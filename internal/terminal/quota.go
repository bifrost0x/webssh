package terminal

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/bifrost0x/webssh/internal/fault"
)

// Quotas is the runtime quota policy (internal/quota). An SSH session,
// including an attempt that is still connecting, holds one unit of kind
// "ssh_session" (QuotaKind.SSH_SESSION of app/quota_manager.py).
type Quotas interface {
	Reserve(ctx context.Context, kind string, userID, amount int64) (release func(), err error)
}

// sessionKind is the quota kind of an SSH session.
const sessionKind = "ssh_session"

// errSessionLimit is the refusal of a full quota. The Python release sent
// "Maximum number of sessions reached" without a code.
var errSessionLimit = fault.New(fault.Busy, "Maximum number of sessions reached.")

// sessionQuota takes session slots from the policy and counts those this
// manager holds (Stats.Reserved).
type sessionQuota struct {
	policy Quotas
	held   atomic.Int64
}

// reserve takes one slot for user and returns its release function, which
// may be called more than once. A full quota is errSessionLimit, whose
// text the page shows.
func (q *sessionQuota) reserve(ctx context.Context, user int64) (release func(), err error) {
	free, err := q.policy.Reserve(ctx, sessionKind, user, 1)
	if err != nil {
		if fault.Is(err, fault.Busy) {
			return nil, errSessionLimit
		}
		return nil, err
	}
	q.held.Add(1)
	var once sync.Once
	return func() {
		once.Do(func() {
			free()
			q.held.Add(-1)
		})
	}, nil
}

func (q *sessionQuota) used() int { return int(q.held.Load()) }
