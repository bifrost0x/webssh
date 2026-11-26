package terminal

import (
	"sync"

	"github.com/bifrost0x/webssh/internal/fault"
)

// quota counts SSH sessions, including attempts that are still connecting,
// against the global and the per-user limit in one step (Python:
// QuotaKind.SSH_SESSION of app/quota_manager.py).
type quota struct {
	global, perUser int
	mu              sync.Mutex
	total           int
	users           map[int64]int
}

func newQuota(global, perUser int) *quota {
	return &quota{global: global, perUser: perUser, users: map[int64]int{}}
}

// errSessionLimit is the refusal of a full quota. The Python release sent
// "Maximum number of sessions reached" without a code.
var errSessionLimit = fault.New(fault.Busy, "Maximum number of sessions reached.")

// reserve takes one slot for user and returns its release function, which
// may be called more than once.
func (q *quota) reserve(user int64) (release func(), err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.users[user] >= q.perUser || q.total >= q.global {
		return nil, errSessionLimit
	}
	q.users[user]++
	q.total++
	var once sync.Once
	return func() {
		once.Do(func() {
			q.mu.Lock()
			defer q.mu.Unlock()
			q.total--
			if q.users[user]--; q.users[user] <= 0 {
				delete(q.users, user)
			}
		})
	}, nil
}

func (q *quota) used() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.total
}
