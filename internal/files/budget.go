package files

import (
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
)

// byteBudget is a per-user token bucket of bytes per minute: the file
// request budget (FILE_CONTROL_BYTES_PER_MINUTE) and the editor body
// budget (EDITOR_SAVE_BYTES_PER_MINUTE) of the Python release. A refused
// charge empties the bucket, so repeated oversized requests cost as much
// as accepted ones.
type byteBudget struct {
	perMinute float64
	now       func() time.Time

	mu    sync.Mutex
	users map[int64]*bucket
}

type bucket struct {
	available float64
	at        time.Time
}

// idleBuckets is the number of users above which full buckets are
// dropped, so the map stays as small as the set of active users.
const idleBuckets = 1024

func newByteBudget(perMinute int64, now func() time.Time) *byteBudget {
	return &byteBudget{perMinute: float64(perMinute), now: now, users: map[int64]*bucket{}}
}

// charge takes n bytes from the user's bucket or fails with
// fault.RateLimited and the time until n bytes are available again.
func (b *byteBudget) charge(userID int64, n int64) error {
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.users) > idleBuckets {
		b.pruneLocked(now)
	}
	u, ok := b.users[userID]
	if !ok {
		u = &bucket{available: b.perMinute, at: now}
		b.users[userID] = u
	}
	u.available = min(b.perMinute, u.available+now.Sub(u.at).Minutes()*b.perMinute)
	u.at = now
	need := float64(n)
	if need <= u.available {
		u.available -= need
		return nil
	}
	u.available = 0
	e := fault.New(fault.RateLimited, "Too many file requests. Try again in a moment.")
	e.RetryAfter = time.Duration(min(need, b.perMinute) / b.perMinute * float64(time.Minute))
	return e
}

func (b *byteBudget) pruneLocked(now time.Time) {
	for id, u := range b.users {
		if u.available+now.Sub(u.at).Minutes()*b.perMinute >= b.perMinute {
			delete(b.users, id)
		}
	}
}
