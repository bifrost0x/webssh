package terminal

import (
	"math"
	"sync"
	"time"
)

// InputLimits are the token buckets of keyboard and paste input in bytes
// and bytes per second (SSH_INPUT_* with the defaults of the Python
// release), the largest input frame and the queue towards the shell.
type InputLimits struct {
	MaxFrameBytes             int // SSH_INPUT_MAX_BYTES, 128 KiB
	SessionRate, SessionBurst float64
	UserRate, UserBurst       float64
	// QueueBytes bounds input accepted but not yet written to the shell
	// (256 KiB). A full queue refuses input with ssh_input_backpressure.
	QueueBytes int
}

func (l *InputLimits) defaults() {
	if l.MaxFrameBytes <= 0 {
		l.MaxFrameBytes = 128 << 10
	}
	defF := func(v *float64, d float64) {
		if *v <= 0 {
			*v = d
		}
	}
	defF(&l.SessionRate, 256<<10)
	defF(&l.SessionBurst, 256<<10)
	defF(&l.UserRate, 512<<10)
	defF(&l.UserBurst, 512<<10)
	if l.QueueBytes <= 0 {
		l.QueueBytes = max(256<<10, l.MaxFrameBytes)
	}
}

type bucket struct {
	tokens float64
	last   time.Time
}

func (b *bucket) refill(now time.Time, rate, burst float64) {
	if b.last.IsZero() {
		b.tokens, b.last = burst, now
		return
	}
	elapsed := max(0, now.Sub(b.last).Seconds())
	b.tokens = math.Min(burst, b.tokens+elapsed*rate)
	b.last = now
}

// maxBuckets triggers the removal of full, unused buckets, as in Python.
const maxBuckets = 1024

// inputBudget holds one bucket per session and one per user. A refused
// frame costs nothing, as in the Python release.
type inputBudget struct {
	lim      InputLimits
	mu       sync.Mutex
	sessions map[string]*bucket
	users    map[int64]*bucket
}

func newInputBudget(lim InputLimits) *inputBudget {
	return &inputBudget{lim: lim, sessions: map[string]*bucket{}, users: map[int64]*bucket{}}
}

// allow takes n bytes from both buckets or reports how long to wait.
func (b *inputBudget) allow(user int64, session string, n int, now time.Time) (bool, time.Duration) {
	if n <= 0 {
		return true, 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.sessions[session]
	if s == nil {
		s = &bucket{}
		b.sessions[session] = s
	}
	u := b.users[user]
	if u == nil {
		u = &bucket{}
		b.users[user] = u
	}
	s.refill(now, b.lim.SessionRate, b.lim.SessionBurst)
	u.refill(now, b.lim.UserRate, b.lim.UserBurst)
	need := float64(n)
	wait := math.Max(math.Max(0, need-s.tokens)/b.lim.SessionRate, math.Max(0, need-u.tokens)/b.lim.UserRate)
	if wait > 0 {
		return false, time.Duration(max(int64(math.Ceil(wait*1000)), 1)) * time.Millisecond
	}
	s.tokens -= need
	u.tokens -= need
	if len(b.users) > maxBuckets {
		b.pruneUsers(now)
	}
	return true, 0
}

// pruneUsers drops user buckets that have refilled completely.
func (b *inputBudget) pruneUsers(now time.Time) {
	idle := max(time.Minute, time.Duration(2*b.lim.UserBurst/b.lim.UserRate*float64(time.Second)))
	for id, u := range b.users {
		if now.Sub(u.last) >= idle {
			delete(b.users, id)
		}
	}
}

func (b *inputBudget) forget(session string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.sessions, session)
}
