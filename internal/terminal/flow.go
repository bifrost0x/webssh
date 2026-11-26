package terminal

import (
	"context"
	"errors"
	"sync"
	"time"
)

// FlowLimits bound terminal output that was sent but not yet acknowledged
// by the browser (written to xterm). When a limit is reached the session's
// shell is not read, so backpressure reaches the remote host through the
// SSH window instead of filling memory here.
type FlowLimits struct {
	StreamBytes, StreamFrames int // one attached terminal
	ConnBytes, ConnFrames     int // one browser connection (SSH_OUTPUT_MAX_UNACKED_*_PER_SOCKET)
	UserBytes, UserFrames     int // all connections of a user (…_PER_USER)
	GlobalBytes, GlobalFrames int // the process (…_GLOBAL)
	// AckTimeout: an attachment whose oldest frame stays unacknowledged
	// longer is detached with terminal.resync_required
	// (SSH_OUTPUT_ACK_TIMEOUT_SECONDS).
	AckTimeout time.Duration
}

// defaultStreamFrames replaces the polling-era delivery window of 8 events
// per socket by a window per stream (K6).
const defaultStreamFrames = 64

func (l *FlowLimits) defaults() {
	def := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&l.ConnBytes, 512<<10)
	def(&l.ConnFrames, 128)
	def(&l.UserBytes, 4<<20)
	def(&l.UserFrames, 1024)
	def(&l.GlobalBytes, 32<<20)
	def(&l.GlobalFrames, 8192)
	def(&l.StreamBytes, l.ConnBytes)
	def(&l.StreamFrames, min(defaultStreamFrames, l.ConnFrames))
	if l.AckTimeout <= 0 {
		l.AckTimeout = 10 * time.Second
	}
}

// usage is one level of the ledger; refs counts the open credits of a
// connection or user level, which is dropped with its last credit.
type usage struct{ bytes, frames, refs int }

func (u usage) fits(n, maxBytes, maxFrames int) bool {
	// An empty level always admits one frame, so a frame larger than a
	// byte limit cannot deadlock the stream.
	if u.frames == 0 {
		return true
	}
	return u.bytes+n <= maxBytes && u.frames+1 <= maxFrames
}

type inflight struct {
	seq  uint64
	n    int
	sent time.Time
}

// credit is the per-attachment part of the ledger. Its fields are guarded
// by ledger.mu.
type credit struct {
	conn    uint64
	user    int64
	use     usage
	pending []inflight
	wake    chan struct{}
	gone    bool
}

// ledger accounts output in flight on all levels under one lock, so a
// frame is admitted only if every level has room (all or nothing).
//
// The user and process levels are shared: a client that does not
// acknowledge can hold its share until AckTimeout detaches its streams,
// and meanwhile other users' output may wait for room on the process
// level. A detached stream may attach again only after reattachCooldown,
// which bounds how often one connection can take the shared budget.
type ledger struct {
	lim     FlowLimits
	now     func() time.Time
	mu      sync.Mutex
	conns   map[uint64]*usage
	users   map[int64]*usage
	global  usage
	waiters map[*credit]struct{}
}

var errDetached = errors.New("terminal: attachment detached")

func newLedger(lim FlowLimits) *ledger {
	return &ledger{lim: lim, now: time.Now, conns: map[uint64]*usage{}, users: map[int64]*usage{}, waiters: map[*credit]struct{}{}}
}

func (l *ledger) open(conn uint64, user int64) *credit {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conns[conn] == nil {
		l.conns[conn] = &usage{}
	}
	l.conns[conn].refs++
	if l.users[user] == nil {
		l.users[user] = &usage{}
	}
	l.users[user].refs++
	return &credit{conn: conn, user: user, wake: make(chan struct{}, 1)}
}

func (l *ledger) fitsLocked(c *credit, n int) bool {
	lim := l.lim
	return c.use.fits(n, lim.StreamBytes, lim.StreamFrames) &&
		l.conns[c.conn].fits(n, lim.ConnBytes, lim.ConnFrames) &&
		l.users[c.user].fits(n, lim.UserBytes, lim.UserFrames) &&
		l.global.fits(n, lim.GlobalBytes, lim.GlobalFrames)
}

func (l *ledger) levels(c *credit) []*usage {
	return []*usage{&c.use, l.conns[c.conn], l.users[c.user], &l.global}
}

func (l *ledger) addLocked(c *credit, seq uint64, n int, now time.Time) {
	for _, u := range l.levels(c) {
		u.bytes += n
		u.frames++
	}
	c.pending = append(c.pending, inflight{seq: seq, n: n, sent: now})
}

// acquire blocks until frame seq of n bytes fits on every level, the
// attachment is detached, or ctx ends. send, if set, delivers the frame
// under the ledger lock right after the admission: a close (detach) either
// happens before and the frame is not sent, or after and releases it, so
// no frame reaches a freed channel once close returned. send must not
// block; an error from it withdraws the frame.
func (l *ledger) acquire(ctx context.Context, c *credit, seq uint64, n int, send func() error) error {
	for {
		l.mu.Lock()
		if c.gone {
			l.mu.Unlock()
			return errDetached
		}
		if l.fitsLocked(c, n) {
			l.addLocked(c, seq, n, l.now())
			delete(l.waiters, c)
			var err error
			if send != nil {
				if err = send(); err != nil {
					c.pending = c.pending[:len(c.pending)-1]
					l.releaseLocked(c, n)
					l.wakeLocked()
				}
			}
			l.mu.Unlock()
			return err
		}
		l.waiters[c] = struct{}{}
		l.mu.Unlock()
		select {
		case <-c.wake:
		case <-ctx.Done():
			l.mu.Lock()
			delete(l.waiters, c)
			l.mu.Unlock()
			return ctx.Err()
		}
	}
}

// reserveReplay accounts a replay at once and returns the part that is
// sent. The stream level may be exceeded (live output then waits until the
// replay is acknowledged), but the connection, user and process levels
// must have room. When they have room for only the newest frames, the
// oldest are left out and cut reports it: the browser then resets its
// screen. ok is false when not even one frame fits on a busy level.
func (l *ledger) reserveReplay(c *credit, frames []chunk) (sent []chunk, cut, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if c.gone {
		return nil, false, false
	}
	lim := l.lim
	conn, user := l.conns[c.conn], l.users[c.user]
	room := func(u *usage, maxBytes, maxFrames, bytes, n int) bool {
		if u.frames == 0 && n == 1 {
			return true // an empty level admits one frame, as fits does
		}
		return u.bytes+bytes <= maxBytes && u.frames+n <= maxFrames
	}
	start, total := len(frames), 0
	for start > 0 {
		next := total + len(frames[start-1].data)
		n := len(frames) - start + 1
		if !room(conn, lim.ConnBytes, lim.ConnFrames, next, n) ||
			!room(user, lim.UserBytes, lim.UserFrames, next, n) ||
			!room(&l.global, lim.GlobalBytes, lim.GlobalFrames, next, n) {
			break
		}
		start--
		total = next
	}
	if start == len(frames) && len(frames) > 0 {
		return nil, false, false
	}
	now := l.now()
	for _, f := range frames[start:] {
		l.addLocked(c, f.seq, len(f.data), now)
	}
	return frames[start:], start > 0, true
}

// ack releases every frame up to and including seq.
func (l *ledger) ack(c *credit, seq uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	i := 0
	for i < len(c.pending) && c.pending[i].seq <= seq {
		l.releaseLocked(c, c.pending[i].n)
		i++
	}
	if i == 0 {
		return
	}
	c.pending = c.pending[i:]
	l.wakeLocked()
}

func (l *ledger) releaseLocked(c *credit, n int) {
	for _, u := range l.levels(c) {
		u.bytes -= n
		u.frames--
	}
}

// wakeLocked lets every waiting reader re-check; a release on the
// connection, user or process level can unblock other attachments.
func (l *ledger) wakeLocked() {
	for w := range l.waiters {
		select {
		case w.wake <- struct{}{}:
		default:
		}
	}
}

// close releases everything the attachment holds and wakes its reader.
func (l *ledger) close(c *credit) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if c.gone {
		return
	}
	c.gone = true
	for _, p := range c.pending {
		l.releaseLocked(c, p.n)
	}
	c.pending = nil
	delete(l.waiters, c)
	if u := l.conns[c.conn]; u != nil {
		if u.refs--; u.refs <= 0 {
			delete(l.conns, c.conn)
		}
	}
	if u := l.users[c.user]; u != nil {
		if u.refs--; u.refs <= 0 {
			delete(l.users, c.user)
		}
	}
	select {
	case c.wake <- struct{}{}:
	default:
	}
	l.wakeLocked()
}

// stale reports whether the oldest unacknowledged frame is overdue.
func (l *ledger) stale(c *credit, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return !c.gone && len(c.pending) > 0 && now.Sub(c.pending[0].sent) >= l.lim.AckTimeout
}

// inFlight is the process level, for diagnostics and tests.
func (l *ledger) inFlight() (bytes, frames int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.global.bytes, l.global.frames
}
