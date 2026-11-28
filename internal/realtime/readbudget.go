package realtime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// Incoming messages are read in two steps. Up to the configured
// ReadLimit (a binary input frame, every ordinary request) a message is
// read without further accounting. A larger message, which only a few
// routes accept (the editor save), first reserves the rest of the read
// limit from a budget shared by all connections and from the share of
// its account; without that reservation within readBudgetWait the
// connection is closed with 1013 and the page reconnects. The read limit
// itself stays the largest payload of any route, so without the budget
// every connection of every account could make the server hold one such
// message at a time, also for types whose own limit is 64 bytes.
const (
	// DefaultReadBudget is the least global budget for large messages.
	DefaultReadBudget = 256 << 20
	readBudgetWait    = 5 * time.Second
)

var errReadBusy = errors.New("realtime: no read budget for a large message")

// readBudget counts the bytes reserved for large messages in total and
// per account.
type readBudget struct {
	mu      sync.Mutex
	free    int64
	perUser int64
	users   map[int64]int64
	changed chan struct{}
}

// readBudgetFor is the budget of an endpoint whose largest message is
// readLimit: by default two such messages per account and the larger of
// DefaultReadBudget and two such messages in total.
func readBudgetFor(cfg Config, readLimit int64) *readBudget {
	total, perUser := cfg.ReadBudget, cfg.ReadBudgetPerUser
	if perUser <= 0 {
		perUser = 2 * readLimit
	}
	if total <= 0 {
		total = max(DefaultReadBudget, 2*readLimit)
	}
	return newReadBudget(total, perUser)
}

func newReadBudget(total, perUser int64) *readBudget {
	return &readBudget{free: total, perUser: perUser, users: map[int64]int64{}, changed: make(chan struct{})}
}

// acquire reserves n bytes for user, waiting at most wait or until ctx
// ends.
func (b *readBudget) acquire(ctx context.Context, user, n int64, wait time.Duration) bool {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		changed, ok := b.take(user, n)
		if ok {
			return true
		}
		select {
		case <-changed:
		case <-timer.C:
			return false
		case <-ctx.Done():
			return false
		}
	}
}

func (b *readBudget) take(user, n int64) (<-chan struct{}, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.free >= n && b.users[user]+n <= b.perUser {
		b.free -= n
		b.users[user] += n
		return nil, true
	}
	return b.changed, false
}

func (b *readBudget) release(user, n int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.free += n
	if b.users[user] -= n; b.users[user] <= 0 {
		delete(b.users, user)
	}
	close(b.changed)
	b.changed = make(chan struct{})
}

// readMessage reads the next message. The returned release gives back a
// reservation for a large message; the caller runs it once the message is
// no longer held (after its handler returned).
func (c *Conn) readMessage() (websocket.MessageType, []byte, func(), error) {
	typ, r, err := c.ws.Reader(c.io)
	if err != nil {
		return 0, nil, nil, err
	}
	free := c.srv.cfg.ReadLimit
	var buf bytes.Buffer
	if _, err := io.CopyN(&buf, r, free); errors.Is(err, io.EOF) {
		return typ, buf.Bytes(), func() {}, nil
	} else if err != nil {
		return 0, nil, nil, err
	}
	// Beyond ReadLimit. Without a larger route the library's read limit
	// ends the message with 1009 on the next read.
	release := func() {}
	if n := c.srv.readLimit - free; n > 0 {
		if !c.srv.reads.acquire(c.ctx, c.p.UserID, n, c.srv.readWait) {
			return 0, nil, nil, errReadBusy
		}
		release = sync.OnceFunc(func() { c.srv.reads.release(c.p.UserID, n) })
	}
	if _, err := buf.ReadFrom(r); err != nil {
		release()
		return 0, nil, nil, err
	}
	return typ, buf.Bytes(), release, nil
}

// used returns the bytes user holds.
func (b *readBudget) used(user int64) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.users[user]
}
