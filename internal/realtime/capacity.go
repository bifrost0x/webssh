package realtime

import (
	"net/http"
	"strconv"
	"sync"

	"github.com/coder/websocket"

	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// capacity bounds open connections in total and per user. It is a plain
// resource and abuse limit; the Python release coupled it to its thread
// budget (W-035).
type capacity struct {
	mu      sync.Mutex
	max     int
	perUser int
	total   int
	users   map[int64]int
	// refused counts the connections each limit refused since the start.
	refusedServer, refusedUser int
}

// limitHit says which limit refused a connection.
type limitHit int

const (
	limitNone limitHit = iota
	limitUser
	limitServer
)

func newCapacity(maxConns, perUser int) *capacity {
	return &capacity{max: maxConns, perUser: perUser, users: map[int64]int{}}
}

// acquire reserves a slot for user or reports the limit that refused it.
func (c *capacity) acquire(user int64) limitHit {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.users[user] >= c.perUser:
		c.refusedUser++
		return limitUser
	case c.total >= c.max:
		c.refusedServer++
		return limitServer
	}
	c.total++
	c.users[user]++
	return limitNone
}

func (c *capacity) release(user int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total--
	if c.users[user]--; c.users[user] <= 0 {
		delete(c.users, user)
	}
}

func (c *capacity) open() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total
}

// limitReason is the close reason of a refused connection. The prefix is
// stable for the browser to match; the rest is readable as is. Both fit
// the 123 bytes a close reason may have.
func (c *capacity) limitReason(hit limitHit) string {
	if hit == limitUser {
		return "connection_limit_user: at most " + strconv.Itoa(c.perUser) +
			" realtime connections per user are open; close a tab or window and reload"
	}
	return "connection_limit_server: the server has reached its limit of " + strconv.Itoa(c.max) +
		" realtime connections; try again later"
}

// refuseOverLimit tells the page why it gets no connection. Python
// refused at the handshake and the browser only saw a transport error
// (baseline). Here the upgrade is accepted and closed at once with 1013
// "try again later" and a readable reason; the number of such short-lived
// connections is bounded by RejectSlots, beyond which plain 503 is sent.
func (s *Server) refuseOverLimit(w http.ResponseWriter, r *http.Request, hit limitHit) {
	reason := s.cap.limitReason(hit)
	s.log.Warn("realtime connection refused at the connection limit", "per_user", hit == limitUser)
	select {
	case s.rejectSlots <- struct{}{}:
		defer func() { <-s.rejectSlots }()
	default:
		w.Header().Set("Retry-After", "5")
		http.Error(w, reason, http.StatusServiceUnavailable)
		return
	}
	// Browsers fail a handshake that does not echo an offered
	// subprotocol, and the page would see 1006 instead of the reason.
	var offer []string
	if v := pickVersion(r); v > 0 {
		offer = []string{protocol.Subprotocol(v)}
	}
	ws, raw, err := upgrade(w, r, offer)
	if err != nil {
		return
	}
	ws.SetReadLimit(1024)
	closeBounded(ws, raw, websocket.StatusTryAgainLater, reason)
}
