package realtime

import (
	"strconv"
	"sync"
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
		return limitUser
	case c.total >= c.max:
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
