package realtime

import (
	"sync"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// sessionIndex maps browser sessions to their open connections, so that a
// revocation reaches every connection of the session at once (condition
// K6, mandatory).
type sessionIndex struct {
	mu    sync.Mutex
	bySID map[string]map[*Conn]struct{}
}

func newSessionIndex() *sessionIndex {
	return &sessionIndex{bySID: map[string]map[*Conn]struct{}{}}
}

func (x *sessionIndex) add(c *Conn) {
	x.mu.Lock()
	defer x.mu.Unlock()
	sid := c.p.SessionID
	set := x.bySID[sid]
	if set == nil {
		set = map[*Conn]struct{}{}
		x.bySID[sid] = set
	}
	set[c] = struct{}{}
}

func (x *sessionIndex) remove(c *Conn) {
	x.mu.Lock()
	defer x.mu.Unlock()
	sid := c.p.SessionID
	delete(x.bySID[sid], c)
	if len(x.bySID[sid]) == 0 {
		delete(x.bySID, sid)
	}
}

// of returns the connections of a session.
func (x *sessionIndex) of(sessionID string) []*Conn {
	x.mu.Lock()
	defer x.mu.Unlock()
	out := make([]*Conn, 0, len(x.bySID[sessionID]))
	for c := range x.bySID[sessionID] {
		out = append(out, c)
	}
	return out
}

func (x *sessionIndex) all() []*Conn {
	x.mu.Lock()
	defer x.mu.Unlock()
	var out []*Conn
	for _, set := range x.bySID {
		for c := range set {
			out = append(out, c)
		}
	}
	return out
}

// revoke is the Revocations subscriber. It never blocks: closeWith cancels
// the connection's context at once (handlers, terminal output and further
// input stop) and writes the close frame from another goroutine.
func (s *Server) revoke(rev principal.Revocation) {
	for _, c := range s.sessions.of(rev.SessionID) {
		if c.p.UserID != rev.UserID {
			// A session ID belongs to exactly one user; a mismatch is a
			// provider bug. Fail closed and close anyway.
			s.log.Error("realtime revocation names another user for the session", "conn", c.id)
		}
		c.closeWith(protocol.CloseUnauthenticated, closeReason(rev.Reason))
	}
}

// closeReason is the close reason for an ended session: the stable reason
// string of internal/principal, or "session_ended".
func closeReason(r principal.Reason) string {
	if r == "" || len(r) > 100 {
		return "session_ended"
	}
	return string(r)
}

// NotifyUser pushes a server event to every open connection of userID and
// returns how many took it. It never blocks; a connection that is gone or
// too slow is skipped. Capabilities use it for events that belong to an
// account rather than to one request, such as detected host facts.
func (s *Server) NotifyUser(userID int64, typ string, payload any) int {
	sent := 0
	for _, c := range s.sessions.all() {
		if c.p.UserID == userID && c.SendEvent(typ, payload) == nil {
			sent++
		}
	}
	return sent
}

// CloseAll closes every open connection with protocol.CloseMaintenance
// and returns how many it closed. Unlike Shutdown it does not refuse new
// upgrades; the caller keeps them out while it needs to (maintenance mode
// answers every route but the probes with 503). It never blocks.
func (s *Server) CloseAll(reason string) int {
	conns := s.sessions.all()
	for _, c := range conns {
		c.closeWith(protocol.CloseMaintenance, reason)
	}
	return len(conns)
}
