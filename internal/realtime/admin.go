package realtime

import (
	"crypto/rand"
	"encoding/base64"
	"slices"
	"time"

	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// The administration's view of the open connections (C-AOPS-06): the
// instance status lists them and ends a single one. The ids are those the
// page learns in hello; the administration shows only their reference.

// closeAdminDisconnect is the close reason of a connection an
// administrator ended. The page treats the 4003 close as final, as
// Socket.IO treated a server-side disconnect, and does not reconnect.
const closeAdminDisconnect = "disconnected_by_administrator"

// newConnectionID returns 20 random characters of base64url, the size of
// an Engine.IO sid.
func newConnectionID() string {
	var b [15]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// OpenConnection is one open realtime connection.
type OpenConnection struct {
	ID     string
	UserID int64
	Opened time.Time
}

// OpenConnections lists the open connections, oldest first.
func (s *Server) OpenConnections() []OpenConnection {
	all := s.sessions.all()
	out := make([]OpenConnection, 0, len(all))
	for _, c := range all {
		if c.ctx != nil && c.ctx.Err() != nil {
			continue
		}
		out = append(out, OpenConnection{ID: c.sid, UserID: c.p.UserID, Opened: c.opened})
	}
	slices.SortStableFunc(out, func(a, b OpenConnection) int { return a.Opened.Compare(b.Opened) })
	return out
}

// DisconnectConnection closes the open connection id and reports whether
// it was still open. The close cancels the connection's work at once.
func (s *Server) DisconnectConnection(id string) bool {
	for _, c := range s.sessions.all() {
		if c.sid == id {
			if c.ctx != nil && c.ctx.Err() != nil {
				return false
			}
			c.closeWith(protocol.CloseUnauthenticated, closeAdminDisconnect)
			return true
		}
	}
	return false
}

// Capacity is the connection capacity and the refusals since the start.
type Capacity struct {
	Open, Max, MaxPerUser         int
	RefusedServer, RefusedPerUser int
}

// Capacity returns the connection capacity.
func (s *Server) Capacity() Capacity {
	c := s.cap
	c.mu.Lock()
	defer c.mu.Unlock()
	return Capacity{Open: c.total, Max: c.max, MaxPerUser: c.perUser, RefusedServer: c.refusedServer, RefusedPerUser: c.refusedUser}
}
