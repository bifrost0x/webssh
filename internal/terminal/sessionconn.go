package terminal

import (
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// SessionConn is the SSH connection of a live terminal session, for the
// channels other capabilities open beside the shell without touching it:
// the SFTP subsystem of the session's file source, the samples of the
// session insights and the Herdr overview. The connection belongs to the
// session; callers never close it, and every channel they open ends with
// the session at the latest (Done).
type SessionConn struct {
	Conn *client.Conn
	// Done is closed when the session ends.
	Done <-chan struct{}
	// ProfileID is the saved host the session was opened from, "" for a
	// connection typed by hand.
	ProfileID string
	Host      string
	Port      int
	Username  string
	// Herdr and UseHerdr are the session's Herdr flags.
	Herdr, UseHerdr bool
}

// SessionConn returns the connection of owner's live session id. Every
// other case, including another user's session and a session that runs
// without a connection of its own, is not_found, so a caller cannot tell
// foreign sessions from missing ones.
func (m *Manager) SessionConn(owner int64, id string) (SessionConn, error) {
	s, err := m.lookup(owner, id)
	if err != nil {
		return SessionConn{}, err
	}
	info, live := s.snapshot()
	if !live || s.host == nil || s.host.sshConn() == nil {
		return SessionConn{}, fault.New(fault.NotFound, "Session not found.")
	}
	return SessionConn{
		Conn: s.host.sshConn(), Done: s.done, ProfileID: info.ProfileID,
		Host: info.Host, Port: info.Port, Username: info.Username, Herdr: info.Herdr, UseHerdr: info.UseHerdr,
	}, nil
}
