package terminal

import (
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
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
	// Name is the display name of the session, if any; Tmux the tmux
	// session the shell runs in, if any (the file source and the directory
	// probe of the session).
	Name string
	Tmux string
	// InputIdle reports, at the moment of the call, whether the shell shows
	// a prompt nobody typed into (input_idle of the session directory).
	InputIdle func() bool
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
	sc := SessionConn{
		Conn: s.host.sshConn(), Done: s.done, ProfileID: info.ProfileID,
		Host: info.Host, Port: info.Port, Username: info.Username, Herdr: info.Herdr, UseHerdr: info.UseHerdr,
		Name: info.DisplayName, InputIdle: s.InputIdle,
	}
	if s.tmux != nil {
		sc.Tmux = s.tmux.name
	}
	return sc, nil
}

// FileSources describes the sftp-session source of owner p's live session
// for the page (SessionInfo.FileSource, the file_source member of
// ssh_connected and ssh_session_restored). info is the session's current
// description; nil means the session has no source to offer.
type FileSources func(p principal.Principal, info protocol.SessionInfo) *protocol.FileSource

// SetFileSources sets the provider of SessionInfo.FileSource. The
// composition root calls it once while wiring, before connections are
// served; without a provider the member stays absent.
func (m *Manager) SetFileSources(f FileSources) { m.fileSources = f }

// withFileSource adds the session's file source to info for p.
func (m *Manager) withFileSource(p principal.Principal, info protocol.SessionInfo) protocol.SessionInfo {
	if m.fileSources != nil {
		info.FileSource = m.fileSources(p, info)
	}
	return info
}
