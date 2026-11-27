package terminal

import (
	"context"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// FileSession is the SSH connection of a live session as the file area
// uses it: the SFTP subsystem of its source and the directory probe run on
// channels beside the shell.
type FileSession struct {
	Conn *client.Conn
	Host string
	Port int
	User string
	// Name is the display name of the session, if any.
	Name string
	// Tmux is the tmux session the shell runs in, if any.
	Tmux string
}

// FileSession returns the connection of the session id of owner. An
// unknown or foreign session, one that ended and one whose shell offers no
// connection of its own fail with fault.SourceUnavailable.
func (m *Manager) FileSession(owner int64, id string) (FileSession, error) {
	unavailable := fault.New(fault.SourceUnavailable, "")
	s, err := m.lookup(owner, id)
	if err != nil {
		return FileSession{}, unavailable
	}
	conn := client.ConnOf(s.shell)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || conn == nil {
		return FileSession{}, unavailable
	}
	f := FileSession{Conn: conn, Host: s.info.Host, Port: s.info.Port, User: s.info.Username, Name: s.info.DisplayName}
	if s.tmux != nil {
		f.Tmux = s.tmux.name
	}
	return f, nil
}

// Target checks and resolves a connection request like terminal.open
// (saved host, typed target, jump host or SOCKS5 proxy, saved passwords
// with their guard), for connections that are not a terminal (Quick SFTP).
func (m *Manager) Target(ctx context.Context, owner int64, req protocol.OpenTarget) (client.Target, error) {
	return m.resolve(ctx, owner, req)
}

// Interaction asks the user of peer about host keys and banners of a
// connection attempt with the terminal's prompts; requestID correlates
// them (Quick SFTP asks like the terminal, D-22).
func (m *Manager) Interaction(peer protocol.Peer, requestID string) client.Interaction {
	return &interaction{m: m, peer: peer, owner: peer.Principal().UserID, requestID: requestID}
}
