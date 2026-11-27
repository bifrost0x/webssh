package terminal

import (
	"context"
	"io"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/ssh/remotecmd"
)

// Live is a connected terminal session as the capabilities that act on it
// see it: server operations, session insights, the runtime inventory and
// Herdr (internal/hostops through cmd/webssh). Exec runs non-interactive
// commands on the session's own SSH connection, on a separate channel,
// never through the PTY. Done is closed when the session ends; it is also
// the identity of the session, so a caller can tell a replacement with the
// same ID from the session it checked.
type Live struct {
	Exec      remotecmd.Executor
	Host      string
	Port      int
	Username  string
	ProfileID string
	// Herdr is the Herdr overview granted when the session connected;
	// UseHerdr says the session runs the Herdr client.
	Herdr    bool
	UseHerdr bool
	Done     <-chan struct{}
}

// Live returns the connected session id of owner. Sessions of other users,
// sessions that ended and sessions whose connection cannot run commands
// (test fixtures) are reported as missing (ok false).
func (m *Manager) Live(owner int64, id string) (Live, bool) {
	s, err := m.lookup(owner, id)
	if err != nil {
		return Live{}, false
	}
	info, open := s.snapshot()
	exec, canExec := s.shell.(remotecmd.Executor)
	if !open || !canExec {
		return Live{}, false
	}
	return Live{
		Exec: exec, Host: info.Host, Port: info.Port, Username: info.Username, ProfileID: info.ProfileID,
		Herdr: info.Herdr, UseHerdr: info.UseHerdr, Done: s.done,
	}, true
}

// errNoExec answers a command on a connection that cannot run one.
var errNoExec = fault.New(fault.Unavailable, "")

// Exec runs a command on the connection of a session that owns it
// (persistent sessions and Herdr), on a separate channel.
func (s ownedShell) Exec(ctx context.Context, command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	exec, ok := s.host.(remotecmd.Executor)
	if !ok {
		return -1, errNoExec
	}
	return exec.Exec(ctx, command, stdin, stdout, stderr)
}

// Exec runs a command on the connection (remotecmd.Executor).
func (h connHost) Exec(ctx context.Context, command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	return h.c.Exec(ctx, command, stdin, stdout, stderr)
}
