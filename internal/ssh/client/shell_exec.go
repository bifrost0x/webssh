package client

import (
	"context"
	"io"
)

// Exec runs a non-interactive command on the shell's connection, on its
// own channel (Conn.Exec). Capabilities that act on a terminal session
// (server operations, insights, Herdr) reach the connection this way and
// never write to the interactive PTY.
func (s *shell) Exec(ctx context.Context, command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	return s.conn.Exec(ctx, command, stdin, stdout, stderr)
}
