package client

import (
	"context"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
)

// ErrNoExitStatus reports a command that ended without an exit status:
// killed by a signal or its channel closed early. Callers treat its outcome
// as unknown.
var ErrNoExitStatus = errors.New("ssh: command ended without an exit status")

// ErrExecUnconfirmed reports that the exec request was sent but its
// start was not confirmed: the command may have started. Callers that
// must not repeat a command treat its outcome as unknown.
var ErrExecUnconfirmed = errors.New("ssh: exec request sent without a confirmed start")

// maxCommandLen bounds one command line. The remote shell receives it as
// one string; it is fixed text built by WebSSH, or the command of an
// automation step (remotecmd.Shell, up to 8 KiB quoted for sudo).
const maxCommandLen = 64 << 10

// unconfirmedError keeps the text and the fault code of a failed start
// and adds ErrExecUnconfirmed.
type unconfirmedError struct{ err error }

func unconfirmed(err error) error           { return &unconfirmedError{err} }
func (e *unconfirmedError) Error() string   { return e.err.Error() }
func (e *unconfirmedError) Unwrap() []error { return []error{ErrExecUnconfirmed, e.err} }

func checkCommand(command string) error {
	if command == "" || len(command) > maxCommandLen || strings.IndexByte(command, 0) >= 0 {
		return fault.New(fault.InvalidValue, "The remote command is invalid.")
	}
	return nil
}

// CommandShell runs command with a PTY of rows x cols as the interactive
// session instead of the login shell (exec request with a PTY). Closing
// the returned shell leaves the connection open.
func (c *Conn) CommandShell(ctx context.Context, command string, rows, cols int) (Shell, error) {
	if err := checkCommand(command); err != nil {
		return nil, err
	}
	s, err := c.openPTY(ctx, rows, cols, command)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Exec runs command on its own channel without a PTY and returns its exit
// status. stdin, stdout and stderr may be nil; stdin must reach EOF, the
// writers must not block. Opening the channel and starting the command
// are bounded by the handshake timeout; a peer that stalls there, or the
// end of ctx meanwhile, closes the whole connection. After the start the
// end of ctx closes the channel only. Exec does not bound the run time or
// output: internal/ssh/remotecmd does.
func (c *Conn) Exec(ctx context.Context, command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if err := checkCommand(command); err != nil {
		return -1, err
	}
	gctx, disarm := c.guard(ctx)
	s, err := c.client.NewSession()
	if err != nil {
		return -1, setupFail(ctx, gctx, disarm(), err)
	}
	defer func() { _ = s.Close() }()
	s.Stdin, s.Stdout, s.Stderr = stdin, stdout, stderr
	if err := s.Start(command); err != nil {
		return -1, unconfirmed(setupFail(ctx, gctx, disarm(), err))
	}
	if disarm() {
		return -1, unconfirmed(setupFail(ctx, gctx, true, nil))
	}
	// Running is bounded by ctx (internal/ssh/remotecmd); its end closes
	// the channel only, so the connection stays usable for a fallback.
	// Wait returns when the server confirms the close. A server that never
	// does would hold the caller and its quota slot, so after the setup
	// budget the whole connection is closed, as the channel guard does
	// before the start.
	waited := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = s.Close()
		c.closeUnlessDone(waited)
	})
	defer stop()
	err = s.Wait()
	close(waited)
	if ctx.Err() != nil {
		return -1, fail(ctx, RoleTarget, false, ctx.Err())
	}
	if err == nil {
		return 0, nil
	}
	if exit, ok := errors.AsType[*ssh.ExitError](err); ok {
		if exit.Signal() != "" {
			return -1, ErrNoExitStatus
		}
		return exit.ExitStatus(), nil
	}
	if _, ok := errors.AsType[*ssh.ExitMissingError](err); ok {
		return -1, ErrNoExitStatus
	}
	return -1, fail(ctx, RoleTarget, false, err)
}
