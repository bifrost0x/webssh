package client

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"

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
// writers must not block and may still be written to after Exec returned.
//
// Every command has its own end: the end of ctx, or the setup budget
// while the channel opens and the command starts. Either ends this
// command only. Exec returns at once; the channel gets SIGTERM and is
// closed, as paramiko closed it, and a goroutine waits for the server to
// confirm while the connection, and the terminal on it, stay open.
// Channels a server never confirms stay counted against the connection;
// with maxAbandoned of them Exec refuses new commands. Exec does not bound
// the run time or output: internal/ssh/remotecmd does.
func (c *Conn) Exec(ctx context.Context, command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if err := checkCommand(command); err != nil {
		return -1, err
	}
	if err := ctx.Err(); err != nil {
		return -1, fail(ctx, RoleTarget, false, err)
	}
	run, err := c.startExec(command, stdin, stdout, stderr)
	if err != nil {
		return -1, err
	}
	budget := c.setup
	if budget <= 0 {
		budget = DefaultHandshakeTimeout
	}
	setup := time.NewTimer(budget)
	defer setup.Stop()
	select {
	case err := <-run.started:
		if err != nil {
			if run.abandon() {
				return -1, unconfirmed(fail(ctx, RoleTarget, false, err))
			}
			return -1, fail(ctx, RoleTarget, false, err)
		}
	case <-ctx.Done():
		return -1, run.giveUp(fail(ctx, RoleTarget, false, ctx.Err()))
	case <-setup.C:
		return -1, run.giveUp(fail(ctx, RoleTarget, true, context.DeadlineExceeded))
	}
	select {
	case err := <-run.finished:
		return exitOf(ctx, err)
	case <-ctx.Done():
		run.abandon()
		return -1, fail(ctx, RoleTarget, false, ctx.Err())
	}
}

// giveUp abandons a run whose setup did not finish and adds
// ErrExecUnconfirmed when the exec request may have left.
func (r *execRun) giveUp(err error) error {
	if r.abandon() {
		return unconfirmed(err)
	}
	return err
}

func exitOf(ctx context.Context, err error) (int, error) {
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
