// Package remotecmd runs one bounded command on a connected host: a fixed
// command line, optional data on stdin, a time limit and a cap on the
// output kept. It is the only way capabilities run non-interactive
// commands over SSH.
//
// Command lines are built by WebSSH from fixed text. Values that come from
// users or from stored data travel on stdin, or, where a program only takes
// them as an argument, as a Word: a token from a small character set that
// no shell treats specially inside single quotes. The one exception is
// Shell, the command of an automation step, which the user wrote for the
// login shell of the target account.
package remotecmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
)

// Executor runs a command on a connection; *client.Conn provides it.
type Executor interface {
	Exec(ctx context.Context, command string, stdin io.Reader, stdout, stderr io.Writer) (int, error)
}

// Limits of a command.
const (
	MaxLine          = 4 << 10
	MaxStdin         = 1 << 20
	DefaultTimeout   = 10 * time.Second
	DefaultMaxOutput = 64 << 10
	MaxOutput        = 4 << 20
	maxStderr        = 4 << 10
	maxWord          = 256
)

// Command is one command to run.
type Command struct {
	// Line is the command line, fixed text of the caller with Words only.
	Line string
	// Stdin is sent to the command, then EOF.
	Stdin []byte
	// Timeout bounds the whole run (DefaultTimeout when zero).
	Timeout time.Duration
	// MaxOutput is the number of stdout bytes kept (DefaultMaxOutput when
	// zero, at most MaxOutput). More output is read and discarded.
	MaxOutput int
	// MaxStderr is the number of stderr bytes kept (4 KiB when zero, at
	// most MaxOutput).
	MaxStderr int

	// shell marks a line built by Shell: a user command for the login
	// shell, which may hold line breaks and be longer than MaxLine.
	shell bool
}

// Result is the outcome of a command that reported an exit status.
type Result struct {
	ExitStatus int
	Stdout     []byte
	// Stderr keeps the first MaxStderr bytes; it is remote text, never
	// shown or logged as is.
	Stderr          []byte
	Truncated       bool // stdout exceeded MaxOutput
	StderrTruncated bool // stderr exceeded MaxStderr
}

var errInvalid = fault.New(fault.InvalidValue, "The remote command is invalid.")

func (c *Command) check() error {
	if c.shell {
		// A Shell line: line breaks and the length are the command's own.
		if c.Line == "" || len(c.Line) > maxShellLine || strings.IndexByte(c.Line, 0) >= 0 {
			return errInvalid
		}
	} else if c.Line == "" || len(c.Line) > MaxLine ||
		// One line only: a newline would start a second command.
		strings.ContainsFunc(c.Line, func(r rune) bool { return r < 0x20 && r != '\t' || r == 0x7f }) {
		return errInvalid
	}
	switch {
	case len(c.Stdin) > MaxStdin:
		return errInvalid
	case c.Timeout < 0 || c.MaxOutput < 0 || c.MaxOutput > MaxOutput:
		return errInvalid
	case c.MaxStderr < 0 || c.MaxStderr > MaxOutput:
		return errInvalid
	}
	if c.MaxStderr == 0 {
		c.MaxStderr = maxStderr
	}
	if c.Timeout == 0 {
		c.Timeout = DefaultTimeout
	}
	if c.MaxOutput == 0 {
		c.MaxOutput = DefaultMaxOutput
	}
	return nil
}

// Run runs c on the connection. It fails with fault.Timeout when the time
// limit ends the command, with the executor's error when the channel
// fails, and passes client.ErrNoExitStatus through for a command without
// an exit status. On a timeout the result holds the output read until
// then (ExitStatus -1), for collectors that accept a partial sample.
func Run(ctx context.Context, on Executor, c Command) (Result, error) {
	if err := c.check(); err != nil {
		return Result{}, err
	}
	rctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	stdout := &capped{max: c.MaxOutput}
	stderr := &capped{max: c.MaxStderr}
	var stdin io.Reader
	if len(c.Stdin) > 0 {
		stdin = bytes.NewReader(c.Stdin)
	}
	status, err := on.Exec(rctx, c.Line, stdin, stdout, stderr)
	if err != nil {
		if ctx.Err() == nil && errors.Is(rctx.Err(), context.DeadlineExceeded) {
			partial := Result{ExitStatus: -1, Stdout: stdout.bytes(), Stderr: stderr.bytes(), Truncated: stdout.isOver(), StderrTruncated: stderr.isOver()}
			return partial, fault.Wrap(fault.Timeout, err, "The remote command timed out.")
		}
		return Result{}, err
	}
	return Result{ExitStatus: status, Stdout: stdout.bytes(), Stderr: stderr.bytes(), Truncated: stdout.isOver(), StderrTruncated: stderr.isOver()}, nil
}

// capped keeps the first max bytes and accepts everything, so the remote
// side is drained and never blocks on a full window. The executor may
// still write after a timeout returned, so access is locked.
type capped struct {
	mu   sync.Mutex
	max  int
	buf  bytes.Buffer
	over bool
}

func (w *capped) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	room := w.max - w.buf.Len()
	if len(p) > room {
		w.over = true
		w.buf.Write(p[:room])
	} else {
		w.buf.Write(p)
	}
	return len(p), nil
}

func (w *capped) bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return bytes.Clone(w.buf.Bytes())
}

func (w *capped) isOver() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.over
}

// Word quotes a token for a command line. It accepts 1 to 256 bytes of
// ASCII letters, digits and _ - . , : / = @ % +, none of which has a
// meaning inside single quotes in sh, bash, zsh, fish or csh, and returns
// the token in single quotes. Anything else is refused: such values go on
// stdin.
func Word(s string) (string, error) {
	if s == "" || len(s) > maxWord {
		return "", errInvalid
	}
	for i := range len(s) {
		if !wordByte(s[i]) {
			return "", errInvalid
		}
	}
	return "'" + s + "'", nil
}

// Inert reports whether every byte of s is in the alphabet of Word, so s
// has no meaning to sh, bash, zsh, fish or csh inside single quotes.
// Outside quotes such a token is inert as well when it starts with a
// letter or a digit (no "=" expansion in zsh, no "~", no option); callers
// that write a token without quotes check that themselves.
func Inert(s string) bool {
	for i := range len(s) {
		if !wordByte(s[i]) {
			return false
		}
	}
	return s != ""
}

func wordByte(b byte) bool {
	switch {
	case 'a' <= b && b <= 'z', 'A' <= b && b <= 'Z', '0' <= b && b <= '9':
		return true
	}
	return strings.IndexByte("_-.,:/=@%+", b) >= 0
}
