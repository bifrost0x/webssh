package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
)

const maxReadyPending = 64 << 10

var (
	errNotReady   = fault.New(fault.Unavailable, "Gateway target did not confirm readiness")
	errReadyLimit = fault.New(fault.Unavailable, "Gateway readiness output exceeds byte limit")
)

// readyLine watches PTY output for one line equal to the marker.
type readyLine struct {
	marker  []byte
	pending []byte
	ready   bool
}

func (r *readyLine) feed(data []byte) error {
	r.pending = append(r.pending, data...)
	for {
		line, rest, ok := bytes.Cut(r.pending, []byte{'\n'})
		if !ok {
			break
		}
		if bytes.Equal(bytes.TrimSuffix(line, []byte{'\r'}), r.marker) {
			r.ready = true
		}
		r.pending = rest
	}
	if len(r.pending) > maxReadyPending {
		return errReadyLimit
	}
	return nil
}

// Session is the part of *ssh.Session the setup uses; tests replace it.
type Session interface {
	RequestPty(term string, h, w int, modes ssh.TerminalModes) error
	StdinPipe() (io.WriteCloser, error)
	StdoutPipe() (io.Reader, error)
	Start(cmd string) error
	Wait() error
	Close() error
}

// PrepareTerminal proves that the gateway reached the target before any
// terminal, tmux or startup command runs. It opens a PTY session, runs a
// fixed printf of a random nonce, streams everything the gateway prints
// (host-key questions, approval links) to the browser and forwards the
// browser's keystrokes. It succeeds only after the nonce line was seen and
// the command exited with status 0.
func PrepareTerminal(ctx context.Context, newSession func() (Session, error), a *Attempt) error {
	ctx, cancel := context.WithTimeout(ctx, SetupTimeout)
	defer cancel()
	if err := a.StartSetup(); err != nil {
		return err
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("gateway: readiness nonce: %w", err)
	}
	marker := "WEBSSH_READY_" + hex.EncodeToString(nonce)

	s, err := newSession()
	if err != nil {
		return fmt.Errorf("gateway: open setup channel: %w", err)
	}
	// Closing the channel is the cancellation path: it unblocks Wait and
	// the reader below.
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()
	defer func() { _ = s.Close() }()

	if err := s.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		return fmt.Errorf("gateway: request pty: %w", cancelled(ctx, err))
	}
	stdin, err := s.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := s.StdoutPipe()
	if err != nil {
		return err
	}
	// Fixed command and a generated hex nonce only; never user input.
	if err := s.Start(`printf '\n%s\n' ` + marker); err != nil {
		return fmt.Errorf("gateway: start readiness probe: %w", cancelled(ctx, err))
	}

	parser := &readyLine{marker: []byte(marker)}
	var wg sync.WaitGroup
	readErr := make(chan error, 1)
	wg.Go(func() {
		err := pumpOutput(ctx, stdout, a, parser)
		if err != nil {
			_ = s.Close() // a stalled browser or a limit must not leave Wait hanging
		}
		readErr <- err
	})
	inputCtx, stopInput := context.WithCancel(ctx)
	wg.Go(func() { pumpInput(inputCtx, stdin, a) })

	waitErr := s.Wait()
	outErr := <-readErr // EOF follows the exit status, or Close above
	ctxErr := ctx.Err()
	stopInput()
	wg.Wait()

	switch {
	case outErr != nil:
		return cancelled(ctx, outErr)
	case ctxErr != nil:
		return ErrCancelled
	case waitErr != nil:
		if _, ok := errors.AsType[*ssh.ExitError](waitErr); ok {
			return errNotReady
		}
		return fmt.Errorf("gateway: readiness probe: %w", waitErr)
	case !parser.ready:
		return errNotReady
	}
	return nil
}

func pumpOutput(ctx context.Context, r io.Reader, a *Attempt, parser *readyLine) error {
	buf := make([]byte, MaxOutputFrame)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if perr := parser.feed(chunk); perr != nil {
				return perr
			}
			if oerr := a.Output(ctx, chunk); oerr != nil {
				return oerr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return cancelled(ctx, err)
		}
	}
}

func pumpInput(ctx context.Context, w io.Writer, a *Attempt) {
	for {
		data, err := a.NextInput(ctx)
		if err != nil {
			return
		}
		if _, err := w.Write(data); err != nil {
			return
		}
	}
}

func cancelled(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ErrCancelled
	}
	return err
}

// SSHSessions adapts *ssh.Client to the Session factory.
func SSHSessions(c *ssh.Client) func() (Session, error) {
	return func() (Session, error) { return c.NewSession() }
}
