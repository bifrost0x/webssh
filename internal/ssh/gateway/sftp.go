package gateway

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/crypto/ssh"
)

// OpenWithPrompts is the Quick SFTP variant of the setup: it keeps a
// temporary PTY channel open so the gateway can show its prompts while
// open (normally the SFTP subsystem on a second channel) runs. The PTY is
// closed before returning. Targets must allow two channels during setup,
// as documented for the Python version.
func OpenWithPrompts[T any](ctx context.Context, newSession func() (Session, error), a *Attempt,
	open func(context.Context) (T, error)) (T, error) {
	var zero T
	ctx, cancel := context.WithTimeout(ctx, SetupTimeout)
	defer cancel()
	if err := a.StartSetup(); err != nil {
		return zero, err
	}

	pty, err := newSession()
	if err != nil {
		return zero, fmt.Errorf("gateway: open prompt channel: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = pty.Close() })
	defer stop()
	if err := pty.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		_ = pty.Close()
		return zero, fmt.Errorf("gateway: request pty: %w", cancelled(ctx, err))
	}
	stdin, err := pty.StdinPipe()
	if err != nil {
		_ = pty.Close()
		return zero, err
	}
	stdout, err := pty.StdoutPipe()
	if err != nil {
		_ = pty.Close()
		return zero, err
	}

	pumpCtx, stopPump := context.WithCancel(ctx)
	var wg sync.WaitGroup
	pumpErr := make(chan error, 1)
	wg.Go(func() {
		err := pumpOutput(pumpCtx, stdout, a, &readyLine{})
		if err != nil && pumpCtx.Err() == nil {
			cancel() // a failed prompt stream fails the whole attempt
		}
		pumpErr <- err
	})
	wg.Go(func() { pumpInput(pumpCtx, stdin, a) })

	result, openErr := open(ctx)
	stopPump()
	_ = pty.Close()
	wg.Wait()
	if err := <-pumpErr; openErr == nil && err != nil && !errors.Is(err, ErrCancelled) {
		openErr = err
	}
	if openErr != nil {
		return zero, cancelled(ctx, openErr)
	}
	return result, nil
}
