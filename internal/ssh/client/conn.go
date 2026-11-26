package client

import (
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
)

// Conn is an authenticated connection to the target with the jump-host
// clients it runs through. Closing it closes the whole chain.
type Conn struct {
	client *ssh.Client
	chain  []*ssh.Client
	// setup bounds opening a channel and its requests (HandshakeTimeout).
	setup time.Duration
	once  sync.Once
	done  chan struct{}
	wg    sync.WaitGroup
}

func newConn(chain []*ssh.Client, keepalive, setup time.Duration) *Conn {
	c := &Conn{client: chain[len(chain)-1], chain: chain, setup: setup, done: make(chan struct{})}
	if keepalive > 0 {
		for _, client := range chain {
			c.wg.Go(func() { c.keepalive(client, keepalive) })
		}
	}
	return c
}

// Close closes the target first, then each jump host, and waits for the
// keepalive goroutines.
func (c *Conn) Close() error {
	var errs []error
	c.once.Do(func() {
		close(c.done)
		for _, v := range slices.Backward(c.chain) {
			if err := v.Close(); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
				errs = append(errs, err)
			}
		}
		c.wg.Wait()
	})
	return errors.Join(errs...)
}

// Done is closed when Close was called.
func (c *Conn) Done() <-chan struct{} { return c.done }

// guard closes the whole connection when ctx ends or the setup budget runs
// out before disarm is called. x/crypto/ssh waits for the answer to a
// channel open or a channel request without a context, so a peer that
// accepts the login and answers keepalives but never confirms a channel
// would hold the caller, and its quota slot, forever. Closing the
// transport is the only way to end that wait. The connection belongs to
// one terminal session, so closing it affects no one else.
//
// disarm reports whether the guard fired; its context tells why.
func (c *Conn) guard(ctx context.Context) (gctx context.Context, disarm func() (fired bool)) {
	budget := c.setup
	if budget <= 0 {
		budget = DefaultHandshakeTimeout
	}
	gctx, cancel := context.WithTimeout(ctx, budget)
	stop := context.AfterFunc(gctx, func() { _ = c.Close() })
	return gctx, func() bool {
		fired := !stop()
		cancel()
		return fired
	}
}

// closeUnlessDone closes the connection when done is not closed within
// the setup budget. It blocks until one of both happens.
func (c *Conn) closeUnlessDone(done <-chan struct{}) {
	budget := c.setup
	if budget <= 0 {
		budget = DefaultHandshakeTimeout
	}
	t := time.NewTimer(budget)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
		_ = c.Close()
	case <-c.done:
	}
}

// setupFail classifies a failed channel setup. A fired guard is reported
// as cancelled or timed out, not as the transport error it caused; gctx
// keeps the reason it ended with.
func setupFail(ctx, gctx context.Context, fired bool, err error) error {
	if fired {
		return fail(gctx, RoleTarget, false, gctx.Err())
	}
	return fail(ctx, RoleTarget, false, err)
}

// keepalive sends a request every interval and closes the chain when the
// peer does not answer within one interval. paramiko sent keepalives
// without expecting an answer, so dead peers went unnoticed.
func (c *Conn) keepalive(client *ssh.Client, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
		}
		answered := make(chan error, 1)
		go func() {
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			answered <- err
		}()
		timer := time.NewTimer(interval)
		select {
		case <-c.done:
			timer.Stop()
			return
		case err := <-answered:
			timer.Stop()
			if err == nil {
				continue
			}
		case <-timer.C:
		}
		// Close from another goroutine: Close waits for this one.
		go func() { _ = c.Close() }()
		return
	}
}

// PTY limits; the terminal clamps sizes before it asks.
const maxPTYSize = 10000

// shell is the Shell of one session. A goroutine waits for the remote
// end from the start, so Close can tell whether the server confirmed it.
type shell struct {
	session   *ssh.Session
	stdin     io.WriteCloser
	stdout    io.Reader
	conn      *Conn
	closeConn *Conn
	once      sync.Once
	exited    chan struct{}
	waitErr   error
}

// Shell starts an interactive login shell with a PTY of rows x cols.
// Closing the shell leaves the connection open.
func (c *Conn) Shell(ctx context.Context, rows, cols int) (Shell, error) {
	s, err := c.openShell(ctx, rows, cols)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (c *Conn) openShell(ctx context.Context, rows, cols int) (*shell, error) {
	return c.openPTY(ctx, rows, cols, "")
}

// openPTY starts command, or the login shell for "", with a PTY.
func (c *Conn) openPTY(ctx context.Context, rows, cols int, command string) (*shell, error) {
	if rows < 1 || cols < 1 || rows > maxPTYSize || cols > maxPTYSize {
		return nil, fault.New(fault.InvalidValue, "The terminal size is out of range.")
	}
	gctx, disarm := c.guard(ctx)
	s, err := c.client.NewSession()
	if err != nil {
		return nil, setupFail(ctx, gctx, disarm(), err)
	}
	failWith := func(err error) (*shell, error) {
		fired := disarm()
		_ = s.Close()
		return nil, setupFail(ctx, gctx, fired, err)
	}
	stdin, err := s.StdinPipe()
	if err != nil {
		return failWith(err)
	}
	stdout, err := s.StdoutPipe()
	if err != nil {
		return failWith(err)
	}
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 38400, ssh.TTY_OP_OSPEED: 38400}
	if err := s.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		return failWith(err)
	}
	if command == "" {
		err = s.Shell()
	} else {
		err = s.Start(command)
	}
	if err != nil {
		return failWith(err)
	}
	if disarm() {
		_ = s.Close()
		return nil, setupFail(ctx, gctx, true, nil)
	}
	sh := &shell{session: s, stdin: stdin, stdout: stdout, conn: c, exited: make(chan struct{})}
	go func() {
		sh.waitErr = s.Wait()
		close(sh.exited)
	}()
	return sh, nil
}

func (s *shell) Read(p []byte) (int, error)  { return s.stdout.Read(p) }
func (s *shell) Write(p []byte) (int, error) { return s.stdin.Write(p) }

// Resize sends a window-change request.
func (s *shell) Resize(rows, cols int) error {
	if rows < 1 || cols < 1 || rows > maxPTYSize || cols > maxPTYSize {
		return fault.New(fault.InvalidValue, "The terminal size is out of range.")
	}
	return s.session.WindowChange(rows, cols)
}

// Wait returns when the remote shell ends.
func (s *shell) Wait() error {
	<-s.exited
	return s.waitErr
}

// Close ends the session and, for a shell from OpenShell, the connection.
// A shell on a connection that stays open (Shell, CommandShell) closes
// the connection after the setup budget when the server does not confirm
// the end of the channel; otherwise Wait would never return.
func (s *shell) Close() error {
	var err error
	s.once.Do(func() {
		err = s.session.Close()
		if errors.Is(err, io.EOF) {
			err = nil
		}
		if s.closeConn != nil {
			err = errors.Join(err, s.closeConn.Close())
			return
		}
		go s.conn.closeUnlessDone(s.exited)
	})
	return err
}
