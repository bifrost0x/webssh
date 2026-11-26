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
	once   sync.Once
	done   chan struct{}
	wg     sync.WaitGroup
}

func newConn(chain []*ssh.Client, keepalive time.Duration) *Conn {
	c := &Conn{client: chain[len(chain)-1], chain: chain, done: make(chan struct{})}
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

// shell is the Shell of one session.
type shell struct {
	session   *ssh.Session
	stdin     io.WriteCloser
	stdout    io.Reader
	closeConn *Conn
	once      sync.Once
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
	s, err := c.client.NewSession()
	if err != nil {
		return nil, fail(ctx, RoleTarget, false, err)
	}
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()
	failWith := func(err error) (*shell, error) {
		_ = s.Close()
		return nil, fail(ctx, RoleTarget, false, err)
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
	if ctx.Err() != nil {
		return failWith(ctx.Err())
	}
	return &shell{session: s, stdin: stdin, stdout: stdout}, nil
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
func (s *shell) Wait() error { return s.session.Wait() }

// Close ends the session and, for a shell from OpenShell, the connection.
func (s *shell) Close() error {
	var err error
	s.once.Do(func() {
		err = s.session.Close()
		if errors.Is(err, io.EOF) {
			err = nil
		}
		if s.closeConn != nil {
			err = errors.Join(err, s.closeConn.Close())
		}
	})
	return err
}
