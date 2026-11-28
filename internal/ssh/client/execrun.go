package client

import (
	"context"
	"io"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
)

// maxAbandoned bounds the channels of commands whose caller has gone and
// whose end the server has not confirmed yet. OpenSSH allows ten sessions
// per connection (MaxSessions); the terminal and its file source need two.
const maxAbandoned = 4

var errTooManyAbandoned = fault.New(fault.Busy, "Earlier commands on this host have not ended yet.")

// execRun is one command of Exec. Its goroutine owns the session: it
// opens the channel, starts the command and waits for its end, so the
// caller can leave at any point without closing the connection.
type execRun struct {
	conn     *Conn
	started  chan error // one value: nil once the command started
	finished chan error // one value: the result of Wait

	mu        sync.Mutex
	gone      bool // the caller left; the goroutine ends the channel
	requested bool // the exec request was sent
	cancel    context.CancelFunc
}

func (c *Conn) startExec(command string, stdin io.Reader, stdout, stderr io.Writer) (*execRun, error) {
	c.execMu.Lock()
	if c.abandoned >= maxAbandoned {
		c.execMu.Unlock()
		return nil, errTooManyAbandoned
	}
	c.execMu.Unlock()
	end, cancel := context.WithCancel(context.Background())
	r := &execRun{conn: c, started: make(chan error, 1), finished: make(chan error, 1), cancel: cancel}
	go r.run(end, command, stdin, stdout, stderr)
	return r, nil
}

func (r *execRun) run(end context.Context, command string, stdin io.Reader, stdout, stderr io.Writer) {
	defer r.done()
	s, err := r.conn.client.NewSession()
	if err != nil {
		r.started <- err
		return
	}
	defer func() { _ = s.Close() }()
	s.Stdin, s.Stdout, s.Stderr = stdin, stdout, stderr
	r.mu.Lock()
	if r.gone {
		r.mu.Unlock()
		return
	}
	r.requested = true
	r.mu.Unlock()
	if err := s.Start(command); err != nil {
		r.started <- err
		return
	}
	// Runs at once when the caller already left while the request was
	// on its way. The signal is a courtesy for servers that honour it
	// (OpenSSH 7.9 and later); the close is what paramiko did.
	stop := context.AfterFunc(end, func() {
		_ = s.Signal(ssh.SIGTERM)
		_ = s.Close()
	})
	defer stop()
	r.started <- nil
	r.finished <- s.Wait()
}

// abandon tells the goroutine that the caller left and reports whether
// the exec request was sent, so the command may have started.
func (r *execRun) abandon() (requested bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.gone {
		r.gone = true
		r.conn.execMu.Lock()
		r.conn.abandoned++
		r.conn.execMu.Unlock()
	}
	r.cancel()
	return r.requested
}

// done runs when the goroutine ends: the server confirmed the channel's
// end or the connection closed.
func (r *execRun) done() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cancel()
	if r.gone {
		r.conn.execMu.Lock()
		r.conn.abandoned--
		r.conn.execMu.Unlock()
	}
	r.gone = true
}
