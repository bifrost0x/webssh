package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
)

// stallMode selects where a stalling server stops answering.
type stallMode int

const (
	// stallOpen never confirms or rejects a channel.
	stallOpen stallMode = iota
	// stallRequest confirms channels but never answers a channel request.
	stallRequest
	// stallClose starts every exec and shell request, then goes silent:
	// nothing more is sent, so the close of a channel is never confirmed.
	stallClose
)

// muteConn discards everything written after the write that follows
// muteAfterNext, so a reply still goes out and nothing after it.
type muteConn struct {
	net.Conn
	next  atomic.Bool
	muted atomic.Bool
}

func (m *muteConn) muteAfterNext() { m.next.Store(true) }

func (m *muteConn) Write(p []byte) (int, error) {
	if m.muted.Load() {
		return len(p), nil
	}
	n, err := m.Conn.Write(p)
	if m.next.Load() {
		m.muted.Store(true)
	}
	return n, err
}

// stallingServer accepts every login and answers keepalives, so the
// transport looks healthy, but stops answering at mode. It reports how
// many TCP connections are still open.
type stallingServer struct {
	host    string
	port    int
	hostKey ssh.PublicKey

	mu   sync.Mutex
	open int
	seen chan struct{} // one value per channel the server is holding
}

func startStallingServer(t *testing.T, mode stallMode) *stallingServer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(signer)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &stallingServer{host: "127.0.0.1", port: l.Addr().(*net.TCPAddr).Port, hostKey: signer.PublicKey(), seen: make(chan struct{}, 64)}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = l.Close(); wg.Wait() })
	wg.Go(func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			wg.Go(func() { s.serve(conn, cfg, mode) })
		}
	})
	return s
}

func (s *stallingServer) serve(conn net.Conn, cfg *ssh.ServerConfig, mode stallMode) {
	s.mu.Lock()
	s.open++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.open--
		s.mu.Unlock()
	}()
	defer func() { _ = conn.Close() }()
	mute := &muteConn{Conn: conn}
	sc, chans, reqs, err := ssh.NewServerConn(mute, cfg)
	if err != nil {
		return
	}
	defer func() { _ = sc.Close() }()
	go func() {
		for req := range reqs {
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		}
	}()
	var accepted []ssh.Channel
	for nc := range chans {
		if mode == stallOpen {
			s.seen <- struct{}{} // neither confirmed nor rejected
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		accepted = append(accepted, ch)
		s.seen <- struct{}{}
		go func() {
			for req := range creqs {
				if mode != stallClose {
					continue // never answered
				}
				if req.Type == "exec" || req.Type == "shell" {
					mute.muteAfterNext()
				}
				_ = req.Reply(true, nil)
			}
		}()
	}
	for _, ch := range accepted {
		_ = ch.Close()
	}
}

func (s *stallingServer) connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.open
}

// waitClosed waits until the server saw every connection end.
func (s *stallingServer) waitClosed(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for s.connections() > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d connections still open", s.connections())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func dialStalling(t *testing.T, mode stallMode, budget time.Duration) (*stallingServer, *Conn) {
	t.Helper()
	s := startStallingServer(t, mode)
	hk := &memHostKeys{keys: map[string]ssh.PublicKey{joinHostPort(s.host, s.port): s.hostKey}}
	d, _ := newDialer(hk, nil)
	d.HandshakeTimeout = budget
	c, err := d.Dial(t.Context(), Target{Owner: 1, Hop: Hop{Host: s.host, Port: s.port, User: "u", Auth: Auth{Password: "pw"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return s, c
}

// A server that holds the channel setup must not hold the caller: the
// handshake budget ends it and closes the connection (R2 M-1).
func TestChannelSetupIsBounded(t *testing.T) {
	const budget = 300 * time.Millisecond
	calls := map[string]func(context.Context, *Conn) error{
		"shell": func(ctx context.Context, c *Conn) error { _, err := c.Shell(ctx, 24, 80); return err },
		"command shell": func(ctx context.Context, c *Conn) error {
			_, err := c.CommandShell(ctx, "tmux new-session", 24, 80)
			return err
		},
		"exec": func(ctx context.Context, c *Conn) error {
			_, err := c.Exec(ctx, "command -v tmux", nil, nil, nil)
			return err
		},
	}
	for mode, stage := range []string{"open", "request"} {
		for name, call := range calls {
			t.Run(stage+"/"+name, func(t *testing.T) {
				s, c := dialStalling(t, stallMode(mode), budget)
				start := time.Now()
				done := make(chan error, 1)
				go func() { done <- call(t.Context(), c) }()
				select {
				case err := <-done:
					if fault.CodeOf(err) != fault.Timeout {
						t.Fatalf("mode %d: %v, want timeout", mode, err)
					}
					// An unanswered exec request may have started the
					// command; a channel that never opened cannot have.
					if sent := name == "exec" && stage == "request"; errors.Is(err, ErrExecUnconfirmed) != sent {
						t.Fatalf("mode %d: unconfirmed %v, want %v", mode, errors.Is(err, ErrExecUnconfirmed), sent)
					}
				case <-time.After(10 * budget):
					t.Fatalf("mode %d: still waiting after %v", mode, time.Since(start))
				}
				if name == "exec" {
					// A command ends on its own; the terminal on the
					// connection stays (RC0-1).
					select {
					case <-c.Done():
						t.Fatal("a stalled command closed the connection")
					case <-time.After(2 * budget):
					}
					_ = c.Close()
					s.waitClosed(t)
					return
				}
				select {
				case <-c.Done():
				case <-time.After(time.Second):
					t.Fatal("connection left open")
				}
				s.waitClosed(t)
			})
		}
	}
}

// Cancelling the caller ends a stalled setup at once, long before the
// budget, and closes the connection.
func TestChannelSetupEndsWithContext(t *testing.T) {
	for _, mode := range []stallMode{stallOpen, stallRequest} {
		s, c := dialStalling(t, mode, time.Minute)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { _, err := c.Shell(ctx, 24, 80); done <- err }()
		<-s.seen
		cancel()
		select {
		case err := <-done:
			if fault.CodeOf(err) != fault.Cancelled {
				t.Fatalf("mode %d: %v, want cancelled", mode, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("mode %d: cancel did not end the setup", mode)
		}
		s.waitClosed(t)
	}
}

// The guard ends with a successful setup: a shell that outlives the budget
// keeps working and the connection stays open.
func TestChannelGuardEndsAfterSetup(t *testing.T) {
	calls := 0
	s := startServer(t, passwordServer("u", "pw", &calls))
	d, _ := newDialer(trusting(s), nil)
	d.HandshakeTimeout = 200 * time.Millisecond
	c, err := d.Dial(t.Context(), target(s, "u", Auth{Password: "pw"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	sh, err := c.Shell(t.Context(), 24, 80)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sh.Close() }()
	time.Sleep(500 * time.Millisecond)
	if _, err := sh.Write([]byte("ping\n")); err != nil {
		t.Fatalf("shell closed after the budget: %v", err)
	}
	if code, err := c.Exec(t.Context(), "exit 0", nil, nil, nil); err != nil || code != 0 {
		t.Fatalf("connection closed after the budget: %d %v", code, err)
	}
}

// A server that never confirms the close of a channel after the command
// started must not hold Exec: it returns at its deadline and leaves the
// connection open. The unconfirmed channels are counted, and with
// maxAbandoned of them Exec refuses new commands instead of piling up
// sessions on the host (RC0-1).
func TestExecEndsWhenTheServerIgnoresTheClose(t *testing.T) {
	s, c := dialStalling(t, stallClose, 300*time.Millisecond)
	for i := range maxAbandoned {
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		start := time.Now()
		_, err := c.Exec(ctx, "sleep 60", nil, nil, nil)
		cancel()
		if fault.CodeOf(err) != fault.Timeout {
			t.Fatalf("exec %d: %v", i, err)
		}
		if took := time.Since(start); took > time.Second {
			t.Fatalf("exec %d returned after %v", i, took)
		}
	}
	if _, err := c.Exec(t.Context(), "true", nil, nil, nil); fault.CodeOf(err) != fault.Busy {
		t.Fatalf("exec beyond the limit: %v, want busy", err)
	}
	select {
	case <-c.Done():
		t.Fatal("the connection was closed")
	default:
	}
	// Closing the connection ends the waiting goroutines.
	_ = c.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.execMu.Lock()
		n := c.abandoned
		c.execMu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d command goroutines still wait after Close", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.waitClosed(t)
}

// The same for a command shell on a connection that stays open: Close
// ends Wait even when the server never confirms.
func TestShellCloseEndsWhenTheServerIgnoresTheClose(t *testing.T) {
	s, c := dialStalling(t, stallClose, 300*time.Millisecond)
	sh, err := c.CommandShell(t.Context(), "tmux attach", 24, 80)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- sh.Wait() }()
	_ = sh.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Wait still blocked after Close")
	}
	s.waitClosed(t)
}

// A server that confirms the close keeps the connection open.
func TestExecKeepsTheConnectionAfterAConfirmedClose(t *testing.T) {
	c := dialExec(t)
	c.setup = 100 * time.Millisecond
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Exec(ctx, "hang", strings.NewReader(""), nil, nil); fault.CodeOf(err) != fault.Timeout {
		t.Fatalf("hang: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if code, err := c.Exec(t.Context(), "exit 0", nil, nil, nil); err != nil || code != 0 {
		t.Fatalf("connection closed after a confirmed close: %d %v", code, err)
	}
}
