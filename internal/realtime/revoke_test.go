package realtime

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// revocationDeadline is the bound of condition K6: "immediately", tested
// as well under one second.
const revocationDeadline = time.Second

// A revocation closes every connection of the session with 4003 and the
// reason, and nothing else.
func TestRevocationClosesEveryConnectionOfTheSession(t *testing.T) {
	e := newEnv(t, Config{RecheckInterval: time.Hour}, testRoutes(new(atomic.Int32), nil))
	tok := e.sessions.token(1, "s1")
	victims := []*client{e.openToken(tok), e.openToken(tok), e.openToken(tok)}
	sameUser := e.open(1, "s2")
	other := e.open(2, "s3")

	start := time.Now()
	e.sessions.revoke(1, "s1", principal.ReasonLogout)
	for i, c := range victims {
		code, reason := c.closeStatus()
		if code != protocol.CloseUnauthenticated || reason != "logout" {
			t.Fatalf("connection %d: close %d %q", i, code, reason)
		}
	}
	if d := time.Since(start); d > revocationDeadline {
		t.Fatalf("revocation took %v", d)
	}
	for _, c := range []*client{sameUser, other} {
		if r := c.request(`{"v":1,"t":"test.echo","id":"e","p":{}}`); !r.OK {
			t.Fatalf("unrelated connection affected: %+v", r)
		}
	}
	waitFor(t, func() bool { return e.srv.Stats().Conns == 2 })
}

// A revocation reaches running work at once: the peer context ends and
// terminal output (SendBinary) is refused, on every channel of the
// connection.
func TestRevocationStopsHandlersAndOutput(t *testing.T) {
	started := make(chan protocol.Peer, 1)
	stopped := make(chan error, 1)
	e := newEnv(t, Config{RecheckInterval: time.Hour}, func(s *Server) {
		s.Mount(protocol.Handle("test.stream", protocol.Spec{Async: true, Timeout: time.Minute},
			func(ctx context.Context, peer protocol.Peer, _ protocol.Empty) (*protocol.Empty, error) {
				started <- peer
				tick := time.NewTicker(time.Millisecond)
				defer tick.Stop()
				for seq := uint64(1); ; seq++ {
					select {
					case <-ctx.Done():
						// Output after the revocation must be refused.
						f := protocol.AppendFrame(nil, protocol.Frame{Kind: protocol.KindOutput, Channel: 1, Seq: seq, Data: []byte("x")})
						stopped <- peer.SendBinary(f)
						return nil, ctx.Err()
					case <-tick.C:
						for ch := uint32(1); ch <= 3; ch++ {
							f := protocol.AppendFrame(nil, protocol.Frame{Kind: protocol.KindOutput, Channel: ch, Seq: seq, Data: []byte("out")})
							_ = peer.SendBinary(f)
						}
					}
				}
			}))
	})
	c := e.open(1, "s1")
	c.write(`{"v":1,"t":"test.stream","id":"st"}`)
	peer := <-started
	if _, _, err := c.ws.Read(c.ctx); err != nil { // output flows
		t.Fatal(err)
	}
	start := time.Now()
	e.sessions.revoke(1, "s1", principal.ReasonRevokedByUser)
	if peer.Context().Err() == nil {
		t.Fatal("peer context still open after the revocation returned")
	}
	if err := peer.SendEvent("terminal.closed", map[string]string{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("SendEvent after revocation: %v", err)
	}
	select {
	case err := <-stopped:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("SendBinary after revocation: %v", err)
		}
	case <-time.After(revocationDeadline):
		t.Fatal("handler did not stop")
	}
	if code, reason := c.closeStatus(); code != protocol.CloseUnauthenticated || reason != "revoked_by_user" {
		t.Fatalf("close %d %q", code, reason)
	}
	if d := time.Since(start); d > revocationDeadline {
		t.Fatalf("revocation took %v", d)
	}
}

// Input that arrives after the revocation is never acted on: neither
// binary frames (keystrokes) nor requests.
func TestRevocationDropsLaterInput(t *testing.T) {
	var frames, mutations atomic.Int32
	e := newEnv(t, Config{RecheckInterval: time.Hour}, func(s *Server) {
		testRoutes(&mutations, nil)(s)
		s.HandleBinary(func(protocol.Peer, []byte) error {
			frames.Add(1)
			return nil
		})
	})
	c := e.open(1, "s1")
	input := protocol.AppendFrame(nil, protocol.Frame{Kind: protocol.KindInput, Channel: 1, Seq: 1, Data: []byte("ls\n")})
	if err := c.ws.Write(c.ctx, websocket.MessageBinary, input); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return frames.Load() == 1 })

	e.sessions.revoke(1, "s1", principal.ReasonPasswordChanged)
	for range 20 {
		if c.ws.Write(c.ctx, websocket.MessageBinary, input) != nil {
			break
		}
		if c.ws.Write(c.ctx, websocket.MessageText, []byte(`{"v":1,"t":"test.mutate","id":"m"}`)) != nil {
			break
		}
	}
	if code, _ := c.closeStatus(); code != protocol.CloseUnauthenticated {
		t.Fatalf("close %d", code)
	}
	waitFor(t, func() bool { return e.srv.Stats().Conns == 0 })
	if frames.Load() != 1 || mutations.Load() != 0 {
		t.Fatalf("after revocation: %d input frames, %d mutations handled", frames.Load()-1, mutations.Load())
	}
}

// The window between Authenticate and registration: a revocation that was
// published before the connection was registered is seen by Check, one
// published during it reaches the registered connection. Neither gets
// hello.
func TestRevocationDuringUpgrade(t *testing.T) {
	for name, publish := range map[string]bool{"published before registration": false, "published after registration": true} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, Config{RecheckInterval: time.Hour}, nil)
			var once atomic.Bool
			e.sessions.mu.Lock()
			e.sessions.onCheck = func(p principal.Principal) {
				if p.SessionID != "race" || once.Swap(true) {
					return
				}
				if publish {
					// Delivered to the registered connection while Check
					// still says valid: only the registration catches it.
					e.sessions.feed.Revoke(principal.Revocation{SessionID: p.SessionID, UserID: p.UserID, Reason: principal.ReasonLogout})
				} else {
					e.sessions.markRevoked(p.SessionID)
				}
			}
			e.sessions.mu.Unlock()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			ws, _, err := e.dial(ctx, e.ts.URL, e.sessions.token(1, "race"))
			if err != nil {
				t.Fatal(err)
			}
			defer ws.CloseNow()
			_, b, err := ws.Read(ctx)
			if err == nil {
				t.Fatalf("got %s before the close", b)
			}
			if websocket.CloseStatus(err) != protocol.CloseUnauthenticated {
				t.Fatalf("close %v", err)
			}
		})
	}
}

// Requests whose Spec has Mutates re-check the session before the handler
// runs, even when no revocation was published.
func TestMutatingRequestRechecksSession(t *testing.T) {
	var ran atomic.Int32
	e := newEnv(t, Config{RecheckInterval: time.Hour}, testRoutes(&ran, nil))
	c := e.open(1, "s1")
	e.sessions.markRevoked("s1")
	if r := c.request(`{"v":1,"t":"test.echo","id":"e","p":{}}`); !r.OK {
		t.Fatalf("read-only request: %+v", r)
	}
	c.write(`{"v":1,"t":"test.mutate","id":"m"}`)
	if code, _ := c.closeStatus(); code != protocol.CloseUnauthenticated {
		t.Fatalf("close %d", code)
	}
	if ran.Load() != 0 {
		t.Fatal("mutating handler ran for an ended session")
	}
}

// The periodic re-check is the backstop for expiry.
func TestPeriodicRecheckEndsExpiredSession(t *testing.T) {
	e := newEnv(t, Config{RecheckInterval: 50 * time.Millisecond}, nil)
	c := e.open(1, "s1")
	e.sessions.markRevoked("s1")
	if code, _ := c.closeStatus(); code != protocol.CloseUnauthenticated {
		t.Fatalf("close %d", code)
	}
}

// After Shutdown the endpoint no longer listens to revocations.
func TestShutdownUnsubscribes(t *testing.T) {
	e := newEnv(t, Config{}, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := e.srv.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.Shutdown(ctx); err != nil { // idempotent
		t.Fatal(err)
	}
	e.sessions.revoke(1, "s1", principal.ReasonLogout) // must not panic or block
}

func TestCloseReason(t *testing.T) {
	if closeReason("") != "session_ended" || closeReason(principal.ReasonExpired) != "expired" {
		t.Fatal("closeReason")
	}
	long := principal.Reason(make([]byte, 200))
	if closeReason(long) != "session_ended" {
		t.Fatal("long reason not replaced")
	}
}
