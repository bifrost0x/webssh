package realtime

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// stalledConn returns a server connection whose writer does not run, so
// that everything sent stays in the outbound queue, and the client end.
func stalledConn(t *testing.T, cfg Config) (*Conn, *client) {
	t.Helper()
	s := newFakeSessions()
	srv, err := NewServer(cfg, Deps{Origin: &OriginPolicy{}, Sessions: s, Revocations: &s.feed, Log: discardLog()})
	if err != nil {
		t.Fatal(err)
	}
	conns := make(chan *Conn, 1)
	done := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, raw, err := upgrade(w, r, nil)
		if err != nil {
			return
		}
		c := newConn(srv, ws, raw, principaltest.User(1))
		c.io = context.WithoutCancel(r.Context())
		c.ctx, c.cancel = context.WithCancelCause(c.io)
		conns <- c
		<-done
		c.closeWith(websocket.StatusNormalClosure, "")
		<-c.closed
	}))
	t.Cleanup(ts.Close)
	t.Cleanup(func() { close(done) })
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(ts.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ws.CloseNow() })
	return <-conns, &client{t: t, ctx: ctx, ws: ws}
}

// The outbound queue is bounded by bytes, not only by messages (condition
// K6: the byte limit must be tested, so that removing it fails here). A
// connection over the limit is closed with 4008 instead of buffering.
func TestQueueByteLimit(t *testing.T) {
	const limit = 10_000
	c, cl := stalledConn(t, Config{QueueBytes: limit, QueueLen: 512})
	frame := make([]byte, 4000)
	for i := range 2 {
		if err := c.SendBinary(frame); err != nil {
			t.Fatalf("frame %d within the limit: %v", i, err)
		}
	}
	if got := c.QueuedBytes(); got != 8000 {
		t.Fatalf("queued %d bytes, want 8000", got)
	}
	if err := c.SendBinary(frame); !errors.Is(err, ErrClosed) {
		t.Fatalf("frame over the byte limit: %v", err)
	}
	if got := c.QueuedBytes(); got > limit {
		t.Fatalf("queued %d bytes over the limit %d", got, limit)
	}
	if err := c.SendEvent("test.event", nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("send after the overflow: %v", err)
	}
	if code, reason := cl.closeStatus(); code != protocol.CloseSlowConsumer || reason != "outbound queue full" {
		t.Fatalf("close %d %q", code, reason)
	}
}

// A frame exactly at the limit still fits.
func TestQueueByteLimitBoundary(t *testing.T) {
	c, _ := stalledConn(t, Config{QueueBytes: 8000})
	if err := c.SendBinary(make([]byte, 8000)); err != nil {
		t.Fatal(err)
	}
	if err := c.SendBinary([]byte{1}); !errors.Is(err, ErrClosed) {
		t.Fatalf("one byte over the limit: %v", err)
	}
}

func TestQueueMessageLimit(t *testing.T) {
	c, cl := stalledConn(t, Config{QueueLen: 4})
	for i := range 4 {
		if err := c.SendBinary([]byte{byte(i)}); err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
	}
	if err := c.SendBinary([]byte{9}); !errors.Is(err, ErrClosed) {
		t.Fatalf("fifth message: %v", err)
	}
	if got := c.QueuedBytes(); got != 4 {
		t.Fatalf("queued bytes %d after a refused message, want 4", got)
	}
	if code, _ := cl.closeStatus(); code != protocol.CloseSlowConsumer {
		t.Fatalf("close %d", code)
	}
}

// A client that stops reading is cut off after WriteTimeout, with a
// bounded queue in between: the end-to-end form of the limits above.
func TestStalledClientIsCutOff(t *testing.T) {
	sent := make(chan error, 1)
	e := newEnv(t, Config{QueueBytes: 1 << 20, WriteTimeout: 300 * time.Millisecond}, func(s *Server) {
		s.Mount(protocol.Handle("test.flood", protocol.Spec{Async: true, Timeout: time.Minute},
			func(ctx context.Context, peer protocol.Peer, _ protocol.Empty) (*protocol.Empty, error) {
				chunk := make([]byte, 64<<10)
				for {
					if err := peer.SendBinary(chunk); err != nil {
						sent <- err
						return nil, nil
					}
					if ctx.Err() != nil {
						sent <- ctx.Err()
						return nil, nil
					}
				}
			}))
	})
	c := e.open(1, "s1")
	c.write(`{"v":1,"t":"test.flood"}`)
	// The client reads nothing; the server must give up on its own.
	select {
	case err := <-sent:
		if !errors.Is(err, ErrClosed) && !errors.Is(err, context.Canceled) {
			t.Fatalf("flood ended with %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server kept buffering for a client that does not read")
	}
	waitFor(t, func() bool { return e.srv.Stats().Conns == 0 })
}
