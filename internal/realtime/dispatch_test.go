package realtime

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

type echoReq struct {
	Text string `json:"text"`
}

// testRoutes mounts the handlers the dispatcher tests use.
func testRoutes(ran *atomic.Int32, release chan struct{}) func(*Server) {
	return func(s *Server) {
		s.Mount(
			protocol.Handle("test.echo", protocol.Spec{MaxPayload: 64}, func(_ context.Context, _ protocol.Peer, r echoReq) (echoReq, error) {
				return r, nil
			}),
			protocol.Handle("test.mutate", protocol.Spec{Mutates: true}, func(context.Context, protocol.Peer, protocol.Empty) (*protocol.Empty, error) {
				ran.Add(1)
				return nil, nil
			}),
			protocol.Handle("test.denied", protocol.Spec{Mutates: true}, func(context.Context, protocol.Peer, protocol.Empty) (*protocol.Empty, error) {
				return nil, fault.New(fault.Forbidden, "")
			}),
			protocol.Handle("test.fail", protocol.Spec{}, func(context.Context, protocol.Peer, protocol.Empty) (*protocol.Empty, error) {
				return nil, errors.New("secret detail /var/lib/webssh")
			}),
			protocol.Handle("test.panic", protocol.Spec{}, func(context.Context, protocol.Peer, protocol.Empty) (*protocol.Empty, error) {
				panic("secret detail")
			}),
			protocol.Handle("test.limited", protocol.Spec{RateKey: "test"}, func(context.Context, protocol.Peer, protocol.Empty) (*protocol.Empty, error) {
				return nil, nil
			}),
			protocol.Handle("test.slow", protocol.Spec{Async: true}, func(ctx context.Context, _ protocol.Peer, _ protocol.Empty) (*protocol.Empty, error) {
				select {
				case <-release:
				case <-ctx.Done():
				}
				return nil, ctx.Err()
			}),
			protocol.Handle("test.timeout", protocol.Spec{Async: true, Timeout: 20 * time.Millisecond}, func(ctx context.Context, _ protocol.Peer, _ protocol.Empty) (*protocol.Empty, error) {
				<-ctx.Done()
				return nil, fault.Wrap(fault.Timeout, ctx.Err(), "")
			}),
		)
	}
}

func TestDispatcher(t *testing.T) {
	var ran atomic.Int32
	e := newEnv(t, Config{}, testRoutes(&ran, nil))
	c := e.open(1, "s1")
	if r := c.request(`{"v":1,"t":"test.echo","id":"a1","p":{"text":"hi"}}`); !r.OK || string(r.P) != `{"text":"hi"}` {
		t.Fatalf("echo: %+v", r)
	}
	if r := c.request(`{"v":1,"t":"test.mutate","id":"a0"}`); !r.OK || len(r.P) != 0 {
		t.Fatalf("mutate: %+v", r)
	}
	for _, tc := range []struct {
		msg  string
		code fault.Code
	}{
		{`{"v":1,"t":"no.such","id":"a2"}`, fault.UnknownType},
		{`{"v":1,"t":"result","id":"a2b"}`, fault.UnknownType},
		{`{"v":1,"t":"test.echo","id":"a3","p":{"text":"` + strings.Repeat("x", 100) + `"}}`, fault.TooLarge},
		{`{"v":1,"t":"test.echo","id":"a4","p":{"text":"x","extra":1}}`, fault.InvalidRequest},
		{`{"v":1,"t":"test.echo","id":"a4b","p":{"Text":"x"}}`, fault.InvalidRequest},
		{`{"v":1,"t":"test.fail","id":"a5"}`, fault.Internal},
		{`{"v":1,"t":"test.panic","id":"a6"}`, fault.Internal},
		{`{"v":1,"t":"test.denied","id":"a7"}`, fault.Forbidden},
	} {
		r := c.request(tc.msg)
		if r.OK || errCode(r) != tc.code {
			t.Errorf("%s: %+v", tc.msg, r)
		}
		if r.Err != nil && strings.Contains(r.Err.Message, "secret") {
			t.Errorf("%s: internal detail leaked: %q", tc.msg, r.Err.Message)
		}
	}
	// The connection survived the panic and every error.
	if r := c.request(`{"v":1,"t":"session.keepalive","id":"k"}`); !r.OK {
		t.Fatalf("keepalive: %+v", r)
	}
	calls := e.auditor.all()
	if len(calls) != 2 || calls[0].typ != "test.mutate" || calls[0].err != nil || calls[1].typ != "test.denied" || !fault.Is(calls[1].err, fault.Forbidden) {
		t.Fatalf("audit calls %+v", calls)
	}
}

func TestFireAndForgetGetsNoResult(t *testing.T) {
	e := newEnv(t, Config{}, testRoutes(new(atomic.Int32), nil))
	c := e.open(1, "s1")
	c.write(`{"v":1,"t":"test.fail"}`)
	c.write(`{"v":1,"t":"no.such"}`)
	c.write(`{"v":1,"t":"test.echo"}`)
	if r := c.request(`{"v":1,"t":"test.echo","id":"x","p":{"text":"after"}}`); string(r.P) != `{"text":"after"}` {
		t.Fatalf("first reply was not for the request with id: %+v", r)
	}
}

func TestRateLimit(t *testing.T) {
	e := newEnv(t, Config{}, testRoutes(new(atomic.Int32), nil))
	e.limiter.deny = true
	c := e.open(1, "s1")
	r := c.request(`{"v":1,"t":"test.limited","id":"r"}`)
	if errCode(r) != fault.RateLimited || r.Err.RetryAfterMS != 1500 {
		t.Fatalf("%+v", r.Err)
	}
	if r := c.request(`{"v":1,"t":"test.echo","id":"e","p":{}}`); !r.OK {
		t.Fatal("routes without RateKey must not be limited")
	}
}

func TestAsyncInflightBound(t *testing.T) {
	release := make(chan struct{})
	e := newEnv(t, Config{InflightPerConn: 2}, testRoutes(new(atomic.Int32), release))
	c := e.open(1, "s1")
	c.write(`{"v":1,"t":"test.slow","id":"1"}`)
	c.write(`{"v":1,"t":"test.slow","id":"2"}`)
	r := c.request(`{"v":1,"t":"test.slow","id":"3"}`)
	if errCode(r) != fault.RateLimited || r.Err.RetryAfterMS != asyncRetry.Milliseconds() {
		t.Fatalf("third async request: %+v", r)
	}
	// Inline requests are not blocked by async ones.
	if r := c.request(`{"v":1,"t":"test.echo","id":"e","p":{}}`); !r.OK {
		t.Fatalf("inline: %+v", r)
	}
	close(release)
	for range 2 {
		if env := c.read(); env.T != protocol.TypeResult {
			t.Fatalf("got %s", env.T)
		}
	}
}

func TestHandlerTimeout(t *testing.T) {
	e := newEnv(t, Config{}, testRoutes(new(atomic.Int32), nil))
	c := e.open(1, "s1")
	if r := c.request(`{"v":1,"t":"test.timeout","id":"t"}`); errCode(r) != fault.Timeout {
		t.Fatalf("%+v", r)
	}
}

func TestMalformedEnvelopeCloses(t *testing.T) {
	for _, msg := range []string{
		`{"v":1,"t":"test.echo","junk":true}`,
		`{"v":1,"t":"test.echo"}}`,
		`{"V":1,"t":"test.echo"}`,
		`{"v":1,"t":"test.echo","t":"other"}`,
		`{"v":1,"t":"test.echo","p":{"text":"x","text":"y"}}`,
		`{"v":2,"t":"test.echo"}`,
		`{"v":1,"t":"Test.Echo"}`,
		`{"v":1,"t":"test.echo","p":[]}`,
		"not json",
	} {
		e := newEnv(t, Config{}, testRoutes(new(atomic.Int32), nil))
		c := e.open(1, "s1")
		c.write(msg)
		if code, _ := c.closeStatus(); code != protocol.CloseProtocolViolation {
			t.Fatalf("%s: close %d", msg, code)
		}
	}
}

func TestBinary(t *testing.T) {
	t.Run("without handler closes", func(t *testing.T) {
		e := newEnv(t, Config{}, nil)
		c := e.open(1, "s1")
		_ = c.ws.Write(c.ctx, websocket.MessageBinary, []byte{1, 2, 3})
		if code, _ := c.closeStatus(); code != protocol.CloseProtocolViolation {
			t.Fatalf("close %d", code)
		}
	})
	t.Run("handler error closes", func(t *testing.T) {
		var got atomic.Int32
		e := newEnv(t, Config{}, func(s *Server) {
			s.HandleBinary(func(_ protocol.Peer, b []byte) error {
				if _, err := protocol.DecodeFrame(b, 1024); err != nil {
					return err
				}
				got.Add(1)
				return nil
			})
		})
		c := e.open(1, "s1")
		frame := protocol.AppendFrame(nil, protocol.Frame{Kind: protocol.KindAck, Channel: 1, Seq: 9})
		_ = c.ws.Write(c.ctx, websocket.MessageBinary, frame)
		_ = c.ws.Write(c.ctx, websocket.MessageBinary, []byte{9})
		if code, _ := c.closeStatus(); code != protocol.CloseProtocolViolation {
			t.Fatalf("close %d", code)
		}
		if got.Load() != 1 {
			t.Fatalf("handled %d frames", got.Load())
		}
	})
}

func TestKeepaliveHook(t *testing.T) {
	var touched atomic.Uint64
	e := newEnv(t, Config{}, func(s *Server) {
		s.OnKeepalive(func(p protocol.Peer) { touched.Store(p.ID()) })
	})
	c := e.open(1, "s1")
	c.write(`{"v":1,"t":"session.keepalive"}`)
	if r := c.request(`{"v":1,"t":"session.keepalive","id":"k","p":{}}`); !r.OK {
		t.Fatalf("%+v", r)
	}
	if touched.Load() == 0 {
		t.Fatal("keepalive hook did not run")
	}
	if r := c.request(`{"v":1,"t":"session.keepalive","id":"k2","p":{"x":1}}`); errCode(r) != fault.InvalidRequest {
		t.Fatalf("%+v", r)
	}
}

func TestMountRejectsWiringErrors(t *testing.T) {
	noop := func(context.Context, protocol.Peer, protocol.Empty) (*protocol.Empty, error) { return nil, nil }
	for name, rt := range map[string]protocol.Route{
		"result type":    protocol.Handle(protocol.TypeResult, protocol.Spec{}, noop),
		"server event":   protocol.Handle(protocol.TypeHello, protocol.Spec{}, noop),
		"invalid name":   protocol.Handle("Bad Type", protocol.Spec{}, noop),
		"nil handler":    {Type: "test.nil"},
		"duplicate type": protocol.Handle(protocol.TypeSessionKeepalive, protocol.Spec{}, noop),
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: Mount did not panic", name)
				}
			}()
			e := newEnv(t, Config{}, nil)
			e.srv.Mount(rt)
		}()
	}
}
