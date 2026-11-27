package realtime

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// ErrClosed is returned by sends after the connection ended or began to
// close.
var ErrClosed = errors.New("realtime: connection closed")

// helloTimeout bounds the lookup of restorable sessions for hello.
const helloTimeout = 5 * time.Second

// Conn is one browser connection. The HTTP handler goroutine runs the read
// loop; a writer goroutine and a keepalive goroutine belong to it. All of
// them end before run returns.
//
// Two contexts are kept apart on purpose. ctx is the peer context handed to
// handlers: it is cancelled the moment the connection starts to close, so
// that a revocation stops work at once. WebSocket I/O uses io, which is
// never cancelled, because the library tears a connection down without a
// close frame when the context of a Read ends (K6, sharp edge 3); Close
// unblocks it instead.
type Conn struct {
	srv *Server
	ws  *websocket.Conn
	raw net.Conn // under ws, for bounded closes
	p   principal.Principal
	id  uint64

	io     context.Context
	ctx    context.Context
	cancel context.CancelCauseFunc

	out    chan outbound
	queued atomic.Int64 // bytes waiting in out

	closeOnce sync.Once
	closed    chan struct{} // closed when the close handshake has ended

	inflight chan struct{}
	wg       sync.WaitGroup
}

type outbound struct {
	typ  websocket.MessageType
	data []byte
}

var connIDs atomic.Uint64

func newConn(s *Server, ws *websocket.Conn, raw net.Conn, p principal.Principal) *Conn {
	return &Conn{
		srv: s, ws: ws, raw: raw, p: p, id: connIDs.Add(1),
		out:      make(chan outbound, s.cfg.QueueLen),
		closed:   make(chan struct{}),
		inflight: make(chan struct{}, s.cfg.InflightPerConn),
	}
}

// ID implements protocol.Peer.
func (c *Conn) ID() uint64 { return c.id }

// Principal implements protocol.Peer.
func (c *Conn) Principal() principal.Principal { return c.p }

// Context implements protocol.Peer.
func (c *Conn) Context() context.Context { return c.ctx }

func (c *Conn) run(parent context.Context) {
	// The request context ends when the handler returns or the hijacked
	// connection goes away; detach so that the close handshake can run.
	c.io = context.WithoutCancel(parent)
	c.ctx, c.cancel = context.WithCancelCause(principal.With(c.io, c.p))
	defer c.finish()

	// Register before the second check and before hello: a revocation is
	// either delivered to this connection or seen by Check (contract).
	c.srv.sessions.add(c)
	for _, f := range c.srv.onOpen {
		f(c)
	}
	if c.srv.shutdown.Load() {
		c.closeWith(protocol.CloseMaintenance, "the server is shutting down")
		return
	}
	if err := c.srv.deps.Sessions.Check(c.ctx, c.p); err != nil {
		c.closeWith(protocol.CloseUnauthenticated, "session_ended")
		return
	}
	c.wg.Go(c.writeLoop)
	c.wg.Go(c.keepalive)
	if err := c.SendEvent(protocol.TypeHello, c.hello()); err != nil {
		return
	}
	c.readLoop()
}

func (c *Conn) hello() protocol.Hello {
	h := protocol.Hello{
		User:       protocol.HelloUser{Username: c.p.Username, IsAdmin: c.p.IsAdmin},
		Schema:     protocol.Version,
		Restorable: []protocol.SessionInfo{},
		Persistent: []protocol.SessionInfo{},
	}
	if c.srv.restorer == nil {
		return h
	}
	ctx, cancel := context.WithTimeout(c.ctx, helloTimeout)
	defer cancel()
	if list, err := c.srv.restorer.Restorable(ctx, c.p); err != nil {
		c.srv.log.Error("realtime hello: restorable sessions", "err", err)
	} else if list != nil {
		h.Restorable = list
	}
	if list, err := c.srv.restorer.Persistent(ctx, c.p); err != nil {
		c.srv.log.Error("realtime hello: persistent sessions", "err", err)
	} else if list != nil {
		h.Persistent = list
	}
	return h
}

func (c *Conn) readLoop() {
	for {
		typ, data, err := c.ws.Read(c.io)
		if err != nil || c.ctx.Err() != nil {
			// Nothing read after the connection began to close is acted
			// on, so a revoked session cannot send input or requests.
			return
		}
		switch typ {
		case websocket.MessageText:
			if err := c.srv.dispatch(c, data); err != nil {
				c.closeWith(protocol.CloseProtocolViolation, "malformed message")
				return
			}
		case websocket.MessageBinary:
			if c.srv.binary == nil {
				c.closeWith(protocol.CloseProtocolViolation, "binary frames not accepted")
				return
			}
			if err := c.srv.binary(c, data); err != nil {
				c.closeWith(protocol.CloseProtocolViolation, "malformed binary frame")
				return
			}
		}
	}
}

func (c *Conn) writeLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case m := <-c.out:
			c.queued.Add(-int64(len(m.data)))
			if c.ctx.Err() != nil {
				return
			}
			wctx, cancel := context.WithTimeout(c.io, c.srv.cfg.WriteTimeout)
			err := c.ws.Write(wctx, m.typ, m.data)
			cancel()
			if err != nil {
				// A client that does not read for WriteTimeout is cut off;
				// nothing is buffered beyond the bounded queue.
				c.closeWith(protocol.CloseSlowConsumer, "write timeout")
				return
			}
		}
	}
}

func (c *Conn) keepalive() {
	ping := time.NewTicker(c.srv.cfg.PingInterval)
	defer ping.Stop()
	recheck := time.NewTicker(c.srv.cfg.RecheckInterval)
	defer recheck.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ping.C:
			pctx, cancel := context.WithTimeout(c.io, c.srv.cfg.WriteTimeout)
			err := c.ws.Ping(pctx)
			cancel()
			if err != nil && c.ctx.Err() == nil {
				c.closeWith(protocol.CloseSlowConsumer, "keepalive timeout")
				return
			}
		case <-recheck.C:
			if err := c.srv.deps.Sessions.Check(c.ctx, c.p); err != nil && c.ctx.Err() == nil {
				c.closeWith(protocol.CloseUnauthenticated, "session_ended")
				return
			}
		}
	}
}

// send enqueues without blocking. A full queue, by messages or by bytes,
// means the client stopped reading: the connection is closed with 4008
// instead of growing a buffer.
func (c *Conn) send(typ websocket.MessageType, data []byte) error {
	if c.ctx.Err() != nil {
		return ErrClosed
	}
	n := int64(len(data))
	if c.queued.Add(n) > c.srv.cfg.QueueBytes {
		c.queued.Add(-n)
		c.closeWith(protocol.CloseSlowConsumer, "outbound queue full")
		return ErrClosed
	}
	select {
	case c.out <- outbound{typ, data}:
		return nil
	default:
		c.queued.Add(-n)
		c.closeWith(protocol.CloseSlowConsumer, "outbound queue full")
		return ErrClosed
	}
}

func (c *Conn) sendText(data []byte) error { return c.send(websocket.MessageText, data) }

// SendEvent implements protocol.Peer: a server event without id.
func (c *Conn) SendEvent(typ string, payload any) error {
	b, err := protocol.EncodeEnvelope(typ, "", payload)
	if err != nil {
		return err
	}
	return c.sendText(b)
}

// SendBinary implements protocol.Peer. Output credit is bounded by the
// terminal; the queue limits are the backstop.
func (c *Conn) SendBinary(frame []byte) error {
	return c.send(websocket.MessageBinary, frame)
}

// closeWith ends the connection with a close code the page can read. It
// never blocks and is safe to call from any goroutine and more than once;
// the first call wins. The peer context is cancelled before it returns.
func (c *Conn) closeWith(code websocket.StatusCode, reason string) {
	c.closeOnce.Do(func() {
		c.cancel(ErrClosed)
		go func() {
			defer close(c.closed)
			// The close frame goes out and the read loop ends with the
			// answer, or after closeGrace without it.
			closeBounded(c.ws, c.raw, code, reason)
		}()
	})
}

// async runs f in its own goroutine if the connection has a free slot.
func (c *Conn) async(f func()) bool {
	select {
	case c.inflight <- struct{}{}:
	default:
		return false
	}
	c.wg.Go(func() {
		defer func() { <-c.inflight }()
		f()
	})
	return true
}

func (c *Conn) finish() {
	// Read errors end here. Without an earlier close use the normal code,
	// then wait for the handshake so that the page sees the code instead
	// of a dropped connection. The close goroutine ends before finish
	// returns.
	c.closeWith(websocket.StatusNormalClosure, "")
	<-c.closed
	_ = c.ws.CloseNow()
	c.wg.Wait()
	c.srv.sessions.remove(c)
	for _, f := range c.srv.onClose {
		f(c)
	}
}

// QueuedBytes reports bytes waiting for the writer.
func (c *Conn) QueuedBytes() int64 { return c.queued.Load() }

var _ protocol.Peer = (*Conn)(nil)
