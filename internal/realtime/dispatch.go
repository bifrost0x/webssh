package realtime

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"time"

	"github.com/coder/websocket"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// asyncRetry is the retry hint when a connection has too many requests in
// flight.
const asyncRetry = 100 * time.Millisecond

// registry maps message types to routes. It is filled before the endpoint
// serves and read-only afterwards.
type registry struct {
	routes     map[string]protocol.Route
	maxPayload int
	keepalive  []func(protocol.Peer)
}

// endpoint is what the dispatcher needs from a connection; *Conn
// implements it, the fuzz test a recorder.
type endpoint interface {
	protocol.Peer
	sendText(data []byte) error
	closeWith(code websocket.StatusCode, reason string)
	async(f func()) bool
}

// Mount adds routes. It panics on a duplicate or invalid type, a wiring
// error found at start.
func (s *Server) Mount(routes ...protocol.Route) {
	s.mustNotServe()
	for _, rt := range routes {
		if !protocol.ValidType(rt.Type) || rt.Type == protocol.TypeResult || rt.Run == nil {
			panic("realtime: invalid route " + rt.Type)
		}
		if m, ok := protocol.Lookup(rt.Type); ok && m.Dir != protocol.ClientRequest {
			panic("realtime: " + rt.Type + " is a server event")
		}
		if _, dup := s.reg.routes[rt.Type]; dup {
			panic("realtime: duplicate message type " + rt.Type)
		}
		if rt.Spec.MaxPayload <= 0 {
			rt.Spec.MaxPayload = protocol.DefaultMaxPayload
		}
		if rt.Spec.Timeout <= 0 {
			rt.Spec.Timeout = protocol.DefaultTimeout
		}
		s.reg.maxPayload = max(s.reg.maxPayload, rt.Spec.MaxPayload)
		s.reg.routes[rt.Type] = rt
	}
}

// OnKeepalive registers a function that runs on every session.keepalive
// of a connection (the terminal records activity). It runs on the read
// loop and must not block.
func (s *Server) OnKeepalive(f func(protocol.Peer)) {
	s.mustNotServe()
	s.reg.keepalive = append(s.reg.keepalive, f)
}

// keepaliveRoute is the endpoint's own message type.
func (s *Server) keepaliveRoute() protocol.Route {
	return protocol.Handle(protocol.TypeSessionKeepalive, protocol.Spec{MaxPayload: 64},
		func(_ context.Context, peer protocol.Peer, _ protocol.Empty) (*protocol.Empty, error) {
			for _, f := range s.reg.keepalive {
				f(peer)
			}
			return nil, nil
		})
}

// dispatch handles one text frame. A returned error is a protocol
// violation and closes the connection; request errors become results.
func (s *Server) dispatch(ep endpoint, data []byte) error {
	env, err := protocol.DecodeEnvelope(data)
	if err != nil {
		return err
	}
	route, ok := s.reg.routes[env.T]
	if !ok {
		s.reply(ep, env, nil, fault.New(fault.UnknownType, ""))
		return nil
	}
	if len(env.P) > route.Spec.MaxPayload {
		s.reply(ep, env, nil, fault.New(fault.TooLarge, ""))
		return nil
	}
	if route.Spec.RateKey != "" && s.deps.Limiter != nil {
		if ok, after := s.deps.Limiter.Allow(ep.Principal().UserID, route.Spec.RateKey); !ok {
			e := fault.New(fault.RateLimited, "")
			e.RetryAfter = after
			s.reply(ep, env, nil, e)
			return nil
		}
	}
	if !route.Spec.Async {
		s.invoke(ep, env, route)
		return nil
	}
	if !ep.async(func() { s.invoke(ep, env, route) }) {
		e := fault.New(fault.RateLimited, "Too many requests are in progress.")
		e.RetryAfter = asyncRetry
		s.reply(ep, env, nil, e)
	}
	return nil
}

func (s *Server) invoke(ep endpoint, env protocol.Envelope, route protocol.Route) {
	ctx, cancel := context.WithTimeout(ep.Context(), route.Spec.Timeout)
	defer cancel()
	p := ep.Principal()
	if route.Spec.Mutates {
		if err := s.deps.Sessions.Check(ctx, p); err != nil {
			// The session ended: the handler must not run (contract).
			ep.closeWith(protocol.CloseUnauthenticated, "session_ended")
			return
		}
	}
	resp, err := s.run(ctx, ep, env, route)
	if route.Spec.Mutates && s.deps.Auditor != nil {
		s.deps.Auditor.RealtimeCall(context.WithoutCancel(ctx), p, env.T, err)
	}
	s.reply(ep, env, resp, err)
}

// run calls the handler and turns a panic into an internal error, so that
// one faulty handler does not end the process.
func (s *Server) run(ctx context.Context, ep endpoint, env protocol.Envelope, route protocol.Route) (resp any, err error) {
	defer func() {
		if r := recover(); r != nil {
			resp, err = nil, fmt.Errorf("realtime: handler %s panicked: %v", env.T, r)
		}
	}()
	return route.Run(ctx, ep, env.P)
}

// reply sends the result of a request that carried an id. Errors are
// converted with protocol.WireError; unclassified ones are logged here and
// leave only "internal" on the wire.
func (s *Server) reply(ep endpoint, env protocol.Envelope, resp any, err error) {
	if err != nil {
		if _, classified := fault.From(err); !classified {
			s.log.Error("realtime handler failed", "type", env.T, "err", err)
		}
	}
	if env.ID == "" || ep.Context().Err() != nil {
		return
	}
	res := protocol.Result{OK: err == nil, Err: protocol.WireError(err)}
	if err == nil && resp != nil {
		raw, merr := json.Marshal(resp)
		switch {
		case merr != nil:
			s.log.Error("realtime result encoding failed", "type", env.T, "err", merr)
			res = protocol.Result{Err: protocol.WireError(fault.New(fault.Internal, ""))}
		case jsontext.Value(raw).Kind() == 'n':
			// A nil pointer result means "no payload".
		default:
			res.P = raw
		}
	}
	b, merr := protocol.EncodeEnvelope(protocol.TypeResult, env.ID, res)
	if merr != nil {
		s.log.Error("realtime result envelope failed", "type", env.T, "err", merr)
		return
	}
	_ = ep.sendText(b)
}
